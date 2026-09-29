// Copyright 2026 Summon Software Labs
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "check.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/exception.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/timestamp.hpp"

namespace {

namespace json = summon::fbm::json;

using summon::fbm::ApprovalId;
using summon::fbm::AssetId;
using summon::fbm::BaselineException;
using summon::fbm::CapabilityId;
using summon::fbm::classify_exception;
using summon::fbm::Diagnostics;
using summon::fbm::ErrorCode;
using summon::fbm::ExceptionId;
using summon::fbm::ExceptionRegistry;
using summon::fbm::ExceptionScope;
using summon::fbm::ExceptionState;
using summon::fbm::exception_state_from_token;
using summon::fbm::exception_state_token;
using summon::fbm::ExceptionStatus;
using summon::fbm::exception_status_token;
using summon::fbm::Expiry;
using summon::fbm::FirmwareComponentId;
using summon::fbm::HardwareClassId;
using summon::fbm::HardwareModelId;
using summon::fbm::HardwareProfile;
using summon::fbm::HardwareRevision;
using summon::fbm::PolicyGeneration;
using summon::fbm::Result;
using summon::fbm::Revision;
using summon::fbm::Timestamp;

constexpr std::uint64_t kBaseNanos = 1700000000000000000ull;

Timestamp instant(std::uint64_t offset_nanos) {
  return Timestamp::from_unix_nanos(kBaseNanos + offset_nanos);
}

HardwareProfile profile_of(std::string_view model) {
  HardwareProfile profile;
  profile.hardware_class = HardwareClassId{std::string{"gpu"}};
  profile.model = HardwareModelId{std::string{model}};
  profile.revision = HardwareRevision{4u};
  profile.capabilities_observed = true;
  profile.capabilities.push_back(CapabilityId{std::string{"nvlink4"}});
  return profile;
}

ExceptionScope scope_of(std::string_view model, std::string_view asset,
                        std::vector<std::string> components) {
  ExceptionScope scope;
  scope.hardware_class = HardwareClassId{std::string{"gpu"}};
  if (!model.empty()) {
    scope.model = HardwareModelId{std::string{model}};
  }
  if (!asset.empty()) {
    scope.asset = AssetId{std::string{asset}};
  }
  for (const std::string& component : components) {
    scope.components.push_back(FirmwareComponentId{component});
  }
  return scope;
}

BaselineException exception_of(std::string_view id, const ExceptionScope& scope, Expiry expiry,
                               PolicyGeneration granted_under,
                               ExceptionState state = ExceptionState::Active) {
  BaselineException exception;
  exception.id = ExceptionId{std::string{id}};
  exception.scope = scope;
  exception.expiry = expiry;
  exception.reason = "approved maintenance window";
  exception.approval = ApprovalId{std::string{"ap-1"}};
  exception.granted_under = granted_under;
  exception.revision = Revision{1u};
  exception.state = state;
  exception.created_at = instant(0u);
  if (state == ExceptionState::Revoked) {
    exception.revoked_at = instant(10u);
  }
  return exception;
}

std::string canonical_of(const json::Value& value) { return json::write_canonical(value); }

json::Value reparsed(const json::Value& value) {
  Result<json::Value> parsed = json::parse(json::write_canonical(value));
  REQUIRE(parsed.has_value());
  return parsed.take();
}

}  // namespace

FBM_TEST(exception_state_and_status_tokens_are_stable) {
  CHECK_EQ(exception_state_token(ExceptionState::Active), std::string_view{"active"});
  CHECK_EQ(exception_state_token(ExceptionState::Revoked), std::string_view{"revoked"});

  Result<ExceptionState> active = exception_state_from_token("active");
  CHECK_OK(active);
  CHECK_EQ(active.value(), ExceptionState::Active);
  Result<ExceptionState> revoked = exception_state_from_token("revoked");
  CHECK_OK(revoked);
  CHECK_EQ(revoked.value(), ExceptionState::Revoked);
  CHECK_ERROR(exception_state_from_token("pending"), ErrorCode::SchemaInvalidEnumValue);
  CHECK_ERROR(exception_state_from_token("Active"), ErrorCode::SchemaInvalidEnumValue);
  CHECK_ERROR(exception_state_from_token(""), ErrorCode::SchemaInvalidEnumValue);

  CHECK_EQ(exception_status_token(ExceptionStatus::Effective), std::string_view{"effective"});
  CHECK_EQ(exception_status_token(ExceptionStatus::Revoked), std::string_view{"revoked"});
  CHECK_EQ(exception_status_token(ExceptionStatus::Expired), std::string_view{"expired"});
  CHECK_EQ(exception_status_token(ExceptionStatus::StalePolicyGeneration),
           std::string_view{"stale_policy_generation"});
}

FBM_TEST(exception_scope_covers_every_combination_of_set_and_unset_members) {
  const AssetId node01{std::string{"node-01"}};
  const AssetId node02{std::string{"node-02"}};
  const FirmwareComponentId bmc{std::string{"bmc"}};
  const FirmwareComponentId bios{std::string{"bios"}};

  for (int model_set = 0; model_set < 2; ++model_set) {
    for (int asset_set = 0; asset_set < 2; ++asset_set) {
      for (int components_set = 0; components_set < 2; ++components_set) {
        const ExceptionScope scope =
            scope_of(model_set != 0 ? "h100" : "", asset_set != 0 ? "node-01" : "",
                     components_set != 0 ? std::vector<std::string>{"bmc"}
                                         : std::vector<std::string>{});
        // An unset model or asset widens the scope to every model or asset in
        // the hardware class.
        CHECK(scope.covers(profile_of("h100"), node01, bmc));
        CHECK_EQ(scope.covers(profile_of("a100"), node01, bmc), model_set == 0);
        CHECK_EQ(scope.covers(profile_of("h100"), node02, bmc), asset_set == 0);
        // An empty component list means every component in scope.
        CHECK_EQ(scope.covers(profile_of("h100"), node01, bios), components_set == 0);
        // A profile whose model was never observed cannot match a model-scoped
        // exception; it is unknown, not equal.
        HardwareProfile unidentified = profile_of("h100");
        unidentified.model = HardwareModelId{};
        CHECK_EQ(scope.covers(unidentified, node01, bmc), model_set == 0);
        // A different hardware class never matches.
        HardwareProfile cpu = profile_of("h100");
        cpu.hardware_class = HardwareClassId{std::string{"cpu"}};
        CHECK(!scope.covers(cpu, node01, bmc));
        // A scope without a hardware class covers nothing.
        ExceptionScope no_class = scope;
        no_class.hardware_class = HardwareClassId{};
        CHECK(!no_class.covers(profile_of("h100"), node01, bmc));
      }
    }
  }

  // Membership in a multi-component list is exact.
  const ExceptionScope pair = scope_of("h100", "node-01", {"bmc", "bios"});
  CHECK(pair.covers(profile_of("h100"), node01, bmc));
  CHECK(pair.covers(profile_of("h100"), node01, bios));
  CHECK(!pair.covers(profile_of("h100"), node01, FirmwareComponentId{std::string{"cpld"}}));
}

FBM_TEST(classify_exception_statuses_and_fixed_check_order) {
  const ExceptionScope scope = scope_of("h100", "", {});
  const PolicyGeneration policy{4u};
  const Timestamp now = instant(0u);
  const Timestamp expiry = instant(1000u);

  const BaselineException live = exception_of("exc-1", scope, Expiry::at(expiry), policy);
  CHECK_EQ(classify_exception(live, policy, now), ExceptionStatus::Effective);

  // Expiry is exclusive: the grant is already expired at exactly its instant.
  CHECK_EQ(classify_exception(live, policy, instant(999u)), ExceptionStatus::Effective);
  CHECK_EQ(classify_exception(live, policy, expiry), ExceptionStatus::Expired);
  CHECK_EQ(classify_exception(live, policy, instant(1001u)), ExceptionStatus::Expired);

  // A policy generation change fences a previously effective exception.
  CHECK_EQ(classify_exception(live, PolicyGeneration{5u}, now),
           ExceptionStatus::StalePolicyGeneration);
  CHECK_EQ(classify_exception(live, PolicyGeneration{3u}, now),
           ExceptionStatus::StalePolicyGeneration);

  // Expired outranks a policy generation change: the expiry is the reason that
  // can be acted on.
  CHECK_EQ(classify_exception(live, PolicyGeneration{5u}, expiry), ExceptionStatus::Expired);

  // A revoked grant is revoked under every other condition.
  const BaselineException revoked =
      exception_of("exc-2", scope, Expiry::at(expiry), policy, ExceptionState::Revoked);
  CHECK_EQ(classify_exception(revoked, policy, now), ExceptionStatus::Revoked);
  CHECK_EQ(classify_exception(revoked, policy, expiry), ExceptionStatus::Revoked);
  CHECK_EQ(classify_exception(revoked, PolicyGeneration{5u}, instant(5000u)),
           ExceptionStatus::Revoked);

  // A never-expiring grant is never expired; it is still fenced by the policy
  // generation.
  const BaselineException eternal = exception_of("exc-3", scope, Expiry::never(), policy);
  CHECK_EQ(classify_exception(eternal, policy, instant(4000000000000000000ull)),
           ExceptionStatus::Effective);
  CHECK_EQ(classify_exception(eternal, PolicyGeneration{5u}, now),
           ExceptionStatus::StalePolicyGeneration);
}

FBM_TEST(exception_registry_effective_for_earliest_expiry_then_lowest_identity) {
  const HardwareProfile h100 = profile_of("h100");
  const AssetId node01{std::string{"node-01"}};
  const AssetId node02{std::string{"node-02"}};
  const FirmwareComponentId bmc{std::string{"bmc"}};
  const FirmwareComponentId bios{std::string{"bios"}};
  const PolicyGeneration policy{4u};
  const Timestamp now = instant(0u);

  const ExceptionScope scope = scope_of("h100", "node-01", {});

  ExceptionRegistry empty;
  CHECK(empty.empty());
  CHECK(empty.effective_for(h100, node01, bmc, policy, now) == nullptr);

  const BaselineException late = exception_of("exc-a", scope, Expiry::at(instant(900u)), policy);
  const BaselineException early = exception_of("exc-b", scope, Expiry::at(instant(300u)), policy);
  const BaselineException eternal = exception_of("exc-c", scope, Expiry::never(), policy);

  // The earliest expiry wins, and it wins whatever the insertion order was:
  // a never-expiring grant never outranks a stated instant.
  ExceptionRegistry forward;
  CHECK_OK(forward.put(late));
  CHECK_OK(forward.put(early));
  CHECK_OK(forward.put(eternal));
  const BaselineException* forward_winner = forward.effective_for(h100, node01, bmc, policy, now);
  REQUIRE(forward_winner != nullptr);
  CHECK_EQ(forward_winner->id.value(), std::string{"exc-b"});

  ExceptionRegistry backward;
  CHECK_OK(backward.put(eternal));
  CHECK_OK(backward.put(early));
  CHECK_OK(backward.put(late));
  const BaselineException* backward_winner = backward.effective_for(h100, node01, bmc, policy, now);
  REQUIRE(backward_winner != nullptr);
  CHECK_EQ(backward_winner->id.value(), std::string{"exc-b"});

  // An exact tie on the expiry instant is broken by the lowest identity.
  const BaselineException tie_high =
      exception_of("exc-z", scope, Expiry::at(instant(500u)), policy);
  const BaselineException tie_low =
      exception_of("exc-y", scope, Expiry::at(instant(500u)), policy);
  ExceptionRegistry ties;
  CHECK_OK(ties.put(tie_high));
  CHECK_OK(ties.put(tie_low));
  const BaselineException* tie_winner = ties.effective_for(h100, node01, bmc, policy, now);
  REQUIRE(tie_winner != nullptr);
  CHECK_EQ(tie_winner->id.value(), std::string{"exc-y"});

  ExceptionRegistry ties_reversed;
  CHECK_OK(ties_reversed.put(tie_low));
  CHECK_OK(ties_reversed.put(tie_high));
  REQUIRE(ties_reversed.effective_for(h100, node01, bmc, policy, now) != nullptr);
  CHECK_EQ(ties_reversed.effective_for(h100, node01, bmc, policy, now)->id.value(),
           std::string{"exc-y"});

  // Only an effective exception is ever applied.
  ExceptionRegistry ineffective;
  CHECK_OK(ineffective.put(
      exception_of("exc-r", scope, Expiry::at(instant(1u)), policy, ExceptionState::Revoked)));
  CHECK(ineffective.effective_for(h100, node01, bmc, policy, now) == nullptr);

  ExceptionRegistry expired;
  CHECK_OK(expired.put(exception_of("exc-e", scope, Expiry::at(now), policy)));
  CHECK(expired.effective_for(h100, node01, bmc, policy, now) == nullptr);

  ExceptionRegistry stale;
  CHECK_OK(stale.put(exception_of("exc-s", scope, Expiry::at(instant(900u)), PolicyGeneration{3u})));
  CHECK(stale.effective_for(h100, node01, bmc, policy, now) == nullptr);

  // Scope is enforced: a different asset, a different model, a different class,
  // and a component outside the list are all non-matches.
  ExceptionRegistry foreign_asset;
  CHECK_OK(foreign_asset.put(
      exception_of("exc-fa", scope_of("h100", "node-02", {}), Expiry::never(), policy)));
  CHECK(foreign_asset.effective_for(h100, node01, bmc, policy, now) == nullptr);

  ExceptionRegistry foreign_model;
  CHECK_OK(foreign_model.put(
      exception_of("exc-fm", scope_of("a100", "node-01", {}), Expiry::never(), policy)));
  CHECK(foreign_model.effective_for(h100, node01, bmc, policy, now) == nullptr);

  ExceptionRegistry foreign_class;
  ExceptionScope cpu_scope = scope;
  cpu_scope.hardware_class = HardwareClassId{std::string{"cpu"}};
  Diagnostics cpu_diagnostics;
  CHECK_OK(cpu_scope.validate({}, cpu_diagnostics));
  CHECK(cpu_diagnostics.empty());
  CHECK_OK(foreign_class.put(exception_of("exc-fc", cpu_scope, Expiry::never(), policy)));
  CHECK(foreign_class.effective_for(h100, node01, bmc, policy, now) == nullptr);

  ExceptionRegistry component_scoped;
  CHECK_OK(component_scoped.put(exception_of(
      "exc-cs", scope_of("h100", "node-01", {"bios"}), Expiry::never(), policy)));
  CHECK(component_scoped.effective_for(h100, node01, bmc, policy, now) == nullptr);
  REQUIRE(component_scoped.effective_for(h100, node01, bios, policy, now) != nullptr);
  CHECK_EQ(component_scoped.effective_for(h100, node01, bios, policy, now)->id.value(),
           std::string{"exc-cs"});

  // Registry lookup and removal.
  REQUIRE(forward.find(ExceptionId{std::string{"exc-b"}}) != nullptr);
  CHECK(forward.find(ExceptionId{std::string{"exc-missing"}}) == nullptr);
  CHECK_EQ(forward.size(), std::size_t{3});
  CHECK(forward.erase(ExceptionId{std::string{"exc-b"}}));
  CHECK(!forward.erase(ExceptionId{std::string{"exc-b"}}));
  CHECK_EQ(forward.size(), std::size_t{2});
  CHECK(forward.effective_for(h100, node01, bmc, policy, now) != nullptr);
  CHECK_EQ(forward.effective_for(h100, node01, bmc, policy, now)->id.value(), std::string{"exc-a"});
  CHECK(foreign_class.effective_for(profile_of("a100"), node01, bmc, policy, now) == nullptr);

  // Putting a replacement for an existing identity replaces it.
  CHECK_OK(forward.put(exception_of("exc-a", scope, Expiry::at(instant(100u)), policy)));
  REQUIRE(forward.find(ExceptionId{std::string{"exc-a"}}) != nullptr);
  CHECK_EQ(forward.find(ExceptionId{std::string{"exc-a"}})->expiry.at(), instant(100u));
}

FBM_TEST(exception_json_round_trip_including_revoked_at) {
  const ExceptionScope scope = scope_of("h100", "node-01", {"bmc", "bios"});
  const PolicyGeneration policy{4u};

  const BaselineException live = exception_of("exc-1", scope, Expiry::at(instant(1000u)), policy);
  const json::Value live_json = live.to_json();
  CHECK(live_json.find("expires_at") != nullptr);
  CHECK(live_json.find("expires") == nullptr);
  CHECK(live_json.find("revoked_at") == nullptr);
  CHECK_EQ(live_json.find("state")->as_string(), std::string{"active"});
  CHECK_EQ(live_json.find("reason")->as_string(), std::string{"approved maintenance window"});
  CHECK_EQ(live_json.find("granted_under")->as_integer(), std::int64_t{4});
  CHECK_EQ(live_json.find("revision")->as_integer(), std::int64_t{1});

  const std::string live_canonical = canonical_of(live_json);
  Result<BaselineException> live_back = BaselineException::from_json(reparsed(live_json), {});
  CHECK_OK(live_back);
  CHECK_EQ(canonical_of(live_back.value().to_json()), live_canonical);
  CHECK_EQ(live_back.value().state, ExceptionState::Active);
  CHECK_EQ(live_back.value().expiry.kind(), Expiry::Kind::At);
  CHECK_EQ(live_back.value().expiry.at(), instant(1000u));
  CHECK_EQ(live_back.value().scope.components.size(), std::size_t{2});
  CHECK_EQ(live_back.value().scope.components[0].value(), std::string{"bmc"});
  CHECK_EQ(live_back.value().revoked_at.is_set(), false);

  const BaselineException revoked =
      exception_of("exc-2", scope, Expiry::at(instant(1000u)), policy, ExceptionState::Revoked);
  const json::Value revoked_json = revoked.to_json();
  CHECK(revoked_json.find("revoked_at") != nullptr);
  CHECK_EQ(revoked_json.find("revoked_at")->as_string(), instant(10u).to_rfc3339());
  const std::string revoked_canonical = canonical_of(revoked_json);
  Result<BaselineException> revoked_back = BaselineException::from_json(reparsed(revoked_json), {});
  CHECK_OK(revoked_back);
  CHECK_EQ(canonical_of(revoked_back.value().to_json()), revoked_canonical);
  CHECK_EQ(revoked_back.value().state, ExceptionState::Revoked);
  CHECK_EQ(revoked_back.value().revoked_at, instant(10u));

  const BaselineException eternal = exception_of("exc-3", scope, Expiry::never(), policy);
  const json::Value eternal_json = eternal.to_json();
  CHECK(eternal_json.find("expires") != nullptr);
  CHECK_EQ(eternal_json.find("expires")->as_string(), std::string{"never"});
  CHECK(eternal_json.find("expires_at") == nullptr);
  const std::string eternal_canonical = canonical_of(eternal_json);
  Result<BaselineException> eternal_back = BaselineException::from_json(reparsed(eternal_json), {});
  CHECK_OK(eternal_back);
  CHECK_EQ(canonical_of(eternal_back.value().to_json()), eternal_canonical);
  CHECK_EQ(eternal_back.value().expiry.kind(), Expiry::Kind::Never);
}

FBM_TEST(exception_from_json_rejects_malformed_documents) {
  const ExceptionScope scope = scope_of("h100", "node-01", {});
  const PolicyGeneration policy{4u};
  const BaselineException live = exception_of("exc-1", scope, Expiry::at(instant(1000u)), policy);
  const BaselineException revoked =
      exception_of("exc-2", scope, Expiry::at(instant(1000u)), policy, ExceptionState::Revoked);

  // revoked_at is required exactly when the state is revoked.
  json::Value revoked_without = revoked.to_json();
  CHECK(revoked_without.erase("revoked_at"));
  CHECK_ERROR(BaselineException::from_json(reparsed(revoked_without), {}),
              ErrorCode::SchemaMissingField);

  json::Value active_with = live.to_json();
  active_with.set("revoked_at", json::Value{instant(10u).to_rfc3339()});
  CHECK_ERROR(BaselineException::from_json(reparsed(active_with), {}),
              ErrorCode::SchemaInconsistentDocument);

  // Exactly one expiry encoding is allowed.
  json::Value both = live.to_json();
  both.set("expires", json::Value{std::string{"never"}});
  CHECK_ERROR(BaselineException::from_json(reparsed(both), {}),
              ErrorCode::SchemaInconsistentDocument);

  json::Value neither = live.to_json();
  CHECK(neither.erase("expires_at"));
  CHECK_ERROR(BaselineException::from_json(reparsed(neither), {}), ErrorCode::SchemaMissingField);

  json::Value bad_never = live.to_json();
  CHECK(bad_never.erase("expires_at"));
  bad_never.set("expires", json::Value{std::string{"sometimes"}});
  CHECK_ERROR(BaselineException::from_json(reparsed(bad_never), {}),
              ErrorCode::SchemaInvalidEnumValue);

  json::Value bad_time = live.to_json();
  bad_time.set("expires_at", json::Value{std::string{"not-a-timestamp"}});
  CHECK_ERROR(BaselineException::from_json(reparsed(bad_time), {}),
              ErrorCode::SchemaInvalidTimestampText);

  json::Value unknown = live.to_json();
  unknown.set("waived", json::Value{true});
  CHECK_ERROR(BaselineException::from_json(reparsed(unknown), {}), ErrorCode::SchemaUnknownField);

  json::Value bad_state = live.to_json();
  bad_state.set("state", json::Value{std::string{"pending"}});
  CHECK_ERROR(BaselineException::from_json(reparsed(bad_state), {}),
              ErrorCode::SchemaInvalidEnumValue);

  json::Value no_scope = live.to_json();
  CHECK(no_scope.erase("scope"));
  CHECK_ERROR(BaselineException::from_json(reparsed(no_scope), {}), ErrorCode::SchemaMissingField);

  json::Value empty_reason = live.to_json();
  empty_reason.set("reason", json::Value{std::string{}});
  CHECK_ERROR(BaselineException::from_json(reparsed(empty_reason), {}),
              ErrorCode::SchemaValueOutOfRange);

  json::Value no_created = live.to_json();
  CHECK(no_created.erase("created_at"));
  CHECK_ERROR(BaselineException::from_json(reparsed(no_created), {}),
              ErrorCode::SchemaMissingField);

  json::Value no_approval = live.to_json();
  CHECK(no_approval.erase("approval"));
  CHECK_ERROR(BaselineException::from_json(reparsed(no_approval), {}),
              ErrorCode::SchemaMissingField);

  json::Value bad_id = live.to_json();
  bad_id.set("id", json::Value{std::string{"exc 1"}});
  CHECK_ERROR(BaselineException::from_json(reparsed(bad_id), {}),
              ErrorCode::SchemaInvalidIdentifier);

  // Scope documents are strict too. json::Value::find() is const, so a nested
  // member is copied out, edited, and written back.
  const json::Value live_json = live.to_json();
  const json::Value* original_scope = live_json.find("scope");
  REQUIRE(original_scope != nullptr);

  json::Value scope_unknown = *original_scope;
  scope_unknown.set("rack", json::Value{std::string{"r1"}});
  json::Value unknown_scope_document = live_json;
  unknown_scope_document.set("scope", scope_unknown);
  CHECK_ERROR(BaselineException::from_json(reparsed(unknown_scope_document), {}),
              ErrorCode::SchemaUnknownField);

  json::Value::Array duplicate_components;
  duplicate_components.push_back(json::Value{std::string{"bmc"}});
  duplicate_components.push_back(json::Value{std::string{"bmc"}});
  json::Value scope_duplicate = *original_scope;
  scope_duplicate.set("components", json::Value{std::move(duplicate_components)});
  json::Value duplicate_scope_document = live_json;
  duplicate_scope_document.set("scope", scope_duplicate);
  CHECK_ERROR(BaselineException::from_json(reparsed(duplicate_scope_document), {}),
              ErrorCode::SchemaDuplicateIdentifier);

  json::Value scope_no_class = *original_scope;
  CHECK(scope_no_class.erase("hardware_class"));
  json::Value class_less_document = live_json;
  class_less_document.set("scope", scope_no_class);
  CHECK_ERROR(BaselineException::from_json(reparsed(class_less_document), {}),
              ErrorCode::SchemaMissingField);

  // An invalid in-memory exception cannot enter the registry.
  ExceptionRegistry registry;
  BaselineException invalid = live;
  invalid.approval = ApprovalId{};
  CHECK_ERROR(registry.put(invalid), ErrorCode::SchemaMissingField);
  CHECK(registry.empty());
  BaselineException no_expiry = live;
  no_expiry.expiry = Expiry{};
  CHECK_ERROR(registry.put(no_expiry), ErrorCode::SchemaMissingField);
  CHECK(registry.empty());
}

FBM_TEST(exception_registry_json_round_trip) {
  const ExceptionScope scope = scope_of("h100", "node-01", {"bmc"});
  const PolicyGeneration policy{4u};

  ExceptionRegistry registry;
  CHECK_OK(registry.put(exception_of("exc-b", scope, Expiry::at(instant(500u)), policy)));
  CHECK_OK(registry.put(exception_of("exc-a", scope, Expiry::never(), policy)));
  CHECK_OK(registry.put(exception_of("exc-c", scope, Expiry::at(instant(900u)), policy,
                                     ExceptionState::Revoked)));

  const json::Value encoded = registry.to_json();
  REQUIRE(encoded.is_array());
  REQUIRE(encoded.as_array().size() == 3u);
  CHECK_EQ(encoded.as_array()[0].find("id")->as_string(), std::string{"exc-a"});
  CHECK_EQ(encoded.as_array()[1].find("id")->as_string(), std::string{"exc-b"});
  CHECK_EQ(encoded.as_array()[2].find("id")->as_string(), std::string{"exc-c"});

  const std::string canonical = canonical_of(encoded);
  Result<ExceptionRegistry> restored = ExceptionRegistry::from_json(reparsed(encoded), {});
  CHECK_OK(restored);
  CHECK_EQ(restored.value().size(), std::size_t{3});
  CHECK_EQ(canonical_of(restored.value().to_json()), canonical);
  CHECK(restored.value().find(ExceptionId{std::string{"exc-a"}}) != nullptr);
  CHECK_EQ(restored.value().find(ExceptionId{std::string{"exc-c"}})->state, ExceptionState::Revoked);

  Diagnostics diagnostics;
  CHECK_OK(restored.value().validate("/exceptions", diagnostics));
  CHECK(diagnostics.empty());

  // Ordering and uniqueness of the array are enforced.
  const json::Value first = registry.find(ExceptionId{std::string{"exc-a"}})->to_json();
  const json::Value second = registry.find(ExceptionId{std::string{"exc-b"}})->to_json();
  CHECK_ERROR(ExceptionRegistry::from_json(
                  json::Value{json::Value::Array{second, first}}, {}),
              ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(ExceptionRegistry::from_json(
                  json::Value{json::Value::Array{first, first}}, {}),
              ErrorCode::SchemaDuplicateIdentifier);
  CHECK_ERROR(ExceptionRegistry::from_json(json::Value::make_object(), {}),
              ErrorCode::SchemaWrongType);
  Result<ExceptionRegistry> empty = ExceptionRegistry::from_json(json::Value::make_array(), {});
  CHECK_OK(empty);
  CHECK(empty.value().empty());
}
