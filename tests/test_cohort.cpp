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

#include "summon/fbm/cohort.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/timestamp.hpp"

namespace {

namespace json = summon::fbm::json;

using summon::fbm::AssetId;
using summon::fbm::BaselineGeneration;
using summon::fbm::BaselineId;
using summon::fbm::Cohort;
using summon::fbm::CohortId;
using summon::fbm::CohortRegistry;
using summon::fbm::CohortState;
using summon::fbm::cohort_state_from_token;
using summon::fbm::cohort_state_token;
using summon::fbm::ControlEpoch;
using summon::fbm::Diagnostics;
using summon::fbm::Digest;
using summon::fbm::digest_from_hex;
using summon::fbm::digest_to_hex;
using summon::fbm::ErrorCode;
using summon::fbm::GateCounts;
using summon::fbm::GateReport;
using summon::fbm::PlanId;
using summon::fbm::PolicyGeneration;
using summon::fbm::Result;
using summon::fbm::Revision;
using summon::fbm::StageIndex;
using summon::fbm::Status;
using summon::fbm::Timestamp;

constexpr std::uint64_t kBaseNanos = 1700000000000000000ull;

Timestamp instant(std::uint64_t offset_nanos) {
  return Timestamp::from_unix_nanos(kBaseNanos + offset_nanos);
}

Digest sample_digest() {
  Result<Digest> parsed = digest_from_hex(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", {});
  REQUIRE(parsed.has_value());
  return parsed.take();
}

Cohort draft_of(std::string_view id, std::vector<std::string> members) {
  // Value-initialized: an absent digest is the all-zero digest, never an
  // indeterminate one.
  Cohort cohort{};
  cohort.id = CohortId{std::string{id}};
  cohort.baseline = BaselineId{std::string{"gpu-h100-train"}};
  cohort.baseline_generation = BaselineGeneration{3u};
  cohort.revision = Revision{1u};
  cohort.stage = StageIndex{1u};
  cohort.required_stages = StageIndex{2u};
  cohort.state = CohortState::Draft;
  for (const std::string& member : members) {
    cohort.members.push_back(AssetId{member});
  }
  cohort.created_at = instant(0u);
  cohort.stage_entered_at = instant(0u);
  return cohort;
}

Cohort active_of(std::string_view id, std::vector<std::string> members) {
  Cohort cohort = draft_of(id, members);
  cohort.state = CohortState::Active;
  cohort.baseline_digest = sample_digest();
  cohort.policy_generation = PolicyGeneration{4u};
  cohort.authorized_epoch = ControlEpoch{9u};
  cohort.plan = PlanId{std::string{"plan-1"}};
  return cohort;
}

Status validate_cohort(const Cohort& cohort) {
  Diagnostics diagnostics;
  return cohort.validate({}, diagnostics);
}

std::string canonical_of(const json::Value& value) { return json::write_canonical(value); }

json::Value reparsed(const json::Value& value) {
  Result<json::Value> parsed = json::parse(json::write_canonical(value));
  REQUIRE(parsed.has_value());
  return parsed.take();
}

json::Value registry_document(json::Value::Array cohorts) {
  return json::Value{std::move(cohorts)};
}

}  // namespace

FBM_TEST(cohort_state_tokens_are_stable) {
  CHECK_EQ(cohort_state_token(CohortState::Draft), std::string_view{"draft"});
  CHECK_EQ(cohort_state_token(CohortState::Authorized), std::string_view{"authorized"});
  CHECK_EQ(cohort_state_token(CohortState::Active), std::string_view{"active"});
  CHECK_EQ(cohort_state_token(CohortState::Paused), std::string_view{"paused"});
  CHECK_EQ(cohort_state_token(CohortState::Completed), std::string_view{"completed"});
  CHECK_EQ(cohort_state_token(CohortState::RolledBack), std::string_view{"rolled_back"});
  CHECK_EQ(cohort_state_token(CohortState::Cancelled), std::string_view{"cancelled"});

  Result<CohortState> rolled_back = cohort_state_from_token("rolled_back");
  CHECK_OK(rolled_back);
  CHECK_EQ(rolled_back.value(), CohortState::RolledBack);
  CHECK_ERROR(cohort_state_from_token("rollback"), ErrorCode::SchemaInvalidEnumValue);
  CHECK_ERROR(cohort_state_from_token("Active"), ErrorCode::SchemaInvalidEnumValue);
  CHECK_ERROR(cohort_state_from_token(""), ErrorCode::SchemaInvalidEnumValue);
}

FBM_TEST(cohort_member_lookup_and_accepts_mutation_per_state) {
  const Cohort cohort = draft_of("wave-1", {"node-01", "node-02"});
  CHECK(cohort.is_member(AssetId{std::string{"node-01"}}));
  CHECK(cohort.is_member(AssetId{std::string{"node-02"}}));
  CHECK(!cohort.is_member(AssetId{std::string{"node-03"}}));
  CHECK(!cohort.is_member(AssetId{}));

  struct StateExpectation {
    CohortState state;
    bool accepts_mutation;
  };
  const StateExpectation expectations[] = {
      {CohortState::Draft, true},       {CohortState::Authorized, true},
      {CohortState::Active, true},      {CohortState::Paused, true},
      {CohortState::Completed, false},  {CohortState::RolledBack, false},
      {CohortState::Cancelled, false},
  };
  for (const StateExpectation& expectation : expectations) {
    Cohort subject = cohort;
    subject.state = expectation.state;
    CHECK_EQ(subject.accepts_mutation(), expectation.accepts_mutation);
  }

  CHECK_EQ(cohort.to_string().rfind("cohort wave-1", 0), std::size_t{0});
  CHECK(cohort.to_string().find("state=draft") != std::string::npos);
  CHECK(cohort.to_string().find("members=2") != std::string::npos);
}

FBM_TEST(cohort_validation_state_dependent_members) {
  const Cohort draft = draft_of("wave-1", {"node-01", "node-02"});
  const Cohort active = active_of("wave-1", {"node-01", "node-02"});
  CHECK_OK(validate_cohort(draft));
  CHECK_OK(validate_cohort(active));

  // A draft must not carry any authorization fact.
  Cohort draft_with_digest = draft;
  draft_with_digest.baseline_digest = sample_digest();
  CHECK_ERROR(validate_cohort(draft_with_digest), ErrorCode::SchemaInconsistentDocument);

  Cohort draft_with_policy = draft;
  draft_with_policy.policy_generation = PolicyGeneration{4u};
  CHECK_ERROR(validate_cohort(draft_with_policy), ErrorCode::SchemaInconsistentDocument);

  Cohort draft_with_epoch = draft;
  draft_with_epoch.authorized_epoch = ControlEpoch{9u};
  CHECK_ERROR(validate_cohort(draft_with_epoch), ErrorCode::SchemaInconsistentDocument);

  Cohort draft_with_plan = draft;
  draft_with_plan.plan = PlanId{std::string{"plan-1"}};
  CHECK_ERROR(validate_cohort(draft_with_plan), ErrorCode::SchemaInconsistentDocument);

  // Every other state must carry all of them.
  Cohort active_without_digest = active;
  active_without_digest.baseline_digest = Digest{};
  CHECK_ERROR(validate_cohort(active_without_digest), ErrorCode::SchemaMissingField);

  Cohort active_without_policy = active;
  active_without_policy.policy_generation = PolicyGeneration{};
  CHECK_ERROR(validate_cohort(active_without_policy), ErrorCode::SchemaMissingField);

  Cohort active_without_epoch = active;
  active_without_epoch.authorized_epoch = ControlEpoch{};
  CHECK_ERROR(validate_cohort(active_without_epoch), ErrorCode::SchemaMissingField);

  Cohort active_without_plan = active;
  active_without_plan.plan = PlanId{};
  CHECK_ERROR(validate_cohort(active_without_plan), ErrorCode::SchemaMissingField);

  // Members: non-empty, unique, and ascending.
  Cohort empty_members = draft;
  empty_members.members.clear();
  CHECK_ERROR(validate_cohort(empty_members), ErrorCode::SchemaEmptyCollection);

  Cohort duplicate_members = draft;
  duplicate_members.members.push_back(AssetId{std::string{"node-01"}});
  CHECK_ERROR(validate_cohort(duplicate_members), ErrorCode::SchemaDuplicateIdentifier);

  Cohort unsorted_members = draft;
  unsorted_members.members = {AssetId{std::string{"node-02"}}, AssetId{std::string{"node-01"}}};
  CHECK_ERROR(validate_cohort(unsorted_members), ErrorCode::SchemaInconsistentDocument);

  Cohort invalid_member = draft;
  invalid_member.members = {AssetId{std::string{"node 01"}}};
  CHECK_ERROR(validate_cohort(invalid_member), ErrorCode::SchemaInvalidIdentifier);

  Cohort unset_member = draft;
  unset_member.members = {AssetId{}};
  CHECK_ERROR(validate_cohort(unset_member), ErrorCode::SchemaMissingField);

  // Staging is one-based and can never exceed the required stage count.
  Cohort stage_zero = draft;
  stage_zero.stage = StageIndex{0u};
  CHECK_ERROR(validate_cohort(stage_zero), ErrorCode::SchemaValueOutOfRange);

  Cohort required_zero = draft;
  required_zero.required_stages = StageIndex{0u};
  CHECK_ERROR(validate_cohort(required_zero), ErrorCode::SchemaValueOutOfRange);

  Cohort stage_beyond = draft;
  stage_beyond.stage = StageIndex{3u};
  CHECK_ERROR(validate_cohort(stage_beyond), ErrorCode::SchemaInconsistentDocument);

  // Required identities, counters, and timestamps.
  Cohort no_id = draft;
  no_id.id = CohortId{};
  CHECK_ERROR(validate_cohort(no_id), ErrorCode::SchemaMissingField);

  Cohort no_baseline = draft;
  no_baseline.baseline = BaselineId{};
  CHECK_ERROR(validate_cohort(no_baseline), ErrorCode::SchemaMissingField);

  Cohort no_generation = draft;
  no_generation.baseline_generation = BaselineGeneration{};
  CHECK_ERROR(validate_cohort(no_generation), ErrorCode::SchemaMissingField);

  Cohort no_revision = draft;
  no_revision.revision = Revision{};
  CHECK_ERROR(validate_cohort(no_revision), ErrorCode::SchemaMissingField);

  Cohort no_stage = draft;
  no_stage.stage = StageIndex{};
  CHECK_ERROR(validate_cohort(no_stage), ErrorCode::SchemaMissingField);

  Cohort no_required_stages = draft;
  no_required_stages.required_stages = StageIndex{};
  CHECK_ERROR(validate_cohort(no_required_stages), ErrorCode::SchemaMissingField);

  Cohort no_created = draft;
  no_created.created_at = Timestamp{};
  CHECK_ERROR(validate_cohort(no_created), ErrorCode::SchemaMissingField);

  Cohort no_stage_entered = draft;
  no_stage_entered.stage_entered_at = Timestamp{};
  CHECK_ERROR(validate_cohort(no_stage_entered), ErrorCode::SchemaMissingField);

  // An invalid cohort never enters the registry.
  CohortRegistry registry;
  CHECK_ERROR(registry.put(draft_with_plan), ErrorCode::SchemaInconsistentDocument);
  CHECK(registry.empty());
}

FBM_TEST(gate_counts_and_report_retain_every_condition) {
  GateCounts counts;
  counts.total_assets = 9u;
  counts.decided_assets = 7u;
  counts.conformant_assets = 6u;
  counts.drifted_assets = 1u;
  counts.unknown_assets = 2u;
  counts.unsupported_assets = 0u;
  counts.blocked_assets = 0u;
  counts.exception_assets = 1u;
  counts.pending_rollout_assets = 0u;
  counts.pending_rollback_assets = 0u;
  counts.conformant_basis_points = 8571u;

  GateReport report;
  report.satisfied = false;
  report.counts = counts;
  report.unmet_conditions = {"minimum_conformant_basis_points", "minimum_decided_assets",
                             "soak_nanos"};
  report.soak_remaining_nanos = 3600000000000ull;
  report.next_stage = StageIndex{2u};

  const json::Value encoded = report.to_json();
  REQUIRE(encoded.find("satisfied") != nullptr);
  CHECK_EQ(encoded.find("satisfied")->as_boolean(), false);
  const json::Value* encoded_counts = encoded.find("counts");
  REQUIRE(encoded_counts != nullptr);
  CHECK_EQ(encoded_counts->find("total_assets")->as_integer(), std::int64_t{9});
  CHECK_EQ(encoded_counts->find("decided_assets")->as_integer(), std::int64_t{7});
  CHECK_EQ(encoded_counts->find("conformant_assets")->as_integer(), std::int64_t{6});
  CHECK_EQ(encoded_counts->find("drifted_assets")->as_integer(), std::int64_t{1});
  CHECK_EQ(encoded_counts->find("unknown_assets")->as_integer(), std::int64_t{2});
  CHECK_EQ(encoded_counts->find("unsupported_assets")->as_integer(), std::int64_t{0});
  CHECK_EQ(encoded_counts->find("blocked_assets")->as_integer(), std::int64_t{0});
  CHECK_EQ(encoded_counts->find("exception_assets")->as_integer(), std::int64_t{1});
  CHECK_EQ(encoded_counts->find("pending_rollout_assets")->as_integer(), std::int64_t{0});
  CHECK_EQ(encoded_counts->find("pending_rollback_assets")->as_integer(), std::int64_t{0});
  CHECK_EQ(encoded_counts->find("conformant_basis_points")->as_integer(), std::int64_t{8571});

  // The unmet conditions are retained in full and in order, never collapsed to
  // the boolean.
  const json::Value* unmet = encoded.find("unmet_conditions");
  REQUIRE(unmet != nullptr);
  REQUIRE(unmet->is_array());
  REQUIRE(unmet->as_array().size() == 3u);
  CHECK_EQ(unmet->as_array()[0].as_string(), std::string{"minimum_conformant_basis_points"});
  CHECK_EQ(unmet->as_array()[1].as_string(), std::string{"minimum_decided_assets"});
  CHECK_EQ(unmet->as_array()[2].as_string(), std::string{"soak_nanos"});
  CHECK_EQ(encoded.find("soak_remaining_nanos")->as_integer(), std::int64_t{3600000000000});
  CHECK_EQ(encoded.find("next_stage")->as_integer(), std::int64_t{2});

  const std::string rendered = report.to_string();
  CHECK_EQ(rendered.rfind("unsatisfied", 0), std::size_t{0});
  CHECK(rendered.find("total_assets=9") != std::string::npos);
  CHECK(rendered.find("decided_assets=7") != std::string::npos);
  CHECK(rendered.find("conformant_assets=6") != std::string::npos);
  CHECK(rendered.find("drifted_assets=1") != std::string::npos);
  CHECK(rendered.find("unknown_assets=2") != std::string::npos);
  CHECK(rendered.find("unsupported_assets=0") != std::string::npos);
  CHECK(rendered.find("blocked_assets=0") != std::string::npos);
  CHECK(rendered.find("exception_assets=1") != std::string::npos);
  CHECK(rendered.find("pending_rollout_assets=0") != std::string::npos);
  CHECK(rendered.find("pending_rollback_assets=0") != std::string::npos);
  CHECK(rendered.find("conformant_basis_points=8571") != std::string::npos);
  CHECK(rendered.find("soak_remaining_nanos=3600000000000") != std::string::npos);
  CHECK(rendered.find("next_stage=2") != std::string::npos);
  const std::size_t first = rendered.find("minimum_conformant_basis_points");
  const std::size_t second = rendered.find("minimum_decided_assets");
  const std::size_t third = rendered.find("soak_nanos");
  REQUIRE(first != std::string::npos);
  REQUIRE(second != std::string::npos);
  REQUIRE(third != std::string::npos);
  CHECK(first < second);
  CHECK(second < third);

  // A satisfied report retains the counts and carries no unmet condition.
  GateReport satisfied;
  satisfied.satisfied = true;
  satisfied.counts = counts;
  const json::Value satisfied_json = satisfied.to_json();
  CHECK_EQ(satisfied_json.find("satisfied")->as_boolean(), true);
  CHECK(satisfied_json.find("unmet_conditions")->as_array().empty());
  CHECK(satisfied_json.find("next_stage") == nullptr);  // unset is omitted, not zero
  CHECK_EQ(satisfied.to_string().rfind("satisfied", 0), std::size_t{0});
  CHECK(satisfied.to_string().find("unmet_conditions=none") != std::string::npos);
  CHECK(satisfied.to_string().find("next_stage=<unset>") != std::string::npos);

  // Every count survives the JSON round trip.
  const json::Value counts_json = counts.to_json();
  const json::Value* counts_again = counts_json.find("conformant_basis_points");
  REQUIRE(counts_again != nullptr);
  CHECK_EQ(counts_again->as_integer(), std::int64_t{8571});
  CHECK_EQ(counts_json.as_object().size(), std::size_t{11});
}

FBM_TEST(cohort_registry_containing_is_ascending_by_identity) {
  const AssetId node01{std::string{"node-01"}};
  const AssetId node09{std::string{"node-09"}};

  CohortRegistry registry;
  CHECK(registry.empty());
  CHECK_OK(registry.put(active_of("wave-c", {"node-01"})));
  CHECK_OK(registry.put(active_of("wave-a", {"node-01", "node-02"})));
  CHECK_OK(registry.put(active_of("wave-b", {"node-07"})));
  CHECK_EQ(registry.size(), std::size_t{3});

  const std::vector<const Cohort*> containing = registry.containing(node01);
  REQUIRE(containing.size() == 2u);
  CHECK_EQ(containing[0]->id.value(), std::string{"wave-a"});
  CHECK_EQ(containing[1]->id.value(), std::string{"wave-c"});
  CHECK(registry.containing(node09).empty());

  REQUIRE(registry.find(CohortId{std::string{"wave-b"}}) != nullptr);
  CHECK(registry.find(CohortId{std::string{"wave-z"}}) == nullptr);

  // A repeated identity replaces the stored cohort.
  Cohort replacement = active_of("wave-b", {"node-09"});
  replacement.revision = Revision{2u};
  CHECK_OK(registry.put(replacement));
  CHECK_EQ(registry.size(), std::size_t{3});
  CHECK_EQ(registry.find(CohortId{std::string{"wave-b"}})->revision.value(), std::uint64_t{2});
  REQUIRE(registry.containing(node09).size() == 1u);
  CHECK_EQ(registry.containing(node09)[0]->id.value(), std::string{"wave-b"});

  CHECK(registry.erase(CohortId{std::string{"wave-b"}}));
  CHECK(!registry.erase(CohortId{std::string{"wave-b"}}));
  CHECK_EQ(registry.size(), std::size_t{2});

  Diagnostics diagnostics;
  CHECK_OK(registry.validate("/cohorts", diagnostics));
  CHECK(diagnostics.empty());
}

FBM_TEST(cohort_json_round_trip) {
  const Cohort draft = draft_of("wave-1", {"node-01", "node-02"});
  const json::Value draft_json = draft.to_json();
  CHECK(draft_json.find("baseline_digest") == nullptr);
  CHECK(draft_json.find("policy_generation") == nullptr);
  CHECK(draft_json.find("authorized_epoch") == nullptr);
  CHECK(draft_json.find("plan") == nullptr);
  CHECK(draft_json.find("last_promoted_at") == nullptr);
  CHECK(draft_json.find("note") == nullptr);
  CHECK_EQ(draft_json.find("state")->as_string(), std::string{"draft"});
  CHECK_EQ(draft_json.find("baseline_generation")->as_integer(), std::int64_t{3});
  CHECK_EQ(draft_json.find("stage")->as_integer(), std::int64_t{1});
  CHECK_EQ(draft_json.find("required_stages")->as_integer(), std::int64_t{2});
  REQUIRE(draft_json.find("members")->is_array());
  CHECK_EQ(draft_json.find("members")->as_array().size(), std::size_t{2});

  const std::string draft_canonical = canonical_of(draft_json);
  Result<Cohort> draft_back = Cohort::from_json(reparsed(draft_json), {});
  CHECK_OK(draft_back);
  CHECK_EQ(canonical_of(draft_back.value().to_json()), draft_canonical);
  CHECK_EQ(draft_back.value().state, CohortState::Draft);
  CHECK_EQ(draft_back.value().members.size(), std::size_t{2});
  CHECK_EQ(draft_back.value().members[0].value(), std::string{"node-01"});
  CHECK_EQ(draft_back.value().baseline_generation.value(), std::uint64_t{3});
  CHECK_EQ(draft_back.value().baseline_digest, Digest{});

  Cohort active = active_of("wave-2", {"node-01"});
  active.note = "first wave";
  active.last_promoted_at = instant(500u);
  const json::Value active_json = active.to_json();
  CHECK_EQ(active_json.find("baseline_digest")->as_string(), digest_to_hex(sample_digest()));
  CHECK_EQ(active_json.find("policy_generation")->as_integer(), std::int64_t{4});
  CHECK_EQ(active_json.find("authorized_epoch")->as_integer(), std::int64_t{9});
  CHECK_EQ(active_json.find("plan")->as_string(), std::string{"plan-1"});
  CHECK_EQ(active_json.find("note")->as_string(), std::string{"first wave"});
  CHECK_EQ(active_json.find("last_promoted_at")->as_string(), instant(500u).to_rfc3339());

  const std::string active_canonical = canonical_of(active_json);
  Result<Cohort> active_back = Cohort::from_json(reparsed(active_json), {});
  CHECK_OK(active_back);
  CHECK_EQ(canonical_of(active_back.value().to_json()), active_canonical);
  CHECK_EQ(active_back.value().state, CohortState::Active);
  CHECK_EQ(active_back.value().baseline_digest, sample_digest());
  CHECK_EQ(active_back.value().policy_generation.value(), std::uint64_t{4});
  CHECK_EQ(active_back.value().authorized_epoch.value(), std::uint64_t{9});
  CHECK_EQ(active_back.value().plan.value(), std::string{"plan-1"});
  CHECK_EQ(active_back.value().note, std::string{"first wave"});
  CHECK_EQ(active_back.value().last_promoted_at, instant(500u));

  // A note that is absent and a note that is empty are the same fact, and the
  // empty note is never written as an empty string.
  Cohort without_note = active_of("wave-3", {"node-01"});
  CHECK(without_note.to_json().find("note") == nullptr);
  Result<Cohort> without_note_back = Cohort::from_json(reparsed(without_note.to_json()), {});
  CHECK_OK(without_note_back);
  CHECK(without_note_back.value().note.empty());
}

FBM_TEST(cohort_from_json_rejects_malformed_documents) {
  const Cohort draft = draft_of("wave-1", {"node-01", "node-02"});
  const Cohort active = active_of("wave-2", {"node-01"});
  const json::Value draft_json = draft.to_json();
  const json::Value active_json = active.to_json();

  CHECK_OK(Cohort::from_json(reparsed(draft_json), {}));
  CHECK_OK(Cohort::from_json(reparsed(active_json), {}));

  json::Value unknown = draft_json;
  unknown.set("wave", json::Value{1});
  CHECK_ERROR(Cohort::from_json(reparsed(unknown), {}), ErrorCode::SchemaUnknownField);

  json::Value no_members = draft_json;
  CHECK(no_members.erase("members"));
  CHECK_ERROR(Cohort::from_json(reparsed(no_members), {}), ErrorCode::SchemaMissingField);

  json::Value empty_members = draft_json;
  empty_members.set("members", json::Value{json::Value::Array{}});
  CHECK_ERROR(Cohort::from_json(reparsed(empty_members), {}), ErrorCode::SchemaEmptyCollection);

  json::Value duplicate_members = draft_json;
  duplicate_members.set("members", json::Value{json::Value::Array{
                                       json::Value{std::string{"node-01"}},
                                       json::Value{std::string{"node-01"}}}});
  CHECK_ERROR(Cohort::from_json(reparsed(duplicate_members), {}),
              ErrorCode::SchemaDuplicateIdentifier);

  json::Value unsorted_members = draft_json;
  unsorted_members.set("members", json::Value{json::Value::Array{
                                      json::Value{std::string{"node-02"}},
                                      json::Value{std::string{"node-01"}}}});
  CHECK_ERROR(Cohort::from_json(reparsed(unsorted_members), {}),
              ErrorCode::SchemaInconsistentDocument);

  json::Value bad_member = draft_json;
  bad_member.set("members", json::Value{json::Value::Array{json::Value{std::string{"node 01"}}}});
  CHECK_ERROR(Cohort::from_json(reparsed(bad_member), {}), ErrorCode::SchemaInvalidIdentifier);

  json::Value member_wrong_type = draft_json;
  member_wrong_type.set("members", json::Value{json::Value::Array{json::Value{true}}});
  CHECK_ERROR(Cohort::from_json(reparsed(member_wrong_type), {}), ErrorCode::SchemaWrongType);

  json::Value bad_state = draft_json;
  bad_state.set("state", json::Value{std::string{"running"}});
  CHECK_ERROR(Cohort::from_json(reparsed(bad_state), {}), ErrorCode::SchemaInvalidEnumValue);

  json::Value no_stage_entered = draft_json;
  CHECK(no_stage_entered.erase("stage_entered_at"));
  CHECK_ERROR(Cohort::from_json(reparsed(no_stage_entered), {}), ErrorCode::SchemaMissingField);

  json::Value no_created = draft_json;
  CHECK(no_created.erase("created_at"));
  CHECK_ERROR(Cohort::from_json(reparsed(no_created), {}), ErrorCode::SchemaMissingField);

  json::Value no_generation = draft_json;
  CHECK(no_generation.erase("baseline_generation"));
  CHECK_ERROR(Cohort::from_json(reparsed(no_generation), {}), ErrorCode::SchemaMissingField);

  json::Value bad_generation = draft_json;
  bad_generation.set("baseline_generation", json::Value{std::int64_t{-1}});
  CHECK_ERROR(Cohort::from_json(reparsed(bad_generation), {}),
              ErrorCode::SchemaValueOutOfRange);

  json::Value stage_beyond = draft_json;
  stage_beyond.set("stage", json::Value{3});
  CHECK_ERROR(Cohort::from_json(reparsed(stage_beyond), {}),
              ErrorCode::SchemaInconsistentDocument);

  // The state-dependent rules are enforced on read, not only in memory.
  json::Value draft_with_digest = draft_json;
  draft_with_digest.set("baseline_digest", json::Value{std::string{
                                                "0123456789abcdef0123456789abcdef0123456789"
                                                "abcdef0123456789abcdef"}});
  CHECK_ERROR(Cohort::from_json(reparsed(draft_with_digest), {}),
              ErrorCode::SchemaInconsistentDocument);

  json::Value draft_with_policy = draft_json;
  draft_with_policy.set("policy_generation", json::Value{4});
  CHECK_ERROR(Cohort::from_json(reparsed(draft_with_policy), {}),
              ErrorCode::SchemaInconsistentDocument);

  json::Value active_without_plan = active_json;
  CHECK(active_without_plan.erase("plan"));
  CHECK_ERROR(Cohort::from_json(reparsed(active_without_plan), {}),
              ErrorCode::SchemaMissingField);

  json::Value active_without_digest = active_json;
  CHECK(active_without_digest.erase("baseline_digest"));
  CHECK_ERROR(Cohort::from_json(reparsed(active_without_digest), {}),
              ErrorCode::SchemaMissingField);

  json::Value active_without_epoch = active_json;
  CHECK(active_without_epoch.erase("authorized_epoch"));
  CHECK_ERROR(Cohort::from_json(reparsed(active_without_epoch), {}),
              ErrorCode::SchemaMissingField);

  json::Value short_digest = active_json;
  short_digest.set("baseline_digest", json::Value{std::string{"0123"}});
  CHECK_ERROR(Cohort::from_json(reparsed(short_digest), {}), ErrorCode::SchemaValueOutOfRange);
}

FBM_TEST(cohort_registry_json_round_trip) {
  CohortRegistry registry;
  CHECK_OK(registry.put(active_of("wave-b", {"node-02"})));
  CHECK_OK(registry.put(draft_of("wave-a", {"node-01"})));
  CHECK_OK(registry.put(active_of("wave-c", {"node-03"})));

  const json::Value encoded = registry.to_json();
  REQUIRE(encoded.is_array());
  REQUIRE(encoded.as_array().size() == 3u);
  CHECK_EQ(encoded.as_array()[0].find("id")->as_string(), std::string{"wave-a"});
  CHECK_EQ(encoded.as_array()[1].find("id")->as_string(), std::string{"wave-b"});
  CHECK_EQ(encoded.as_array()[2].find("id")->as_string(), std::string{"wave-c"});

  const std::string canonical = canonical_of(encoded);
  Result<CohortRegistry> restored = CohortRegistry::from_json(reparsed(encoded), {});
  CHECK_OK(restored);
  CHECK_EQ(restored.value().size(), std::size_t{3});
  CHECK_EQ(canonical_of(restored.value().to_json()), canonical);
  REQUIRE(restored.value().find(CohortId{std::string{"wave-a"}}) != nullptr);
  CHECK_EQ(restored.value().find(CohortId{std::string{"wave-a"}})->state, CohortState::Draft);
  REQUIRE(restored.value().find(CohortId{std::string{"wave-b"}}) != nullptr);
  CHECK_EQ(restored.value().find(CohortId{std::string{"wave-b"}})->state, CohortState::Active);
  CHECK_EQ(restored.value().containing(AssetId{std::string{"node-02"}}).size(), std::size_t{1});

  const json::Value first = registry.find(CohortId{std::string{"wave-a"}})->to_json();
  const json::Value second = registry.find(CohortId{std::string{"wave-b"}})->to_json();
  CHECK_ERROR(CohortRegistry::from_json(registry_document({second, first}), {}),
              ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(CohortRegistry::from_json(registry_document({first, first}), {}),
              ErrorCode::SchemaDuplicateIdentifier);
  CHECK_ERROR(CohortRegistry::from_json(json::Value::make_object(), {}),
              ErrorCode::SchemaWrongType);
  Result<CohortRegistry> empty = CohortRegistry::from_json(registry_document({}), {});
  CHECK_OK(empty);
  CHECK(empty.value().empty());
}
