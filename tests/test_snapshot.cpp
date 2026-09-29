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

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/baseline.hpp"
#include "summon/fbm/cohort.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/exception.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/observation.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/snapshot.hpp"
#include "summon/fbm/timestamp.hpp"

// json is a namespace, so it is aliased rather than imported with a
// using-declaration.
namespace json = summon::fbm::json;

namespace {

using summon::fbm::ApprovalId;
using summon::fbm::AssetId;
using summon::fbm::AuthorizationAuthority;
using summon::fbm::AuthorityBinding;
using summon::fbm::AuthorizationRegistry;
using summon::fbm::Baseline;
using summon::fbm::BaselineException;
using summon::fbm::BaselineGeneration;
using summon::fbm::BaselineId;
using summon::fbm::BaselineState;
using summon::fbm::Cohort;
using summon::fbm::CohortId;
using summon::fbm::CohortState;
using summon::fbm::CommitSequence;
using summon::fbm::ComponentRequirement;
using summon::fbm::ControlEpoch;
using summon::fbm::Digest;
using summon::fbm::Diagnostics;
using summon::fbm::ErrorCode;
using summon::fbm::EvidenceId;
using summon::fbm::ExceptionId;
using summon::fbm::ExceptionRegistry;
using summon::fbm::ExceptionState;
using summon::fbm::Expiry;
using summon::fbm::FirmwareComponentId;
using summon::fbm::FirmwareGeneration;
using summon::fbm::FirmwareVersion;
using summon::fbm::FreshnessBound;
using summon::fbm::HardwareClassId;
using summon::fbm::HardwareGeneration;
using summon::fbm::HardwareModelId;
using summon::fbm::HardwareObservation;
using summon::fbm::HardwareSelector;
using summon::fbm::IncarnationId;
using summon::fbm::ObservationId;
using summon::fbm::ObservationSequence;
using summon::fbm::PlanId;
using summon::fbm::PolicyGeneration;
using summon::fbm::PromotionGate;
using summon::fbm::RequestId;
using summon::fbm::Revision;
using summon::fbm::Snapshot;
using summon::fbm::StageIndex;
using summon::fbm::Timestamp;

// Fixed instants: the library never reads a clock, so every test is a pure
// function of these values.
constexpr std::uint64_t kCreatedAt = 1700000000ull;
constexpr std::uint64_t kUpdatedAt = kCreatedAt + 1000000ull;
constexpr std::uint64_t kExpiresAt = kCreatedAt + 60000000000ull;

Timestamp instant(std::uint64_t nanos) { return Timestamp::from_unix_nanos(nanos); }

FirmwareVersion version_of(std::string_view text) {
  auto parsed = FirmwareVersion::parse(text, "test");
  REQUIRE(parsed.has_value());
  return parsed.value();
}

Baseline draft_baseline() {
  Baseline baseline;
  baseline.id = BaselineId{std::string{"gpu-h100-train"}};
  baseline.generation = BaselineGeneration{3u};
  baseline.revision = Revision{5u};
  baseline.state = BaselineState::Draft;
  baseline.title = "H100 training baseline";

  HardwareSelector selector;
  selector.hardware_class = HardwareClassId{std::string{"gpu"}};
  selector.model = HardwareModelId{std::string{"h100"}};
  baseline.selectors.push_back(selector);

  // FirmwareVersion has no default constructor, so a component requirement is
  // built by aggregate initialization rather than default construction.
  ComponentRequirement requirement{
      .component = FirmwareComponentId{std::string{"bmc"}},
      .approved_version = version_of("2.4.1"),
      .conformant_versions = {},
      .rollback_targets = {},
      .freshness = FreshnessBound::within(86400000000000ull)};
  requirement.conformant_versions.push_back(requirement.approved_version);
  baseline.components.push_back(requirement);

  baseline.gate = PromotionGate{};
  baseline.created_at = instant(kCreatedAt);
  return baseline;
}

HardwareObservation hardware_observation() {
  HardwareObservation observation;
  observation.id = ObservationId{std::string{"obs-1"}};
  observation.evidence = EvidenceId{std::string{"ev-1"}};
  observation.asset = AssetId{std::string{"node-01"}};
  observation.hardware.hardware_class = HardwareClassId{std::string{"gpu"}};
  observation.hardware.model = HardwareModelId{std::string{"h100"}};
  observation.hardware.capabilities_observed = true;
  observation.hardware_generation = HardwareGeneration{7u};
  observation.sequence = ObservationSequence{12u};
  observation.observed_at = instant(kCreatedAt);
  observation.reporter = IncarnationId{3u};
  return observation;
}

BaselineException active_exception() {
  BaselineException exception;
  exception.id = ExceptionId{std::string{"exc-1"}};
  exception.scope.hardware_class = HardwareClassId{std::string{"gpu"}};
  exception.scope.components.push_back(FirmwareComponentId{std::string{"bmc"}});
  exception.expiry = Expiry::at(instant(kExpiresAt));
  exception.reason = "vendor firmware regression";
  exception.approval = ApprovalId{std::string{"ap-1"}};
  exception.granted_under = PolicyGeneration{4u};
  exception.revision = Revision{1u};
  exception.state = ExceptionState::Active;
  exception.created_at = instant(kCreatedAt);
  return exception;
}

Cohort authorized_cohort(const Baseline& baseline) {
  Cohort cohort;
  cohort.id = CohortId{std::string{"wave-1"}};
  cohort.baseline = baseline.id;
  cohort.baseline_generation = baseline.generation;
  cohort.baseline_digest = baseline.content_digest();
  cohort.policy_generation = PolicyGeneration{4u};
  cohort.authorized_epoch = ControlEpoch{9u};
  cohort.revision = Revision{2u};
  cohort.stage = StageIndex{1u};
  cohort.required_stages = StageIndex{2u};
  cohort.state = CohortState::Authorized;
  cohort.members.push_back(AssetId{std::string{"node-01"}});
  cohort.plan = PlanId{std::string{"plan-1"}};
  cohort.created_at = instant(kCreatedAt);
  cohort.stage_entered_at = instant(kCreatedAt);
  return cohort;
}

AuthorityBinding authorization_binding(const Baseline& baseline) {
  AuthorityBinding binding;
  binding.scope = "cohort/wave-1/rollout";
  binding.baseline = baseline.id;
  binding.baseline_generation = baseline.generation;
  binding.baseline_revision = baseline.revision;
  binding.baseline_digest = baseline.content_digest();
  binding.policy_generation = PolicyGeneration{4u};
  binding.control_epoch = ControlEpoch{9u};
  binding.commit_sequence = CommitSequence{11u};
  binding.plan = PlanId{std::string{"plan-1"}};
  binding.request = RequestId{std::string{"req-1"}};
  binding.incarnation = IncarnationId{3u};
  binding.subject_digest = baseline.content_digest();
  binding.issued_at = instant(kCreatedAt);
  binding.expiry = Expiry::at(instant(kExpiresAt));
  binding.mode = summon::fbm::SignatureMode::None;
  return binding;
}

// One snapshot that exercises every registry and every counter.
Snapshot populated_snapshot() {
  Snapshot snapshot;
  snapshot.commit_sequence = CommitSequence{11u};
  snapshot.control_epoch = ControlEpoch{9u};
  snapshot.policy_generation = PolicyGeneration{4u};
  snapshot.revision = Revision{12u};
  snapshot.incarnation = IncarnationId{3u};
  snapshot.created_at = instant(kCreatedAt);
  snapshot.updated_at = instant(kUpdatedAt);

  const Baseline baseline = draft_baseline();
  CHECK_OK(snapshot.baselines.put(baseline));

  auto recorded = snapshot.observations.record(hardware_observation());
  CHECK_OK(recorded);
  CHECK(recorded.value() == summon::fbm::ObservationOutcome::Recorded);

  CHECK_OK(snapshot.exceptions.put(active_exception()));
  CHECK_OK(snapshot.cohorts.put(authorized_cohort(baseline)));

  const AuthorizationAuthority authority = AuthorizationAuthority::unsigned_authority();
  auto filed = snapshot.authorizations.record(authority.mint(authorization_binding(baseline)));
  CHECK_OK(filed);
  CHECK(filed.value() == AuthorizationRegistry::RecordOutcome::Recorded);
  return snapshot;
}

}  // namespace

// --- The empty snapshot -----------------------------------------------------

FBM_TEST(snapshot_empty_has_no_counters_and_no_registry_entries) {
  const Snapshot empty = Snapshot::empty();

  CHECK(!empty.commit_sequence.is_set());
  CHECK(!empty.control_epoch.is_set());
  CHECK(!empty.policy_generation.is_set());
  CHECK(!empty.revision.is_set());
  CHECK(!empty.incarnation.is_set());
  CHECK(!empty.created_at.is_set());
  CHECK(!empty.updated_at.is_set());

  CHECK(empty.baselines.empty());
  CHECK_EQ(empty.observations.profile_count(), std::size_t{0});
  CHECK_EQ(empty.observations.component_count(), std::size_t{0});
  CHECK(empty.exceptions.empty());
  CHECK(empty.cohorts.empty());
  CHECK(empty.authorizations.empty());

  Diagnostics diagnostics;
  CHECK_OK(empty.validate("/snapshot", diagnostics));
  CHECK(diagnostics.empty());
}

FBM_TEST(snapshot_empty_round_trips_without_inventing_values) {
  const Snapshot empty = Snapshot::empty();
  const json::Value encoded = empty.to_json();

  REQUIRE(encoded.is_object());
  REQUIRE(encoded.find("format") != nullptr);
  CHECK_EQ(encoded.find("format")->as_string(), std::string{"summon.fbm.snapshot"});
  REQUIRE(encoded.find("format_version") != nullptr);
  CHECK_EQ(encoded.find("format_version")->as_integer(), std::int64_t{1});
  REQUIRE(encoded.find("baselines") != nullptr);
  CHECK(encoded.find("baselines")->is_array());
  REQUIRE(encoded.find("observations") != nullptr);
  CHECK(encoded.find("observations")->is_object());

  // Every unset member is omitted. Nothing is written as zero.
  for (const char* key : {"commit_sequence", "control_epoch", "policy_generation", "revision",
                          "incarnation", "created_at", "updated_at"}) {
    CHECK_MSG(encoded.find(key) == nullptr, "member " << key << " must be omitted when unset");
  }

  auto parsed = Snapshot::from_json(encoded, "/snapshot");
  CHECK_OK(parsed);
  CHECK(!parsed.value().commit_sequence.is_set());
  CHECK(!parsed.value().created_at.is_set());
  CHECK_EQ(parsed.value().canonical_bytes(), empty.canonical_bytes());
  CHECK(parsed.value().content_digest() == empty.content_digest());
  CHECK(parsed.value().baselines.empty());
  CHECK(parsed.value().authorizations.empty());
}

// --- Format marker and version ----------------------------------------------

FBM_TEST(snapshot_rejects_a_wrong_format_string) {
  json::Value encoded = populated_snapshot().to_json();
  encoded.set("format", json::Value{"summon.fbm.store"});

  auto parsed = Snapshot::from_json(encoded, "/snapshot");
  CHECK_ERROR(parsed, ErrorCode::FormatMagicMismatch);
  CHECK_EQ(parsed.error().path(), std::string{"/snapshot/format"});

  // A missing marker is a missing required member, not a licence to guess.
  json::Value absent = populated_snapshot().to_json();
  CHECK(absent.erase("format"));
  CHECK_ERROR(Snapshot::from_json(absent, "/snapshot"), ErrorCode::SchemaMissingField);

  // A marker of the wrong type is a type defect.
  json::Value wrong_type = populated_snapshot().to_json();
  wrong_type.set("format", json::Value{1});
  CHECK_ERROR(Snapshot::from_json(wrong_type, "/snapshot"), ErrorCode::SchemaWrongType);
}

FBM_TEST(snapshot_rejects_an_unsupported_format_version) {
  json::Value encoded = populated_snapshot().to_json();
  encoded.set("format_version", json::Value{2});

  auto parsed = Snapshot::from_json(encoded, "/snapshot");
  CHECK_ERROR(parsed, ErrorCode::FormatVersionUnsupported);
  CHECK_EQ(parsed.error().path(), std::string{"/snapshot/format_version"});

  json::Value negative = populated_snapshot().to_json();
  negative.set("format_version", json::Value{-1});
  CHECK_ERROR(Snapshot::from_json(negative, "/snapshot"), ErrorCode::SchemaValueOutOfRange);
}

FBM_TEST(snapshot_format_marker_and_version_are_enforced_first) {
  // A document that is wrong in every way still reports the frame defect: a
  // document this build cannot interpret is never partially interpreted.
  json::Value broken = populated_snapshot().to_json();
  broken.set("format", json::Value{"other.format"});
  broken.set("format_version", json::Value{99});
  broken.set("unknown_member", json::Value{1});
  CHECK(broken.erase("cohorts"));
  CHECK(broken.erase("created_at"));

  auto parsed = Snapshot::from_json(broken, "/snapshot");
  CHECK_ERROR(parsed, ErrorCode::FormatMagicMismatch);

  // With the marker correct, the version outranks every schema defect.
  json::Value version_only = populated_snapshot().to_json();
  version_only.set("format_version", json::Value{99});
  version_only.set("unknown_member", json::Value{1});
  CHECK(version_only.erase("cohorts"));

  auto version_parsed = Snapshot::from_json(version_only, "/snapshot");
  CHECK_ERROR(version_parsed, ErrorCode::FormatVersionUnsupported);

  // The same order holds when the defect is found through validate() rather
  // than through the reader.
  const Snapshot clean = populated_snapshot();
  Diagnostics diagnostics;
  CHECK_OK(clean.validate("/snapshot", diagnostics));
  CHECK(diagnostics.empty());
}

FBM_TEST(snapshot_rejects_unknown_missing_and_mistyped_members) {
  json::Value unknown = populated_snapshot().to_json();
  unknown.set("generation", json::Value{3});
  auto unknown_parsed = Snapshot::from_json(unknown, "/snapshot");
  CHECK_ERROR(unknown_parsed, ErrorCode::SchemaUnknownField);
  CHECK_EQ(unknown_parsed.error().path(), std::string{"/snapshot/generation"});

  json::Value missing = populated_snapshot().to_json();
  CHECK(missing.erase("observations"));
  CHECK_ERROR(Snapshot::from_json(missing, "/snapshot"), ErrorCode::SchemaMissingField);

  json::Value mistyped = populated_snapshot().to_json();
  mistyped.set("observations", json::Value::make_array());
  CHECK_ERROR(Snapshot::from_json(mistyped, "/snapshot"), ErrorCode::SchemaWrongType);

  json::Value mistyped_counter = populated_snapshot().to_json();
  mistyped_counter.set("revision", json::Value{"twelve"});
  CHECK_ERROR(Snapshot::from_json(mistyped_counter, "/snapshot"), ErrorCode::SchemaWrongType);

  json::Value negative_counter = populated_snapshot().to_json();
  negative_counter.set("revision", json::Value{-3});
  CHECK_ERROR(Snapshot::from_json(negative_counter, "/snapshot"),
              ErrorCode::SchemaValueOutOfRange);

  json::Value not_an_object = json::Value::make_array();
  CHECK_ERROR(Snapshot::from_json(not_an_object, "/snapshot"), ErrorCode::SchemaWrongType);
}

// --- Canonical bytes and digest ---------------------------------------------

FBM_TEST(snapshot_canonical_bytes_are_stable_across_a_round_trip) {
  const Snapshot original = populated_snapshot();

  // The canonical bytes are the canonical serialization of the value.
  CHECK_EQ(original.canonical_bytes(), json::write_canonical(original.to_json()));
  CHECK(original.content_digest() == summon::fbm::Sha256::of(original.canonical_bytes()));

  // The value may be rebuilt from its own JSON, and again from those bytes.
  auto parsed = Snapshot::from_json(original.to_json(), "/snapshot");
  CHECK_OK(parsed);
  CHECK_EQ(parsed.value().canonical_bytes(), original.canonical_bytes());
  CHECK(parsed.value().content_digest() == original.content_digest());

  auto reparsed_value = json::parse(original.canonical_bytes());
  CHECK_OK(reparsed_value);
  auto reparsed = Snapshot::from_json(reparsed_value.value(), "/snapshot");
  CHECK_OK(reparsed);
  CHECK_EQ(reparsed.value().canonical_bytes(), original.canonical_bytes());
  CHECK(reparsed.value().content_digest() == original.content_digest());

  // Nothing was dropped on the way: every counter and every registry entry is
  // present again.
  CHECK_EQ(reparsed.value().commit_sequence.value(), std::uint64_t{11});
  CHECK_EQ(reparsed.value().control_epoch.value(), std::uint64_t{9});
  CHECK_EQ(reparsed.value().policy_generation.value(), std::uint64_t{4});
  CHECK_EQ(reparsed.value().revision.value(), std::uint64_t{12});
  CHECK_EQ(reparsed.value().incarnation.value(), std::uint64_t{3});
  CHECK_EQ(reparsed.value().created_at, instant(kCreatedAt));
  CHECK_EQ(reparsed.value().updated_at, instant(kUpdatedAt));
  CHECK_EQ(reparsed.value().baselines.size(), std::size_t{1});
  CHECK_EQ(reparsed.value().observations.profile_count(), std::size_t{1});
  CHECK_EQ(reparsed.value().exceptions.size(), std::size_t{1});
  CHECK_EQ(reparsed.value().cohorts.size(), std::size_t{1});
  CHECK_EQ(reparsed.value().authorizations.size(), std::size_t{1});

  Diagnostics diagnostics;
  CHECK_OK(reparsed.value().validate("/snapshot", diagnostics));
  CHECK(diagnostics.empty());

  // Canonical bytes do not depend on how the document was written: the same
  // value written twice produces identical bytes.
  CHECK_EQ(Snapshot::empty().canonical_bytes(), Snapshot::empty().canonical_bytes());
  CHECK_EQ(original.canonical_bytes(), populated_snapshot().canonical_bytes());
}

FBM_TEST(snapshot_digest_changes_when_any_field_changes) {
  const Snapshot original = populated_snapshot();
  const Digest base = original.content_digest();

  Snapshot changed = original;
  changed.commit_sequence = CommitSequence{12u};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.control_epoch = ControlEpoch{10u};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.policy_generation = PolicyGeneration{5u};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.revision = Revision{13u};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.incarnation = IncarnationId{4u};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.created_at = instant(kCreatedAt + 1u);
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.updated_at = instant(kUpdatedAt + 1u);
  CHECK(changed.content_digest() != base);

  // Clearing a counter changes the digest too: an unset counter is omitted,
  // not written as zero.
  changed = original;
  changed.commit_sequence = CommitSequence::unset();
  CHECK(changed.content_digest() != base);

  // Every registry takes part in the digest.
  changed = original;
  changed.baselines = summon::fbm::BaselineRegistry{};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.observations = summon::fbm::ObservationLog{};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.exceptions = ExceptionRegistry{};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.cohorts = summon::fbm::CohortRegistry{};
  CHECK(changed.content_digest() != base);

  changed = original;
  changed.authorizations = AuthorizationRegistry{};
  CHECK(changed.content_digest() != base);

  // ... and each registry can be added to the empty snapshot on its own.
  const Snapshot empty = Snapshot::empty();
  const Digest empty_digest = empty.content_digest();

  Snapshot with_baseline = empty;
  CHECK_OK(with_baseline.baselines.put(draft_baseline()));
  CHECK(with_baseline.content_digest() != empty_digest);
  CHECK(with_baseline.content_digest() != base);

  Snapshot with_observation = empty;
  CHECK_OK(with_observation.observations.record(hardware_observation()));
  CHECK(with_observation.content_digest() != empty_digest);

  Snapshot with_exception = empty;
  CHECK_OK(with_exception.exceptions.put(active_exception()));
  CHECK(with_exception.content_digest() != empty_digest);

  Snapshot with_cohort = empty;
  const Baseline baseline = draft_baseline();
  CHECK_OK(with_cohort.baselines.put(baseline));
  CHECK_OK(with_cohort.cohorts.put(authorized_cohort(baseline)));
  CHECK(with_cohort.content_digest() != empty_digest);

  Snapshot with_authorization = empty;
  const AuthorizationAuthority authority = AuthorizationAuthority::unsigned_authority();
  CHECK_OK(with_authorization.authorizations.record(authority.mint(authorization_binding(baseline))));
  CHECK(with_authorization.content_digest() != empty_digest);

  // Two structurally equal documents always produce identical digest bytes.
  CHECK(populated_snapshot().content_digest() == base);
}

// --- Cross-registry consistency ---------------------------------------------

FBM_TEST(snapshot_validate_rejects_cross_registry_inconsistency) {
  // A cohort that names a baseline the snapshot does not contain.
  Snapshot missing_baseline = populated_snapshot();
  missing_baseline.authorizations = AuthorizationRegistry{};
  CHECK(missing_baseline.baselines.erase(BaselineId{std::string{"gpu-h100-train"}}));
  Diagnostics diagnostics;
  CHECK(!missing_baseline.validate("/snapshot", diagnostics).has_value());
  CHECK_EQ(diagnostics.primary().code(), ErrorCode::IdentityUnknownBaseline);
  CHECK_EQ(diagnostics.primary().path(), std::string{"/snapshot/cohorts/0/baseline"});

  // An authorization that names a baseline the snapshot does not contain.
  Snapshot missing_authorization_baseline = populated_snapshot();
  missing_authorization_baseline.cohorts = summon::fbm::CohortRegistry{};
  CHECK(missing_authorization_baseline.baselines.erase(
      BaselineId{std::string{"gpu-h100-train"}}));
  Diagnostics authorization_diagnostics;
  CHECK(!missing_authorization_baseline.validate("/snapshot", authorization_diagnostics).has_value());
  CHECK_EQ(authorization_diagnostics.primary().code(), ErrorCode::IdentityUnknownBaseline);
  CHECK_EQ(authorization_diagnostics.primary().path(),
           std::string{"/snapshot/authorizations/0/binding/baseline"});

  // updated_at cannot precede created_at.
  Snapshot reversed = populated_snapshot();
  reversed.created_at = instant(kUpdatedAt);
  reversed.updated_at = instant(kCreatedAt);
  Diagnostics reversed_diagnostics;
  CHECK(!reversed.validate("/snapshot", reversed_diagnostics).has_value());
  CHECK_EQ(reversed_diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
  CHECK_EQ(reversed_diagnostics.primary().path(), std::string{"/snapshot/updated_at"});

  // A document read from JSON is validated too, so an inconsistent snapshot is
  // never returned as if it were durable state.
  CHECK_ERROR(Snapshot::from_json(missing_baseline.to_json(), "/snapshot"),
              ErrorCode::IdentityUnknownBaseline);
}
