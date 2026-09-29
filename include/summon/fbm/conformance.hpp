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

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {

enum class ConformanceState : std::uint8_t {
  Unknown = 0,
  Unsupported = 1,
  Blocked = 2,
  Exception = 3,
  PendingRollback = 4,
  PendingRollout = 5,
  Drifted = 6,
  Conformant = 7,
};

std::string_view conformance_state_token(ConformanceState state) noexcept;
Result<ConformanceState> conformance_state_from_token(std::string_view token);

// Documented resolution precedence. The state with the highest precedence among
// the states that apply is the reported state. The order is:
//
//   1. Unsupported  - the asset is outside every authoritative baseline scope
//   2. Unknown      - no authoritative baseline, or required evidence missing,
//                     stale, or undetermined
//   3. Blocked      - a facility gate denies mutation, or the evidence floor
//                     excludes the available evidence
//   4. Exception    - an effective exception covers every outstanding residual
//   5. PendingRollback - an authorized rollback plan targets this asset
//   6. PendingRollout  - an authorized rollout plan targets this asset
//   7. Drifted      - at least one residual remains
//   8. Conformant   - no residual remains
//
// This precedence is a pure function of the state, so the same evidence always
// resolves to the same primary state.
std::uint8_t conformance_precedence(ConformanceState state) noexcept;

enum class DriftKind : std::uint8_t {
  MissingObservation = 0,
  StaleObservation = 1,
  UnknownVersion = 2,
  VersionMismatch = 3,
  UnexpectedComponent = 4,
  IncompatibleCombination = 5,
  UnverifiableRule = 6,
};

std::string_view drift_kind_token(DriftKind kind) noexcept;

// The exact observed-versus-required residual. Drift is never collapsed to a
// boolean: the observed version, the required version, the signed distance, the
// evidence age, and the rule that produced the residual are all retained.
struct DriftResidual {
  DriftKind kind = DriftKind::MissingObservation;
  FirmwareComponentId component;
  RuleId rule;
  std::optional<FirmwareVersion> observed;
  std::optional<FirmwareVersion> required;
  bool has_version_delta = false;
  std::int64_t version_delta = 0;
  Timestamp observed_at;
  FreshnessBound freshness;
  std::string detail;
  std::string path;

  json::Value to_json() const;
  std::string to_string() const;
};

struct ComponentEvaluation {
  FirmwareComponentId component;
  FirmwareVersion required;
  std::optional<FirmwareVersion> observed;
  bool evidence_present = false;
  bool evidence_fresh = false;
  bool conformant = false;
  bool has_version_delta = false;
  std::int64_t version_delta = 0;
  Timestamp observed_at;
  ObservationSequence observation_sequence;
  EvidenceId evidence;

  json::Value to_json() const;
};

// Facility gates owned by other DCP repositories. This repository never closes
// or opens them; it consumes them. An unset gate is Unknown, and Unknown is
// never read as open.
enum class GateState : std::uint8_t {
  Open = 0,
  Closed = 1,
  Unknown = 2,
};

std::string_view gate_state_token(GateState state) noexcept;
Result<GateState> gate_state_from_token(std::string_view token);

struct FacilityGates {
  GateState capacity = GateState::Unknown;
  CapacityGeneration capacity_generation;
  GateState dependency = GateState::Unknown;
  DependencyGeneration dependency_generation;
  GateState maintenance = GateState::Unknown;
  MaintenanceGeneration maintenance_generation;
  GateState topology = GateState::Unknown;
  TopologyGeneration topology_generation;
  std::string closed_reason;

  bool all_open() const;
  // Gate names that are not Open, in the fixed order capacity, dependency,
  // maintenance, topology.
  std::vector<std::string> not_open() const;

  json::Value to_json() const;
  static Result<FacilityGates> from_json(const json::Value& value, std::string_view path);
};

// Stable reason tokens. They are part of the CLI and JSON contract.
namespace reason_code {
inline constexpr std::string_view kConformant = "conformant";
inline constexpr std::string_view kDrift = "drift";
inline constexpr std::string_view kBaselineAbsent = "baseline_absent";
inline constexpr std::string_view kBaselineAmbiguous = "baseline_ambiguous";
inline constexpr std::string_view kSelectorOutOfScope = "selector_out_of_scope";
inline constexpr std::string_view kEvidenceMissing = "evidence_missing";
inline constexpr std::string_view kEvidenceStale = "evidence_stale";
inline constexpr std::string_view kVersionUnknown = "version_unknown";
inline constexpr std::string_view kGateClosed = "gate_closed";
inline constexpr std::string_view kGateUnknown = "gate_unknown";
inline constexpr std::string_view kEvidenceFloor = "evidence_floor";
inline constexpr std::string_view kExceptionEffective = "exception_effective";
inline constexpr std::string_view kPendingRollout = "pending_rollout";
inline constexpr std::string_view kPendingRollback = "pending_rollback";
inline constexpr std::string_view kRuleViolated = "rule_violated";
inline constexpr std::string_view kRuleUnverifiable = "rule_unverifiable";
inline constexpr std::string_view kRollbackTargetUnknown = "rollback_target_unknown";
inline constexpr std::string_view kRollbackTargetIncompatible = "rollback_target_incompatible";
inline constexpr std::string_view kNotEligibleConformance = "not_eligible_conformance";
inline constexpr std::string_view kEligible = "eligible";
}  // namespace reason_code

struct ConformanceVerdict {
  ConformanceState state = ConformanceState::Unknown;
  std::string reason_code_value;
  std::string reason;

  AssetId asset;
  HardwareProfile hardware;

  BaselineId baseline;
  BaselineGeneration baseline_generation;
  Revision baseline_revision;
  Digest baseline_digest{};

  PolicyGeneration policy_generation;
  ControlEpoch control_epoch;
  CommitSequence commit_sequence;
  Timestamp evaluated_at;

  // Ascending by component identity.
  std::vector<ComponentEvaluation> components;
  // Ascending by (kind, component, rule). Deterministic.
  std::vector<DriftResidual> residuals;
  // Ascending by rule identity.
  std::vector<RuleEvaluation> rules;

  ExceptionId applied_exception;
  bool has_applied_exception = false;

  bool is_conformant() const { return state == ConformanceState::Conformant; }

  json::Value to_json() const;
  std::string to_string() const;
};

enum class Eligibility : std::uint8_t {
  Eligible = 0,
  NotEligible = 1,
  // Not decidable from the evidence and gates supplied. Never folded into
  // Eligible.
  Unknown = 2,
};

std::string_view eligibility_token(Eligibility eligibility) noexcept;

struct EligibilityVerdict {
  Eligibility eligibility = Eligibility::Unknown;
  std::string reason_code_value;
  std::string reason;

  AssetId asset;
  BaselineId baseline;
  BaselineGeneration baseline_generation;
  Revision baseline_revision;
  PolicyGeneration policy_generation;
  ControlEpoch control_epoch;
  CommitSequence commit_sequence;
  Timestamp evaluated_at;

  std::optional<FirmwareVersion> rollout_target;
  std::optional<FirmwareVersion> rollback_target;
  RollbackGeneration rollback_generation;

  FacilityGates gates;
  ConformanceVerdict conformance;
  // Exact blocking conditions in a fixed order. Empty exactly when Eligible.
  std::vector<std::string> blockers;

  json::Value to_json() const;
  std::string to_string() const;
};

// Everything an evaluation needs beyond the durable snapshot. The current time
// is supplied by the caller so that evaluation is reproducible.
struct EvaluationRequest {
  AssetId asset;
  Timestamp now;
  FacilityGates gates;
  // Evidence recorded at or below this sequence is ignored. Unset disables the
  // floor.
  ObservationSequence evidence_floor;
  // The rollback target the caller intends to use. It must be a known rollback
  // target of the authoritative baseline; anything else is reported as
  // unknown or incompatible rather than attempted.
  std::optional<FirmwareVersion> requested_rollback_target;
  bool require_gates_open = false;
};

}  // namespace summon::fbm
