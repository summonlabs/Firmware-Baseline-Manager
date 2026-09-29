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

#include "summon/fbm/conformance.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/text_format.hpp"

namespace summon::fbm {
namespace {

// --- Published token vocabularies -------------------------------------------
//
// Tokens are stable lower_snake_case strings and are part of the CLI and JSON
// contract: a token is never renamed and never reused for a different meaning.
// One table per enumeration drives both directions, so the token that is
// written is always exactly the token that is read back.

struct ConformanceStateToken {
  ConformanceState state;
  std::string_view token;
};

constexpr ConformanceStateToken kConformanceStateTokens[] = {
    {ConformanceState::Unknown, "unknown"},
    {ConformanceState::Unsupported, "unsupported"},
    {ConformanceState::Blocked, "blocked"},
    {ConformanceState::Exception, "exception"},
    {ConformanceState::PendingRollback, "pending_rollback"},
    {ConformanceState::PendingRollout, "pending_rollout"},
    {ConformanceState::Drifted, "drifted"},
    {ConformanceState::Conformant, "conformant"},
};

struct DriftKindToken {
  DriftKind kind;
  std::string_view token;
};

constexpr DriftKindToken kDriftKindTokens[] = {
    {DriftKind::MissingObservation, "missing_observation"},
    {DriftKind::StaleObservation, "stale_observation"},
    {DriftKind::UnknownVersion, "unknown_version"},
    {DriftKind::VersionMismatch, "version_mismatch"},
    {DriftKind::UnexpectedComponent, "unexpected_component"},
    {DriftKind::IncompatibleCombination, "incompatible_combination"},
    {DriftKind::UnverifiableRule, "unverifiable_rule"},
};

struct GateStateToken {
  GateState state;
  std::string_view token;
};

constexpr GateStateToken kGateStateTokens[] = {
    {GateState::Open, "open"},
    {GateState::Closed, "closed"},
    {GateState::Unknown, "unknown"},
};

struct EligibilityToken {
  Eligibility eligibility;
  std::string_view token;
};

constexpr EligibilityToken kEligibilityTokens[] = {
    {Eligibility::Eligible, "eligible"},
    {Eligibility::NotEligible, "not_eligible"},
    {Eligibility::Unknown, "unknown"},
};

// A value that is not a declared enumerator has no token in the vocabulary. It
// is named as unrecognised rather than being folded into a neighbouring
// enumerator, and the name deliberately does not parse back.
std::string_view conformance_state_token_of(ConformanceState state) noexcept {
  for (const ConformanceStateToken& entry : kConformanceStateTokens) {
    if (entry.state == state) {
      return entry.token;
    }
  }
  return "unknown_state";
}

std::string_view drift_kind_token_of(DriftKind kind) noexcept {
  for (const DriftKindToken& entry : kDriftKindTokens) {
    if (entry.kind == kind) {
      return entry.token;
    }
  }
  return "unknown_kind";
}

std::string_view gate_state_token_of(GateState state) noexcept {
  for (const GateStateToken& entry : kGateStateTokens) {
    if (entry.state == state) {
      return entry.token;
    }
  }
  return "unknown_gate";
}

std::string_view eligibility_token_of(Eligibility eligibility) noexcept {
  for (const EligibilityToken& entry : kEligibilityTokens) {
    if (entry.eligibility == eligibility) {
      return entry.token;
    }
  }
  return "unknown_eligibility";
}

Error invalid_token_error(std::string_view kind, std::string_view token) {
  std::string message{"unknown "};
  message += kind;
  message += " token \"";
  message += token;
  message += '"';
  return Error{ErrorCode::SchemaInvalidEnumValue, std::move(message), std::string{}};
}

// --- Shared renderings ------------------------------------------------------

// The exact value of a counter, or the explicit statement that it was never
// set. An unset generation is never rendered as zero.
template <class ScalarT>
std::string scalar_text(const ScalarT& value) {
  if (!value.is_set()) {
    return std::string{"<unset>"};
  }
  return std::to_string(value.value());
}

std::string text_or_unset(const std::string& value) {
  return value.empty() ? std::string{"<unset>"} : value;
}

std::string signed_text(std::int64_t value) {
  std::string out;
  if (value > 0) {
    out += '+';
  }
  out += std::to_string(value);
  return out;
}

std::string freshness_text(const FreshnessBound& bound) {
  if (!bound.is_set()) {
    return std::string{"<unset>"};
  }
  if (bound.is_unbounded()) {
    return std::string{"unbounded"};
  }
  return "max_age_nanos=" + std::to_string(bound.max_age_nanos());
}

std::string capabilities_text(const HardwareProfile& hardware) {
  if (!hardware.capabilities_observed) {
    return std::string{"not observed"};
  }
  if (hardware.capabilities.empty()) {
    // Observed, and observed to expose nothing: a different fact from an
    // unobserved capability set.
    return std::string{"observed (none)"};
  }
  std::string out{"observed ("};
  for (std::size_t index = 0; index < hardware.capabilities.size(); ++index) {
    if (index != 0) {
      out += ", ";
    }
    out += hardware.capabilities[index].to_string();
  }
  out += ')';
  return out;
}

std::string rule_evaluation_text(const RuleEvaluation& evaluation) {
  std::string out{"rule="};
  out += evaluation.rule.to_string();
  out += " outcome=";
  out += rule_outcome_token(evaluation.outcome);
  out += " requirement_outcome=";
  out += requirement_outcome_token(evaluation.requirement_outcome);
  out += " detail=";
  out += text_or_unset(evaluation.detail);
  return out;
}

// --- JSON helpers -----------------------------------------------------------

json::Value string_value(std::string_view text) { return json::Value{std::string{text}}; }

json::Value freshness_to_json(const FreshnessBound& bound) {
  json::Value out = json::Value::make_object();
  if (bound.is_unbounded()) {
    out.set("unbounded", json::Value{true});
  } else {
    out.set("max_age_nanos", json::Value{bound.max_age_nanos()});
  }
  return out;
}

json::Value rule_evaluation_to_json(const RuleEvaluation& evaluation) {
  json::Value out = json::Value::make_object();
  if (evaluation.rule.is_set()) {
    out.set("rule", json::Value{evaluation.rule.value()});
  }
  out.set("outcome", string_value(rule_outcome_token(evaluation.outcome)));
  out.set("requirement_outcome",
          string_value(requirement_outcome_token(evaluation.requirement_outcome)));
  if (!evaluation.detail.empty()) {
    out.set("detail", json::Value{evaluation.detail});
  }
  return out;
}

// --- Strict field readers ---------------------------------------------------

GateState read_gate(json::ObjectReader& reader, std::string_view key,
                    Diagnostics& diagnostics) {
  const json::Value* value = reader.required(key, json::Type::String);
  if (value == nullptr) {
    return GateState::Unknown;
  }
  const Result<GateState> parsed = gate_state_from_token(value->as_string());
  if (!parsed.has_value()) {
    // The defect is reported at the exact JSON pointer of the gate it came
    // from; the object itself is discarded by the caller.
    diagnostics.add(Error{parsed.error().code(), parsed.error().message(), reader.child_path(key)});
    return GateState::Unknown;
  }
  return parsed.value();
}

template <class ScalarT>
ScalarT read_generation(json::ObjectReader& reader, std::string_view key,
                        Diagnostics& diagnostics) {
  const json::Value* value = reader.required(key, json::Type::Integer);
  if (value == nullptr) {
    return ScalarT{};
  }
  const std::int64_t raw = value->as_integer();
  if (raw < 0) {
    std::string message{key};
    message += " must be a non-negative integer";
    diagnostics.add(Error{ErrorCode::SchemaValueOutOfRange, std::move(message),
                          reader.child_path(key)});
    return ScalarT{};
  }
  return ScalarT{static_cast<std::uint64_t>(raw)};
}

}  // namespace

// --- Conformance state ------------------------------------------------------

std::string_view conformance_state_token(ConformanceState state) noexcept {
  return conformance_state_token_of(state);
}

Result<ConformanceState> conformance_state_from_token(std::string_view token) {
  for (const ConformanceStateToken& entry : kConformanceStateTokens) {
    if (entry.token == token) {
      return entry.state;
    }
  }
  return invalid_token_error("conformance state", token);
}

std::uint8_t conformance_precedence(ConformanceState state) noexcept {
  // Documented resolution precedence, matching the ordering published in
  // conformance.hpp. Larger wins: Unsupported 8, Unknown 7, Blocked 6,
  // Exception 5, PendingRollback 4, PendingRollout 3, Drifted 2, Conformant 1.
  // A value that is not a declared state has no precedence.
  switch (state) {
    case ConformanceState::Unsupported:
      return 8u;
    case ConformanceState::Unknown:
      return 7u;
    case ConformanceState::Blocked:
      return 6u;
    case ConformanceState::Exception:
      return 5u;
    case ConformanceState::PendingRollback:
      return 4u;
    case ConformanceState::PendingRollout:
      return 3u;
    case ConformanceState::Drifted:
      return 2u;
    case ConformanceState::Conformant:
      return 1u;
  }
  return 0u;
}

// --- Drift ------------------------------------------------------------------

std::string_view drift_kind_token(DriftKind kind) noexcept { return drift_kind_token_of(kind); }

json::Value DriftResidual::to_json() const {
  json::Value out = json::Value::make_object();
  out.set("kind", string_value(drift_kind_token(kind)));
  if (component.is_set()) {
    out.set("component", json::Value{component.value()});
  }
  if (rule.is_set()) {
    out.set("rule", json::Value{rule.value()});
  }
  if (observed.has_value()) {
    out.set("observed", json::Value{observed->to_string()});
  }
  if (required.has_value()) {
    out.set("required", json::Value{required->to_string()});
  }
  if (has_version_delta) {
    out.set("version_delta", json::Value{version_delta});
  }
  if (observed_at.is_set()) {
    out.set("observed_at", json::Value{observed_at.to_rfc3339()});
  }
  if (freshness.is_set()) {
    out.set("freshness", freshness_to_json(freshness));
  }
  if (!detail.empty()) {
    out.set("detail", json::Value{detail});
  }
  if (!path.empty()) {
    out.set("path", json::Value{path});
  }
  return out;
}

std::string DriftResidual::to_string() const {
  std::string out{"kind="};
  out += drift_kind_token(kind);
  out += " component=";
  out += component.to_string();
  out += " rule=";
  out += rule.to_string();
  out += " observed=";
  out += text::format_optional_version(observed);
  out += " required=";
  out += text::format_optional_version(required);
  if (has_version_delta) {
    out += " delta=";
    out += signed_text(version_delta);
  }
  out += " observed_at=";
  out += text::format_timestamp(observed_at);
  if (freshness.is_set()) {
    out += " freshness=";
    out += freshness_text(freshness);
  }
  out += " detail=";
  out += text_or_unset(detail);
  if (!path.empty()) {
    out += " path=";
    out += path;
  }
  return out;
}

json::Value ComponentEvaluation::to_json() const {
  json::Value out = json::Value::make_object();
  if (component.is_set()) {
    out.set("component", json::Value{component.value()});
  }
  out.set("required", json::Value{required.to_string()});
  if (observed.has_value()) {
    out.set("observed", json::Value{observed->to_string()});
  }
  out.set("evidence_present", json::Value{evidence_present});
  out.set("evidence_fresh", json::Value{evidence_fresh});
  out.set("conformant", json::Value{conformant});
  if (has_version_delta) {
    out.set("version_delta", json::Value{version_delta});
  }
  if (observed_at.is_set()) {
    out.set("observed_at", json::Value{observed_at.to_rfc3339()});
  }
  if (observation_sequence.is_set()) {
    out.set("observation_sequence", json::Value{observation_sequence.value()});
  }
  if (evidence.is_set()) {
    out.set("evidence", json::Value{evidence.value()});
  }
  return out;
}

// --- Facility gates ---------------------------------------------------------

std::string_view gate_state_token(GateState state) noexcept { return gate_state_token_of(state); }

Result<GateState> gate_state_from_token(std::string_view token) {
  for (const GateStateToken& entry : kGateStateTokens) {
    if (entry.token == token) {
      return entry.state;
    }
  }
  return invalid_token_error("gate state", token);
}

bool FacilityGates::all_open() const {
  return capacity == GateState::Open && dependency == GateState::Open &&
         maintenance == GateState::Open && topology == GateState::Open;
}

std::vector<std::string> FacilityGates::not_open() const {
  // Fixed order: capacity, dependency, maintenance, topology.
  std::vector<std::string> out;
  if (capacity != GateState::Open) {
    out.emplace_back("capacity");
  }
  if (dependency != GateState::Open) {
    out.emplace_back("dependency");
  }
  if (maintenance != GateState::Open) {
    out.emplace_back("maintenance");
  }
  if (topology != GateState::Open) {
    out.emplace_back("topology");
  }
  return out;
}

json::Value FacilityGates::to_json() const {
  json::Value out = json::Value::make_object();
  out.set("capacity", string_value(gate_state_token(capacity)));
  if (capacity_generation.is_set()) {
    out.set("capacity_generation", json::Value{capacity_generation.value()});
  }
  out.set("dependency", string_value(gate_state_token(dependency)));
  if (dependency_generation.is_set()) {
    out.set("dependency_generation", json::Value{dependency_generation.value()});
  }
  out.set("maintenance", string_value(gate_state_token(maintenance)));
  if (maintenance_generation.is_set()) {
    out.set("maintenance_generation", json::Value{maintenance_generation.value()});
  }
  out.set("topology", string_value(gate_state_token(topology)));
  if (topology_generation.is_set()) {
    out.set("topology_generation", json::Value{topology_generation.value()});
  }
  if (!closed_reason.empty()) {
    out.set("closed_reason", json::Value{closed_reason});
  }
  return out;
}

Result<FacilityGates> FacilityGates::from_json(const json::Value& value, std::string_view path) {
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType, "facility gates must be a JSON object",
                 std::string{path}};
  }
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);

  FacilityGates gates;
  gates.capacity = read_gate(reader, "capacity", diagnostics);
  gates.capacity_generation =
      read_generation<CapacityGeneration>(reader, "capacity_generation", diagnostics);
  gates.dependency = read_gate(reader, "dependency", diagnostics);
  gates.dependency_generation =
      read_generation<DependencyGeneration>(reader, "dependency_generation", diagnostics);
  gates.maintenance = read_gate(reader, "maintenance", diagnostics);
  gates.maintenance_generation =
      read_generation<MaintenanceGeneration>(reader, "maintenance_generation", diagnostics);
  gates.topology = read_gate(reader, "topology", diagnostics);
  gates.topology_generation =
      read_generation<TopologyGeneration>(reader, "topology_generation", diagnostics);
  if (const json::Value* reason = reader.optional("closed_reason", json::Type::String)) {
    gates.closed_reason = reason->as_string();
  }
  reader.finish();

  if (!diagnostics.empty()) {
    // Every defect was collected; the primary one is selected deterministically
    // by precedence, path, and message - never by discovery order.
    return diagnostics.primary();
  }
  return gates;
}

// --- Conformance verdict ----------------------------------------------------

json::Value ConformanceVerdict::to_json() const {
  json::Value out = json::Value::make_object();
  out.set("state", string_value(conformance_state_token(state)));
  out.set("reason_code", json::Value{reason_code_value});
  out.set("reason", json::Value{reason});
  if (asset.is_set()) {
    out.set("asset", json::Value{asset.value()});
  }
  out.set("hardware", hardware.to_json());
  if (baseline.is_set()) {
    out.set("baseline", json::Value{baseline.value()});
  }
  if (baseline_generation.is_set()) {
    out.set("baseline_generation", json::Value{baseline_generation.value()});
  }
  if (baseline_revision.is_set()) {
    out.set("baseline_revision", json::Value{baseline_revision.value()});
  }
  out.set("baseline_digest", json::Value{digest_to_hex(baseline_digest)});
  if (policy_generation.is_set()) {
    out.set("policy_generation", json::Value{policy_generation.value()});
  }
  if (control_epoch.is_set()) {
    out.set("control_epoch", json::Value{control_epoch.value()});
  }
  if (commit_sequence.is_set()) {
    out.set("commit_sequence", json::Value{commit_sequence.value()});
  }
  if (evaluated_at.is_set()) {
    out.set("evaluated_at", json::Value{evaluated_at.to_rfc3339()});
  }

  json::Value component_rows = json::Value::make_array();
  for (const ComponentEvaluation& evaluation : this->components) {
    component_rows.push_back(evaluation.to_json());
  }
  out.set("components", std::move(component_rows));

  json::Value residual_rows = json::Value::make_array();
  for (const DriftResidual& residual : this->residuals) {
    residual_rows.push_back(residual.to_json());
  }
  out.set("residuals", std::move(residual_rows));

  json::Value rule_rows = json::Value::make_array();
  for (const RuleEvaluation& evaluation : this->rules) {
    rule_rows.push_back(rule_evaluation_to_json(evaluation));
  }
  out.set("rules", std::move(rule_rows));

  if (has_applied_exception && applied_exception.is_set()) {
    out.set("applied_exception", json::Value{applied_exception.value()});
  }
  return out;
}

std::string ConformanceVerdict::to_string() const {
  std::string out{"state: "};
  out += conformance_state_token(state);
  out += "\nreason_code: ";
  out += text_or_unset(reason_code_value);
  out += "\nreason: ";
  out += text_or_unset(reason);
  out += "\nasset: ";
  out += asset.to_string();
  out += "\nhardware_class: ";
  out += hardware.hardware_class.to_string();
  out += "\nhardware_model: ";
  out += hardware.model.to_string();
  out += "\nhardware_revision: ";
  out += scalar_text(hardware.revision);
  out += "\ncapabilities: ";
  out += capabilities_text(hardware);
  out += "\nbaseline: ";
  out += baseline.to_string();
  out += "\nbaseline_generation: ";
  out += scalar_text(baseline_generation);
  out += "\nbaseline_revision: ";
  out += scalar_text(baseline_revision);
  out += "\nbaseline_digest: ";
  out += digest_to_hex(baseline_digest);
  out += "\npolicy_generation: ";
  out += scalar_text(policy_generation);
  out += "\ncontrol_epoch: ";
  out += scalar_text(control_epoch);
  out += "\ncommit_sequence: ";
  out += scalar_text(commit_sequence);
  out += "\nevaluated_at: ";
  out += text::format_timestamp(evaluated_at);
  if (has_applied_exception) {
    out += "\napplied_exception: ";
    out += applied_exception.to_string();
  }

  const std::vector<std::string> headers{"component", "required", "observed", "conformant",
                                         "delta"};
  const std::vector<std::size_t> right_aligned{3u, 4u};
  text::Table table(headers, right_aligned);
  for (const ComponentEvaluation& evaluation : components) {
    table.add_row({evaluation.component.to_string(),
                   evaluation.required.to_string(),
                   text::format_optional_version(evaluation.observed),
                   evaluation.conformant ? "true" : "false",
                   evaluation.has_version_delta ? signed_text(evaluation.version_delta)
                                                : std::string{"<unset>"}});
  }
  out += "\ncomponents:\n";
  out += table.render();

  if (residuals.empty()) {
    out += "residuals: none\n";
  } else {
    out += "residuals:\n";
    for (const DriftResidual& residual : residuals) {
      out += "- ";
      out += residual.to_string();
      out += '\n';
    }
  }

  if (rules.empty()) {
    out += "rules: none\n";
  } else {
    out += "rules:\n";
    for (const RuleEvaluation& evaluation : rules) {
      out += "- ";
      out += rule_evaluation_text(evaluation);
      out += '\n';
    }
  }
  return out;
}

// --- Eligibility ------------------------------------------------------------

std::string_view eligibility_token(Eligibility eligibility) noexcept {
  return eligibility_token_of(eligibility);
}

namespace {

std::string gates_text(const FacilityGates& gates) {
  std::string out{"capacity="};
  out += gate_state_token(gates.capacity);
  out += " generation=";
  out += scalar_text(gates.capacity_generation);
  out += "  dependency=";
  out += gate_state_token(gates.dependency);
  out += " generation=";
  out += scalar_text(gates.dependency_generation);
  out += "  maintenance=";
  out += gate_state_token(gates.maintenance);
  out += " generation=";
  out += scalar_text(gates.maintenance_generation);
  out += "  topology=";
  out += gate_state_token(gates.topology);
  out += " generation=";
  out += scalar_text(gates.topology_generation);
  return out;
}

// One line, so that embedding the conformance verdict inside the eligibility
// verdict stays readable instead of recursing into a second full report.
std::string conformance_summary_text(const ConformanceVerdict& verdict) {
  std::string out{"state="};
  out += conformance_state_token(verdict.state);
  out += " reason_code=";
  out += text_or_unset(verdict.reason_code_value);
  out += " baseline=";
  out += verdict.baseline.to_string();
  out += " baseline_generation=";
  out += scalar_text(verdict.baseline_generation);
  out += " baseline_revision=";
  out += scalar_text(verdict.baseline_revision);
  out += " components=";
  out += std::to_string(verdict.components.size());
  out += " residuals=";
  out += std::to_string(verdict.residuals.size());
  out += " rules=";
  out += std::to_string(verdict.rules.size());
  if (verdict.has_applied_exception) {
    out += " applied_exception=";
    out += verdict.applied_exception.to_string();
  }
  return out;
}

}  // namespace

json::Value EligibilityVerdict::to_json() const {
  json::Value out = json::Value::make_object();
  out.set("eligibility", string_value(eligibility_token(eligibility)));
  out.set("reason_code", json::Value{reason_code_value});
  out.set("reason", json::Value{reason});
  if (asset.is_set()) {
    out.set("asset", json::Value{asset.value()});
  }
  if (baseline.is_set()) {
    out.set("baseline", json::Value{baseline.value()});
  }
  if (baseline_generation.is_set()) {
    out.set("baseline_generation", json::Value{baseline_generation.value()});
  }
  if (baseline_revision.is_set()) {
    out.set("baseline_revision", json::Value{baseline_revision.value()});
  }
  if (policy_generation.is_set()) {
    out.set("policy_generation", json::Value{policy_generation.value()});
  }
  if (control_epoch.is_set()) {
    out.set("control_epoch", json::Value{control_epoch.value()});
  }
  if (commit_sequence.is_set()) {
    out.set("commit_sequence", json::Value{commit_sequence.value()});
  }
  if (evaluated_at.is_set()) {
    out.set("evaluated_at", json::Value{evaluated_at.to_rfc3339()});
  }
  if (rollout_target.has_value()) {
    out.set("rollout_target", json::Value{rollout_target->to_string()});
  }
  if (rollback_target.has_value()) {
    out.set("rollback_target", json::Value{rollback_target->to_string()});
  }
  if (rollback_generation.is_set()) {
    out.set("rollback_generation", json::Value{rollback_generation.value()});
  }
  out.set("gates", gates.to_json());
  out.set("conformance", conformance.to_json());

  json::Value blocker_rows = json::Value::make_array();
  for (const std::string& blocker : this->blockers) {
    blocker_rows.push_back(json::Value{blocker});
  }
  out.set("blockers", std::move(blocker_rows));
  return out;
}

std::string EligibilityVerdict::to_string() const {
  std::string out{"eligibility: "};
  out += eligibility_token(eligibility);
  out += "\nreason_code: ";
  out += text_or_unset(reason_code_value);
  out += "\nreason: ";
  out += text_or_unset(reason);
  out += "\nasset: ";
  out += asset.to_string();
  out += "\nbaseline: ";
  out += baseline.to_string();
  out += "\nbaseline_generation: ";
  out += scalar_text(baseline_generation);
  out += "\nbaseline_revision: ";
  out += scalar_text(baseline_revision);
  out += "\npolicy_generation: ";
  out += scalar_text(policy_generation);
  out += "\ncontrol_epoch: ";
  out += scalar_text(control_epoch);
  out += "\ncommit_sequence: ";
  out += scalar_text(commit_sequence);
  out += "\nevaluated_at: ";
  out += text::format_timestamp(evaluated_at);
  if (rollout_target.has_value()) {
    out += "\nrollout_target: ";
    out += text::format_optional_version(rollout_target);
  }
  if (rollback_target.has_value()) {
    out += "\nrollback_target: ";
    out += text::format_optional_version(rollback_target);
  }
  if (rollback_generation.is_set()) {
    out += "\nrollback_generation: ";
    out += scalar_text(rollback_generation);
  }
  out += "\ngates: ";
  out += gates_text(gates);
  if (!gates.closed_reason.empty()) {
    out += "\nclosed_reason: ";
    out += gates.closed_reason;
  }
  out += "\nconformance: ";
  out += conformance_summary_text(conformance);

  if (blockers.empty()) {
    out += "\nblockers: none\n";
  } else {
    out += "\nblockers:\n";
    for (const std::string& blocker : blockers) {
      out += "- ";
      out += text_or_unset(blocker);
      out += '\n';
    }
  }
  return out;
}

}  // namespace summon::fbm
