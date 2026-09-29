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

#include "summon/fbm/engine.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/text_format.hpp"

namespace summon::fbm {
namespace {

struct Candidate {
  ConformanceState state = ConformanceState::Unknown;
  std::string code;
  std::string reason;
};

void add_candidate(std::vector<Candidate>& candidates, ConformanceState state, std::string code,
                   std::string reason) {
  candidates.push_back(Candidate{state, std::move(code), std::move(reason)});
}

// Picks the highest-precedence candidate. Ties break on the state value and
// then on the reason code, so the choice is deterministic even when several
// candidates share a precedence rank.
const Candidate& pick_candidate(const std::vector<Candidate>& candidates) {
  std::size_t best = 0;
  for (std::size_t index = 1; index < candidates.size(); ++index) {
    const std::uint8_t rank = conformance_precedence(candidates[index].state);
    const std::uint8_t best_rank = conformance_precedence(candidates[best].state);
    if (rank > best_rank) {
      best = index;
    } else if (rank == best_rank) {
      if (candidates[index].code < candidates[best].code) {
        best = index;
      }
    }
  }
  return candidates[best];
}

bool residual_less(const DriftResidual& a, const DriftResidual& b) {
  if (a.kind != b.kind) {
    return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
  }
  if (!(a.component == b.component)) {
    return a.component < b.component;
  }
  if (!(a.rule == b.rule)) {
    return a.rule < b.rule;
  }
  return a.detail < b.detail;
}

std::string describe_optional_version(const std::optional<FirmwareVersion>& version) {
  return version.has_value() ? version->to_string() : std::string{"<unknown>"};
}

// Baseline and rollback generations are deliberately distinct types so that a
// baseline generation can never be passed where a rollback generation is
// required. This is the one place where the value is carried across, and the
// unset case stays unset.
RollbackGeneration to_rollback_generation(BaselineGeneration generation) {
  return generation.is_set() ? RollbackGeneration{generation.value()} : RollbackGeneration{};
}

}  // namespace

Engine::Engine(std::shared_ptr<const Snapshot> snapshot) : snapshot_(std::move(snapshot)) {
  FBM_PRECONDITION(snapshot_ != nullptr);
}

Result<Engine::Resolution> Engine::resolve(const EvaluationRequest& request) const {
  Resolution resolution;

  if (!request.asset.is_set()) {
    return Error{ErrorCode::InvalidArgument, "an asset identity is required", "/asset"};
  }
  if (!request.now.is_set()) {
    return Error{ErrorCode::InvalidArgument,
                 "an evaluation time is required; the engine never reads a clock", "/now"};
  }

  std::vector<Candidate> candidates;

  const HardwareObservation* profile_observation = snapshot_->observations.profile(request.asset);
  if (profile_observation == nullptr) {
    add_candidate(candidates, ConformanceState::Unknown, std::string{reason_code::kEvidenceMissing},
                  "no hardware profile evidence has been recorded for asset " +
                      request.asset.to_string());
    resolution.state = pick_candidate(candidates).state;
    resolution.reason_code = pick_candidate(candidates).code;
    resolution.reason = pick_candidate(candidates).reason;
    return resolution;
  }

  const bool profile_excluded_by_floor =
      request.evidence_floor.is_set() &&
      (!profile_observation->sequence.is_set() ||
       profile_observation->sequence.value() <= request.evidence_floor.value());

  const HardwareProfile& hardware = profile_observation->hardware;

  auto authoritative = snapshot_->baselines.authoritative(hardware);
  if (!authoritative.has_value()) {
    add_candidate(candidates, ConformanceState::Unknown, std::string{reason_code::kBaselineAmbiguous},
                  authoritative.error().message());
    resolution.state = pick_candidate(candidates).state;
    resolution.reason_code = pick_candidate(candidates).code;
    resolution.reason = pick_candidate(candidates).reason;
    return resolution;
  }

  const Baseline* baseline = authoritative.value();
  if (baseline == nullptr) {
    const bool class_known = std::any_of(
        snapshot_->baselines.items().begin(), snapshot_->baselines.items().end(),
        [&hardware](const auto& entry) {
          return entry.second.state == BaselineState::Published &&
                 !entry.second.selectors.empty() &&
                 entry.second.selectors.front().hardware_class == hardware.hardware_class;
        });
    if (class_known) {
      add_candidate(candidates, ConformanceState::Unsupported,
                    std::string{reason_code::kSelectorOutOfScope},
                    "no published baseline covers hardware class " + hardware.hardware_class.to_string() +
                        " model " + hardware.model.to_string() + " revision " +
                        (hardware.revision.is_set() ? std::to_string(hardware.revision.value())
                                                    : std::string{"<unobserved>"}));
    } else {
      add_candidate(candidates, ConformanceState::Unknown, std::string{reason_code::kBaselineAbsent},
                    "no published baseline exists for hardware class " +
                        hardware.hardware_class.to_string());
    }
    resolution.state = pick_candidate(candidates).state;
    resolution.reason_code = pick_candidate(candidates).code;
    resolution.reason = pick_candidate(candidates).reason;
    return resolution;
  }

  resolution.baseline = baseline;

  if (profile_excluded_by_floor) {
    add_candidate(candidates, ConformanceState::Blocked, std::string{reason_code::kEvidenceFloor},
                  "the hardware profile evidence for " + request.asset.to_string() +
                      " is at or below the requested evidence floor of " +
                      std::to_string(request.evidence_floor.value()));
  }

  const ComponentEvidenceMap evidence = snapshot_->observations.evidence_for(request.asset);

  // --- Governed components ---------------------------------------------------
  for (const ComponentRequirement& requirement : baseline->components) {
    ComponentEvaluation evaluation{.component = requirement.component,
                                   .required = requirement.approved_version};

    const FirmwareObservation* observation =
        snapshot_->observations.component(request.asset, requirement.component);

    if (observation != nullptr) {
      evaluation.evidence_present = true;
      evaluation.evidence = observation->evidence;
      evaluation.observed_at = observation->observed_at;
      evaluation.observation_sequence = observation->sequence;
      evaluation.evidence_fresh =
          !requirement.freshness.is_stale(observation->observed_at, request.now);
    }

    const bool excluded_by_floor =
        request.evidence_floor.is_set() &&
        (observation == nullptr || !observation->sequence.is_set() ||
         observation->sequence.value() <= request.evidence_floor.value());

    if (excluded_by_floor) {
      evaluation.evidence_present = false;
      evaluation.evidence_fresh = false;
      add_candidate(candidates, ConformanceState::Blocked, std::string{reason_code::kEvidenceFloor},
                    "evidence for component " + requirement.component.to_string() +
                        " is at or below the requested evidence floor of " +
                        std::to_string(request.evidence_floor.value()));
    }

    if (observation == nullptr) {
      DriftResidual residual;
      residual.kind = DriftKind::MissingObservation;
      residual.component = requirement.component;
      residual.required = requirement.approved_version;
      residual.detail = "component " + requirement.component.to_string() +
                        " has no recorded observation; required version is " +
                        requirement.approved_version.to_string();
      residual.path = "/components/" + requirement.component.to_string();
      resolution.residuals.push_back(std::move(residual));
      add_candidate(candidates, ConformanceState::Unknown, std::string{reason_code::kEvidenceMissing},
                    "component " + requirement.component.to_string() +
                        " has never been observed, so its conformance is not established");
    } else if (excluded_by_floor) {
      // Already reported as a floor block; no separate residual is needed, but
      // the component is not conformant.
    } else if (!evaluation.evidence_fresh) {
      DriftResidual residual;
      residual.kind = DriftKind::StaleObservation;
      residual.component = requirement.component;
      residual.required = requirement.approved_version;
      residual.observed = observation->version;
      residual.observed_at = observation->observed_at;
      residual.freshness = requirement.freshness;
      residual.detail =
          "component " + requirement.component.to_string() + " evidence observed at " +
          text::format_timestamp(observation->observed_at) + " is older than the bound of " +
          text::format_duration_nanos(requirement.freshness.max_age_nanos()) +
          "; observed version is " + describe_optional_version(observation->version) +
          ", required version is " + requirement.approved_version.to_string();
      residual.path = "/components/" + requirement.component.to_string();
      resolution.residuals.push_back(std::move(residual));
      add_candidate(candidates, ConformanceState::Unknown, std::string{reason_code::kEvidenceStale},
                    "component " + requirement.component.to_string() +
                        " evidence is older than the freshness bound, so its current version is "
                        "not established");
    } else if (!observation->version.has_value()) {
      DriftResidual residual;
      residual.kind = DriftKind::UnknownVersion;
      residual.component = requirement.component;
      residual.required = requirement.approved_version;
      residual.observed_at = observation->observed_at;
      residual.freshness = requirement.freshness;
      residual.detail = "component " + requirement.component.to_string() +
                        " was observed but its version was not determined; required version is " +
                        requirement.approved_version.to_string();
      residual.path = "/components/" + requirement.component.to_string();
      resolution.residuals.push_back(std::move(residual));
      add_candidate(candidates, ConformanceState::Unknown, std::string{reason_code::kVersionUnknown},
                    "component " + requirement.component.to_string() +
                        " was observed with an undetermined version, and an unknown version is "
                        "never conformant");
    } else {
      evaluation.observed = observation->version;
      const bool conformant = requirement.is_conformant(observation->version.value());
      evaluation.conformant = conformant;
      if (!same_precedence(observation->version.value(), requirement.approved_version)) {
        evaluation.has_version_delta = true;
        evaluation.version_delta = observation->version.value() < requirement.approved_version
                                       ? -version_distance(observation->version.value(),
                                                           requirement.approved_version)
                                       : version_distance(requirement.approved_version,
                                                          observation->version.value());
      }
      if (!conformant) {
        DriftResidual residual;
        residual.kind = DriftKind::VersionMismatch;
        residual.component = requirement.component;
        residual.required = requirement.approved_version;
        residual.observed = observation->version;
        residual.observed_at = observation->observed_at;
        residual.freshness = requirement.freshness;
        residual.has_version_delta = evaluation.has_version_delta;
        residual.version_delta = evaluation.version_delta;
        residual.detail = "component " + requirement.component.to_string() + " observed at " +
                          observation->version.value().to_string() + ", required " +
                          requirement.approved_version.to_string() + "; signed distance " +
                          std::to_string(evaluation.version_delta);
        residual.path = "/components/" + requirement.component.to_string();
        resolution.residuals.push_back(std::move(residual));
      }
    }

    resolution.components.push_back(std::move(evaluation));
  }

  // --- Compatibility rules ---------------------------------------------------
  resolution.rules = baseline->rules.evaluate(hardware, evidence);
  for (const RuleEvaluation& evaluation : resolution.rules) {
    if (evaluation.outcome == RuleOutcome::Satisfied ||
        evaluation.outcome == RuleOutcome::NotTriggered) {
      continue;
    }
    const CompatibilityRule* rule = baseline->rules.find(evaluation.rule);
    DriftResidual residual;
    residual.rule = evaluation.rule;
    residual.detail = evaluation.detail;
    residual.path = "/rules/" + evaluation.rule.to_string();
    if (evaluation.outcome == RuleOutcome::Violated) {
      residual.kind = DriftKind::IncompatibleCombination;
    } else {
      residual.kind = DriftKind::UnverifiableRule;
      add_candidate(candidates, ConformanceState::Unknown,
                    std::string{reason_code::kRuleUnverifiable},
                    "compatibility rule " + evaluation.rule.to_string() +
                        " cannot be decided from the available evidence, so conformance is not "
                        "established");
    }
    if (rule != nullptr && rule->requirement.component.is_set()) {
      residual.component = rule->requirement.component;
    }
    resolution.residuals.push_back(std::move(residual));
  }

  // --- A rule that constrains a component the baseline does not govern ------
  for (const CompatibilityRule& rule : baseline->rules.rules()) {
    const FirmwareComponentId& referenced = rule.requirement.component;
    if (!referenced.is_set()) {
      continue;
    }
    if (baseline->find_component(referenced) != nullptr) {
      continue;
    }
    const FirmwareObservation* observation =
        snapshot_->observations.component(request.asset, referenced);
    if (observation == nullptr) {
      continue;
    }
    if (request.evidence_floor.is_set() && observation->sequence.is_set() &&
        observation->sequence.value() <= request.evidence_floor.value()) {
      continue;
    }
    DriftResidual residual;
    residual.kind = DriftKind::UnexpectedComponent;
    residual.component = referenced;
    residual.rule = rule.id;
    residual.observed = observation->version;
    residual.observed_at = observation->observed_at;
    residual.detail = "component " + referenced.to_string() +
                      " is referenced by rule " + rule.id.to_string() +
                      " but is not governed by baseline " + baseline->id.to_string() +
                      "; observed version is " + describe_optional_version(observation->version);
    residual.path = "/rules/" + rule.id.to_string();
    resolution.residuals.push_back(std::move(residual));
  }

  std::sort(resolution.residuals.begin(), resolution.residuals.end(), residual_less);

  // --- Exceptions ------------------------------------------------------------
  bool all_covered = !resolution.residuals.empty();
  ExceptionId covering;
  for (const DriftResidual& residual : resolution.residuals) {
    // Only a determinate drift determination is waivable. Missing, stale, or
    // undetermined evidence is uncertainty, and an exception must not convert
    // uncertainty into a waiver.
    if (residual.kind != DriftKind::VersionMismatch &&
        residual.kind != DriftKind::UnexpectedComponent) {
      all_covered = false;
      break;
    }
    const BaselineException* exception =
        snapshot_->exceptions.effective_for(hardware, request.asset, residual.component,
                                            snapshot_->policy_generation, request.now);
    if (exception == nullptr) {
      all_covered = false;
      break;
    }
    if (!covering.is_set() || exception->id < covering) {
      covering = exception->id;
    }
  }
  if (all_covered) {
    resolution.exception = snapshot_->exceptions.find(covering);
  }

  // --- Facility gates (only when the caller demands them) --------------------
  if (request.require_gates_open) {
    const bool any_unknown = request.gates.capacity == GateState::Unknown ||
                             request.gates.dependency == GateState::Unknown ||
                             request.gates.maintenance == GateState::Unknown ||
                             request.gates.topology == GateState::Unknown;
    if (any_unknown) {
      std::string names;
      for (const std::string& name : request.gates.not_open()) {
        if (!names.empty()) {
          names += ", ";
        }
        names += name;
      }
      add_candidate(candidates, ConformanceState::Blocked, std::string{reason_code::kGateUnknown},
                    "the following facility gates are not established as open: " + names);
    } else if (!request.gates.all_open()) {
      std::string names;
      for (const std::string& name : request.gates.not_open()) {
        if (!names.empty()) {
          names += ", ";
        }
        names += name;
      }
      std::string reason = "the following facility gates are closed: " + names;
      if (!request.gates.closed_reason.empty()) {
        reason += " (" + request.gates.closed_reason + ")";
      }
      add_candidate(candidates, ConformanceState::Blocked, std::string{reason_code::kGateClosed},
                    std::move(reason));
    }
  }

  // --- Pending rollout and rollback plans ------------------------------------
  bool pending_rollout = false;
  bool pending_rollback = false;
  std::vector<CohortId> rollout_cohorts;
  for (const Cohort* cohort : snapshot_->cohorts.containing(request.asset)) {
    if (!(cohort->baseline == baseline->id)) {
      continue;
    }
    if (!(cohort->baseline_generation == baseline->generation)) {
      continue;
    }
    if (cohort->state == CohortState::Authorized || cohort->state == CohortState::Active ||
        cohort->state == CohortState::Paused) {
      pending_rollout = true;
      rollout_cohorts.push_back(cohort->id);
    }
    for (const auto& entry : snapshot_->authorizations.items()) {
      const AuthorityBinding& binding = entry.second.binding;
      if (binding.scope != "cohort/" + cohort->id.to_string() + "/rollback") {
        continue;
      }
      if (!(binding.baseline_generation == baseline->generation)) {
        continue;
      }
      pending_rollback = true;
    }
  }

  // A pending plan is reported only for an asset that still has something to
  // do. An asset that is already conformant is Conformant even while it belongs
  // to a running cohort, otherwise a promotion gate could never count the very
  // members it is gating, and "pending rollout" would be reported for a device
  // that has nothing left to roll out.
  const bool has_outstanding_work = !resolution.residuals.empty();

  if (pending_rollback && has_outstanding_work) {
    add_candidate(candidates, ConformanceState::PendingRollback,
                  std::string{reason_code::kPendingRollback},
                  "an authorized rollback plan targets asset " + request.asset.to_string() +
                      " against baseline " + baseline->id.to_string());
  }
  if (pending_rollout && has_outstanding_work) {
    std::string names;
    for (const CohortId& id : rollout_cohorts) {
      if (!names.empty()) {
        names += ", ";
      }
      names += id.to_string();
    }
    add_candidate(candidates, ConformanceState::PendingRollout,
                  std::string{reason_code::kPendingRollout},
                  "asset " + request.asset.to_string() + " belongs to staged cohort(s) " + names +
                      " for baseline " + baseline->id.to_string());
  }

  // --- Residual resolution ---------------------------------------------------
  if (resolution.residuals.empty()) {
    add_candidate(candidates, ConformanceState::Conformant, std::string{reason_code::kConformant},
                  "every governed component is observed, fresh, and conformant, and every "
                  "compatibility rule is satisfied");
  } else if (all_covered && resolution.exception != nullptr) {
    add_candidate(candidates, ConformanceState::Exception,
                  std::string{reason_code::kExceptionEffective},
                  "every outstanding residual is covered by exception " +
                      resolution.exception->id.to_string());
  } else {
    const bool any_rule_unverifiable = std::any_of(
        resolution.residuals.begin(), resolution.residuals.end(), [](const DriftResidual& r) {
          return r.kind == DriftKind::UnverifiableRule;
        });
    add_candidate(candidates, ConformanceState::Drifted,
                  std::string{any_rule_unverifiable ? reason_code::kRuleUnverifiable
                                                    : reason_code::kDrift},
                  std::to_string(resolution.residuals.size()) +
                      " residual(s) remain for asset " + request.asset.to_string());
  }

  const Candidate& chosen = pick_candidate(candidates);
  resolution.state = chosen.state;
  resolution.reason_code = chosen.code;
  resolution.reason = chosen.reason;
  return resolution;
}

Result<ConformanceVerdict> Engine::evaluate_conformance(const EvaluationRequest& request) const {
  auto resolution = resolve(request);
  if (!resolution.has_value()) {
    return resolution.error();
  }

  ConformanceVerdict verdict{};
  verdict.state = resolution.value().state;
  verdict.reason_code_value = resolution.value().reason_code;
  verdict.reason = resolution.value().reason;
  verdict.asset = request.asset;
  verdict.evaluated_at = request.now;
  verdict.policy_generation = snapshot_->policy_generation;
  verdict.control_epoch = snapshot_->control_epoch;
  verdict.commit_sequence = snapshot_->commit_sequence;
  verdict.residuals = std::move(resolution.value().residuals);
  verdict.rules = std::move(resolution.value().rules);
  verdict.components = std::move(resolution.value().components);

  if (const HardwareObservation* observation = snapshot_->observations.profile(request.asset);
      observation != nullptr) {
    verdict.hardware = observation->hardware;
  }

  if (resolution.value().baseline != nullptr) {
    verdict.baseline = resolution.value().baseline->id;
    verdict.baseline_generation = resolution.value().baseline->generation;
    verdict.baseline_revision = resolution.value().baseline->revision;
    verdict.baseline_digest = resolution.value().baseline->content_digest();
  }

  if (resolution.value().exception != nullptr) {
    verdict.applied_exception = resolution.value().exception->id;
    verdict.has_applied_exception = true;
  }

  return verdict;
}

Result<std::vector<DriftResidual>> Engine::list_drift(const EvaluationRequest& request) const {
  auto resolution = resolve(request);
  if (!resolution.has_value()) {
    return resolution.error();
  }
  return std::move(resolution.value().residuals);
}

Result<std::string> Engine::explain(const EvaluationRequest& request) const {
  auto verdict = evaluate_conformance(request);
  if (!verdict.has_value()) {
    return verdict.error();
  }
  return text::format_conformance_report(verdict.value());
}

namespace {

// Builds the eligibility verdict that both rollout and rollback share.
EligibilityVerdict start_eligibility(const EvaluationRequest& request,
                                     const ConformanceVerdict& conformance, Eligibility eligibility,
                                     std::string code, std::string reason) {
  EligibilityVerdict verdict{};
  verdict.eligibility = eligibility;
  verdict.reason_code_value = std::move(code);
  verdict.reason = std::move(reason);
  verdict.asset = request.asset;
  verdict.evaluated_at = request.now;
  verdict.gates = request.gates;
  verdict.conformance = conformance;
  verdict.baseline = conformance.baseline;
  verdict.baseline_generation = conformance.baseline_generation;
  verdict.baseline_revision = conformance.baseline_revision;
  verdict.policy_generation = conformance.policy_generation;
  verdict.control_epoch = conformance.control_epoch;
  verdict.commit_sequence = conformance.commit_sequence;
  return verdict;
}

void append_gate_blockers(const FacilityGates& gates, std::vector<std::string>& blockers,
                          bool& any_unknown, bool& any_closed) {
  const std::pair<const char*, GateState> ordered[] = {
      {"capacity", gates.capacity},
      {"dependency", gates.dependency},
      {"maintenance", gates.maintenance},
      {"topology", gates.topology},
  };
  for (const auto& entry : ordered) {
    if (entry.second == GateState::Open) {
      continue;
    }
    if (entry.second == GateState::Unknown) {
      any_unknown = true;
      blockers.push_back(std::string{entry.first} + " gate is not established (unknown)");
    } else {
      any_closed = true;
      blockers.push_back(std::string{entry.first} + " gate is closed");
    }
  }
}

}  // namespace

Result<EligibilityVerdict> Engine::evaluate_rollout_eligibility(
    const EvaluationRequest& request) const {
  EvaluationRequest effective = request;
  effective.require_gates_open = true;

  auto conformance = evaluate_conformance(effective);
  if (!conformance.has_value()) {
    return conformance.error();
  }
  const ConformanceVerdict& verdict = conformance.value();

  bool any_unknown = false;
  bool any_closed = false;
  std::vector<std::string> blockers;
  append_gate_blockers(request.gates, blockers, any_unknown, any_closed);

  const bool conformance_unknown = verdict.state == ConformanceState::Unknown;
  const bool conformance_unsupported = verdict.state == ConformanceState::Unsupported;

  auto evaluate_target = [&]() -> std::optional<FirmwareVersion> {
    std::optional<FirmwareVersion> target;
    for (const DriftResidual& residual : verdict.residuals) {
      if (residual.kind == DriftKind::UnverifiableRule) {
        return std::nullopt;
      }
      if (!residual.required.has_value()) {
        continue;
      }
      if (!target.has_value()) {
        target = residual.required;
      } else if (!(target.value() == residual.required.value())) {
        return std::nullopt;
      }
    }
    return target;
  };

  if (conformance_unknown) {
    blockers.push_back("conformance is unknown: " + verdict.reason);
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::Unknown,
                                               std::string{reason_code::kEvidenceMissing},
                                               verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }
  if (conformance_unsupported) {
    blockers.push_back("the asset is outside every authoritative baseline scope");
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kSelectorOutOfScope},
                                               verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }
  if (any_unknown) {
    EligibilityVerdict out = start_eligibility(
        request, verdict, Eligibility::Unknown, std::string{reason_code::kGateUnknown},
        "one or more facility gates are not established, so eligibility cannot be decided");
    out.blockers = std::move(blockers);
    return out;
  }
  if (any_closed) {
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kGateClosed},
                                               "one or more facility gates are closed");
    out.blockers = std::move(blockers);
    return out;
  }
  if (verdict.state == ConformanceState::Conformant) {
    blockers.push_back("the asset is already conformant; there is nothing to roll forward");
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kConformant},
                                               verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }
  if (verdict.state == ConformanceState::Exception) {
    blockers.push_back(
        "an exception waives the residual but does not authorize a rollout");
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kExceptionEffective},
                                               verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }
  if (verdict.state == ConformanceState::PendingRollback) {
    blockers.push_back("a rollback plan is outstanding for this asset");
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kPendingRollback},
                                               verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }
  if (verdict.state == ConformanceState::Blocked) {
    blockers.push_back("the conformance evaluation is blocked: " + verdict.reason);
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               verdict.reason_code_value, verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }

  EligibilityVerdict out = start_eligibility(
      request, verdict, Eligibility::Eligible, std::string{reason_code::kEligible},
      "the asset is drifted or pending rollout, every facility gate is open, and no blocker "
      "remains");
  out.blockers.clear();
  out.rollout_target = evaluate_target();
  return out;
}

Result<EligibilityVerdict> Engine::evaluate_rollback_eligibility(
    const EvaluationRequest& request) const {
  EvaluationRequest effective = request;
  effective.require_gates_open = true;

  auto conformance = evaluate_conformance(effective);
  if (!conformance.has_value()) {
    return conformance.error();
  }
  const ConformanceVerdict& verdict = conformance.value();

  bool any_unknown = false;
  bool any_closed = false;
  std::vector<std::string> blockers;
  append_gate_blockers(request.gates, blockers, any_unknown, any_closed);

  const Baseline* baseline = snapshot_->baselines.find(verdict.baseline);

  if (verdict.state == ConformanceState::Unknown) {
    blockers.push_back("conformance is unknown: " + verdict.reason);
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::Unknown,
                                               std::string{reason_code::kEvidenceMissing},
                                               verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }
  if (baseline == nullptr) {
    blockers.push_back("no authoritative baseline is resolved for this asset");
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::Unknown,
                                               std::string{reason_code::kBaselineAbsent},
                                               verdict.reason);
    out.blockers = std::move(blockers);
    return out;
  }
  if (any_unknown) {
    EligibilityVerdict out = start_eligibility(
        request, verdict, Eligibility::Unknown, std::string{reason_code::kGateUnknown},
        "one or more facility gates are not established, so eligibility cannot be decided");
    out.blockers = std::move(blockers);
    return out;
  }
  if (any_closed) {
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kGateClosed},
                                               "one or more facility gates are closed");
    out.blockers = std::move(blockers);
    return out;
  }
  if (!request.requested_rollback_target.has_value()) {
    blockers.push_back("no rollback target was requested");
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::Unknown,
                                               std::string{reason_code::kRollbackTargetUnknown},
                                               "a rollback target must be named explicitly");
    out.blockers = std::move(blockers);
    return out;
  }

  const FirmwareVersion& target = request.requested_rollback_target.value();

  // The requested target must be a declared rollback target of the baseline,
  // and the asset must not already be at it.
  bool target_known = false;
  bool already_at_target = false;
  bool target_is_currently_conformant = false;
  std::optional<ComponentRequirement> governing;
  for (const ComponentRequirement& requirement : baseline->components) {
    if (!requirement.is_rollback_target(target)) {
      continue;
    }
    target_known = true;
    governing = requirement;
    const FirmwareObservation* observation =
        snapshot_->observations.component(request.asset, requirement.component);
    if (observation != nullptr && observation->version.has_value()) {
      if (same_precedence(observation->version.value(), target)) {
        already_at_target = true;
      }
      if (requirement.is_conformant(observation->version.value())) {
        target_is_currently_conformant = true;
      }
    }
  }

  if (!target_known) {
    blockers.push_back("version " + target.to_string() +
                       " is not a declared rollback target of baseline " +
                       baseline->id.to_string());
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kRollbackTargetUnknown},
                                               "the requested rollback target is not known to the "
                                               "authoritative baseline");
    out.blockers = std::move(blockers);
    out.rollback_target = target;
    return out;
  }
  if (already_at_target) {
    blockers.push_back("the asset is already at the requested rollback target " +
                       target.to_string());
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kRollbackTargetIncompatible},
                                               "the requested rollback target is already observed");
    out.blockers = std::move(blockers);
    out.rollback_target = target;
    out.rollback_generation = to_rollback_generation(baseline->generation);
    return out;
  }
  if (target_is_currently_conformant) {
    blockers.push_back("a governed component is already conformant, so rolling it back would "
                        "move it out of conformance");
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kRollbackTargetIncompatible},
                                               "the rollback would move a conformant component out "
                                               "of conformance");
    out.blockers = std::move(blockers);
    out.rollback_target = target;
    out.rollback_generation = to_rollback_generation(baseline->generation);
    return out;
  }

  // Compatibility of the resulting combination: substitute the target version
  // for the component and re-evaluate every rule.
  ComponentEvidenceMap projected = snapshot_->observations.evidence_for(request.asset);
  projected[governing->component] = target;
  const std::vector<RuleEvaluation> projected_rules =
      baseline->rules.evaluate(verdict.hardware, projected);
  for (const RuleEvaluation& evaluation : projected_rules) {
    if (evaluation.outcome == RuleOutcome::Violated) {
      blockers.push_back("rule " + evaluation.rule.to_string() +
                         " is violated by the projected rollback combination");
    } else if (evaluation.outcome == RuleOutcome::Unverifiable ||
               evaluation.outcome == RuleOutcome::TriggerUnknown) {
      blockers.push_back("rule " + evaluation.rule.to_string() +
                         " cannot be decided for the projected rollback combination");
    }
  }

  if (!blockers.empty()) {
    EligibilityVerdict out = start_eligibility(request, verdict, Eligibility::NotEligible,
                                               std::string{reason_code::kRollbackTargetIncompatible},
                                               "the projected rollback combination is not "
                                               "compatible under the authoritative baseline");
    out.blockers = std::move(blockers);
    out.rollback_target = target;
    out.rollback_generation = to_rollback_generation(baseline->generation);
    return out;
  }

  EligibilityVerdict out = start_eligibility(
      request, verdict, Eligibility::Eligible, std::string{reason_code::kEligible},
      "the requested rollback target is a known-compatible target of the authoritative baseline, "
      "every facility gate is open, and the projected combination satisfies every rule");
  out.rollback_target = target;
  out.rollback_generation = to_rollback_generation(baseline->generation);
  return out;
}

Result<GateReport> Engine::evaluate_cohort_gate(const Cohort& cohort,
                                                const EvaluationRequest& request) const {
  GateReport report;
  report.counts.total_assets = static_cast<std::uint32_t>(cohort.members.size());

  for (const AssetId& asset : cohort.members) {
    EvaluationRequest member_request = request;
    member_request.asset = asset;
    auto conformance = evaluate_conformance(member_request);
    if (!conformance.has_value()) {
      return conformance.error();
    }
    switch (conformance.value().state) {
      case ConformanceState::Conformant:
        ++report.counts.decided_assets;
        ++report.counts.conformant_assets;
        break;
      case ConformanceState::Drifted:
        ++report.counts.decided_assets;
        ++report.counts.drifted_assets;
        break;
      case ConformanceState::Exception:
        ++report.counts.decided_assets;
        ++report.counts.exception_assets;
        break;
      case ConformanceState::PendingRollout:
        ++report.counts.decided_assets;
        ++report.counts.pending_rollout_assets;
        break;
      case ConformanceState::PendingRollback:
        ++report.counts.decided_assets;
        ++report.counts.pending_rollback_assets;
        break;
      case ConformanceState::Unknown:
        ++report.counts.unknown_assets;
        break;
      case ConformanceState::Unsupported:
        ++report.counts.unsupported_assets;
        break;
      case ConformanceState::Blocked:
        ++report.counts.blocked_assets;
        break;
    }
  }

  if (report.counts.decided_assets > 0u) {
    const std::uint64_t numerator =
        static_cast<std::uint64_t>(report.counts.conformant_assets) * 10000ull;
    report.counts.conformant_basis_points =
        static_cast<std::uint32_t>(numerator / report.counts.decided_assets);
  }

  const PromotionGate& gate = snapshot_->baselines.find(cohort.baseline) != nullptr
                                  ? snapshot_->baselines.find(cohort.baseline)->gate
                                  : PromotionGate{};

  if (report.counts.decided_assets < gate.minimum_decided_assets) {
    report.unmet_conditions.push_back(
        "decided assets " + std::to_string(report.counts.decided_assets) +
        " is below the required minimum of " + std::to_string(gate.minimum_decided_assets));
  }
  if (report.counts.conformant_assets < gate.minimum_conformant_assets) {
    report.unmet_conditions.push_back(
        "conformant assets " + std::to_string(report.counts.conformant_assets) +
        " is below the required minimum of " + std::to_string(gate.minimum_conformant_assets));
  }
  if (report.counts.conformant_basis_points < gate.minimum_conformant_basis_points) {
    report.unmet_conditions.push_back(
        "conformant ratio " + text::format_basis_points(report.counts.conformant_basis_points) +
        " is below the required " + text::format_basis_points(gate.minimum_conformant_basis_points));
  }
  if (report.counts.unknown_assets > 0u) {
    report.unmet_conditions.push_back(std::to_string(report.counts.unknown_assets) +
                                      " asset(s) have an unknown conformance state");
  }
  if (report.counts.unsupported_assets > 0u) {
    report.unmet_conditions.push_back(std::to_string(report.counts.unsupported_assets) +
                                      " asset(s) are outside every baseline scope");
  }
  if (report.counts.blocked_assets > 0u) {
    report.unmet_conditions.push_back(std::to_string(report.counts.blocked_assets) +
                                      " asset(s) are blocked");
  }

  if (cohort.stage_entered_at.is_set() && request.now.is_set()) {
    const std::int64_t elapsed = request.now.delta_nanos(cohort.stage_entered_at);
    const std::uint64_t elapsed_nanos = elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0u;
    if (elapsed_nanos < gate.soak_nanos) {
      report.soak_remaining_nanos = gate.soak_nanos - elapsed_nanos;
      report.unmet_conditions.push_back(
          "soak time remaining is " + text::format_duration_nanos(report.soak_remaining_nanos));
    }
  } else if (gate.soak_nanos > 0u) {
    report.soak_remaining_nanos = gate.soak_nanos;
    report.unmet_conditions.push_back("the cohort has no recorded stage entry time, so the soak "
                                      "requirement of " +
                                      text::format_duration_nanos(gate.soak_nanos) +
                                      " cannot be shown to be satisfied");
  }

  StageIndex next;
  if (cohort.stage.checked_next(next)) {
    report.next_stage = next;
  } else {
    report.next_stage = cohort.stage;
    report.unmet_conditions.push_back("the stage counter has reached its maximum value");
  }

  report.satisfied = report.unmet_conditions.empty();
  return report;
}

}  // namespace summon::fbm
