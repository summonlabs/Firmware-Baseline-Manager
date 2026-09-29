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
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"

namespace summon::fbm {

// Hardware facts an evaluation runs against. Every field is evidence. A
// capability is listed only when it was actually observed: discovering a device
// never implies any of its capabilities, so an unreported capability set leaves
// capability requirements undecidable rather than failed.
struct HardwareProfile {
  HardwareClassId hardware_class;
  HardwareModelId model;
  HardwareRevision revision;
  bool capabilities_observed = false;
  std::vector<CapabilityId> capabilities;

  bool has_capability(const CapabilityId& capability) const;
  bool is_identified() const;
  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<HardwareProfile> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

// What was established about each firmware component. A component present with
// an empty optional was observed but its version was not determined; a
// component absent from the map was not observed at all. The two are different
// facts and are never collapsed together.
using ComponentEvidenceMap = std::map<FirmwareComponentId, std::optional<FirmwareVersion>>;

const std::optional<FirmwareVersion>* find_component_evidence(const ComponentEvidenceMap& evidence,
                                                             const FirmwareComponentId& component);

enum class RequirementKind : std::uint8_t {
  ComponentVersionInRange = 0,
  ComponentVersionNotInRange = 1,
  HardwareRevisionInRange = 2,
  CapabilityPresent = 3,
  CapabilityAbsent = 4,
};

std::string_view requirement_kind_token(RequirementKind kind) noexcept;
Result<RequirementKind> requirement_kind_from_token(std::string_view token);

enum class RequirementOutcome : std::uint8_t {
  Satisfied = 0,
  Violated = 1,
  // The inputs needed to decide are missing or unknown. Never folded into
  // either Satisfied or Violated.
  Unverifiable = 2,
};

std::string_view requirement_outcome_token(RequirementOutcome outcome) noexcept;

// A single condition that must hold. Only the fields selected by kind are
// meaningful; validation rejects a requirement that populates fields belonging
// to a different kind, so an impossible combination cannot be represented in
// durable state.
struct Requirement {
  RequirementKind kind = RequirementKind::ComponentVersionInRange;
  FirmwareComponentId component;
  VersionRange versions;
  HardwareRevision minimum_revision;
  HardwareRevision maximum_revision;
  CapabilityId capability;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;

  // Evaluates the condition. On Unverifiable or Violated, detail receives the
  // exact residual text: what was required and what was actually established.
  RequirementOutcome evaluate(const HardwareProfile& hardware,
                              const ComponentEvidenceMap& evidence, std::string& detail) const;

  json::Value to_json() const;
  static Result<Requirement> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

enum class RuleOutcome : std::uint8_t {
  // The trigger component's version is known and lies outside the trigger range.
  NotTriggered = 0,
  Satisfied = 1,
  Violated = 2,
  // The rule fired but the condition could not be decided from the evidence.
  Unverifiable = 3,
  // The trigger component was observed but its version was not determined, so
  // the rule can be neither applied nor dismissed.
  TriggerUnknown = 4,
};

std::string_view rule_outcome_token(RuleOutcome outcome) noexcept;

struct RuleEvaluation {
  RuleId rule;
  RuleOutcome outcome = RuleOutcome::NotTriggered;
  RequirementOutcome requirement_outcome = RequirementOutcome::Unverifiable;
  std::string detail;
};

// A compatibility rule: when the trigger component is at a version inside the
// trigger range, the stated requirement must hold. Rules are constraints, not
// upgrade instructions.
struct CompatibilityRule {
  RuleId id;
  FirmwareComponentId when_component;
  VersionRange when_versions;
  HardwareRevision when_minimum_revision;
  HardwareRevision when_maximum_revision;
  Requirement requirement;
  std::string reason;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<CompatibilityRule> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

// An ordered, duplicate-free set of rules. Iteration and evaluation are always
// in ascending RuleId order, so the same policy and the same evidence always
// produce the same evaluation sequence.
class CompatibilityRuleSet {
 public:
  Status add(CompatibilityRule rule);
  Status validate(std::string_view path, Diagnostics& diagnostics) const;

  bool empty() const noexcept { return rules_.empty(); }
  std::size_t size() const noexcept { return rules_.size(); }
  const std::vector<CompatibilityRule>& rules() const noexcept { return rules_; }
  const CompatibilityRule* find(const RuleId& id) const;

  // Rules that require a range of their own trigger component disjoint from
  // that trigger range can never be satisfied; they are reported as
  // PolicySelfContradiction by validate().
  std::vector<RuleId> self_contradictions() const;

  std::vector<RuleEvaluation> evaluate(const HardwareProfile& hardware,
                                       const ComponentEvidenceMap& evidence) const;

  json::Value to_json() const;
  static Result<CompatibilityRuleSet> from_json(const json::Value& value, std::string_view path);

 private:
  std::vector<CompatibilityRule> rules_;
};

}  // namespace summon::fbm
