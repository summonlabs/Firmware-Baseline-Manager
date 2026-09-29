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

#include "summon/fbm/compatibility.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"

namespace summon::fbm {
namespace {

// ---------------------------------------------------------------------------
// Rendering helpers. Every diagnostic names what was required and what was
// actually established, so a report never reduces a missing fact to a value.
// ---------------------------------------------------------------------------

std::string describe_revision(const HardwareRevision& revision) {
  if (!revision.is_set()) {
    return std::string{"<unset>"};
  }
  return std::to_string(revision.value());
}

std::string describe_component(const FirmwareComponentId& component) {
  return component.is_set() ? component.to_string() : std::string{"<unset>"};
}

std::string describe_capability(const CapabilityId& capability) {
  return capability.is_set() ? capability.to_string() : std::string{"<unset>"};
}

std::string describe_hardware(const HardwareProfile& hardware) {
  std::string out;
  out += hardware.hardware_class.is_set() ? hardware.hardware_class.to_string()
                                          : std::string{"<unset>"};
  out += '/';
  out += hardware.model.is_set() ? hardware.model.to_string() : std::string{"<unset>"};
  return out;
}

// True when the range states at least one bound. A range with no bound at all is
// unbounded on both sides and is not a stated requirement.
bool range_is_present(const VersionRange& range) {
  return range.has_minimum() || range.has_maximum();
}

std::string requirement_summary(const Requirement& requirement) {
  switch (requirement.kind) {
    case RequirementKind::ComponentVersionInRange:
      return "component \"" + describe_component(requirement.component) + "\" version in " +
             requirement.versions.to_string();
    case RequirementKind::ComponentVersionNotInRange:
      return "component \"" + describe_component(requirement.component) + "\" version outside " +
             requirement.versions.to_string();
    case RequirementKind::HardwareRevisionInRange: {
      std::string out{"hardware revision "};
      if (requirement.minimum_revision.is_set() && requirement.maximum_revision.is_set()) {
        out += "in [" + describe_revision(requirement.minimum_revision) + ", " +
               describe_revision(requirement.maximum_revision) + "]";
      } else if (requirement.minimum_revision.is_set()) {
        out += "at least " + describe_revision(requirement.minimum_revision);
      } else if (requirement.maximum_revision.is_set()) {
        out += "at most " + describe_revision(requirement.maximum_revision);
      } else {
        out += "with no stated bound";
      }
      return out;
    }
    case RequirementKind::CapabilityPresent:
      return "capability \"" + describe_capability(requirement.capability) + "\" present";
    case RequirementKind::CapabilityAbsent:
      return "capability \"" + describe_capability(requirement.capability) + "\" absent";
  }
  return std::string{"requirement"};
}

std::string revision_trigger_summary(const CompatibilityRule& rule) {
  std::string out;
  if (rule.when_minimum_revision.is_set() && rule.when_maximum_revision.is_set()) {
    out = "[" + describe_revision(rule.when_minimum_revision) + ", " +
          describe_revision(rule.when_maximum_revision) + "]";
  } else if (rule.when_minimum_revision.is_set()) {
    out = "at least " + describe_revision(rule.when_minimum_revision);
  } else if (rule.when_maximum_revision.is_set()) {
    out = "at most " + describe_revision(rule.when_maximum_revision);
  } else {
    out = "unbounded";
  }
  return out;
}

std::string rule_name(const CompatibilityRule& rule) {
  return rule.id.is_set() ? rule.id.to_string() : std::string{"<unset>"};
}

// A JSON pointer for a field of a document that is not tied to a specific input
// path. The empty base yields the pointer of the field as it appears in a
// standalone document of this type.
std::string field_path(std::string_view field) { return json::join_path(std::string_view{}, field); }

// ---------------------------------------------------------------------------
// JSON conversion helpers
// ---------------------------------------------------------------------------

std::optional<HardwareRevision> read_revision(const json::Value* value, std::string_view path,
                                              Diagnostics& diagnostics) {
  if (value == nullptr) {
    return std::nullopt;
  }
  const std::int64_t raw = value->as_integer();
  const std::int64_t maximum =
      static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max());
  if (raw < 0 || raw > maximum) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    "hardware revision " + std::to_string(raw) + " is outside the range [0, " +
                        std::to_string(maximum) + "]",
                    std::string{path});
    return std::nullopt;
  }
  return HardwareRevision{static_cast<std::uint32_t>(raw)};
}

json::Value version_range_to_json(const VersionRange& range) {
  json::Value out = json::Value::make_object();
  if (range.has_minimum()) {
    out.set("min", json::Value{range.minimum()->to_string()});
    out.set("min_inclusive", json::Value{range.minimum_inclusive()});
  }
  if (range.has_maximum()) {
    out.set("max", json::Value{range.maximum()->to_string()});
    out.set("max_inclusive", json::Value{range.maximum_inclusive()});
  }
  return out;
}

Result<VersionRange> parse_version_range(const json::Value& value, std::string_view path) {
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "version range expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* minimum = reader.optional("min", json::Type::String);
  const json::Value* minimum_inclusive = reader.optional("min_inclusive", json::Type::Boolean);
  const json::Value* maximum = reader.optional("max", json::Type::String);
  const json::Value* maximum_inclusive = reader.optional("max_inclusive", json::Type::Boolean);
  reader.finish();

  const std::string minimum_inclusive_path = json::join_path(path, "min_inclusive");
  const std::string maximum_inclusive_path = json::join_path(path, "max_inclusive");
  if (minimum != nullptr && minimum_inclusive == nullptr) {
    diagnostics.add(ErrorCode::SchemaMissingField,
                    "min_inclusive is required exactly when min is present",
                    minimum_inclusive_path);
  }
  if (minimum == nullptr && minimum_inclusive != nullptr) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "min_inclusive is present but min is absent", minimum_inclusive_path);
  }
  if (maximum != nullptr && maximum_inclusive == nullptr) {
    diagnostics.add(ErrorCode::SchemaMissingField,
                    "max_inclusive is required exactly when max is present",
                    maximum_inclusive_path);
  }
  if (maximum == nullptr && maximum_inclusive != nullptr) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "max_inclusive is present but max is absent", maximum_inclusive_path);
  }

  std::optional<FirmwareVersion> parsed_minimum;
  std::optional<FirmwareVersion> parsed_maximum;
  if (minimum != nullptr) {
    Result<FirmwareVersion> parsed =
        FirmwareVersion::parse(minimum->as_string(), json::join_path(path, "min"));
    if (parsed.has_value()) {
      parsed_minimum = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (maximum != nullptr) {
    Result<FirmwareVersion> parsed =
        FirmwareVersion::parse(maximum->as_string(), json::join_path(path, "max"));
    if (parsed.has_value()) {
      parsed_maximum = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  const bool parsed_minimum_inclusive =
      minimum == nullptr || (minimum_inclusive != nullptr && minimum_inclusive->as_boolean());
  const bool parsed_maximum_inclusive =
      maximum == nullptr || (maximum_inclusive != nullptr && maximum_inclusive->as_boolean());
  return VersionRange::make(std::move(parsed_minimum), parsed_minimum_inclusive,
                            std::move(parsed_maximum), parsed_maximum_inclusive, path);
}

// True when the two ranges share at least one version. Empty ranges share
// nothing, and a shared endpoint is only a member when both sides include it.
bool ranges_intersect(const VersionRange& left, const VersionRange& right) {
  if (left.is_empty() || right.is_empty()) {
    return false;
  }
  std::optional<FirmwareVersion> lower;
  bool lower_inclusive = true;
  if (left.has_minimum() && right.has_minimum()) {
    const FirmwareVersion& a = *left.minimum();
    const FirmwareVersion& b = *right.minimum();
    if (a < b) {
      lower = b;
      lower_inclusive = right.minimum_inclusive();
    } else if (b < a) {
      lower = a;
      lower_inclusive = left.minimum_inclusive();
    } else {
      lower = a;
      lower_inclusive = left.minimum_inclusive() && right.minimum_inclusive();
    }
  } else if (left.has_minimum()) {
    lower = left.minimum();
    lower_inclusive = left.minimum_inclusive();
  } else if (right.has_minimum()) {
    lower = right.minimum();
    lower_inclusive = right.minimum_inclusive();
  }

  std::optional<FirmwareVersion> upper;
  bool upper_inclusive = true;
  if (left.has_maximum() && right.has_maximum()) {
    const FirmwareVersion& a = *left.maximum();
    const FirmwareVersion& b = *right.maximum();
    if (a < b) {
      upper = a;
      upper_inclusive = left.maximum_inclusive();
    } else if (b < a) {
      upper = b;
      upper_inclusive = right.maximum_inclusive();
    } else {
      upper = a;
      upper_inclusive = left.maximum_inclusive() && right.maximum_inclusive();
    }
  } else if (left.has_maximum()) {
    upper = left.maximum();
    upper_inclusive = left.maximum_inclusive();
  } else if (right.has_maximum()) {
    upper = right.maximum();
    upper_inclusive = right.maximum_inclusive();
  }

  if (!lower.has_value() || !upper.has_value()) {
    return true;  // at least one side is unbounded, so the intervals overlap
  }
  if (*lower < *upper) {
    return true;
  }
  if (*upper < *lower) {
    return false;
  }
  return lower_inclusive && upper_inclusive;
}

// A rule that can never be satisfied: it triggers on exactly the component it
// constrains, requires that component's version to be in a range that shares no
// version with the trigger range, and therefore fires only where it must fail.
bool is_self_contradictory(const CompatibilityRule& rule) {
  if (rule.requirement.kind != RequirementKind::ComponentVersionInRange) {
    return false;
  }
  if (!rule.when_component.is_set() || !rule.requirement.component.is_set()) {
    return false;
  }
  if (rule.when_component != rule.requirement.component) {
    return false;
  }
  return !ranges_intersect(rule.when_versions, rule.requirement.versions);
}

// Reads one string array element and constructs the tagged identity. The caller
// has already verified the element is a string.
Result<CapabilityId> read_capability(const json::Value& value, std::string_view path) {
  return make_id<CapabilityId>(value.as_string(), path);
}

}  // namespace

// ---------------------------------------------------------------------------
// HardwareProfile
// ---------------------------------------------------------------------------

bool HardwareProfile::has_capability(const CapabilityId& capability) const {
  return std::find(capabilities.begin(), capabilities.end(), capability) != capabilities.end();
}

bool HardwareProfile::is_identified() const {
  return hardware_class.is_set() && model.is_set() && revision.is_set();
}

Status HardwareProfile::validate(std::string_view path, Diagnostics& diagnostics) const {
  const std::string hardware_class_path = json::join_path(path, "hardware_class");
  if (!hardware_class.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "hardware_class is required",
                    hardware_class_path);
  } else {
    Status status = validate_identifier(hardware_class.view(), hardware_class_path);
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
  }

  const std::string model_path = json::join_path(path, "model");
  if (!model.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "model is required", model_path);
  } else {
    Status status = validate_identifier(model.view(), model_path);
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
  }

  const std::string capabilities_path = json::join_path(path, "capabilities");
  if (!capabilities.empty() && !capabilities_observed) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "capabilities is non-empty while capabilities_observed is false; an "
                    "unobserved capability set cannot state observed capabilities",
                    capabilities_path);
  }
  for (std::size_t index = 0; index < capabilities.size(); ++index) {
    const std::string element_path = json::join_index(capabilities_path, index);
    Status status = validate_identifier(capabilities[index].view(), element_path);
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
    if (index == 0) {
      continue;
    }
    if (capabilities[index] == capabilities[index - 1]) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "capabilities contains \"" + capabilities[index].to_string() +
                          "\" more than once",
                      element_path);
    } else if (capabilities[index] < capabilities[index - 1]) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "capabilities is not sorted ascending: \"" +
                          capabilities[index].to_string() + "\" follows \"" +
                          capabilities[index - 1].to_string() + "\"",
                      element_path);
    }
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value HardwareProfile::to_json() const {
  json::Value out = json::Value::make_object();
  if (hardware_class.is_set()) {
    out.set("hardware_class", json::Value{hardware_class.value()});
  }
  if (model.is_set()) {
    out.set("model", json::Value{model.value()});
  }
  if (revision.is_set()) {
    out.set("revision", json::Value{static_cast<std::int64_t>(revision.value())});
  }
  out.set("capabilities_observed", json::Value{capabilities_observed});
  if (!capabilities.empty()) {
    json::Value list = json::Value::make_array();
    for (const CapabilityId& capability : capabilities) {
      list.push_back(json::Value{capability.value()});
    }
    out.set("capabilities", std::move(list));
  }
  return out;
}

Result<HardwareProfile> HardwareProfile::from_json(const json::Value& value,
                                                    std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "hardware profile expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* hardware_class = reader.required("hardware_class", json::Type::String);
  const json::Value* model = reader.optional("model", json::Type::String);
  const json::Value* revision = reader.optional("revision", json::Type::Integer);
  const json::Value* capabilities_observed =
      reader.required("capabilities_observed", json::Type::Boolean);
  const json::Value* capabilities = reader.optional("capabilities", json::Type::Array);
  reader.finish();

  HardwareProfile profile;
  if (hardware_class != nullptr) {
    Result<HardwareClassId> parsed =
        make_id<HardwareClassId>(hardware_class->as_string(),
                                 json::join_path(path, "hardware_class"));
    if (parsed.has_value()) {
      profile.hardware_class = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (model != nullptr) {
    Result<HardwareModelId> parsed =
        make_id<HardwareModelId>(model->as_string(), json::join_path(path, "model"));
    if (parsed.has_value()) {
      profile.model = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (revision != nullptr) {
    const std::optional<HardwareRevision> parsed =
        read_revision(revision, json::join_path(path, "revision"), diagnostics);
    if (parsed.has_value()) {
      profile.revision = *parsed;
    }
  }
  if (capabilities_observed != nullptr) {
    profile.capabilities_observed = capabilities_observed->as_boolean();
  }
  if (capabilities != nullptr) {
    const json::Value::Array& elements = capabilities->as_array();
    const std::string capabilities_path = json::join_path(path, "capabilities");
    for (std::size_t index = 0; index < elements.size(); ++index) {
      const std::string element_path = json::join_index(capabilities_path, index);
      if (!elements[index].is_string()) {
        diagnostics.add(ErrorCode::SchemaWrongType,
                        "capability expected string but found " +
                            std::string{json::type_name(elements[index].type())},
                        element_path);
        continue;
      }
      Result<CapabilityId> parsed = read_capability(elements[index], element_path);
      if (parsed.has_value()) {
        profile.capabilities.push_back(parsed.take());
      } else {
        diagnostics.add(parsed.error());
      }
    }
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = profile.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return profile;
}

std::string HardwareProfile::to_string() const {
  std::string out = describe_hardware(*this);
  out += " revision " + describe_revision(revision);
  out += capabilities_observed ? " capabilities_observed" : " capabilities_not_observed";
  out += " capabilities=[";
  for (std::size_t index = 0; index < capabilities.size(); ++index) {
    if (index != 0) {
      out += ", ";
    }
    out += capabilities[index].to_string();
  }
  out += "]";
  return out;
}

// ---------------------------------------------------------------------------
// Component evidence
// ---------------------------------------------------------------------------

const std::optional<FirmwareVersion>* find_component_evidence(
    const ComponentEvidenceMap& evidence, const FirmwareComponentId& component) {
  const ComponentEvidenceMap::const_iterator found = evidence.find(component);
  if (found == evidence.end()) {
    return nullptr;
  }
  return &found->second;
}

// ---------------------------------------------------------------------------
// Requirement kinds and outcomes
// ---------------------------------------------------------------------------

std::string_view requirement_kind_token(RequirementKind kind) noexcept {
  switch (kind) {
    case RequirementKind::ComponentVersionInRange:
      return "component_version_in_range";
    case RequirementKind::ComponentVersionNotInRange:
      return "component_version_not_in_range";
    case RequirementKind::HardwareRevisionInRange:
      return "hardware_revision_in_range";
    case RequirementKind::CapabilityPresent:
      return "capability_present";
    case RequirementKind::CapabilityAbsent:
      return "capability_absent";
  }
  return "unknown";
}

Result<RequirementKind> requirement_kind_from_token(std::string_view token) {
  if (token == "component_version_in_range") {
    return RequirementKind::ComponentVersionInRange;
  }
  if (token == "component_version_not_in_range") {
    return RequirementKind::ComponentVersionNotInRange;
  }
  if (token == "hardware_revision_in_range") {
    return RequirementKind::HardwareRevisionInRange;
  }
  if (token == "capability_present") {
    return RequirementKind::CapabilityPresent;
  }
  if (token == "capability_absent") {
    return RequirementKind::CapabilityAbsent;
  }
  return Error{ErrorCode::SchemaInvalidEnumValue,
               "unknown requirement kind token \"" + std::string{token} +
                   "\"; expected one of component_version_in_range, "
                   "component_version_not_in_range, hardware_revision_in_range, "
                   "capability_present, capability_absent",
               {}};
}

std::string_view requirement_outcome_token(RequirementOutcome outcome) noexcept {
  switch (outcome) {
    case RequirementOutcome::Satisfied:
      return "satisfied";
    case RequirementOutcome::Violated:
      return "violated";
    case RequirementOutcome::Unverifiable:
      return "unverifiable";
  }
  return "unknown";
}

std::string_view rule_outcome_token(RuleOutcome outcome) noexcept {
  switch (outcome) {
    case RuleOutcome::NotTriggered:
      return "not_triggered";
    case RuleOutcome::Satisfied:
      return "satisfied";
    case RuleOutcome::Violated:
      return "violated";
    case RuleOutcome::Unverifiable:
      return "unverifiable";
    case RuleOutcome::TriggerUnknown:
      return "trigger_unknown";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Requirement
// ---------------------------------------------------------------------------

Status Requirement::validate(std::string_view path, Diagnostics& diagnostics) const {
  const std::string kind_token{requirement_kind_token(kind)};
  const std::string component_path = json::join_path(path, "component");
  const std::string versions_path = json::join_path(path, "versions");
  const std::string minimum_path = json::join_path(path, "minimum_revision");
  const std::string maximum_path = json::join_path(path, "maximum_revision");
  const std::string capability_path = json::join_path(path, "capability");

  switch (kind) {
    case RequirementKind::ComponentVersionInRange:
    case RequirementKind::ComponentVersionNotInRange: {
      if (!component.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "kind " + kind_token + " requires component", component_path);
      } else {
        Status status = validate_identifier(component.view(), component_path);
        if (!status.has_value()) {
          diagnostics.add(status.error());
        }
      }
      if (!range_is_present(versions)) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "kind " + kind_token + " requires versions", versions_path);
      } else if (versions.is_empty()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "kind " + kind_token + " requires a non-empty versions range, but " +
                            versions.to_string() + " has no members",
                        versions_path);
      }
      if (minimum_revision.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "minimum_revision belongs to kind hardware_revision_in_range, not to " +
                            kind_token,
                        minimum_path);
      }
      if (maximum_revision.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "maximum_revision belongs to kind hardware_revision_in_range, not to " +
                            kind_token,
                        maximum_path);
      }
      if (capability.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "capability belongs to the capability kinds, not to " + kind_token,
                        capability_path);
      }
      break;
    }
    case RequirementKind::HardwareRevisionInRange: {
      if (!minimum_revision.is_set() && !maximum_revision.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "kind hardware_revision_in_range requires minimum_revision or "
                        "maximum_revision",
                        minimum_path);
      }
      if (minimum_revision.is_set() && maximum_revision.is_set() &&
          maximum_revision < minimum_revision) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "maximum_revision " + describe_revision(maximum_revision) +
                            " is below minimum_revision " + describe_revision(minimum_revision) +
                            ", so the range has no members",
                        maximum_path);
      }
      if (component.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "component belongs to the component version kinds, not to " + kind_token,
                        component_path);
      }
      if (range_is_present(versions)) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "versions belongs to the component version kinds, not to " + kind_token,
                        versions_path);
      }
      if (capability.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "capability belongs to the capability kinds, not to " + kind_token,
                        capability_path);
      }
      break;
    }
    case RequirementKind::CapabilityPresent:
    case RequirementKind::CapabilityAbsent: {
      if (!capability.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "kind " + kind_token + " requires capability", capability_path);
      } else {
        Status status = validate_identifier(capability.view(), capability_path);
        if (!status.has_value()) {
          diagnostics.add(status.error());
        }
      }
      if (component.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "component belongs to the component version kinds, not to " + kind_token,
                        component_path);
      }
      if (range_is_present(versions)) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "versions belongs to the component version kinds, not to " + kind_token,
                        versions_path);
      }
      if (minimum_revision.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "minimum_revision belongs to kind hardware_revision_in_range, not to " +
                            kind_token,
                        minimum_path);
      }
      if (maximum_revision.is_set()) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "maximum_revision belongs to kind hardware_revision_in_range, not to " +
                            kind_token,
                        maximum_path);
      }
      break;
    }
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

RequirementOutcome Requirement::evaluate(const HardwareProfile& hardware,
                                         const ComponentEvidenceMap& evidence,
                                         std::string& detail) const {
  const std::string summary = requirement_summary(*this);
  switch (kind) {
    case RequirementKind::ComponentVersionInRange:
    case RequirementKind::ComponentVersionNotInRange: {
      const std::string name = describe_component(component);
      const std::optional<FirmwareVersion>* found = find_component_evidence(evidence, component);
      if (found == nullptr) {
        detail = "required " + summary + "; established: component \"" + name +
                 "\" was not observed, so the requirement cannot be decided";
        return RequirementOutcome::Unverifiable;
      }
      if (!found->has_value()) {
        detail = "required " + summary + "; established: component \"" + name +
                 "\" was observed but its version was not determined, so the requirement cannot "
                 "be decided";
        return RequirementOutcome::Unverifiable;
      }
      const FirmwareVersion& observed = **found;
      const bool contained = versions.contains(observed);
      const bool satisfied =
          kind == RequirementKind::ComponentVersionInRange ? contained : !contained;
      detail = "required " + summary + "; established: component \"" + name + "\" has version " +
               observed.to_string() +
               (satisfied ? ", which satisfies the requirement"
                          : ", which violates the requirement");
      return satisfied ? RequirementOutcome::Satisfied : RequirementOutcome::Violated;
    }
    case RequirementKind::HardwareRevisionInRange: {
      if (!hardware.revision.is_set()) {
        detail = "required " + summary + "; established: the hardware revision of " +
                 describe_hardware(hardware) +
                 " was not observed, so the requirement cannot be decided";
        return RequirementOutcome::Unverifiable;
      }
      const std::uint32_t observed = hardware.revision.value();
      bool satisfied = true;
      if (minimum_revision.is_set() && observed < minimum_revision.value()) {
        satisfied = false;
      }
      if (maximum_revision.is_set() && observed > maximum_revision.value()) {
        satisfied = false;
      }
      detail = "required " + summary + "; established: hardware revision " +
               std::to_string(observed) +
               (satisfied ? ", which satisfies the requirement"
                          : ", which violates the requirement");
      return satisfied ? RequirementOutcome::Satisfied : RequirementOutcome::Violated;
    }
    case RequirementKind::CapabilityPresent:
    case RequirementKind::CapabilityAbsent: {
      const std::string name = describe_capability(capability);
      if (!hardware.capabilities_observed) {
        detail = "required " + summary + "; established: capabilities were not observed for " +
                 describe_hardware(hardware) + ", so the requirement cannot be decided";
        return RequirementOutcome::Unverifiable;
      }
      const bool present = hardware.has_capability(capability);
      const bool satisfied =
          kind == RequirementKind::CapabilityPresent ? present : !present;
      detail = "required " + summary + "; established: capability \"" + name + "\" was " +
               (present ? "observed present" : "observed absent") +
               (satisfied ? ", which satisfies the requirement"
                          : ", which violates the requirement");
      return satisfied ? RequirementOutcome::Satisfied : RequirementOutcome::Violated;
    }
  }
  detail = "required " + summary + "; established: nothing, because the requirement kind is " +
           std::string{requirement_kind_token(kind)};
  return RequirementOutcome::Unverifiable;
}

json::Value Requirement::to_json() const {
  json::Value out = json::Value::make_object();
  out.set("kind", json::Value{std::string{requirement_kind_token(kind)}});
  switch (kind) {
    case RequirementKind::ComponentVersionInRange:
    case RequirementKind::ComponentVersionNotInRange:
      if (component.is_set()) {
        out.set("component", json::Value{component.value()});
      }
      out.set("versions", version_range_to_json(versions));
      break;
    case RequirementKind::HardwareRevisionInRange:
      if (minimum_revision.is_set()) {
        out.set("minimum_revision",
                json::Value{static_cast<std::int64_t>(minimum_revision.value())});
      }
      if (maximum_revision.is_set()) {
        out.set("maximum_revision",
                json::Value{static_cast<std::int64_t>(maximum_revision.value())});
      }
      break;
    case RequirementKind::CapabilityPresent:
    case RequirementKind::CapabilityAbsent:
      if (capability.is_set()) {
        out.set("capability", json::Value{capability.value()});
      }
      break;
  }
  return out;
}

Result<Requirement> Requirement::from_json(const json::Value& value, std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "requirement expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* kind_value = reader.required("kind", json::Type::String);
  const json::Value* component_value = reader.optional("component", json::Type::String);
  const json::Value* versions_value = reader.optional("versions", json::Type::Object);
  const json::Value* minimum_value = reader.optional("minimum_revision", json::Type::Integer);
  const json::Value* maximum_value = reader.optional("maximum_revision", json::Type::Integer);
  const json::Value* capability_value = reader.optional("capability", json::Type::String);
  reader.finish();

  Requirement requirement;
  if (kind_value != nullptr) {
    Result<RequirementKind> parsed = requirement_kind_from_token(kind_value->as_string());
    if (parsed.has_value()) {
      requirement.kind = parsed.value();
    } else {
      diagnostics.add(Error{parsed.error().code(), parsed.error().message(),
                            json::join_path(path, "kind")});
    }
  }
  if (component_value != nullptr) {
    Result<FirmwareComponentId> parsed = make_id<FirmwareComponentId>(
        component_value->as_string(), json::join_path(path, "component"));
    if (parsed.has_value()) {
      requirement.component = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (versions_value != nullptr) {
    Result<VersionRange> parsed = parse_version_range(*versions_value, json::join_path(path, "versions"));
    if (parsed.has_value()) {
      requirement.versions = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (minimum_value != nullptr) {
    const std::optional<HardwareRevision> parsed =
        read_revision(minimum_value, json::join_path(path, "minimum_revision"), diagnostics);
    if (parsed.has_value()) {
      requirement.minimum_revision = *parsed;
    }
  }
  if (maximum_value != nullptr) {
    const std::optional<HardwareRevision> parsed =
        read_revision(maximum_value, json::join_path(path, "maximum_revision"), diagnostics);
    if (parsed.has_value()) {
      requirement.maximum_revision = *parsed;
    }
  }
  if (capability_value != nullptr) {
    Result<CapabilityId> parsed = make_id<CapabilityId>(capability_value->as_string(),
                                                        json::join_path(path, "capability"));
    if (parsed.has_value()) {
      requirement.capability = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = requirement.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return requirement;
}

std::string Requirement::to_string() const { return requirement_summary(*this); }

// ---------------------------------------------------------------------------
// CompatibilityRule
// ---------------------------------------------------------------------------

Status CompatibilityRule::validate(std::string_view path, Diagnostics& diagnostics) const {
  const std::string id_path = json::join_path(path, "id");
  if (!id.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "rule id is required", id_path);
  } else {
    Status status = validate_identifier(id.view(), id_path);
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
  }

  const std::string when_component_path = json::join_path(path, "when_component");
  if (!when_component.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "when_component is required",
                    when_component_path);
  } else {
    Status status = validate_identifier(when_component.view(), when_component_path);
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
  }

  const std::string when_versions_path = json::join_path(path, "when_versions");
  if (!range_is_present(when_versions)) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "when_versions is required and must state at least one bound",
                    when_versions_path);
  } else if (when_versions.is_empty()) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "when_versions " + when_versions.to_string() +
                        " has no members, so the rule could never trigger",
                    when_versions_path);
  }

  const std::string when_maximum_path = json::join_path(path, "when_maximum_revision");
  if (when_minimum_revision.is_set() && when_maximum_revision.is_set() &&
      when_maximum_revision < when_minimum_revision) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "when_maximum_revision " + describe_revision(when_maximum_revision) +
                        " is below when_minimum_revision " + describe_revision(when_minimum_revision) +
                        ", so the trigger revision range has no members",
                    when_maximum_path);
  }

  if (reason.empty()) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "reason is empty; a rule must state why it exists",
                    json::join_path(path, "reason"));
  }

  requirement.validate(json::join_path(path, "requirement"), diagnostics);

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value CompatibilityRule::to_json() const {
  json::Value out = json::Value::make_object();
  if (id.is_set()) {
    out.set("id", json::Value{id.value()});
  }
  if (when_component.is_set()) {
    out.set("when_component", json::Value{when_component.value()});
  }
  out.set("when_versions", version_range_to_json(when_versions));
  if (when_minimum_revision.is_set()) {
    out.set("when_minimum_revision",
            json::Value{static_cast<std::int64_t>(when_minimum_revision.value())});
  }
  if (when_maximum_revision.is_set()) {
    out.set("when_maximum_revision",
            json::Value{static_cast<std::int64_t>(when_maximum_revision.value())});
  }
  out.set("requirement", requirement.to_json());
  out.set("reason", json::Value{reason});
  return out;
}

Result<CompatibilityRule> CompatibilityRule::from_json(const json::Value& value,
                                                       std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "compatibility rule expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* id_value = reader.required("id", json::Type::String);
  const json::Value* when_component_value = reader.required("when_component", json::Type::String);
  const json::Value* when_versions_value = reader.required("when_versions", json::Type::Object);
  const json::Value* when_minimum_value =
      reader.optional("when_minimum_revision", json::Type::Integer);
  const json::Value* when_maximum_value =
      reader.optional("when_maximum_revision", json::Type::Integer);
  const json::Value* requirement_value = reader.required("requirement", json::Type::Object);
  const json::Value* reason_value = reader.required("reason", json::Type::String);
  reader.finish();

  CompatibilityRule rule;
  if (id_value != nullptr) {
    Result<RuleId> parsed = make_id<RuleId>(id_value->as_string(), json::join_path(path, "id"));
    if (parsed.has_value()) {
      rule.id = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (when_component_value != nullptr) {
    Result<FirmwareComponentId> parsed = make_id<FirmwareComponentId>(
        when_component_value->as_string(), json::join_path(path, "when_component"));
    if (parsed.has_value()) {
      rule.when_component = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (when_versions_value != nullptr) {
    Result<VersionRange> parsed =
        parse_version_range(*when_versions_value, json::join_path(path, "when_versions"));
    if (parsed.has_value()) {
      rule.when_versions = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (when_minimum_value != nullptr) {
    const std::optional<HardwareRevision> parsed = read_revision(
        when_minimum_value, json::join_path(path, "when_minimum_revision"), diagnostics);
    if (parsed.has_value()) {
      rule.when_minimum_revision = *parsed;
    }
  }
  if (when_maximum_value != nullptr) {
    const std::optional<HardwareRevision> parsed = read_revision(
        when_maximum_value, json::join_path(path, "when_maximum_revision"), diagnostics);
    if (parsed.has_value()) {
      rule.when_maximum_revision = *parsed;
    }
  }
  if (requirement_value != nullptr) {
    Result<Requirement> parsed =
        Requirement::from_json(*requirement_value, json::join_path(path, "requirement"));
    if (parsed.has_value()) {
      rule.requirement = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (reason_value != nullptr) {
    rule.reason = reason_value->as_string();
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = rule.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return rule;
}

std::string CompatibilityRule::to_string() const {
  std::string out = "rule \"" + rule_name(*this) + "\": when " + describe_component(when_component) +
                    " in " + when_versions.to_string() + " with hardware revision " +
                    revision_trigger_summary(*this) + ", require " + requirement_summary(requirement) +
                    " (reason: " + reason + ")";
  return out;
}

// ---------------------------------------------------------------------------
// CompatibilityRuleSet
// ---------------------------------------------------------------------------

Status CompatibilityRuleSet::add(CompatibilityRule rule) {
  if (find(rule.id) != nullptr) {
    return Error{ErrorCode::SchemaDuplicateIdentifier,
                 "rule \"" + rule.id.to_string() + "\" is already defined in this rule set", {}};
  }
  std::size_t index = 0;
  while (index < rules_.size() && rules_[index].id < rule.id) {
    ++index;
  }
  rules_.insert(rules_.begin() + static_cast<std::ptrdiff_t>(index), std::move(rule));
  return ok_status();
}

Status CompatibilityRuleSet::validate(std::string_view path, Diagnostics& diagnostics) const {
  for (std::size_t index = 0; index < rules_.size(); ++index) {
    rules_[index].validate(json::join_index(path, index), diagnostics);
  }
  for (std::size_t index = 1; index < rules_.size(); ++index) {
    if (rules_[index].id == rules_[index - 1].id) {
      diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                      "rule \"" + rules_[index].id.to_string() + "\" is defined more than once",
                      json::join_index(path, index));
    }
  }
  for (std::size_t index = 0; index < rules_.size(); ++index) {
    const CompatibilityRule& rule = rules_[index];
    if (!is_self_contradictory(rule)) {
      continue;
    }
    diagnostics.add(
        ErrorCode::PolicySelfContradiction,
        "rule \"" + rule_name(rule) + "\" can never be satisfied: it triggers on component \"" +
            rule.when_component.to_string() + "\" in " + rule.when_versions.to_string() +
            " and requires the same component's version to be in " +
            rule.requirement.versions.to_string() +
            ", which shares no version with the trigger range",
        json::join_index(path, index));
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

const CompatibilityRule* CompatibilityRuleSet::find(const RuleId& id) const {
  std::size_t index = 0;
  while (index < rules_.size() && rules_[index].id < id) {
    ++index;
  }
  if (index < rules_.size() && rules_[index].id == id) {
    return &rules_[index];
  }
  return nullptr;
}

std::vector<RuleId> CompatibilityRuleSet::self_contradictions() const {
  std::vector<RuleId> contradictions;
  for (const CompatibilityRule& rule : rules_) {
    if (is_self_contradictory(rule)) {
      contradictions.push_back(rule.id);
    }
  }
  return contradictions;
}

std::vector<RuleEvaluation> CompatibilityRuleSet::evaluate(
    const HardwareProfile& hardware, const ComponentEvidenceMap& evidence) const {
  std::vector<RuleEvaluation> evaluations;
  evaluations.reserve(rules_.size());
  for (const CompatibilityRule& rule : rules_) {
    RuleEvaluation evaluation;
    evaluation.rule = rule.id;
    const std::string name = rule_name(rule);
    const std::string component_name = describe_component(rule.when_component);
    const std::optional<FirmwareVersion>* found =
        find_component_evidence(evidence, rule.when_component);
    if (found == nullptr) {
      evaluation.outcome = RuleOutcome::NotTriggered;
      evaluation.detail = "rule \"" + name + "\" was not triggered: trigger component \"" +
                          component_name + "\" was not observed in the evidence";
      evaluations.push_back(std::move(evaluation));
      continue;
    }
    if (!found->has_value()) {
      evaluation.outcome = RuleOutcome::TriggerUnknown;
      evaluation.detail = "rule \"" + name + "\": trigger component \"" + component_name +
                          "\" was observed but its version was not determined, so the rule can "
                          "neither be applied nor dismissed";
      evaluations.push_back(std::move(evaluation));
      continue;
    }
    const FirmwareVersion& trigger_version = **found;
    if (!rule.when_versions.contains(trigger_version)) {
      evaluation.outcome = RuleOutcome::NotTriggered;
      evaluation.detail = "rule \"" + name + "\" was not triggered: trigger component \"" +
                          component_name + "\" has version " + trigger_version.to_string() +
                          ", which is outside the trigger range " +
                          rule.when_versions.to_string();
      evaluations.push_back(std::move(evaluation));
      continue;
    }
    const bool revision_below = rule.when_minimum_revision.is_set() &&
                                hardware.revision.is_set() &&
                                hardware.revision < rule.when_minimum_revision;
    const bool revision_above = rule.when_maximum_revision.is_set() &&
                                hardware.revision.is_set() &&
                                hardware.revision > rule.when_maximum_revision;
    if (revision_below || revision_above) {
      evaluation.outcome = RuleOutcome::NotTriggered;
      evaluation.detail = "rule \"" + name + "\" was not triggered: hardware revision " +
                          describe_revision(hardware.revision) +
                          " is outside the trigger revision bounds " +
                          revision_trigger_summary(rule);
      evaluations.push_back(std::move(evaluation));
      continue;
    }

    std::string requirement_detail;
    const RequirementOutcome outcome =
        rule.requirement.evaluate(hardware, evidence, requirement_detail);
    evaluation.requirement_outcome = outcome;
    switch (outcome) {
      case RequirementOutcome::Satisfied:
        evaluation.outcome = RuleOutcome::Satisfied;
        break;
      case RequirementOutcome::Violated:
        evaluation.outcome = RuleOutcome::Violated;
        break;
      case RequirementOutcome::Unverifiable:
        evaluation.outcome = RuleOutcome::Unverifiable;
        break;
    }
    std::string residual;
    switch (outcome) {
      case RequirementOutcome::Satisfied:
        residual = "none";
        break;
      case RequirementOutcome::Violated:
        residual = "the requirement is not met";
        break;
      case RequirementOutcome::Unverifiable:
        residual = "the requirement cannot be decided from the evidence";
        break;
    }
    evaluation.detail = "rule \"" + name + "\" triggered by trigger component \"" +
                        component_name + "\" version " + trigger_version.to_string() + "; " +
                        requirement_detail + "; residual: " + residual;
    evaluations.push_back(std::move(evaluation));
  }
  return evaluations;
}

json::Value CompatibilityRuleSet::to_json() const {
  json::Value out = json::Value::make_array();
  for (const CompatibilityRule& rule : rules_) {
    out.push_back(rule.to_json());
  }
  return out;
}

Result<CompatibilityRuleSet> CompatibilityRuleSet::from_json(const json::Value& value,
                                                             std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_array()) {
    return Error{ErrorCode::SchemaWrongType,
                 "compatibility rules expected array but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  CompatibilityRuleSet set;
  const json::Value::Array& elements = value.as_array();
  for (std::size_t index = 0; index < elements.size(); ++index) {
    const std::string element_path = json::join_index(path, index);
    Result<CompatibilityRule> parsed = CompatibilityRule::from_json(elements[index], element_path);
    if (!parsed.has_value()) {
      diagnostics.add(parsed.error());
      continue;
    }
    Status status = set.add(parsed.take());
    if (!status.has_value()) {
      diagnostics.add(Error{status.error().code(), status.error().message(), element_path});
    }
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = set.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return set;
}

}  // namespace summon::fbm
