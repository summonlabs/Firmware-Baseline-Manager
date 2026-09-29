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

#include "summon/fbm/baseline.hpp"

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

#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {
namespace {

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

std::string describe_revision(const HardwareRevision& revision) {
  if (!revision.is_set()) {
    return std::string{"<unset>"};
  }
  return std::to_string(revision.value());
}

std::string describe_generation(const BaselineGeneration& generation) {
  if (!generation.is_set()) {
    return std::string{"<unset>"};
  }
  return std::to_string(generation.value());
}

std::string describe_hardware(const HardwareProfile& hardware) {
  std::string out;
  out += hardware.hardware_class.is_set() ? hardware.hardware_class.to_string()
                                          : std::string{"<unset>"};
  out += '/';
  out += hardware.model.is_set() ? hardware.model.to_string() : std::string{"<unset>"};
  return out;
}

std::string selector_summary(const HardwareSelector& selector) {
  std::string out = selector.hardware_class.is_set() ? selector.hardware_class.to_string()
                                                     : std::string{"<unset>"};
  out += '/';
  out += selector.model.is_set() ? selector.model.to_string() : std::string{"<any model>"};
  out += " revision ";
  if (selector.minimum_revision.is_set() && selector.maximum_revision.is_set()) {
    out += "[" + describe_revision(selector.minimum_revision) + ", " +
           describe_revision(selector.maximum_revision) + "]";
  } else if (selector.minimum_revision.is_set()) {
    out += "at least " + describe_revision(selector.minimum_revision);
  } else if (selector.maximum_revision.is_set()) {
    out += "at most " + describe_revision(selector.maximum_revision);
  } else {
    out += "any";
  }
  return out;
}

std::string baseline_state_name(BaselineState state) {
  return std::string{baseline_state_token(state)};
}

// ---------------------------------------------------------------------------
// JSON conversion helpers
// ---------------------------------------------------------------------------

json::Value versions_to_json(const std::vector<FirmwareVersion>& versions) {
  json::Value out = json::Value::make_array();
  for (const FirmwareVersion& version : versions) {
    out.push_back(json::Value{version.to_string()});
  }
  return out;
}

std::optional<FirmwareVersion> read_version(const json::Value& value, std::string_view path,
                                            Diagnostics& diagnostics) {
  Result<FirmwareVersion> parsed = FirmwareVersion::parse(value.as_string(), path);
  if (!parsed.has_value()) {
    diagnostics.add(parsed.error());
    return std::nullopt;
  }
  return parsed.take();
}

std::vector<FirmwareVersion> read_version_array(const json::Value& value, std::string_view path,
                                                Diagnostics& diagnostics) {
  std::vector<FirmwareVersion> versions;
  const json::Value::Array& elements = value.as_array();
  versions.reserve(elements.size());
  for (std::size_t index = 0; index < elements.size(); ++index) {
    const std::string element_path = json::join_index(path, index);
    if (!elements[index].is_string()) {
      diagnostics.add(ErrorCode::SchemaWrongType,
                      "firmware version expected string but found " +
                          std::string{json::type_name(elements[index].type())},
                      element_path);
      continue;
    }
    const std::optional<FirmwareVersion> parsed =
        read_version(elements[index], element_path, diagnostics);
    if (parsed.has_value()) {
      versions.push_back(*parsed);
    }
  }
  return versions;
}

// Index of the first element that repeats an earlier element, or npos when the
// collection is duplicate free. Comparing against every earlier element keeps
// the result independent of the order of the collection.
std::size_t duplicate_version_index(const std::vector<FirmwareVersion>& versions) {
  for (std::size_t index = 1; index < versions.size(); ++index) {
    for (std::size_t earlier = 0; earlier < index; ++earlier) {
      if (versions[index] == versions[earlier]) {
        return index;
      }
    }
  }
  return versions.size();
}

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

std::optional<std::uint32_t> read_uint32(const json::Value* value, std::string_view path,
                                         std::string_view field, Diagnostics& diagnostics) {
  if (value == nullptr) {
    return std::nullopt;
  }
  const std::int64_t raw = value->as_integer();
  const std::int64_t maximum =
      static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max());
  if (raw < 0 || raw > maximum) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    std::string{field} + " is outside the range [0, " + std::to_string(maximum) +
                        "]",
                    std::string{path});
    return std::nullopt;
  }
  return static_cast<std::uint32_t>(raw);
}

std::optional<std::uint64_t> read_counter(const json::Value* value, std::string_view path,
                                          std::string_view field, Diagnostics& diagnostics) {
  if (value == nullptr) {
    return std::nullopt;
  }
  const std::int64_t raw = value->as_integer();
  if (raw < 0) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    std::string{field} + " must be a non-negative integer, found " +
                        std::to_string(raw),
                    std::string{path});
    return std::nullopt;
  }
  return static_cast<std::uint64_t>(raw);
}

std::optional<Timestamp> read_timestamp(const json::Value* value, std::string_view path,
                                        Diagnostics& diagnostics) {
  if (value == nullptr) {
    return std::nullopt;
  }
  Result<Timestamp> parsed = Timestamp::parse_rfc3339(value->as_string(), path);
  if (!parsed.has_value()) {
    diagnostics.add(parsed.error());
    return std::nullopt;
  }
  return parsed.take();
}

json::Value freshness_to_json(const FreshnessBound& freshness) {
  json::Value out = json::Value::make_object();
  if (freshness.is_unbounded()) {
    out.set("unbounded", json::Value{true});
  } else {
    out.set("max_age_nanos", json::Value{static_cast<std::int64_t>(freshness.max_age_nanos())});
  }
  return out;
}

std::optional<FreshnessBound> read_freshness(const json::Value* value, std::string_view path,
                                             Diagnostics& diagnostics) {
  if (value == nullptr) {
    return std::nullopt;
  }
  json::ObjectReader reader(*value, std::string{path}, diagnostics);
  const json::Value* max_age = reader.optional("max_age_nanos", json::Type::Integer);
  const json::Value* unbounded = reader.optional("unbounded", json::Type::Boolean);
  reader.finish();
  if (max_age != nullptr && unbounded != nullptr) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "freshness states both max_age_nanos and unbounded; exactly one is required",
                    std::string{path});
    return std::nullopt;
  }
  if (max_age == nullptr && unbounded == nullptr) {
    diagnostics.add(ErrorCode::SchemaMissingField,
                    "freshness requires exactly one of max_age_nanos or unbounded",
                    std::string{path});
    return std::nullopt;
  }
  if (unbounded != nullptr) {
    if (!unbounded->as_boolean()) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "unbounded is false; state max_age_nanos or unbounded true",
                      json::join_path(path, "unbounded"));
      return std::nullopt;
    }
    return FreshnessBound::unbounded();
  }
  const std::int64_t raw = max_age->as_integer();
  if (raw < 0) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    "max_age_nanos must be a non-negative integer, found " +
                        std::to_string(raw),
                    json::join_path(path, "max_age_nanos"));
    return std::nullopt;
  }
  return FreshnessBound::within(static_cast<std::uint64_t>(raw));
}

// --- selector ordering ------------------------------------------------------

bool selector_less(const HardwareSelector& left, const HardwareSelector& right) {
  if (!(left.hardware_class == right.hardware_class)) {
    return left.hardware_class < right.hardware_class;
  }
  if (!(left.model == right.model)) {
    return left.model < right.model;
  }
  if (!(left.minimum_revision == right.minimum_revision)) {
    return left.minimum_revision < right.minimum_revision;
  }
  return left.maximum_revision < right.maximum_revision;
}

bool selector_equal(const HardwareSelector& left, const HardwareSelector& right) {
  return left.hardware_class == right.hardware_class && left.model == right.model &&
         left.minimum_revision == right.minimum_revision &&
         left.maximum_revision == right.maximum_revision;
}

bool selectors_share_hardware_class(const std::vector<HardwareSelector>& left,
                                    const std::vector<HardwareSelector>& right) {
  for (const HardwareSelector& a : left) {
    if (!a.hardware_class.is_set()) {
      continue;
    }
    for (const HardwareSelector& b : right) {
      if (b.hardware_class.is_set() && a.hardware_class == b.hardware_class) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// BaselineState
// ---------------------------------------------------------------------------

std::string_view baseline_state_token(BaselineState state) noexcept {
  switch (state) {
    case BaselineState::Draft:
      return "draft";
    case BaselineState::Published:
      return "published";
    case BaselineState::Retired:
      return "retired";
  }
  return "unknown";
}

Result<BaselineState> baseline_state_from_token(std::string_view token) {
  if (token == "draft") {
    return BaselineState::Draft;
  }
  if (token == "published") {
    return BaselineState::Published;
  }
  if (token == "retired") {
    return BaselineState::Retired;
  }
  return Error{ErrorCode::SchemaInvalidEnumValue,
               "unknown baseline state token \"" + std::string{token} +
                   "\"; expected one of draft, published, retired",
               {}};
}

// ---------------------------------------------------------------------------
// HardwareSelector
// ---------------------------------------------------------------------------

bool HardwareSelector::covers(const HardwareProfile& hardware) const {
  if (!hardware_class.is_set() || !hardware.hardware_class.is_set()) {
    return false;
  }
  if (!(hardware_class == hardware.hardware_class)) {
    return false;
  }
  if (model.is_set()) {
    if (!hardware.model.is_set() || !(model == hardware.model)) {
      return false;
    }
  }
  if (minimum_revision.is_set()) {
    if (!hardware.revision.is_set() || hardware.revision < minimum_revision) {
      return false;
    }
  }
  if (maximum_revision.is_set()) {
    if (!hardware.revision.is_set() || hardware.revision > maximum_revision) {
      return false;
    }
  }
  return true;
}

Status HardwareSelector::validate(std::string_view path, Diagnostics& diagnostics) const {
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
  if (model.is_set()) {
    Status status = validate_identifier(model.view(), json::join_path(path, "model"));
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
  }
  if (minimum_revision.is_set() && maximum_revision.is_set() &&
      maximum_revision < minimum_revision) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "maximum_revision " + describe_revision(maximum_revision) +
                        " is below minimum_revision " + describe_revision(minimum_revision) +
                        ", so the selector has no members",
                    json::join_path(path, "maximum_revision"));
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value HardwareSelector::to_json() const {
  json::Value out = json::Value::make_object();
  if (hardware_class.is_set()) {
    out.set("hardware_class", json::Value{hardware_class.value()});
  }
  if (model.is_set()) {
    out.set("model", json::Value{model.value()});
  }
  if (minimum_revision.is_set()) {
    out.set("minimum_revision",
            json::Value{static_cast<std::int64_t>(minimum_revision.value())});
  }
  if (maximum_revision.is_set()) {
    out.set("maximum_revision",
            json::Value{static_cast<std::int64_t>(maximum_revision.value())});
  }
  return out;
}

Result<HardwareSelector> HardwareSelector::from_json(const json::Value& value,
                                                     std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "hardware selector expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* hardware_class = reader.required("hardware_class", json::Type::String);
  const json::Value* model = reader.optional("model", json::Type::String);
  const json::Value* minimum = reader.optional("minimum_revision", json::Type::Integer);
  const json::Value* maximum = reader.optional("maximum_revision", json::Type::Integer);
  reader.finish();

  HardwareSelector selector;
  if (hardware_class != nullptr) {
    Result<HardwareClassId> parsed = make_id<HardwareClassId>(
        hardware_class->as_string(), json::join_path(path, "hardware_class"));
    if (parsed.has_value()) {
      selector.hardware_class = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (model != nullptr) {
    Result<HardwareModelId> parsed =
        make_id<HardwareModelId>(model->as_string(), json::join_path(path, "model"));
    if (parsed.has_value()) {
      selector.model = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (minimum != nullptr) {
    const std::optional<HardwareRevision> parsed =
        read_revision(minimum, json::join_path(path, "minimum_revision"), diagnostics);
    if (parsed.has_value()) {
      selector.minimum_revision = *parsed;
    }
  }
  if (maximum != nullptr) {
    const std::optional<HardwareRevision> parsed =
        read_revision(maximum, json::join_path(path, "maximum_revision"), diagnostics);
    if (parsed.has_value()) {
      selector.maximum_revision = *parsed;
    }
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = selector.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return selector;
}

std::string HardwareSelector::to_string() const { return selector_summary(*this); }

// ---------------------------------------------------------------------------
// ComponentRequirement
// ---------------------------------------------------------------------------

bool ComponentRequirement::is_conformant(const FirmwareVersion& version) const {
  return std::find(conformant_versions.begin(), conformant_versions.end(), version) !=
         conformant_versions.end();
}

bool ComponentRequirement::is_rollback_target(const FirmwareVersion& version) const {
  return std::find(rollback_targets.begin(), rollback_targets.end(), version) !=
         rollback_targets.end();
}

Status ComponentRequirement::validate(std::string_view path, Diagnostics& diagnostics) const {
  const std::string component_path = json::join_path(path, "component");
  if (!component.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "component is required", component_path);
  } else {
    Status status = validate_identifier(component.view(), component_path);
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
  }

  const std::string conformant_path = json::join_path(path, "conformant");
  if (conformant_versions.empty()) {
    diagnostics.add(ErrorCode::SchemaEmptyCollection,
                    "conformant must not be empty and must contain the approved version " +
                        approved_version.to_string(),
                    conformant_path);
  } else {
    if (!is_conformant(approved_version)) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "conformant does not contain the approved version " +
                          approved_version.to_string(),
                      conformant_path);
    }
    for (std::size_t index = 1; index < conformant_versions.size(); ++index) {
      if (conformant_versions[index] == conformant_versions[index - 1]) {
        diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                        "version " + conformant_versions[index].to_string() +
                            " appears more than once in conformant",
                        json::join_index(conformant_path, index));
      } else if (conformant_versions[index] < conformant_versions[index - 1]) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "conformant is not sorted ascending: " +
                            conformant_versions[index].to_string() + " follows " +
                            conformant_versions[index - 1].to_string(),
                        json::join_index(conformant_path, index));
      }
    }
  }

  const std::string rollback_path = json::join_path(path, "rollback_targets");
  for (std::size_t index = 0; index < rollback_targets.size(); ++index) {
    for (std::size_t earlier = 0; earlier < index; ++earlier) {
      if (rollback_targets[index] == rollback_targets[earlier]) {
        diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                        "rollback target " + rollback_targets[index].to_string() +
                            " appears more than once",
                        json::join_index(rollback_path, index));
        break;
      }
    }
    if (is_conformant(rollback_targets[index])) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "rollback target " + rollback_targets[index].to_string() +
                          " is also a conformant version; a version cannot be both the "
                          "version to leave and the version to return to",
                      json::join_index(rollback_path, index));
    }
  }

  if (!freshness.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "freshness is required",
                    json::join_path(path, "freshness"));
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value ComponentRequirement::to_json() const {
  json::Value out = json::Value::make_object();
  if (component.is_set()) {
    out.set("component", json::Value{component.value()});
  }
  out.set("approved", json::Value{approved_version.to_string()});
  out.set("conformant", versions_to_json(conformant_versions));
  out.set("rollback_targets", versions_to_json(rollback_targets));
  if (freshness.is_set()) {
    out.set("freshness", freshness_to_json(freshness));
  }
  return out;
}

Result<ComponentRequirement> ComponentRequirement::from_json(const json::Value& value,
                                                             std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "component requirement expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* component = reader.required("component", json::Type::String);
  const json::Value* approved = reader.required("approved", json::Type::String);
  const json::Value* conformant = reader.required("conformant", json::Type::Array);
  const json::Value* rollback = reader.required("rollback_targets", json::Type::Array);
  const json::Value* freshness = reader.required("freshness", json::Type::Object);
  reader.finish();

  std::optional<FirmwareComponentId> component_id;
  std::optional<FirmwareVersion> approved_version;
  std::vector<FirmwareVersion> conformant_versions;
  std::vector<FirmwareVersion> rollback_versions;
  std::optional<FreshnessBound> freshness_bound;
  if (component != nullptr) {
    Result<FirmwareComponentId> parsed = make_id<FirmwareComponentId>(
        component->as_string(), json::join_path(path, "component"));
    if (parsed.has_value()) {
      component_id = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (approved != nullptr) {
    approved_version = read_version(*approved, json::join_path(path, "approved"), diagnostics);
  }
  if (conformant != nullptr) {
    const std::string conformant_path = json::join_path(path, "conformant");
    conformant_versions = read_version_array(*conformant, conformant_path, diagnostics);
    const std::size_t duplicate = duplicate_version_index(conformant_versions);
    if (duplicate != conformant_versions.size()) {
      diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                      "version " + conformant_versions[duplicate].to_string() +
                          " appears more than once in conformant",
                      json::join_index(conformant_path, duplicate));
    } else {
      std::sort(conformant_versions.begin(), conformant_versions.end());
    }
  }
  if (rollback != nullptr) {
    const std::string rollback_path = json::join_path(path, "rollback_targets");
    rollback_versions = read_version_array(*rollback, rollback_path, diagnostics);
    const std::size_t duplicate = duplicate_version_index(rollback_versions);
    if (duplicate != rollback_versions.size()) {
      diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                      "rollback target " + rollback_versions[duplicate].to_string() +
                          " appears more than once",
                      json::join_index(rollback_path, duplicate));
    }
  }
  if (freshness != nullptr) {
    freshness_bound = read_freshness(freshness, json::join_path(path, "freshness"), diagnostics);
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  if (!component_id.has_value() || !approved_version.has_value() ||
      !freshness_bound.has_value()) {
    return Error{ErrorCode::InternalInvariantViolation,
                 "component requirement is missing a required field after parsing",
                 std::string{path}};
  }
  ComponentRequirement requirement{std::move(*component_id), std::move(*approved_version),
                                   std::move(conformant_versions), std::move(rollback_versions),
                                   *freshness_bound};
  Status status = requirement.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return requirement;
}

std::string ComponentRequirement::to_string() const {
  std::string out = component.is_set() ? component.to_string() : std::string{"<unset>"};
  out += " approved " + approved_version.to_string() + " conformant [";
  for (std::size_t index = 0; index < conformant_versions.size(); ++index) {
    if (index != 0) {
      out += ", ";
    }
    out += conformant_versions[index].to_string();
  }
  out += "] rollback [";
  for (std::size_t index = 0; index < rollback_targets.size(); ++index) {
    if (index != 0) {
      out += ", ";
    }
    out += rollback_targets[index].to_string();
  }
  out += "] freshness ";
  out += freshness.is_set() ? (freshness.is_unbounded()
                                   ? std::string{"unbounded"}
                                   : std::to_string(freshness.max_age_nanos()) + "ns")
                            : std::string{"<unset>"};
  return out;
}

// ---------------------------------------------------------------------------
// PromotionGate
// ---------------------------------------------------------------------------

Status PromotionGate::validate(std::string_view path, Diagnostics& diagnostics) const {
  if (minimum_conformant_basis_points > 10000u) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    "minimum_conformant_basis_points " +
                        std::to_string(minimum_conformant_basis_points) +
                        " is above the maximum of 10000",
                    json::join_path(path, "minimum_conformant_basis_points"));
  }
  if (!required_stages.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "required_stages is required",
                    json::join_path(path, "required_stages"));
  } else if (required_stages.value() < 1u) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    "required_stages must be at least 1",
                    json::join_path(path, "required_stages"));
  }
  // minimum_conformant_assets may be zero: a policy author is allowed to gate a
  // stage on decided assets alone. It is never a way to promote on nothing,
  // because minimum_decided_assets must still be at least one, and the gate
  // evaluator independently reports every asset whose state is unknown,
  // unsupported, or blocked as an unmet condition rather than counting it.
  if (minimum_decided_assets < 1u) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    "minimum_decided_assets must be at least 1",
                    json::join_path(path, "minimum_decided_assets"));
  }
  if (minimum_decided_assets < minimum_conformant_assets) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "minimum_decided_assets " + std::to_string(minimum_decided_assets) +
                        " is below minimum_conformant_assets " +
                        std::to_string(minimum_conformant_assets) +
                        "; a decided minimum of zero assets cannot contain the conformant minimum",
                    json::join_path(path, "minimum_decided_assets"));
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value PromotionGate::to_json() const {
  json::Value out = json::Value::make_object();
  out.set("minimum_conformant_basis_points",
          json::Value{static_cast<std::int64_t>(minimum_conformant_basis_points)});
  out.set("minimum_decided_assets",
          json::Value{static_cast<std::int64_t>(minimum_decided_assets)});
  out.set("minimum_conformant_assets",
          json::Value{static_cast<std::int64_t>(minimum_conformant_assets)});
  out.set("soak_nanos", json::Value{static_cast<std::int64_t>(soak_nanos)});
  if (required_stages.is_set()) {
    out.set("required_stages",
            json::Value{static_cast<std::int64_t>(required_stages.value())});
  }
  return out;
}

Result<PromotionGate> PromotionGate::from_json(const json::Value& value, std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "promotion gate expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* basis_points =
      reader.required("minimum_conformant_basis_points", json::Type::Integer);
  const json::Value* decided = reader.required("minimum_decided_assets", json::Type::Integer);
  const json::Value* conformant = reader.required("minimum_conformant_assets", json::Type::Integer);
  const json::Value* soak = reader.required("soak_nanos", json::Type::Integer);
  const json::Value* stages = reader.required("required_stages", json::Type::Integer);
  reader.finish();

  PromotionGate gate;
  if (basis_points != nullptr) {
    const std::optional<std::uint32_t> parsed =
        read_uint32(basis_points, json::join_path(path, "minimum_conformant_basis_points"),
                    "minimum_conformant_basis_points", diagnostics);
    if (parsed.has_value()) {
      gate.minimum_conformant_basis_points = *parsed;
    }
  }
  if (decided != nullptr) {
    const std::optional<std::uint32_t> parsed =
        read_uint32(decided, json::join_path(path, "minimum_decided_assets"),
                    "minimum_decided_assets", diagnostics);
    if (parsed.has_value()) {
      gate.minimum_decided_assets = *parsed;
    }
  }
  if (conformant != nullptr) {
    const std::optional<std::uint32_t> parsed =
        read_uint32(conformant, json::join_path(path, "minimum_conformant_assets"),
                    "minimum_conformant_assets", diagnostics);
    if (parsed.has_value()) {
      gate.minimum_conformant_assets = *parsed;
    }
  }
  if (soak != nullptr) {
    const std::optional<std::uint64_t> parsed =
        read_counter(soak, json::join_path(path, "soak_nanos"), "soak_nanos", diagnostics);
    if (parsed.has_value()) {
      gate.soak_nanos = *parsed;
    }
  }
  if (stages != nullptr) {
    const std::optional<std::uint32_t> parsed =
        read_uint32(stages, json::join_path(path, "required_stages"), "required_stages",
                    diagnostics);
    if (parsed.has_value()) {
      gate.required_stages = StageIndex{*parsed};
    }
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = gate.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return gate;
}

std::string PromotionGate::to_string() const {
  std::string out = "gate basis_points <= " + std::to_string(minimum_conformant_basis_points) +
                    ", decided >= " + std::to_string(minimum_decided_assets) +
                    ", conformant >= " + std::to_string(minimum_conformant_assets) +
                    ", soak_nanos >= " + std::to_string(soak_nanos) + ", required_stages ";
  out += required_stages.is_set() ? std::to_string(required_stages.value())
                                  : std::string{"<unset>"};
  return out;
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

Status Baseline::validate(std::string_view path, Diagnostics& diagnostics) const {
  const std::string id_path = json::join_path(path, "id");
  if (!id.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "baseline id is required", id_path);
  } else {
    Status status = validate_identifier(id.view(), id_path);
    if (!status.has_value()) {
      diagnostics.add(status.error());
    }
  }
  if (!generation.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "generation is required",
                    json::join_path(path, "generation"));
  }
  if (!revision.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "revision is required",
                    json::join_path(path, "revision"));
  }

  const std::string selectors_path = json::join_path(path, "selectors");
  if (selectors.empty()) {
    diagnostics.add(ErrorCode::SchemaEmptyCollection,
                    "selectors must not be empty; a baseline that selects nothing is not policy",
                    selectors_path);
  }
  for (std::size_t index = 0; index < selectors.size(); ++index) {
    selectors[index].validate(json::join_index(selectors_path, index), diagnostics);
  }
  for (std::size_t index = 1; index < selectors.size(); ++index) {
    const std::string element_path = json::join_index(selectors_path, index);
    if (selector_equal(selectors[index], selectors[index - 1])) {
      diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                      "selector " + selector_summary(selectors[index]) +
                          " appears more than once",
                      element_path);
    } else if (selector_less(selectors[index], selectors[index - 1])) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "selectors is not sorted ascending by (hardware_class, model, "
                      "minimum_revision, maximum_revision): " +
                          selector_summary(selectors[index]) + " follows " +
                          selector_summary(selectors[index - 1]),
                      element_path);
    }
  }

  const std::string components_path = json::join_path(path, "components");
  if (components.empty()) {
    diagnostics.add(ErrorCode::SchemaEmptyCollection,
                    "components must not be empty; a baseline that approves nothing is not policy",
                    components_path);
  }
  for (std::size_t index = 0; index < components.size(); ++index) {
    components[index].validate(json::join_index(components_path, index), diagnostics);
  }
  for (std::size_t index = 1; index < components.size(); ++index) {
    const std::string element_path = json::join_index(components_path, index);
    if (components[index].component == components[index - 1].component) {
      diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                      "component " +
                          (components[index].component.is_set()
                               ? components[index].component.to_string()
                               : std::string{"<unset>"}) +
                          " appears more than once in components",
                      element_path);
    } else if (components[index].component < components[index - 1].component) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "components is not sorted ascending by component identity",
                      element_path);
    }
  }

  rules.validate(json::join_path(path, "rules"), diagnostics);
  gate.validate(json::join_path(path, "gate"), diagnostics);

  if (!created_at.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "created_at is required",
                    json::join_path(path, "created_at"));
  }
  if (state == BaselineState::Draft) {
    if (published_at.is_set()) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "published_at must be absent for a draft baseline",
                      json::join_path(path, "published_at"));
    }
  } else if (!published_at.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField,
                    "published_at is required when state is " + baseline_state_name(state),
                    json::join_path(path, "published_at"));
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

bool Baseline::covers(const HardwareProfile& hardware) const {
  for (const HardwareSelector& selector : selectors) {
    if (selector.covers(hardware)) {
      return true;
    }
  }
  return false;
}

const ComponentRequirement* Baseline::find_component(
    const FirmwareComponentId& component) const {
  for (const ComponentRequirement& requirement : components) {
    if (requirement.component == component) {
      return &requirement;
    }
  }
  return nullptr;
}

json::Value Baseline::to_json() const {
  json::Value out = json::Value::make_object();
  if (id.is_set()) {
    out.set("id", json::Value{id.value()});
  }
  if (generation.is_set()) {
    out.set("generation", json::Value{static_cast<std::int64_t>(generation.value())});
  }
  if (revision.is_set()) {
    out.set("revision", json::Value{static_cast<std::int64_t>(revision.value())});
  }
  out.set("state", json::Value{baseline_state_name(state)});
  if (!title.empty()) {
    out.set("title", json::Value{title});
  }
  json::Value selector_array = json::Value::make_array();
  for (const HardwareSelector& selector : selectors) {
    selector_array.push_back(selector.to_json());
  }
  out.set("selectors", std::move(selector_array));
  json::Value component_array = json::Value::make_array();
  for (const ComponentRequirement& requirement : components) {
    component_array.push_back(requirement.to_json());
  }
  out.set("components", std::move(component_array));
  out.set("rules", rules.to_json());
  out.set("gate", gate.to_json());
  if (created_at.is_set()) {
    out.set("created_at", json::Value{created_at.to_rfc3339()});
  }
  if (published_at.is_set()) {
    out.set("published_at", json::Value{published_at.to_rfc3339()});
  }
  return out;
}

Result<Baseline> Baseline::from_json(const json::Value& value, std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "baseline expected object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  const json::Value* id = reader.required("id", json::Type::String);
  const json::Value* generation = reader.required("generation", json::Type::Integer);
  const json::Value* revision = reader.required("revision", json::Type::Integer);
  const json::Value* state = reader.required("state", json::Type::String);
  const json::Value* title = reader.optional("title", json::Type::String);
  const json::Value* selectors = reader.required("selectors", json::Type::Array);
  const json::Value* components = reader.required("components", json::Type::Array);
  const json::Value* rules = reader.required("rules", json::Type::Array);
  const json::Value* gate = reader.required("gate", json::Type::Object);
  const json::Value* created_at = reader.required("created_at", json::Type::String);
  const json::Value* published_at = reader.optional("published_at", json::Type::String);
  reader.finish();

  Baseline baseline;
  if (id != nullptr) {
    Result<BaselineId> parsed = make_id<BaselineId>(id->as_string(), json::join_path(path, "id"));
    if (parsed.has_value()) {
      baseline.id = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (generation != nullptr) {
    const std::optional<std::uint64_t> parsed =
        read_counter(generation, json::join_path(path, "generation"), "generation", diagnostics);
    if (parsed.has_value()) {
      baseline.generation = BaselineGeneration{*parsed};
    }
  }
  if (revision != nullptr) {
    const std::optional<std::uint64_t> parsed =
        read_counter(revision, json::join_path(path, "revision"), "revision", diagnostics);
    if (parsed.has_value()) {
      baseline.revision = Revision{*parsed};
    }
  }
  if (state != nullptr) {
    Result<BaselineState> parsed = baseline_state_from_token(state->as_string());
    if (parsed.has_value()) {
      baseline.state = parsed.value();
    } else {
      diagnostics.add(Error{parsed.error().code(), parsed.error().message(),
                            json::join_path(path, "state")});
    }
  }
  if (title != nullptr) {
    baseline.title = title->as_string();
  }
  if (selectors != nullptr) {
    const std::string selectors_path = json::join_path(path, "selectors");
    const json::Value::Array& elements = selectors->as_array();
    for (std::size_t index = 0; index < elements.size(); ++index) {
      Result<HardwareSelector> parsed =
          HardwareSelector::from_json(elements[index], json::join_index(selectors_path, index));
      if (parsed.has_value()) {
        baseline.selectors.push_back(parsed.take());
      } else {
        diagnostics.add(parsed.error());
      }
    }
    std::stable_sort(baseline.selectors.begin(), baseline.selectors.end(), selector_less);
    for (std::size_t index = 1; index < baseline.selectors.size(); ++index) {
      if (selector_equal(baseline.selectors[index], baseline.selectors[index - 1])) {
        diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                        "selector " + selector_summary(baseline.selectors[index]) +
                            " appears more than once in selectors",
                        json::join_index(selectors_path, index));
      }
    }
  }
  if (components != nullptr) {
    const std::string components_path = json::join_path(path, "components");
    const json::Value::Array& elements = components->as_array();
    for (std::size_t index = 0; index < elements.size(); ++index) {
      Result<ComponentRequirement> parsed = ComponentRequirement::from_json(
          elements[index], json::join_index(components_path, index));
      if (parsed.has_value()) {
        baseline.components.push_back(parsed.take());
      } else {
        diagnostics.add(parsed.error());
      }
    }
    std::stable_sort(baseline.components.begin(), baseline.components.end(),
                     [](const ComponentRequirement& left, const ComponentRequirement& right) {
                       return left.component < right.component;
                     });
    for (std::size_t index = 1; index < baseline.components.size(); ++index) {
      if (baseline.components[index].component == baseline.components[index - 1].component) {
        diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                        "component " +
                            (baseline.components[index].component.is_set()
                                 ? baseline.components[index].component.to_string()
                                 : std::string{"<unset>"}) +
                            " appears more than once in components",
                        json::join_index(components_path, index));
      }
    }
  }
  if (rules != nullptr) {
    Result<CompatibilityRuleSet> parsed = CompatibilityRuleSet::from_json(
        *rules, json::join_path(path, "rules"));
    if (parsed.has_value()) {
      baseline.rules = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (gate != nullptr) {
    Result<PromotionGate> parsed = PromotionGate::from_json(*gate, json::join_path(path, "gate"));
    if (parsed.has_value()) {
      baseline.gate = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (created_at != nullptr) {
    const std::optional<Timestamp> parsed =
        read_timestamp(created_at, json::join_path(path, "created_at"), diagnostics);
    if (parsed.has_value()) {
      baseline.created_at = *parsed;
    }
  }
  if (published_at != nullptr) {
    const std::optional<Timestamp> parsed =
        read_timestamp(published_at, json::join_path(path, "published_at"), diagnostics);
    if (parsed.has_value()) {
      baseline.published_at = *parsed;
    }
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = baseline.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return baseline;
}

Digest Baseline::content_digest() const {
  const std::string canonical = json::write_canonical(to_json());
  return Sha256::of(canonical);
}

std::string Baseline::to_string() const {
  std::string out = "baseline \"" + (id.is_set() ? id.to_string() : std::string{"<unset>"}) +
                    "\" generation " + describe_generation(generation) + " revision ";
  out += revision.is_set() ? std::to_string(revision.value()) : std::string{"<unset>"};
  out += " state " + baseline_state_name(state);
  return out;
}

// ---------------------------------------------------------------------------
// BaselineRegistry
// ---------------------------------------------------------------------------

Status BaselineRegistry::put(Baseline baseline) {
  if (items_.find(baseline.id) != items_.end()) {
    return Error{ErrorCode::SchemaDuplicateIdentifier,
                 "baseline \"" + baseline.id.to_string() + "\" is already present in the registry",
                 json::join_path(std::string_view{}, "id")};
  }
  if (baseline.state == BaselineState::Published) {
    if (baseline.selectors.empty()) {
      return Error{ErrorCode::SchemaEmptyCollection,
                   "published baseline \"" + baseline.id.to_string() +
                       "\" has no selectors, so it can never apply to any hardware",
                   json::join_path(std::string_view{}, "selectors")};
    }
    for (const auto& entry : items_) {
      const Baseline& existing = entry.second;
      if (existing.state != BaselineState::Published) {
        continue;
      }
      if (!existing.generation.is_set() || !baseline.generation.is_set()) {
        continue;
      }
      if (!(existing.generation == baseline.generation)) {
        continue;
      }
      if (selectors_share_hardware_class(existing.selectors, baseline.selectors)) {
        return Error{ErrorCode::PolicySelfContradiction,
                     "published baseline \"" + existing.id.to_string() + "\" already publishes "
                     "generation " + describe_generation(existing.generation) +
                         " for a hardware class selected by \"" + baseline.id.to_string() +
                         "\"; two published baselines cannot share a hardware class and "
                         "generation",
                     json::join_path(std::string_view{}, "generation")};
      }
    }
  }
  const BaselineId key = baseline.id;
  items_.emplace(key, std::move(baseline));
  return ok_status();
}

bool BaselineRegistry::erase(const BaselineId& id) { return items_.erase(id) != 0; }

const Baseline* BaselineRegistry::find(const BaselineId& id) const {
  const auto found = items_.find(id);
  if (found == items_.end()) {
    return nullptr;
  }
  return &found->second;
}

Result<const Baseline*> BaselineRegistry::authoritative(const HardwareProfile& hardware) const {
  const Baseline* best = nullptr;
  for (const auto& entry : items_) {
    const Baseline& baseline = entry.second;
    if (!baseline.is_authoritative_candidate() || !baseline.covers(hardware)) {
      continue;
    }
    if (best == nullptr || best->generation < baseline.generation) {
      best = &baseline;
    }
  }
  if (best == nullptr) {
    return static_cast<const Baseline*>(nullptr);
  }
  std::vector<const Baseline*> tied;
  for (const auto& entry : items_) {
    const Baseline& baseline = entry.second;
    if (!baseline.is_authoritative_candidate() || !baseline.covers(hardware)) {
      continue;
    }
    if (baseline.generation == best->generation) {
      tied.push_back(&baseline);
    }
  }
  if (tied.size() > 1) {
    std::string message = "baseline authority is ambiguous for " + describe_hardware(hardware) +
                          ": ";
    for (std::size_t index = 0; index < tied.size(); ++index) {
      if (index != 0) {
        message += ", ";
      }
      message += "\"" + tied[index]->id.to_string() + "\"";
    }
    message += " all publish generation " + describe_generation(best->generation) +
               " and cover the profile";
    return Error{ErrorCode::IdentityAmbiguousBaseline, message, {}};
  }
  return best;
}

std::vector<const Baseline*> BaselineRegistry::candidates(
    const HardwareProfile& hardware) const {
  std::vector<const Baseline*> covering;
  for (const auto& entry : items_) {
    const Baseline& baseline = entry.second;
    if (baseline.is_authoritative_candidate() && baseline.covers(hardware)) {
      covering.push_back(&baseline);
    }
  }
  std::stable_sort(covering.begin(), covering.end(),
                   [](const Baseline* left, const Baseline* right) {
                     if (!(left->generation == right->generation)) {
                       return left->generation < right->generation;
                     }
                     return left->id < right->id;
                   });
  return covering;
}

Status BaselineRegistry::validate(std::string_view path, Diagnostics& diagnostics) const {
  std::vector<const Baseline*> ordered;
  ordered.reserve(items_.size());
  for (const auto& entry : items_) {
    ordered.push_back(&entry.second);
  }
  for (std::size_t index = 0; index < ordered.size(); ++index) {
    ordered[index]->validate(json::join_index(path, index), diagnostics);
  }
  for (std::size_t index = 0; index < ordered.size(); ++index) {
    const Baseline& left = *ordered[index];
    if (left.state != BaselineState::Published || !left.generation.is_set()) {
      continue;
    }
    for (std::size_t other = index + 1; other < ordered.size(); ++other) {
      const Baseline& right = *ordered[other];
      if (right.state != BaselineState::Published || !right.generation.is_set()) {
        continue;
      }
      if (!(right.generation == left.generation)) {
        continue;
      }
      if (selectors_share_hardware_class(left.selectors, right.selectors)) {
        diagnostics.add(ErrorCode::PolicySelfContradiction,
                        "published baselines \"" + left.id.to_string() + "\" and \"" +
                            right.id.to_string() + "\" share hardware class and generation " +
                            describe_generation(left.generation),
                        json::join_index(path, other));
      }
    }
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value BaselineRegistry::to_json() const {
  json::Value out = json::Value::make_array();
  for (const auto& entry : items_) {
    out.push_back(entry.second.to_json());
  }
  return out;
}

Result<BaselineRegistry> BaselineRegistry::from_json(const json::Value& value,
                                                     std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_array()) {
    return Error{ErrorCode::SchemaWrongType,
                 "baseline registry expected array but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }
  BaselineRegistry registry;
  const json::Value::Array& elements = value.as_array();
  for (std::size_t index = 0; index < elements.size(); ++index) {
    const std::string element_path = json::join_index(path, index);
    Result<Baseline> parsed = Baseline::from_json(elements[index], element_path);
    if (!parsed.has_value()) {
      diagnostics.add(parsed.error());
      continue;
    }
    Status status = registry.put(parsed.take());
    if (!status.has_value()) {
      diagnostics.add(Error{status.error().code(), status.error().message(), element_path});
    }
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  Status status = registry.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return registry;
}

}  // namespace summon::fbm
