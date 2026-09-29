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

#include "summon/fbm/observation.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {
namespace {

// Publishes the defects collected in a nested diagnostics set and returns the
// most primary of them. A nested validate() therefore reports exactly its own
// defects and never a defect that belongs to its caller.
Status publish(Diagnostics& local, Diagnostics& diagnostics) {
  if (local.empty()) {
    return ok_status();
  }
  for (const Error& error : local.errors()) {
    diagnostics.add(error);
  }
  return Status{local.primary()};
}

// --- field readers ----------------------------------------------------------
//
// Every reader diagnoses the exact defect itself: a missing field, a wrong JSON
// type, an invalid identifier, an unparsable timestamp, or an integer that
// cannot be represented as a non-negative counter. A field that could not be
// read is left unset, which is what the validator then reports; it is never
// replaced by zero or by an empty identity.

template <class ScalarT>
bool read_scalar(json::ObjectReader& reader, std::string_view key, ScalarT& out,
                 Diagnostics& diagnostics) {
  const json::Value* value = reader.required(key, json::Type::Integer);
  if (value == nullptr) {
    return false;
  }
  const std::int64_t raw = value->as_integer();
  using ValueType = typename ScalarT::value_type;
  constexpr ValueType kMaximum = std::numeric_limits<ValueType>::max();
  if (raw < 0 || static_cast<std::uint64_t>(raw) > static_cast<std::uint64_t>(kMaximum)) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    std::string{key} + " must be a non-negative integer no greater than " +
                        std::to_string(kMaximum),
                    reader.child_path(key));
    return false;
  }
  out = ScalarT{static_cast<ValueType>(raw)};
  return true;
}

template <class ScalarT>
bool read_optional_scalar(json::ObjectReader& reader, std::string_view key, ScalarT& out,
                          Diagnostics& diagnostics) {
  if (!reader.has(key)) {
    // Absence is a real fact: the counter stays unset rather than becoming zero.
    return false;
  }
  const json::Value* value = reader.optional(key, json::Type::Integer);
  if (value == nullptr) {
    return false;  // wrong JSON type, already diagnosed by the reader
  }
  const std::int64_t raw = value->as_integer();
  using ValueType = typename ScalarT::value_type;
  constexpr ValueType kMaximum = std::numeric_limits<ValueType>::max();
  if (raw < 0 || static_cast<std::uint64_t>(raw) > static_cast<std::uint64_t>(kMaximum)) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    std::string{key} + " must be a non-negative integer no greater than " +
                        std::to_string(kMaximum),
                    reader.child_path(key));
    return false;
  }
  out = ScalarT{static_cast<ValueType>(raw)};
  return true;
}

template <class Id>
bool read_identifier(json::ObjectReader& reader, std::string_view key, Id& out,
                     Diagnostics& diagnostics) {
  const json::Value* value = reader.required(key, json::Type::String);
  if (value == nullptr) {
    return false;
  }
  const std::string& text = value->as_string();
  const std::string path = reader.child_path(key);
  const Status status = validate_identifier(text, path);
  if (!status.has_value()) {
    diagnostics.add(status.error());
    return false;
  }
  out = Id{text};
  return true;
}

bool read_timestamp(json::ObjectReader& reader, std::string_view key, Timestamp& out,
                    Diagnostics& diagnostics) {
  const json::Value* value = reader.required(key, json::Type::String);
  if (value == nullptr) {
    return false;
  }
  Result<Timestamp> parsed = Timestamp::parse_rfc3339(value->as_string(), reader.child_path(key));
  if (!parsed.has_value()) {
    diagnostics.add(parsed.error());
    return false;
  }
  out = parsed.take();
  return true;
}

bool read_optional_timestamp(json::ObjectReader& reader, std::string_view key, Timestamp& out,
                             Diagnostics& diagnostics) {
  const json::Value* value = reader.optional(key, json::Type::String);
  if (value == nullptr) {
    return false;
  }
  Result<Timestamp> parsed = Timestamp::parse_rfc3339(value->as_string(), reader.child_path(key));
  if (!parsed.has_value()) {
    diagnostics.add(parsed.error());
    return false;
  }
  out = parsed.take();
  return true;
}

// --- validators -------------------------------------------------------------

template <class Id>
void validate_identity(const Id& id, std::string_view path, std::string_view name,
                       Diagnostics& diagnostics) {
  if (!id.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, std::string{name} + " is required",
                    std::string{path});
    return;
  }
  const Status status = validate_identifier(id.view(), path);
  if (!status.has_value()) {
    diagnostics.add(status.error());
  }
}

template <class ScalarT>
void validate_scalar(const ScalarT& value, std::string_view path, std::string_view name,
                     Diagnostics& diagnostics) {
  if (!value.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, std::string{name} + " is required",
                    std::string{path});
  }
}

void validate_timestamp(const Timestamp& value, std::string_view path, std::string_view name,
                        Diagnostics& diagnostics) {
  if (!value.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, std::string{name} + " is required",
                    std::string{path});
  }
}

// --- content identity -------------------------------------------------------
//
// Idempotent replay is decided on the content of the evidence, not on the
// identity of the submission: a retried request may carry a fresh observation
// identity but must carry byte-identical evidence.

bool same_hardware_profile(const HardwareProfile& left, const HardwareProfile& right) {
  return left.hardware_class == right.hardware_class && left.model == right.model &&
         left.revision == right.revision &&
         left.capabilities_observed == right.capabilities_observed &&
         left.capabilities == right.capabilities;
}

bool same_evidence(const HardwareObservation& left, const HardwareObservation& right) {
  return same_hardware_profile(left.hardware, right.hardware) &&
         left.hardware_generation == right.hardware_generation &&
         left.observed_at == right.observed_at && left.evidence == right.evidence &&
         left.reporter == right.reporter;
}

bool same_evidence(const FirmwareObservation& left, const FirmwareObservation& right) {
  return left.version == right.version &&
         left.firmware_generation == right.firmware_generation &&
         left.observed_at == right.observed_at && left.evidence == right.evidence &&
         left.reporter == right.reporter;
}

std::string sequence_conflict_message(std::string_view kind, const std::string& asset,
                                      std::uint64_t sequence, std::uint64_t stored_sequence) {
  return std::string{kind} + " observation for asset \"" + asset + "\" has sequence " +
         std::to_string(sequence) + " which is lower than the stored sequence " +
         std::to_string(stored_sequence);
}

std::string sequence_conflicting_message(std::string_view kind, const std::string& asset,
                                         std::uint64_t sequence) {
  return std::string{kind} + " observation for asset \"" + asset + "\" has sequence " +
         std::to_string(sequence) +
         " but differs from the stored evidence at the same sequence";
}

}  // namespace

// --- HardwareObservation ----------------------------------------------------

Status HardwareObservation::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  validate_identity(id, json::join_path(path, "id"), "id", local);
  validate_identity(evidence, json::join_path(path, "evidence"), "evidence", local);
  validate_identity(asset, json::join_path(path, "asset"), "asset", local);
  hardware.validate(json::join_path(path, "hardware"), local);
  validate_scalar(hardware_generation, json::join_path(path, "hardware_generation"),
                  "hardware_generation", local);
  validate_scalar(sequence, json::join_path(path, "sequence"), "sequence", local);
  validate_timestamp(observed_at, json::join_path(path, "observed_at"), "observed_at", local);
  validate_scalar(reporter, json::join_path(path, "reporter"), "reporter", local);
  return publish(local, diagnostics);
}

json::Value HardwareObservation::to_json() const {
  json::Value::Object object;
  object.emplace_back("id", json::Value{id.value()});
  object.emplace_back("evidence", json::Value{evidence.value()});
  object.emplace_back("asset", json::Value{asset.value()});
  object.emplace_back("hardware", hardware.to_json());
  object.emplace_back("hardware_generation", json::Value{hardware_generation.value()});
  object.emplace_back("sequence", json::Value{sequence.value()});
  object.emplace_back("observed_at", json::Value{observed_at.to_rfc3339()});
  object.emplace_back("reporter", json::Value{reporter.value()});
  return json::Value{std::move(object)};
}

Result<HardwareObservation> HardwareObservation::from_json(const json::Value& value,
                                                           std::string_view path) {
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  HardwareObservation observation;
  read_identifier(reader, "id", observation.id, diagnostics);
  read_identifier(reader, "evidence", observation.evidence, diagnostics);
  read_identifier(reader, "asset", observation.asset, diagnostics);
  if (const json::Value* hardware_value = reader.required("hardware", json::Type::Object);
      hardware_value != nullptr) {
    Result<HardwareProfile> parsed =
        HardwareProfile::from_json(*hardware_value, reader.child_path("hardware"));
    if (parsed.has_value()) {
      observation.hardware = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  read_scalar(reader, "hardware_generation", observation.hardware_generation, diagnostics);
  read_scalar(reader, "sequence", observation.sequence, diagnostics);
  read_timestamp(reader, "observed_at", observation.observed_at, diagnostics);
  read_scalar(reader, "reporter", observation.reporter, diagnostics);
  reader.finish();
  if (diagnostics.empty()) {
    observation.validate(path, diagnostics);
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return observation;
}

// --- FirmwareObservation ----------------------------------------------------

Status FirmwareObservation::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  validate_identity(id, json::join_path(path, "id"), "id", local);
  validate_identity(evidence, json::join_path(path, "evidence"), "evidence", local);
  validate_identity(asset, json::join_path(path, "asset"), "asset", local);
  validate_identity(component, json::join_path(path, "component"), "component", local);
  // version is deliberately optional: an observed component whose version was
  // not determined is a complete, valid observation.
  validate_scalar(firmware_generation, json::join_path(path, "firmware_generation"),
                  "firmware_generation", local);
  validate_scalar(sequence, json::join_path(path, "sequence"), "sequence", local);
  validate_timestamp(observed_at, json::join_path(path, "observed_at"), "observed_at", local);
  validate_scalar(reporter, json::join_path(path, "reporter"), "reporter", local);
  return publish(local, diagnostics);
}

json::Value FirmwareObservation::to_json() const {
  json::Value::Object object;
  object.emplace_back("id", json::Value{id.value()});
  object.emplace_back("evidence", json::Value{evidence.value()});
  object.emplace_back("asset", json::Value{asset.value()});
  object.emplace_back("component", json::Value{component.value()});
  if (version.has_value()) {
    object.emplace_back("version", json::Value{version->to_string()});
  }
  object.emplace_back("firmware_generation", json::Value{firmware_generation.value()});
  object.emplace_back("sequence", json::Value{sequence.value()});
  object.emplace_back("observed_at", json::Value{observed_at.to_rfc3339()});
  object.emplace_back("reporter", json::Value{reporter.value()});
  return json::Value{std::move(object)};
}

Result<FirmwareObservation> FirmwareObservation::from_json(const json::Value& value,
                                                           std::string_view path) {
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  FirmwareObservation observation;
  read_identifier(reader, "id", observation.id, diagnostics);
  read_identifier(reader, "evidence", observation.evidence, diagnostics);
  read_identifier(reader, "asset", observation.asset, diagnostics);
  read_identifier(reader, "component", observation.component, diagnostics);
  // An absent version is meaningful: the component was observed but its version
  // was not determined. It is never read as the approved version or as zero.
  if (const json::Value* version_value = reader.optional("version", json::Type::String);
      version_value != nullptr) {
    Result<FirmwareVersion> parsed =
        FirmwareVersion::parse(version_value->as_string(), reader.child_path("version"));
    if (parsed.has_value()) {
      observation.version = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  read_scalar(reader, "firmware_generation", observation.firmware_generation, diagnostics);
  read_scalar(reader, "sequence", observation.sequence, diagnostics);
  read_timestamp(reader, "observed_at", observation.observed_at, diagnostics);
  read_scalar(reader, "reporter", observation.reporter, diagnostics);
  reader.finish();
  if (diagnostics.empty()) {
    observation.validate(path, diagnostics);
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return observation;
}

// --- ObservationOutcome -----------------------------------------------------

std::string_view observation_outcome_token(ObservationOutcome outcome) noexcept {
  switch (outcome) {
    case ObservationOutcome::Recorded:
      return "recorded";
    case ObservationOutcome::IdempotentReplay:
      return "idempotent_replay";
  }
  return "unknown_observation_outcome";
}

// --- ObservationLog ---------------------------------------------------------

Result<ObservationOutcome> ObservationLog::record(HardwareObservation observation) {
  // Only evidence that is complete and well formed may enter the durable store:
  // an unset sequence would otherwise order below every recorded sequence and
  // silently win or lose an ordering decision it cannot decide.
  Diagnostics diagnostics;
  if (!observation.validate({}, diagnostics).has_value()) {
    return diagnostics.primary();
  }

  const auto found = profiles_.find(observation.asset);
  if (found == profiles_.end()) {
    const AssetId key = observation.asset;
    profiles_.emplace(key, std::move(observation));
    return ObservationOutcome::Recorded;
  }

  const HardwareObservation& stored = found->second;
  if (observation.sequence < stored.sequence) {
    return Error{ErrorCode::EvidenceOutOfOrder,
                 sequence_conflict_message("hardware", observation.asset.to_string(),
                                           observation.sequence.value(), stored.sequence.value()),
                 json::join_path({}, "sequence")};
  }
  if (observation.sequence == stored.sequence) {
    // A retried request whose response was lost arrives with the same sequence
    // and byte-identical evidence. It is accepted and the stored record is left
    // exactly as it was.
    if (same_evidence(stored, observation)) {
      return ObservationOutcome::IdempotentReplay;
    }
    return Error{ErrorCode::EvidenceConflicting,
                 sequence_conflicting_message("hardware", observation.asset.to_string(),
                                              observation.sequence.value()),
                 json::join_path({}, "sequence")};
  }
  found->second = std::move(observation);
  return ObservationOutcome::Recorded;
}

Result<ObservationOutcome> ObservationLog::record(FirmwareObservation observation) {
  Diagnostics diagnostics;
  if (!observation.validate({}, diagnostics).has_value()) {
    return diagnostics.primary();
  }

  const std::pair<AssetId, FirmwareComponentId> key{observation.asset, observation.component};
  const auto found = components_.find(key);
  if (found == components_.end()) {
    components_.emplace(key, std::move(observation));
    return ObservationOutcome::Recorded;
  }

  const FirmwareObservation& stored = found->second;
  if (observation.sequence < stored.sequence) {
    return Error{ErrorCode::EvidenceOutOfOrder,
                 sequence_conflict_message("firmware", observation.asset.to_string(),
                                           observation.sequence.value(), stored.sequence.value()),
                 json::join_path({}, "sequence")};
  }
  if (observation.sequence == stored.sequence) {
    if (same_evidence(stored, observation)) {
      return ObservationOutcome::IdempotentReplay;
    }
    return Error{ErrorCode::EvidenceConflicting,
                 sequence_conflicting_message("firmware", observation.asset.to_string(),
                                              observation.sequence.value()),
                 json::join_path({}, "sequence")};
  }
  found->second = std::move(observation);
  return ObservationOutcome::Recorded;
}

const HardwareObservation* ObservationLog::profile(const AssetId& asset) const {
  const auto found = profiles_.find(asset);
  return found == profiles_.end() ? nullptr : &found->second;
}

const FirmwareObservation* ObservationLog::component(const AssetId& asset,
                                                     const FirmwareComponentId& component) const {
  const auto found = components_.find(std::make_pair(asset, component));
  return found == components_.end() ? nullptr : &found->second;
}

std::vector<const FirmwareObservation*> ObservationLog::components_of(
    const AssetId& asset) const {
  std::vector<const FirmwareObservation*> out;
  // components_ is ordered by (asset, component), so filtering preserves
  // ascending component identity order.
  for (const auto& entry : components_) {
    if (entry.first.first == asset) {
      out.push_back(&entry.second);
    }
  }
  return out;
}

ComponentEvidenceMap ObservationLog::evidence_for(const AssetId& asset) const {
  ComponentEvidenceMap evidence;
  for (const auto& entry : components_) {
    if (entry.first.first == asset) {
      // An undetermined version is inserted as an empty optional; it is never
      // dropped and never replaced by a version.
      evidence.emplace(entry.first.second, entry.second.version);
    }
  }
  return evidence;
}

std::vector<AssetId> ObservationLog::assets() const {
  std::vector<AssetId> out;
  out.reserve(profiles_.size() + components_.size());
  for (const auto& entry : profiles_) {
    out.push_back(entry.first);
  }
  for (const auto& entry : components_) {
    out.push_back(entry.first.first);
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

Status ObservationLog::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  const std::string profiles_path = json::join_path(path, "profiles");
  std::size_t index = 0;
  for (const auto& entry : profiles_) {
    entry.second.validate(json::join_index(profiles_path, index), local);
    ++index;
  }
  const std::string components_path = json::join_path(path, "components");
  index = 0;
  for (const auto& entry : components_) {
    entry.second.validate(json::join_index(components_path, index), local);
    ++index;
  }
  return publish(local, diagnostics);
}

json::Value ObservationLog::to_json() const {
  json::Value::Array profiles;
  profiles.reserve(profiles_.size());
  for (const auto& entry : profiles_) {
    profiles.push_back(entry.second.to_json());
  }
  json::Value::Array components;
  components.reserve(components_.size());
  for (const auto& entry : components_) {
    components.push_back(entry.second.to_json());
  }
  json::Value::Object object;
  object.emplace_back("profiles", json::Value{std::move(profiles)});
  object.emplace_back("components", json::Value{std::move(components)});
  return json::Value{std::move(object)};
}

Result<ObservationLog> ObservationLog::from_json(const json::Value& value,
                                                 std::string_view path) {
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  ObservationLog log;

  const std::string profiles_path = json::join_path(path, "profiles");
  if (const json::Value* profiles_value = reader.required("profiles", json::Type::Array);
      profiles_value != nullptr) {
    const json::Value::Array& elements = profiles_value->as_array();
    std::optional<AssetId> previous;
    for (std::size_t i = 0; i < elements.size(); ++i) {
      const std::string element_path = json::join_index(profiles_path, i);
      Result<HardwareObservation> parsed = HardwareObservation::from_json(elements[i], element_path);
      if (!parsed.has_value()) {
        diagnostics.add(parsed.error());
        continue;
      }
      HardwareObservation observation = parsed.take();
      if (previous.has_value()) {
        if (observation.asset == *previous) {
          diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                          "asset \"" + observation.asset.to_string() +
                              "\" appears more than once in profiles",
                          json::join_path(element_path, "asset"));
          continue;
        }
        if (observation.asset < *previous) {
          diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                          "profiles must be ascending by asset identity",
                          json::join_path(element_path, "asset"));
          continue;
        }
      }
      previous = observation.asset;
      const AssetId key = observation.asset;
      log.profiles_.emplace(key, std::move(observation));
    }
  }

  const std::string components_path = json::join_path(path, "components");
  if (const json::Value* components_value = reader.required("components", json::Type::Array);
      components_value != nullptr) {
    const json::Value::Array& elements = components_value->as_array();
    std::optional<std::pair<AssetId, FirmwareComponentId>> previous;
    for (std::size_t i = 0; i < elements.size(); ++i) {
      const std::string element_path = json::join_index(components_path, i);
      Result<FirmwareObservation> parsed = FirmwareObservation::from_json(elements[i], element_path);
      if (!parsed.has_value()) {
        diagnostics.add(parsed.error());
        continue;
      }
      FirmwareObservation observation = parsed.take();
      const std::pair<AssetId, FirmwareComponentId> key{observation.asset, observation.component};
      if (previous.has_value()) {
        if (key == *previous) {
          diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                          "component \"" + observation.component.to_string() +
                              "\" appears more than once for asset \"" +
                              observation.asset.to_string() + "\"",
                          json::join_path(element_path, "component"));
          continue;
        }
        if (key < *previous) {
          diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                          "components must be ascending by asset identity then component identity",
                          json::join_path(element_path, "component"));
          continue;
        }
      }
      previous = key;
      log.components_.emplace(key, std::move(observation));
    }
  }

  reader.finish();
  if (diagnostics.empty()) {
    log.validate(path, diagnostics);
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return log;
}

}  // namespace summon::fbm
