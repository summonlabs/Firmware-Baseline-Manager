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
#include "summon/fbm/observation.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/timestamp.hpp"

namespace {

namespace json = summon::fbm::json;

using summon::fbm::AssetId;
using summon::fbm::CapabilityId;
using summon::fbm::ComponentEvidenceMap;
using summon::fbm::Diagnostics;
using summon::fbm::ErrorCode;
using summon::fbm::EvidenceId;
using summon::fbm::FirmwareComponentId;
using summon::fbm::FirmwareGeneration;
using summon::fbm::FirmwareObservation;
using summon::fbm::FirmwareVersion;
using summon::fbm::HardwareClassId;
using summon::fbm::HardwareGeneration;
using summon::fbm::HardwareModelId;
using summon::fbm::HardwareObservation;
using summon::fbm::HardwareProfile;
using summon::fbm::HardwareRevision;
using summon::fbm::IncarnationId;
using summon::fbm::ObservationId;
using summon::fbm::ObservationLog;
using summon::fbm::ObservationOutcome;
using summon::fbm::ObservationSequence;
using summon::fbm::observation_outcome_token;
using summon::fbm::Result;
using summon::fbm::Status;
using summon::fbm::Timestamp;

// Every test uses a fixed instant; nothing here reads a clock.
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

HardwareObservation hardware_of(std::string_view id, std::string_view asset, std::string_view evidence,
                                std::uint64_t sequence, std::uint64_t generation) {
  HardwareObservation observation;
  observation.id = ObservationId{std::string{id}};
  observation.evidence = EvidenceId{std::string{evidence}};
  observation.asset = AssetId{std::string{asset}};
  observation.hardware = profile_of("h100");
  observation.hardware_generation = HardwareGeneration{generation};
  observation.sequence = ObservationSequence{sequence};
  observation.observed_at = instant(sequence);
  observation.reporter = IncarnationId{3u};
  return observation;
}

FirmwareObservation firmware_of(std::string_view id, std::string_view asset,
                                std::string_view component, std::string_view evidence,
                                std::uint64_t sequence, std::optional<std::string_view> version,
                                std::uint64_t generation) {
  FirmwareObservation observation;
  observation.id = ObservationId{std::string{id}};
  observation.evidence = EvidenceId{std::string{evidence}};
  observation.asset = AssetId{std::string{asset}};
  observation.component = FirmwareComponentId{std::string{component}};
  if (version.has_value()) {
    Result<FirmwareVersion> parsed = FirmwareVersion::parse(*version, {});
    REQUIRE(parsed.has_value());
    observation.version = parsed.take();
  }
  observation.firmware_generation = FirmwareGeneration{generation};
  observation.sequence = ObservationSequence{sequence};
  observation.observed_at = instant(sequence);
  observation.reporter = IncarnationId{3u};
  return observation;
}

std::string canonical_of(const json::Value& value) { return json::write_canonical(value); }

json::Value reparsed(const json::Value& value) {
  Result<json::Value> parsed = json::parse(json::write_canonical(value));
  REQUIRE(parsed.has_value());
  return parsed.take();
}

json::Value log_document(json::Value::Array profiles, json::Value::Array components) {
  json::Value document = json::Value::make_object();
  document.set("profiles", json::Value{std::move(profiles)});
  document.set("components", json::Value{std::move(components)});
  return document;
}

}  // namespace

FBM_TEST(observation_outcome_tokens_are_stable) {
  CHECK_EQ(observation_outcome_token(ObservationOutcome::Recorded), std::string_view{"recorded"});
  CHECK_EQ(observation_outcome_token(ObservationOutcome::IdempotentReplay),
           std::string_view{"idempotent_replay"});
}

FBM_TEST(hardware_evidence_ordering_outcomes) {
  const AssetId node01{std::string{"node-01"}};
  ObservationLog log;
  CHECK_EQ(log.profile_count(), std::size_t{0});
  CHECK(log.profile(node01) == nullptr);

  // First evidence for an asset is recorded.
  Result<ObservationOutcome> first = log.record(hardware_of("obs-1", "node-01", "ev-1", 5u, 1u));
  CHECK_OK(first);
  CHECK_EQ(first.value(), ObservationOutcome::Recorded);
  REQUIRE(log.profile(node01) != nullptr);
  CHECK_EQ(log.profile(node01)->evidence.value(), std::string{"ev-1"});
  CHECK_EQ(log.profile(node01)->sequence.value(), std::uint64_t{5});
  CHECK_EQ(log.profile_count(), std::size_t{1});

  const std::string stored_first = canonical_of(log.profile(node01)->to_json());

  // An equal sequence with different content is a conflict and never overwrites.
  Result<ObservationOutcome> conflicting =
      log.record(hardware_of("obs-2", "node-01", "ev-2", 5u, 1u));
  CHECK_ERROR(conflicting, ErrorCode::EvidenceConflicting);
  CHECK_EQ(canonical_of(log.profile(node01)->to_json()), stored_first);

  // A lower sequence is out of order and never replaces newer evidence.
  Result<ObservationOutcome> stale = log.record(hardware_of("obs-3", "node-01", "ev-3", 4u, 1u));
  CHECK_ERROR(stale, ErrorCode::EvidenceOutOfOrder);
  CHECK_EQ(canonical_of(log.profile(node01)->to_json()), stored_first);

  // A retried submission whose response was lost carries the same sequence and
  // byte-identical evidence; it is accepted and the stored record is untouched.
  HardwareObservation replay = hardware_of("obs-retry", "node-01", "ev-1", 5u, 1u);
  CHECK_EQ(canonical_of(replay.to_json()) == stored_first, false);  // the identity differs
  Result<ObservationOutcome> replayed = log.record(replay);
  CHECK_OK(replayed);
  CHECK_EQ(replayed.value(), ObservationOutcome::IdempotentReplay);
  CHECK_EQ(canonical_of(log.profile(node01)->to_json()), stored_first);
  CHECK_EQ(log.profile_count(), std::size_t{1});

  // Any difference at an equal sequence is a conflict: here the reporter.
  HardwareObservation other_reporter = replay;
  other_reporter.reporter = IncarnationId{9u};
  CHECK_ERROR(log.record(other_reporter), ErrorCode::EvidenceConflicting);

  // A strictly greater sequence replaces the record.
  Result<ObservationOutcome> newer = log.record(hardware_of("obs-4", "node-01", "ev-4", 6u, 2u));
  CHECK_OK(newer);
  CHECK_EQ(newer.value(), ObservationOutcome::Recorded);
  CHECK_EQ(log.profile(node01)->evidence.value(), std::string{"ev-4"});
  CHECK_EQ(log.profile(node01)->sequence.value(), std::uint64_t{6});
  CHECK_EQ(log.profile_count(), std::size_t{1});

  // The stale sequence is still rejected after the newer record was stored.
  CHECK_ERROR(log.record(hardware_of("obs-5", "node-01", "ev-1", 5u, 1u)),
              ErrorCode::EvidenceOutOfOrder);
  CHECK_EQ(log.profile(node01)->sequence.value(), std::uint64_t{6});

  // A record for a different asset is independent of the first.
  CHECK_OK(log.record(hardware_of("obs-6", "node-02", "ev-6", 1u, 1u)));
  CHECK_EQ(log.profile_count(), std::size_t{2});
}

FBM_TEST(firmware_evidence_ordering_per_component) {
  const AssetId node01{std::string{"node-01"}};
  const FirmwareComponentId bmc{std::string{"bmc"}};
  const FirmwareComponentId bios{std::string{"bios"}};

  ObservationLog log;
  // Inserted out of component order on purpose: storage order must not follow
  // insertion order.
  CHECK_OK(log.record(firmware_of("obs-bios", "node-01", "bios", "ev-bios", 2u,
                                  std::string_view{"3.1.0"}, 1u)));
  CHECK_OK(log.record(firmware_of("obs-bmc", "node-01", "bmc", "ev-bmc", 5u,
                                  std::string_view{"2.4.0"}, 1u)));
  CHECK_EQ(log.component_count(), std::size_t{2});

  REQUIRE(log.component(node01, bmc) != nullptr);
  REQUIRE(log.component(node01, bios) != nullptr);
  CHECK_EQ(log.component(node01, bmc)->version->to_string(), std::string{"2.4.0"});

  const std::string stored_bmc = canonical_of(log.component(node01, bmc)->to_json());

  // The ordering rules apply per (asset, component).
  CHECK_ERROR(log.record(firmware_of("obs-x", "node-01", "bmc", "ev-other", 5u,
                                     std::string_view{"2.4.1"}, 1u)),
              ErrorCode::EvidenceConflicting);
  CHECK_EQ(canonical_of(log.component(node01, bmc)->to_json()), stored_bmc);
  CHECK_ERROR(log.record(firmware_of("obs-y", "node-01", "bmc", "ev-bmc", 4u, std::nullopt, 1u)),
              ErrorCode::EvidenceOutOfOrder);
  CHECK_EQ(canonical_of(log.component(node01, bmc)->to_json()), stored_bmc);

  // An equal sequence with an identical undetermined version is a replay.
  CHECK_OK(log.record(firmware_of("obs-no-version", "node-02", "bmc", "ev-n2", 7u, std::nullopt, 3u)));
  const std::string stored_unknown = canonical_of(log.component(AssetId{std::string{"node-02"}}, bmc)->to_json());
  Result<ObservationOutcome> replayed =
      log.record(firmware_of("obs-no-version-retry", "node-02", "bmc", "ev-n2", 7u, std::nullopt, 3u));
  CHECK_OK(replayed);
  CHECK_EQ(replayed.value(), ObservationOutcome::IdempotentReplay);
  CHECK_EQ(canonical_of(log.component(AssetId{std::string{"node-02"}}, bmc)->to_json()),
           stored_unknown);

  // Presence of a version is part of the content: determined at the same
  // sequence as an undetermined observation is a conflict.
  CHECK_ERROR(log.record(firmware_of("obs-v", "node-02", "bmc", "ev-n2", 7u,
                                     std::string_view{"2.4.0"}, 3u)),
              ErrorCode::EvidenceConflicting);
  CHECK_EQ(log.component(AssetId{std::string{"node-02"}}, bmc)->version.has_value(), false);

  // A greater sequence replaces the record, including the version.
  CHECK_OK(log.record(firmware_of("obs-z", "node-02", "bmc", "ev-n3", 8u,
                                  std::string_view{"2.4.2"}, 4u)));
  REQUIRE(log.component(AssetId{std::string{"node-02"}}, bmc) != nullptr);
  CHECK_EQ(log.component(AssetId{std::string{"node-02"}}, bmc)->version->to_string(),
           std::string{"2.4.2"});

  // A component of the same asset is ordered independently of the other one:
  // a greater sequence for bios replaces bios while bmc keeps its own record.
  CHECK_OK(log.record(firmware_of("obs-bios-2", "node-01", "bios", "ev-bios2", 3u,
                                  std::string_view{"3.0.9"}, 1u)));
  CHECK_EQ(log.component(node01, bios)->sequence.value(), std::uint64_t{3});
  CHECK_EQ(log.component(node01, bmc)->sequence.value(), std::uint64_t{5});
}

FBM_TEST(observation_log_lookup_and_evidence_map) {
  const AssetId node01{std::string{"node-01"}};
  const AssetId node02{std::string{"node-02"}};
  const FirmwareComponentId bmc{std::string{"bmc"}};
  const FirmwareComponentId bios{std::string{"bios"}};
  const FirmwareComponentId cpld{std::string{"cpld"}};

  ObservationLog log;
  CHECK_OK(log.record(firmware_of("obs-1", "node-01", "bios", "ev-1", 2u,
                                  std::string_view{"3.1.0"}, 1u)));
  CHECK_OK(log.record(firmware_of("obs-2", "node-01", "bmc", "ev-2", 3u, std::nullopt, 1u)));
  CHECK_OK(log.record(firmware_of("obs-3", "node-01", "cpld", "ev-3", 4u,
                                  std::string_view{"9.9.9"}, 1u)));
  CHECK_OK(log.record(firmware_of("obs-4", "node-02", "bmc", "ev-4", 5u,
                                  std::string_view{"2.0.0"}, 1u)));
  CHECK_OK(log.record(hardware_of("obs-5", "node-01", "ev-5", 6u, 1u)));

  // components_of returns pointers into the stored records in ascending
  // component identity order, whatever order they were recorded in.
  const std::vector<const FirmwareObservation*> components = log.components_of(node01);
  REQUIRE(components.size() == 3u);
  CHECK_EQ(components[0]->component.value(), std::string{"bios"});
  CHECK_EQ(components[1]->component.value(), std::string{"bmc"});
  CHECK_EQ(components[2]->component.value(), std::string{"cpld"});
  CHECK(components[1] == log.component(node01, bmc));
  CHECK_EQ(log.components_of(node02).size(), std::size_t{1});

  // An undetermined version is an empty optional in the evidence map, not an
  // absent component and never a version.
  const ComponentEvidenceMap evidence = log.evidence_for(node01);
  CHECK_EQ(evidence.size(), std::size_t{3});
  REQUIRE(evidence.find(bmc) != evidence.end());
  CHECK_EQ(evidence.at(bmc).has_value(), false);
  REQUIRE(evidence.find(bios) != evidence.end());
  CHECK_EQ(evidence.at(bios)->to_string(), std::string{"3.1.0"});
  CHECK(evidence.find(cpld) != evidence.end());
  CHECK(evidence.find(FirmwareComponentId{std::string{"nic"}}) == evidence.end());

  const ComponentEvidenceMap empty = log.evidence_for(AssetId{std::string{"node-99"}});
  CHECK(empty.empty());

  // assets() is the union of assets with hardware evidence and assets with
  // component evidence, ascending and unique.
  const std::vector<AssetId> assets = log.assets();
  REQUIRE(assets.size() == 2u);
  CHECK_EQ(assets[0].value(), std::string{"node-01"});
  CHECK_EQ(assets[1].value(), std::string{"node-02"});

  ObservationLog component_only;
  CHECK_OK(component_only.record(firmware_of("obs-6", "node-07", "bmc", "ev-7", 1u, std::nullopt, 1u)));
  const std::vector<AssetId> only = component_only.assets();
  REQUIRE(only.size() == 1u);
  CHECK_EQ(only[0].value(), std::string{"node-07"});
}

FBM_TEST(observation_log_json_round_trip) {
  ObservationLog log;
  CHECK_OK(log.record(firmware_of("obs-4", "node-02", "bmc", "ev-4", 5u,
                                  std::string_view{"2.0.0"}, 1u)));
  CHECK_OK(log.record(hardware_of("obs-1", "node-01", "ev-1", 5u, 1u)));
  CHECK_OK(log.record(hardware_of("obs-2", "node-02", "ev-2", 6u, 2u)));
  CHECK_OK(log.record(firmware_of("obs-3", "node-01", "bmc", "ev-3", 3u, std::nullopt, 1u)));
  CHECK_OK(log.record(firmware_of("obs-5", "node-01", "bios", "ev-5", 4u,
                                  std::string_view{"3.1.0"}, 1u)));

  const json::Value encoded = log.to_json();
  const std::string canonical = canonical_of(encoded);

  // The arrays are ascending by identity in the encoded document.
  const json::Value* profiles = encoded.find("profiles");
  REQUIRE(profiles != nullptr);
  REQUIRE(profiles->is_array());
  REQUIRE(profiles->as_array().size() == 2u);
  CHECK_EQ(profiles->as_array()[0].find("asset")->as_string(), std::string{"node-01"});
  CHECK_EQ(profiles->as_array()[1].find("asset")->as_string(), std::string{"node-02"});

  const json::Value* components = encoded.find("components");
  REQUIRE(components != nullptr);
  REQUIRE(components->as_array().size() == 3u);
  CHECK_EQ(components->as_array()[0].find("asset")->as_string(), std::string{"node-01"});
  CHECK_EQ(components->as_array()[0].find("component")->as_string(), std::string{"bios"});
  CHECK_EQ(components->as_array()[1].find("component")->as_string(), std::string{"bmc"});
  CHECK_EQ(components->as_array()[2].find("asset")->as_string(), std::string{"node-02"});

  // The undetermined version is omitted, never written as an empty string and
  // never fabricated from another component's version.
  REQUIRE(components->as_array()[0].find("version") != nullptr);
  CHECK_EQ(components->as_array()[0].find("version")->as_string(), std::string{"3.1.0"});
  CHECK(components->as_array()[1].find("version") == nullptr);

  Result<ObservationLog> restored = ObservationLog::from_json(reparsed(encoded), {});
  CHECK_OK(restored);
  CHECK_EQ(canonical_of(restored.value().to_json()), canonical);
  CHECK_EQ(restored.value().profile_count(), std::size_t{2});
  CHECK_EQ(restored.value().component_count(), std::size_t{3});

  const AssetId node01{std::string{"node-01"}};
  REQUIRE(restored.value().profile(node01) != nullptr);
  CHECK_EQ(restored.value().profile(node01)->evidence.value(), std::string{"ev-1"});
  CHECK_EQ(restored.value().profile(node01)->sequence.value(), std::uint64_t{5});
  CHECK_EQ(restored.value().profile(node01)->observed_at, instant(5u));
  CHECK_EQ(restored.value().profile(node01)->reporter.value(), std::uint64_t{3});
  REQUIRE(restored.value().component(node01, FirmwareComponentId{std::string{"bmc"}}) != nullptr);
  CHECK_EQ(restored.value().component(node01, FirmwareComponentId{std::string{"bmc"}})
               ->version.has_value(),
           false);

  // The canonical writer is stable across a second round trip.
  CHECK_EQ(canonical_of(restored.value().to_json()), canonical);
}

FBM_TEST(observation_from_json_rejects_malformed_documents) {
  HardwareObservation observation = hardware_of("obs-1", "node-01", "ev-1", 5u, 1u);
  const json::Value well_formed = observation.to_json();
  CHECK_OK(HardwareObservation::from_json(reparsed(well_formed), {}));

  json::Value unknown = well_formed;
  unknown.set("unexpected", json::Value{1});
  CHECK_ERROR(HardwareObservation::from_json(reparsed(unknown), {}), ErrorCode::SchemaUnknownField);

  json::Value missing = well_formed;
  CHECK(missing.erase("sequence"));
  CHECK_ERROR(HardwareObservation::from_json(reparsed(missing), {}), ErrorCode::SchemaMissingField);

  json::Value missing_reporter = well_formed;
  CHECK(missing_reporter.erase("reporter"));
  CHECK_ERROR(HardwareObservation::from_json(reparsed(missing_reporter), {}),
              ErrorCode::SchemaMissingField);

  json::Value wrong_type = well_formed;
  wrong_type.set("sequence", json::Value{std::string{"five"}});
  CHECK_ERROR(HardwareObservation::from_json(reparsed(wrong_type), {}), ErrorCode::SchemaWrongType);

  json::Value negative = well_formed;
  negative.set("sequence", json::Value{std::int64_t{-1}});
  CHECK_ERROR(HardwareObservation::from_json(reparsed(negative), {}),
              ErrorCode::SchemaValueOutOfRange);

  json::Value bad_asset = well_formed;
  bad_asset.set("asset", json::Value{std::string{"-node"}});
  CHECK_ERROR(HardwareObservation::from_json(reparsed(bad_asset), {}),
              ErrorCode::SchemaInvalidIdentifier);

  json::Value bad_time = well_formed;
  bad_time.set("observed_at", json::Value{std::string{"2023-11-14 22:13:20"}});
  CHECK_ERROR(HardwareObservation::from_json(reparsed(bad_time), {}),
              ErrorCode::SchemaInvalidTimestampText);

  json::Value no_hardware = well_formed;
  CHECK(no_hardware.erase("hardware"));
  CHECK_ERROR(HardwareObservation::from_json(reparsed(no_hardware), {}),
              ErrorCode::SchemaMissingField);

  // A firmware observation whose component was observed but whose version was
  // not determined is complete and valid.
  FirmwareObservation firmware = firmware_of("obs-2", "node-01", "bmc", "ev-2", 6u, std::nullopt, 1u);
  const json::Value firmware_json = firmware.to_json();
  CHECK(firmware_json.find("version") == nullptr);
  Result<FirmwareObservation> firmware_back = FirmwareObservation::from_json(reparsed(firmware_json), {});
  CHECK_OK(firmware_back);
  CHECK_EQ(firmware_back.value().version.has_value(), false);

  json::Value bad_version = firmware_json;
  bad_version.set("version", json::Value{std::string{"not a version"}});
  CHECK_ERROR(FirmwareObservation::from_json(reparsed(bad_version), {}),
              ErrorCode::SchemaInvalidVersionText);

  json::Value bad_component = firmware_json;
  bad_component.set("component", json::Value{std::string{"bmc:0"}});
  CHECK_ERROR(FirmwareObservation::from_json(reparsed(bad_component), {}),
              ErrorCode::SchemaInvalidIdentifier);
}

FBM_TEST(observation_log_from_json_rejects_unsorted_or_duplicate_entries) {
  const json::Value node01 = hardware_of("obs-1", "node-01", "ev-1", 5u, 1u).to_json();
  const json::Value node02 = hardware_of("obs-2", "node-02", "ev-2", 6u, 1u).to_json();
  const json::Value bmc = firmware_of("obs-3", "node-01", "bmc", "ev-3", 3u,
                                      std::string_view{"2.4.0"}, 1u)
                              .to_json();
  const json::Value bios = firmware_of("obs-4", "node-01", "bios", "ev-4", 4u,
                                       std::string_view{"3.1.0"}, 1u)
                               .to_json();

  // Ascending component order is byte order: "bios" precedes "bmc".
  CHECK_OK(ObservationLog::from_json(log_document({node01, node02}, {bios, bmc}), {}));

  // Duplicate asset identity.
  CHECK_ERROR(ObservationLog::from_json(log_document({node01, node01}, {}), {}),
              ErrorCode::SchemaDuplicateIdentifier);
  // Unsorted profiles.
  CHECK_ERROR(ObservationLog::from_json(log_document({node02, node01}, {}), {}),
              ErrorCode::SchemaInconsistentDocument);
  // Duplicate (asset, component) pair.
  CHECK_ERROR(ObservationLog::from_json(log_document({}, {bmc, bmc}), {}),
              ErrorCode::SchemaDuplicateIdentifier);
  // Unsorted components.
  CHECK_ERROR(ObservationLog::from_json(log_document({}, {bmc, bios}), {}),
              ErrorCode::SchemaInconsistentDocument);
  // A component before another asset's component is out of order too.
  const json::Value bmc_node02 = firmware_of("obs-5", "node-02", "bmc", "ev-5", 5u,
                                             std::string_view{"2.0.0"}, 1u)
                                     .to_json();
  CHECK_ERROR(ObservationLog::from_json(log_document({}, {bmc_node02, bios}), {}),
              ErrorCode::SchemaInconsistentDocument);

  // Structural defects.
  json::Value missing = log_document({}, {});
  CHECK(missing.erase("components"));
  CHECK_ERROR(ObservationLog::from_json(missing, {}), ErrorCode::SchemaMissingField);

  json::Value wrong_type = log_document({}, {});
  wrong_type.set("profiles", json::Value{std::string{"not an array"}});
  CHECK_ERROR(ObservationLog::from_json(wrong_type, {}), ErrorCode::SchemaWrongType);

  json::Value not_object = json::Value::make_array();
  CHECK_ERROR(ObservationLog::from_json(not_object, {}), ErrorCode::SchemaWrongType);

  json::Value unknown = log_document({}, {});
  unknown.set("extra", json::Value{true});
  CHECK_ERROR(ObservationLog::from_json(unknown, {}), ErrorCode::SchemaUnknownField);

  // A record that cannot be read makes the whole document invalid.
  json::Value bad_record = node01;
  bad_record.set("sequence", json::Value{std::int64_t{-3}});
  CHECK_ERROR(ObservationLog::from_json(log_document({bad_record}, {}), {}),
              ErrorCode::SchemaValueOutOfRange);

  // An empty log is a valid document: no evidence is not an error.
  Result<ObservationLog> empty = ObservationLog::from_json(log_document({}, {}), {});
  CHECK_OK(empty);
  CHECK_EQ(empty.value().profile_count(), std::size_t{0});
  CHECK_EQ(empty.value().component_count(), std::size_t{0});
  CHECK(empty.value().assets().empty());
}

FBM_TEST(observation_record_rejects_incomplete_observations) {
  ObservationLog log;

  HardwareObservation no_sequence = hardware_of("obs-1", "node-01", "ev-1", 5u, 1u);
  no_sequence.sequence = ObservationSequence{};
  CHECK_ERROR(log.record(no_sequence), ErrorCode::SchemaMissingField);
  CHECK_EQ(log.profile_count(), std::size_t{0});

  HardwareObservation no_asset = hardware_of("obs-2", "node-01", "ev-2", 5u, 1u);
  no_asset.asset = AssetId{};
  CHECK_ERROR(log.record(no_asset), ErrorCode::SchemaMissingField);
  CHECK_EQ(log.profile_count(), std::size_t{0});

  HardwareObservation bad_asset = hardware_of("obs-3", "node-01", "ev-3", 5u, 1u);
  bad_asset.asset = AssetId{std::string{"node 01"}};
  CHECK_ERROR(log.record(bad_asset), ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(log.profile_count(), std::size_t{0});

  HardwareObservation no_time = hardware_of("obs-4", "node-01", "ev-4", 5u, 1u);
  no_time.observed_at = Timestamp{};
  CHECK_ERROR(log.record(no_time), ErrorCode::SchemaMissingField);
  CHECK_EQ(log.profile_count(), std::size_t{0});

  // The log itself validates every stored record.
  Diagnostics diagnostics;
  ObservationLog empty;
  CHECK_OK(empty.validate("/observations", diagnostics));
  CHECK(diagnostics.empty());

  CHECK_OK(log.record(hardware_of("obs-5", "node-01", "ev-5", 5u, 1u)));
  Diagnostics valid_diagnostics;
  CHECK_OK(log.validate("/observations", valid_diagnostics));
  CHECK(valid_diagnostics.empty());
}
