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
#include <utility>
#include <vector>

#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {

// What was actually established about an asset's hardware, with the provenance
// and time that make it evidence rather than authority.
struct HardwareObservation {
  ObservationId id;
  EvidenceId evidence;
  AssetId asset;
  HardwareProfile hardware;
  HardwareGeneration hardware_generation;
  ObservationSequence sequence;
  Timestamp observed_at;
  IncarnationId reporter;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<HardwareObservation> from_json(const json::Value& value, std::string_view path);
};

// What was actually established about one firmware component's version.
struct FirmwareObservation {
  ObservationId id;
  EvidenceId evidence;
  AssetId asset;
  FirmwareComponentId component;
  // Empty when the component was observed but its version was not determined.
  // An unknown version is never read as a version, and in particular never as
  // the approved version.
  std::optional<FirmwareVersion> version;
  FirmwareGeneration firmware_generation;
  ObservationSequence sequence;
  Timestamp observed_at;
  IncarnationId reporter;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<FirmwareObservation> from_json(const json::Value& value, std::string_view path);
};

enum class ObservationOutcome : std::uint8_t {
  Recorded = 0,
  // An exactly identical observation arrived again with the same sequence. This
  // is the lost-response replay case and is accepted before stale rejection is
  // considered, because retrying a request whose response was lost must not
  // look like a stale request.
  IdempotentReplay = 1,
};

std::string_view observation_outcome_token(ObservationOutcome outcome) noexcept;

// Durable evidence store. Every collection is ordered, so recovery and
// serialization are deterministic.
class ObservationLog {
 public:
  ObservationLog() = default;

  // Records hardware evidence for an asset.
  //   sequence lower than the stored sequence        -> EvidenceOutOfOrder
  //   equal sequence, identical content              -> IdempotentReplay
  //   equal sequence, different content              -> EvidenceConflicting
  //   greater sequence                               -> Recorded
  Result<ObservationOutcome> record(HardwareObservation observation);

  // Records firmware evidence for one component of one asset, with the same
  // ordering rules.
  Result<ObservationOutcome> record(FirmwareObservation observation);

  const HardwareObservation* profile(const AssetId& asset) const;
  const FirmwareObservation* component(const AssetId& asset,
                                       const FirmwareComponentId& component) const;

  // Every recorded component observation for an asset, in ascending component
  // identity order.
  std::vector<const FirmwareObservation*> components_of(const AssetId& asset) const;

  // Component evidence for an asset in the shape the compatibility evaluator
  // consumes. A component observed with an undetermined version appears with an
  // empty optional.
  ComponentEvidenceMap evidence_for(const AssetId& asset) const;

  std::vector<AssetId> assets() const;
  std::size_t profile_count() const noexcept { return profiles_.size(); }
  std::size_t component_count() const noexcept { return components_.size(); }

  const std::map<AssetId, HardwareObservation>& profiles() const noexcept { return profiles_; }
  const std::map<std::pair<AssetId, FirmwareComponentId>, FirmwareObservation>& components()
      const noexcept {
    return components_;
  }

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<ObservationLog> from_json(const json::Value& value, std::string_view path);

 private:
  std::map<AssetId, HardwareObservation> profiles_;
  std::map<std::pair<AssetId, FirmwareComponentId>, FirmwareObservation> components_;
};

}  // namespace summon::fbm
