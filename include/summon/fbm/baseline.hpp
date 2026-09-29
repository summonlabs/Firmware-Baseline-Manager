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

#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {

// A baseline is published policy. Publishing is what makes it authoritative;
// an approved version is never evidence that anything is installed.
enum class BaselineState : std::uint8_t {
  Draft = 0,
  Published = 1,
  Retired = 2,
};

std::string_view baseline_state_token(BaselineState state) noexcept;
Result<BaselineState> baseline_state_from_token(std::string_view token);

// Selects the hardware a baseline applies to. An unset model or revision bound
// means the baseline does not restrict on that dimension; it never means "zero"
// or "the default model".
struct HardwareSelector {
  HardwareClassId hardware_class;
  HardwareModelId model;
  HardwareRevision minimum_revision;
  HardwareRevision maximum_revision;

  bool covers(const HardwareProfile& hardware) const;
  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<HardwareSelector> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

// The approved state of one firmware component under a baseline.
struct ComponentRequirement {
  FirmwareComponentId component;
  FirmwareVersion approved_version;
  // Versions that count as conformant. Always contains approved_version, sorted
  // and duplicate free.
  std::vector<FirmwareVersion> conformant_versions;
  // Ordered rollback targets, most preferred first. Disjoint from
  // conformant_versions: a version cannot be both the thing to leave and the
  // thing to return to.
  std::vector<FirmwareVersion> rollback_targets;
  // How old evidence for this component may be. Stated explicitly.
  FreshnessBound freshness;

  bool is_conformant(const FirmwareVersion& version) const;
  bool is_rollback_target(const FirmwareVersion& version) const;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<ComponentRequirement> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

// Promotion gate for a cohort stage. Every threshold is explicit; none of them
// has a silent default that would let a stage promote on no evidence.
struct PromotionGate {
  // Required share of decided assets that must be Conformant, in basis points.
  std::uint32_t minimum_conformant_basis_points = 10000u;
  // Minimum number of assets with a decided conformance state.
  std::uint32_t minimum_decided_assets = 1u;
  // Minimum number of Conformant assets.
  std::uint32_t minimum_conformant_assets = 1u;
  // Minimum time the cohort must have spent in the current stage.
  std::uint64_t soak_nanos = 0u;
  // Number of stages the cohort must pass through to complete.
  StageIndex required_stages = StageIndex::first();

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<PromotionGate> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

struct Baseline {
  BaselineId id;
  BaselineGeneration generation;
  Revision revision;
  BaselineState state = BaselineState::Draft;
  std::string title;
  std::vector<HardwareSelector> selectors;
  std::vector<ComponentRequirement> components;
  CompatibilityRuleSet rules;
  PromotionGate gate;
  Timestamp created_at;
  Timestamp published_at;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;

  bool covers(const HardwareProfile& hardware) const;
  const ComponentRequirement* find_component(const FirmwareComponentId& component) const;
  bool is_authoritative_candidate() const { return state == BaselineState::Published; }

  // The document body of this baseline. Deliberately excludes the content
  // digest, which is computed over exactly these bytes.
  json::Value to_json() const;
  static Result<Baseline> from_json(const json::Value& value, std::string_view path);

  // SHA-256 over the canonical serialization of to_json(). This digest is what
  // authorization tokens bind to, so any change to the baseline changes it.
  Digest content_digest() const;
  std::string to_string() const;
};

// All known baselines, keyed by identity. Iteration is in ascending BaselineId
// order, so recovery, migration, and serialization never depend on hash or
// insertion order.
class BaselineRegistry {
 public:
  BaselineRegistry() = default;

  Status put(Baseline baseline);
  bool erase(const BaselineId& id);

  bool empty() const noexcept { return items_.empty(); }
  std::size_t size() const noexcept { return items_.size(); }
  const std::map<BaselineId, Baseline>& items() const noexcept { return items_; }

  const Baseline* find(const BaselineId& id) const;

  // The authoritative baseline for a profile is the Published baseline with the
  // highest generation that covers it. When two Published baselines share that
  // highest generation, authority is ambiguous and the query fails rather than
  // choosing one. A null pointer in the result means no baseline covers the
  // profile at all, which is different from ambiguity.
  Result<const Baseline*> authoritative(const HardwareProfile& hardware) const;

  // Every Published baseline covering the profile, ascending by generation.
  std::vector<const Baseline*> candidates(const HardwareProfile& hardware) const;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<BaselineRegistry> from_json(const json::Value& value, std::string_view path);

 private:
  std::map<BaselineId, Baseline> items_;
};

}  // namespace summon::fbm
