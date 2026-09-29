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
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {

enum class CohortState : std::uint8_t {
  Draft = 0,
  Authorized = 1,
  Active = 2,
  Paused = 3,
  Completed = 4,
  RolledBack = 5,
  Cancelled = 6,
};

std::string_view cohort_state_token(CohortState state) noexcept;
Result<CohortState> cohort_state_from_token(std::string_view token);

// A staged rollout cohort. Authorizing a cohort binds it to the exact baseline
// generation, baseline content digest, policy generation, control epoch, and
// revision that it was authorized against. When any of those advance, the
// authorization is fenced and must be re-established.
struct Cohort {
  CohortId id;
  BaselineId baseline;
  BaselineGeneration baseline_generation;
  Digest baseline_digest{};
  PolicyGeneration policy_generation;
  ControlEpoch authorized_epoch;
  Revision revision;
  StageIndex stage;
  StageIndex required_stages;
  CohortState state = CohortState::Draft;
  std::vector<AssetId> members;
  PlanId plan;
  Timestamp created_at;
  Timestamp stage_entered_at;
  Timestamp last_promoted_at;
  std::string note;

  bool is_member(const AssetId& asset) const;
  bool accepts_mutation() const;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<Cohort> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

// Exact counts behind a promotion decision. Retained in full so that a gate
// result is never reduced to a bare boolean.
struct GateCounts {
  std::uint32_t total_assets = 0;
  std::uint32_t decided_assets = 0;
  std::uint32_t conformant_assets = 0;
  std::uint32_t drifted_assets = 0;
  std::uint32_t unknown_assets = 0;
  std::uint32_t unsupported_assets = 0;
  std::uint32_t blocked_assets = 0;
  std::uint32_t exception_assets = 0;
  std::uint32_t pending_rollout_assets = 0;
  std::uint32_t pending_rollback_assets = 0;
  // conformant_assets scaled to basis points of decided_assets. Zero when there
  // are no decided assets, which is reported as an unmet minimum rather than as
  // a passing ratio.
  std::uint32_t conformant_basis_points = 0;

  json::Value to_json() const;
};

struct GateReport {
  bool satisfied = false;
  GateCounts counts;
  // Exact unmet conditions in a fixed order. Empty exactly when satisfied.
  std::vector<std::string> unmet_conditions;
  std::uint64_t soak_remaining_nanos = 0;
  StageIndex next_stage;

  json::Value to_json() const;
  std::string to_string() const;
};

class CohortRegistry {
 public:
  CohortRegistry() = default;

  Status put(Cohort cohort);
  bool erase(const CohortId& id);

  bool empty() const noexcept { return items_.empty(); }
  std::size_t size() const noexcept { return items_.size(); }
  const std::map<CohortId, Cohort>& items() const noexcept { return items_; }

  const Cohort* find(const CohortId& id) const;

  // Cohorts containing an asset, ascending by cohort identity.
  std::vector<const Cohort*> containing(const AssetId& asset) const;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<CohortRegistry> from_json(const json::Value& value, std::string_view path);

 private:
  std::map<CohortId, Cohort> items_;
};

}  // namespace summon::fbm
