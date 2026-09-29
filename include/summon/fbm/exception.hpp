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

#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {

enum class ExceptionState : std::uint8_t {
  Active = 0,
  Revoked = 1,
};

std::string_view exception_state_token(ExceptionState state) noexcept;
Result<ExceptionState> exception_state_from_token(std::string_view token);

// Which assets and components an exception waives drift for. An unset model or
// asset widens the scope to every model or asset in the named hardware class; a
// component list that is empty means every component in scope. The widening is
// always explicit in the stored document.
struct ExceptionScope {
  HardwareClassId hardware_class;
  HardwareModelId model;
  AssetId asset;
  std::vector<FirmwareComponentId> components;

  bool covers(const HardwareProfile& hardware, const AssetId& asset_id,
              const FirmwareComponentId& component) const;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<ExceptionScope> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

// A time-bounded, scope-bounded waiver of drift. An exception is authority, so
// it carries the identity of the approval that granted it, and it is fenced by
// the baseline policy generation it was granted under: a policy change makes
// every existing exception ineffective until it is re-granted.
struct BaselineException {
  ExceptionId id;
  ExceptionScope scope;
  Expiry expiry;
  std::string reason;
  ApprovalId approval;
  PolicyGeneration granted_under;
  Revision revision;
  ExceptionState state = ExceptionState::Active;
  Timestamp created_at;
  Timestamp revoked_at;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<BaselineException> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

enum class ExceptionStatus : std::uint8_t {
  Effective = 0,
  Revoked = 1,
  Expired = 2,
  // Granted under an older baseline policy generation. Reported as stale rather
  // than silently inheriting authority it was never given.
  StalePolicyGeneration = 3,
};

std::string_view exception_status_token(ExceptionStatus status) noexcept;

// Classifies an exception against the current policy generation and time. An
// unset expiry is a programming error rather than an eternal grant.
ExceptionStatus classify_exception(const BaselineException& exception,
                                   PolicyGeneration current_policy_generation, Timestamp now);

class ExceptionRegistry {
 public:
  ExceptionRegistry() = default;

  Status put(BaselineException exception);
  bool erase(const ExceptionId& id);

  bool empty() const noexcept { return items_.empty(); }
  std::size_t size() const noexcept { return items_.size(); }
  const std::map<ExceptionId, BaselineException>& items() const noexcept { return items_; }

  const BaselineException* find(const ExceptionId& id) const;

  // The effective exception covering this asset and component, if any. When
  // several qualify, the one with the earliest expiry wins, then the lowest
  // identity, so the choice never depends on map ordering.
  const BaselineException* effective_for(const HardwareProfile& hardware, const AssetId& asset,
                                         const FirmwareComponentId& component,
                                         PolicyGeneration current_policy_generation,
                                         Timestamp now) const;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<ExceptionRegistry> from_json(const json::Value& value, std::string_view path);

 private:
  std::map<ExceptionId, BaselineException> items_;
};

}  // namespace summon::fbm
