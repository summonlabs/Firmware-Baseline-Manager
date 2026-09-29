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

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "summon/fbm/result.hpp"
#include "summon/fbm/strong_types.hpp"

// Semantically distinct identity and generation types. Confusing any two of
// these is a compile error, not a code review comment. Every generation that
// fences an authorization is a distinct type so that, for example, a hardware
// generation can never be passed where a policy generation is required.
namespace summon::fbm {

// --- Facility and asset identity -------------------------------------------
struct SiteIdTag;
using SiteId = StrongId<SiteIdTag>;

struct RackIdTag;
using RackId = StrongId<RackIdTag>;

struct AssetIdTag;
using AssetId = StrongId<AssetIdTag>;

// --- Hardware selection -----------------------------------------------------
struct HardwareClassIdTag;
using HardwareClassId = StrongId<HardwareClassIdTag>;

struct HardwareModelIdTag;
using HardwareModelId = StrongId<HardwareModelIdTag>;

struct HardwareRevisionTag;
using HardwareRevision = Scalar<HardwareRevisionTag, std::uint32_t>;

// A capability is something a device was *observed* to expose. Discovering a
// device never implies any of its capabilities.
struct CapabilityIdTag;
using CapabilityId = StrongId<CapabilityIdTag>;

// --- Firmware ---------------------------------------------------------------
struct FirmwareComponentIdTag;
using FirmwareComponentId = StrongId<FirmwareComponentIdTag>;

struct FirmwareGenerationTag;
using FirmwareGeneration = Scalar<FirmwareGenerationTag>;

// --- Policy documents -------------------------------------------------------
struct BaselineIdTag;
using BaselineId = StrongId<BaselineIdTag>;

struct RuleIdTag;
using RuleId = StrongId<RuleIdTag>;

struct PolicyIdTag;
using PolicyId = StrongId<PolicyIdTag>;

struct CohortIdTag;
using CohortId = StrongId<CohortIdTag>;

struct ExceptionIdTag;
using ExceptionId = StrongId<ExceptionIdTag>;

struct ExceptionScopeIdTag;
using ExceptionScopeId = StrongId<ExceptionScopeIdTag>;

// --- Plans, attempts, evidence ---------------------------------------------
struct PlanIdTag;
using PlanId = StrongId<PlanIdTag>;

struct AttemptIdTag;
using AttemptId = StrongId<AttemptIdTag>;

struct ObservationIdTag;
using ObservationId = StrongId<ObservationIdTag>;

struct EvidenceIdTag;
using EvidenceId = StrongId<EvidenceIdTag>;

struct ApprovalIdTag;
using ApprovalId = StrongId<ApprovalIdTag>;

// Request identity used for idempotent lost-response replay.
struct RequestIdTag;
using RequestId = StrongId<RequestIdTag>;

// --- Generations and epochs -------------------------------------------------
struct BaselineGenerationTag;
using BaselineGeneration = Scalar<BaselineGenerationTag>;

struct HardwareGenerationTag;
using HardwareGeneration = Scalar<HardwareGenerationTag>;

struct DependencyGenerationTag;
using DependencyGeneration = Scalar<DependencyGenerationTag>;

struct CapacityGenerationTag;
using CapacityGeneration = Scalar<CapacityGenerationTag>;

struct TopologyGenerationTag;
using TopologyGeneration = Scalar<TopologyGenerationTag>;

struct MaintenanceGenerationTag;
using MaintenanceGeneration = Scalar<MaintenanceGenerationTag>;

struct PolicyGenerationTag;
using PolicyGeneration = Scalar<PolicyGenerationTag>;

struct RollbackGenerationTag;
using RollbackGeneration = Scalar<RollbackGenerationTag>;

struct ControlEpochTag;
using ControlEpoch = Scalar<ControlEpochTag>;

struct IncarnationIdTag;
using IncarnationId = Scalar<IncarnationIdTag>;

struct RevisionTag;
using Revision = Scalar<RevisionTag>;

struct CommitSequenceTag;
using CommitSequence = Scalar<CommitSequenceTag>;

struct ObservationSequenceTag;
using ObservationSequence = Scalar<ObservationSequenceTag>;

struct StageIndexTag;
using StageIndex = Scalar<StageIndexTag, std::uint32_t>;

// --- Identifier rules -------------------------------------------------------
// An identifier is 1..128 bytes of ASCII. The first byte is [A-Za-z0-9]; every
// subsequent byte is [A-Za-z0-9._-]. The rule deliberately excludes the colon
// (Windows alternate data streams), the path separator, the backslash, and the
// dot-only forms that could be read as a relative path component.
inline constexpr std::size_t kMaxIdentifierBytes = 128u;

bool is_valid_identifier(std::string_view text) noexcept;

// Validates an identifier and reports the exact reason on failure.
Status validate_identifier(std::string_view text, std::string_view path);

// Validates and constructs a tagged identity.
template <class Id>
Result<Id> make_id(std::string_view text, std::string_view path) {
  Status status = validate_identifier(text, path);
  if (!status.has_value()) {
    return status.error();
  }
  return Id{std::string{text}};
}

// Validates and constructs a tagged scalar.
template <class ScalarT, class UInt>
Result<ScalarT> make_scalar(UInt value, UInt minimum, UInt maximum, std::string_view path,
                            std::string_view field_name) {
  if (value < minimum) {
    return Error{ErrorCode::SchemaValueOutOfRange,
                 std::string{field_name} + " is below the minimum of " + std::to_string(minimum),
                 std::string{path}};
  }
  if (value > maximum) {
    return Error{ErrorCode::SchemaValueOutOfRange,
                 std::string{field_name} + " is above the maximum of " + std::to_string(maximum),
                 std::string{path}};
  }
  return ScalarT{value};
}

}  // namespace summon::fbm
