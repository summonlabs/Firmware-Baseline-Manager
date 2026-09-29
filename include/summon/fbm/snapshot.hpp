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
#include <string>
#include <string_view>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/baseline.hpp"
#include "summon/fbm/cohort.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/exception.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/observation.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {

// The complete durable state, as one value. A snapshot is immutable once
// published: a mutation builds a new snapshot, commits it, and only then
// becomes visible to readers. Readers therefore never observe a torn or
// partially applied generation.
struct Snapshot {
  CommitSequence commit_sequence;
  ControlEpoch control_epoch;
  PolicyGeneration policy_generation;
  Revision revision;
  IncarnationId incarnation;
  Timestamp created_at;
  Timestamp updated_at;

  BaselineRegistry baselines;
  ObservationLog observations;
  ExceptionRegistry exceptions;
  CohortRegistry cohorts;
  AuthorizationRegistry authorizations;

  static Snapshot empty();

  Status validate(std::string_view path, Diagnostics& diagnostics) const;

  json::Value to_json() const;
  static Result<Snapshot> from_json(const json::Value& value, std::string_view path);

  std::string canonical_bytes() const;
  Digest content_digest() const;
};

}  // namespace summon::fbm
