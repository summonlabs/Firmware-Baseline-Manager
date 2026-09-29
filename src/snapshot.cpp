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

#include "summon/fbm/snapshot.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

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
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/timestamp.hpp"
#include "summon/fbm/version.hpp"

namespace summon::fbm {
namespace {

// The document marker written as the "format" member. A document that states a
// different marker is a different format, not this one read leniently.
constexpr std::string_view kSnapshotFormat = "summon.fbm.snapshot";

std::string quoted(std::string_view text) { return "\"" + std::string{text} + "\""; }

// --- Field readers ----------------------------------------------------------
//
// Every reader records a diagnostic instead of inventing a value. A field that
// is absent stays absent: an unset counter or timestamp is never replaced by
// zero or by the epoch.

template <class ScalarT>
void assign_counter(const json::Value* field, json::ObjectReader& reader, std::string_view key,
                    ScalarT& out, Diagnostics& diagnostics) {
  if (field == nullptr) {
    return;
  }
  using Value = typename ScalarT::value_type;
  const std::int64_t raw = field->as_integer();
  if (raw < 0 || static_cast<std::uint64_t>(raw) >
                     static_cast<std::uint64_t>(std::numeric_limits<Value>::max())) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                    "field " + quoted(key) +
                        " must be a non-negative integer that fits the counter representation",
                    reader.child_path(key));
    return;
  }
  out = ScalarT{static_cast<Value>(raw)};
}

template <class ScalarT>
void read_optional_counter(json::ObjectReader& reader, std::string_view key, ScalarT& out,
                           Diagnostics& diagnostics) {
  assign_counter(reader.optional(key, json::Type::Integer), reader, key, out, diagnostics);
}

void assign_timestamp(const json::Value* field, json::ObjectReader& reader, std::string_view key,
                      Timestamp& out, Diagnostics& diagnostics) {
  if (field == nullptr) {
    return;
  }
  auto parsed = Timestamp::parse_rfc3339(field->as_string(), reader.child_path(key));
  if (parsed.has_value()) {
    out = parsed.take();
  } else {
    diagnostics.add(parsed.error());
  }
}

void read_optional_timestamp(json::ObjectReader& reader, std::string_view key, Timestamp& out,
                             Diagnostics& diagnostics) {
  assign_timestamp(reader.optional(key, json::Type::String), reader, key, out, diagnostics);
}

}  // namespace

Snapshot Snapshot::empty() {
  // Every counter is unset and every registry is empty. Nothing here is zero
  // "by default": an unset counter is omitted from JSON and absent once parsed.
  return Snapshot{};
}

Status Snapshot::validate(std::string_view path, Diagnostics& diagnostics) const {
  // The format marker and the format version are checked before any other
  // member is interpreted; see from_json below. A Snapshot value exists only
  // after that check has passed, so validation of the value itself starts with
  // the registries and adds no format defect of its own.
  const std::string base{path};

  baselines.validate(json::join_path(base, "baselines"), diagnostics);
  observations.validate(json::join_path(base, "observations"), diagnostics);
  exceptions.validate(json::join_path(base, "exceptions"), diagnostics);
  cohorts.validate(json::join_path(base, "cohorts"), diagnostics);
  authorizations.validate(json::join_path(base, "authorizations"), diagnostics);

  // Cross-field and cross-registry consistency that needs no store.
  if (created_at.is_set() && updated_at.is_set() && updated_at < created_at) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "field \"updated_at\" precedes \"created_at\"",
                    json::join_path(base, "updated_at"));
  }

  std::size_t cohort_index = 0;
  for (const auto& entry : cohorts.items()) {
    if (baselines.find(entry.second.baseline) == nullptr) {
      diagnostics.add(ErrorCode::IdentityUnknownBaseline,
                      "cohort " + quoted(entry.first.to_string()) + " references baseline " +
                          quoted(entry.second.baseline.to_string()) +
                          ", which this snapshot does not contain",
                      json::join_path(
                          json::join_index(json::join_path(base, "cohorts"), cohort_index),
                          "baseline"));
    }
    ++cohort_index;
  }

  std::size_t authorization_index = 0;
  for (const auto& entry : authorizations.items()) {
    if (baselines.find(entry.second.binding.baseline) == nullptr) {
      diagnostics.add(ErrorCode::IdentityUnknownBaseline,
                      "authorization for request " + quoted(entry.first.to_string()) +
                          " references baseline " +
                          quoted(entry.second.binding.baseline.to_string()) +
                          ", which this snapshot does not contain",
                      json::join_path(
                          json::join_path(
                              json::join_index(json::join_path(base, "authorizations"),
                                               authorization_index),
                              "binding"),
                          "baseline"));
    }
    ++authorization_index;
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value Snapshot::to_json() const {
  // One fixed member order, mirroring the schema: the marker, the version, the
  // counters, the timestamps, then the registries. The canonical writer sorts
  // members, so this order is for the reader, not for the digest.
  json::Value::Object members;
  members.emplace_back("format", std::string{kSnapshotFormat});
  members.emplace_back("format_version",
                       static_cast<std::int64_t>(kDurableFormatVersion));
  if (commit_sequence.is_set()) {
    members.emplace_back("commit_sequence", static_cast<std::int64_t>(commit_sequence.value()));
  }
  if (control_epoch.is_set()) {
    members.emplace_back("control_epoch", static_cast<std::int64_t>(control_epoch.value()));
  }
  if (policy_generation.is_set()) {
    members.emplace_back("policy_generation", static_cast<std::int64_t>(policy_generation.value()));
  }
  if (revision.is_set()) {
    members.emplace_back("revision", static_cast<std::int64_t>(revision.value()));
  }
  if (incarnation.is_set()) {
    members.emplace_back("incarnation", static_cast<std::int64_t>(incarnation.value()));
  }
  if (created_at.is_set()) {
    members.emplace_back("created_at", created_at.to_rfc3339());
  }
  if (updated_at.is_set()) {
    members.emplace_back("updated_at", updated_at.to_rfc3339());
  }
  members.emplace_back("baselines", baselines.to_json());
  members.emplace_back("observations", observations.to_json());
  members.emplace_back("exceptions", exceptions.to_json());
  members.emplace_back("cohorts", cohorts.to_json());
  members.emplace_back("authorizations", authorizations.to_json());
  return json::Value{std::move(members)};
}

Result<Snapshot> Snapshot::from_json(const json::Value& value, std::string_view path) {
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "snapshot must be an object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }

  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  Snapshot snapshot;

  // The format marker and the format version come first. They are frame-level
  // defects, so they outrank every schema defect collected below and the
  // document is never partially interpreted.
  const json::Value* format = reader.required("format", json::Type::String);
  if (format != nullptr && format->as_string() != kSnapshotFormat) {
    diagnostics.add(ErrorCode::FormatMagicMismatch,
                    "snapshot format must be " + quoted(kSnapshotFormat) + " but found " +
                        quoted(format->as_string()),
                    reader.child_path("format"));
  }

  const json::Value* format_version = reader.required("format_version", json::Type::Integer);
  if (format_version != nullptr) {
    const std::int64_t raw = format_version->as_integer();
    if (raw < 0) {
      diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                      "field \"format_version\" must be a non-negative integer",
                      reader.child_path("format_version"));
    } else if (static_cast<std::uint64_t>(raw) !=
               static_cast<std::uint64_t>(kDurableFormatVersion)) {
      diagnostics.add(ErrorCode::FormatVersionUnsupported,
                      "snapshot format_version " + std::to_string(raw) +
                          " is not supported by this build, which writes " +
                          std::to_string(kDurableFormatVersion),
                      reader.child_path("format_version"));
    }
  }

  read_optional_counter(reader, "commit_sequence", snapshot.commit_sequence, diagnostics);
  read_optional_counter(reader, "control_epoch", snapshot.control_epoch, diagnostics);
  read_optional_counter(reader, "policy_generation", snapshot.policy_generation, diagnostics);
  read_optional_counter(reader, "revision", snapshot.revision, diagnostics);
  read_optional_counter(reader, "incarnation", snapshot.incarnation, diagnostics);
  read_optional_timestamp(reader, "created_at", snapshot.created_at, diagnostics);
  read_optional_timestamp(reader, "updated_at", snapshot.updated_at, diagnostics);

  const json::Value* baselines = reader.required("baselines", json::Type::Array);
  const json::Value* observations = reader.required("observations", json::Type::Object);
  const json::Value* exceptions = reader.required("exceptions", json::Type::Array);
  const json::Value* cohorts = reader.required("cohorts", json::Type::Array);
  const json::Value* authorizations = reader.required("authorizations", json::Type::Array);

  if (baselines != nullptr) {
    auto parsed = BaselineRegistry::from_json(*baselines, reader.child_path("baselines"));
    if (parsed.has_value()) {
      snapshot.baselines = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (observations != nullptr) {
    auto parsed = ObservationLog::from_json(*observations, reader.child_path("observations"));
    if (parsed.has_value()) {
      snapshot.observations = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (exceptions != nullptr) {
    auto parsed = ExceptionRegistry::from_json(*exceptions, reader.child_path("exceptions"));
    if (parsed.has_value()) {
      snapshot.exceptions = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (cohorts != nullptr) {
    auto parsed = CohortRegistry::from_json(*cohorts, reader.child_path("cohorts"));
    if (parsed.has_value()) {
      snapshot.cohorts = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  if (authorizations != nullptr) {
    auto parsed = AuthorizationRegistry::from_json(*authorizations,
                                                   reader.child_path("authorizations"));
    if (parsed.has_value()) {
      snapshot.authorizations = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }

  reader.finish();
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }

  // The document-level rules - each registry's own invariants plus the
  // cross-registry consistency - are enforced by validate() so that there is a
  // single source of truth for what a valid snapshot is. A snapshot that cannot
  // be validated is never handed back as if it were durable state.
  Status status = snapshot.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return snapshot;
}

std::string Snapshot::canonical_bytes() const { return json::write_canonical(to_json()); }

Digest Snapshot::content_digest() const { return Sha256::of(canonical_bytes()); }

}  // namespace summon::fbm
