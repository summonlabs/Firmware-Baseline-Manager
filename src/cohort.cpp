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

#include "summon/fbm/cohort.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {
namespace {

// Publishes the defects collected in a nested diagnostics set and returns the
// most primary of them, so a nested validate() never reports a defect that
// belongs to its caller.
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

template <class Id>
bool read_optional_identifier(json::ObjectReader& reader, std::string_view key, Id& out,
                              Diagnostics& diagnostics) {
  const json::Value* value = reader.optional(key, json::Type::String);
  if (value == nullptr) {
    return false;  // absent, or of the wrong type and already diagnosed
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

// A digest is a fixed-size value with no separate "unset" flag, so the all-zero
// digest is the stored representation of "absent". It is never a real SHA-256
// content digest, and it is never read as authority for a non-draft cohort.
bool digest_is_absent(const Digest& digest) { return digest == Digest{}; }

std::string scalar_text(std::uint64_t value, bool is_set) {
  return is_set ? std::to_string(value) : std::string{"<unset>"};
}

}  // namespace

// --- CohortState ------------------------------------------------------------

std::string_view cohort_state_token(CohortState state) noexcept {
  switch (state) {
    case CohortState::Draft:
      return "draft";
    case CohortState::Authorized:
      return "authorized";
    case CohortState::Active:
      return "active";
    case CohortState::Paused:
      return "paused";
    case CohortState::Completed:
      return "completed";
    case CohortState::RolledBack:
      return "rolled_back";
    case CohortState::Cancelled:
      return "cancelled";
  }
  return "unknown_cohort_state";
}

Result<CohortState> cohort_state_from_token(std::string_view token) {
  if (token == "draft") {
    return CohortState::Draft;
  }
  if (token == "authorized") {
    return CohortState::Authorized;
  }
  if (token == "active") {
    return CohortState::Active;
  }
  if (token == "paused") {
    return CohortState::Paused;
  }
  if (token == "completed") {
    return CohortState::Completed;
  }
  if (token == "rolled_back") {
    return CohortState::RolledBack;
  }
  if (token == "cancelled") {
    return CohortState::Cancelled;
  }
  return Error{ErrorCode::SchemaInvalidEnumValue,
               "unknown cohort state token \"" + std::string{token} + "\"", std::string{}};
}

// --- Cohort -----------------------------------------------------------------

bool Cohort::is_member(const AssetId& asset) const {
  // The member list is small and is validated as sorted and unique, but lookup
  // does not depend on that ordering, so an unvalidated cohort still answers
  // correctly.
  return std::find(members.begin(), members.end(), asset) != members.end();
}

bool Cohort::accepts_mutation() const {
  // A cohort in a terminal state is a closed record: it may still be read and
  // reported, but no further stage, pause, resume, or cancellation may be
  // applied to it. Every other state is still being driven.
  switch (state) {
    case CohortState::Draft:
    case CohortState::Authorized:
    case CohortState::Active:
    case CohortState::Paused:
      return true;
    case CohortState::Completed:
    case CohortState::RolledBack:
    case CohortState::Cancelled:
      return false;
  }
  return false;
}

Status Cohort::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  validate_identity(id, json::join_path(path, "id"), "id", local);
  validate_identity(baseline, json::join_path(path, "baseline"), "baseline", local);
  validate_scalar(baseline_generation, json::join_path(path, "baseline_generation"),
                  "baseline_generation", local);
  validate_scalar(revision, json::join_path(path, "revision"), "revision", local);
  validate_scalar(stage, json::join_path(path, "stage"), "stage", local);
  validate_scalar(required_stages, json::join_path(path, "required_stages"), "required_stages",
                  local);
  validate_timestamp(created_at, json::join_path(path, "created_at"), "created_at", local);
  validate_timestamp(stage_entered_at, json::join_path(path, "stage_entered_at"),
                     "stage_entered_at", local);

  // Stages are one-based: a cohort enters stage 1 and completes after the last
  // required stage. A stage beyond the required count is impossible.
  if (stage.is_set() && stage.value() == 0u) {
    local.add(ErrorCode::SchemaValueOutOfRange, "stage must be at least 1",
              json::join_path(path, "stage"));
  }
  if (required_stages.is_set() && required_stages.value() == 0u) {
    local.add(ErrorCode::SchemaValueOutOfRange, "required_stages must be at least 1",
              json::join_path(path, "required_stages"));
  }
  if (stage.is_set() && required_stages.is_set() && stage.value() > required_stages.value()) {
    local.add(ErrorCode::SchemaInconsistentDocument,
              "stage " + std::to_string(stage.value()) + " exceeds required_stages " +
                  std::to_string(required_stages.value()),
              json::join_path(path, "stage"));
  }

  // members: non-empty, unique, and ascending by asset identity.
  const std::string members_path = json::join_path(path, "members");
  if (members.empty()) {
    local.add(ErrorCode::SchemaEmptyCollection, "members must not be empty", members_path);
  }
  std::optional<AssetId> previous;
  for (std::size_t i = 0; i < members.size(); ++i) {
    const std::string element_path = json::join_index(members_path, i);
    const AssetId& member = members[i];
    if (!member.is_set()) {
      local.add(ErrorCode::SchemaMissingField, "member identity is required", element_path);
      continue;
    }
    const Status status = validate_identifier(member.view(), element_path);
    if (!status.has_value()) {
      local.add(status.error());
      continue;
    }
    // Duplicates are detected against every earlier member, not only the
    // adjacent one, so a repeat that is also out of order is still reported as
    // a duplicate.
    bool duplicate = false;
    for (std::size_t j = 0; j < i; ++j) {
      if (members[j] == member) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      local.add(ErrorCode::SchemaDuplicateIdentifier,
                "asset \"" + member.to_string() + "\" appears more than once in members",
                element_path);
    }
    if (previous.has_value() && member < *previous) {
      local.add(ErrorCode::SchemaInconsistentDocument,
                "members must be ascending by asset identity", element_path);
    }
    previous = member;
  }

  // State-dependent members. A draft carries none of the authorization facts;
  // every other state carries all of them.
  const bool draft = state == CohortState::Draft;
  if (draft) {
    if (!digest_is_absent(baseline_digest)) {
      local.add(ErrorCode::SchemaInconsistentDocument,
                "baseline_digest must be absent for a draft",
                json::join_path(path, "baseline_digest"));
    }
    if (policy_generation.is_set()) {
      local.add(ErrorCode::SchemaInconsistentDocument,
                "policy_generation must be absent for a draft",
                json::join_path(path, "policy_generation"));
    }
    if (authorized_epoch.is_set()) {
      local.add(ErrorCode::SchemaInconsistentDocument,
                "authorized_epoch must be absent for a draft",
                json::join_path(path, "authorized_epoch"));
    }
    if (plan.is_set()) {
      local.add(ErrorCode::SchemaInconsistentDocument, "plan must be absent for a draft",
                json::join_path(path, "plan"));
    }
  } else {
    if (digest_is_absent(baseline_digest)) {
      local.add(ErrorCode::SchemaMissingField,
                "baseline_digest is required when state is not draft",
                json::join_path(path, "baseline_digest"));
    }
    validate_scalar(policy_generation, json::join_path(path, "policy_generation"),
                    "policy_generation", local);
    validate_scalar(authorized_epoch, json::join_path(path, "authorized_epoch"),
                    "authorized_epoch", local);
    validate_identity(plan, json::join_path(path, "plan"), "plan", local);
  }
  return publish(local, diagnostics);
}

json::Value Cohort::to_json() const {
  json::Value::Object object;
  object.emplace_back("id", json::Value{id.value()});
  object.emplace_back("baseline", json::Value{baseline.value()});
  object.emplace_back("baseline_generation", json::Value{baseline_generation.value()});
  if (state != CohortState::Draft) {
    object.emplace_back("baseline_digest", json::Value{digest_to_hex(baseline_digest)});
    object.emplace_back("policy_generation", json::Value{policy_generation.value()});
    object.emplace_back("authorized_epoch", json::Value{authorized_epoch.value()});
  }
  object.emplace_back("revision", json::Value{revision.value()});
  object.emplace_back("stage", json::Value{stage.value()});
  object.emplace_back("required_stages", json::Value{required_stages.value()});
  object.emplace_back("state", json::Value{std::string{cohort_state_token(state)}});
  json::Value::Array member_array;
  member_array.reserve(members.size());
  for (const AssetId& member : members) {
    member_array.push_back(json::Value{member.value()});
  }
  object.emplace_back("members", json::Value{std::move(member_array)});
  if (state != CohortState::Draft && plan.is_set()) {
    object.emplace_back("plan", json::Value{plan.value()});
  }
  object.emplace_back("created_at", json::Value{created_at.to_rfc3339()});
  object.emplace_back("stage_entered_at", json::Value{stage_entered_at.to_rfc3339()});
  if (last_promoted_at.is_set()) {
    object.emplace_back("last_promoted_at", json::Value{last_promoted_at.to_rfc3339()});
  }
  if (!note.empty()) {
    object.emplace_back("note", json::Value{note});
  }
  return json::Value{std::move(object)};
}

Result<Cohort> Cohort::from_json(const json::Value& value, std::string_view path) {
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  // Value-initialized so that an absent digest is the all-zero digest rather
  // than an indeterminate one.
  Cohort cohort{};

  read_identifier(reader, "id", cohort.id, diagnostics);
  read_identifier(reader, "baseline", cohort.baseline, diagnostics);
  read_scalar(reader, "baseline_generation", cohort.baseline_generation, diagnostics);

  // baseline_digest, policy_generation, authorized_epoch, and plan are read
  // only if present; their presence is checked against the state by validate().
  if (const json::Value* digest_value = reader.optional("baseline_digest", json::Type::String);
      digest_value != nullptr) {
    Result<Digest> parsed = digest_from_hex(digest_value->as_string(), reader.child_path("baseline_digest"));
    if (parsed.has_value()) {
      cohort.baseline_digest = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }
  read_optional_scalar(reader, "policy_generation", cohort.policy_generation, diagnostics);
  read_optional_scalar(reader, "authorized_epoch", cohort.authorized_epoch, diagnostics);

  read_scalar(reader, "revision", cohort.revision, diagnostics);
  read_scalar(reader, "stage", cohort.stage, diagnostics);
  read_scalar(reader, "required_stages", cohort.required_stages, diagnostics);

  if (const json::Value* state_value = reader.required("state", json::Type::String);
      state_value != nullptr) {
    Result<CohortState> parsed = cohort_state_from_token(state_value->as_string());
    if (parsed.has_value()) {
      cohort.state = parsed.take();
    } else {
      const Error& error = parsed.error();
      diagnostics.add(Error{error.code(), error.message(), reader.child_path("state")});
    }
  }

  if (const json::Value* members_value = reader.required("members", json::Type::Array);
      members_value != nullptr) {
    const json::Value::Array& elements = members_value->as_array();
    for (std::size_t i = 0; i < elements.size(); ++i) {
      const std::string element_path = json::join_index(reader.child_path("members"), i);
      const json::Value& element = elements[i];
      if (!element.is_string()) {
        diagnostics.add(ErrorCode::SchemaWrongType,
                        "member identity must be a string but found " +
                            std::string{json::type_name(element.type())},
                        element_path);
        continue;
      }
      Result<AssetId> member = make_id<AssetId>(element.as_string(), element_path);
      if (!member.has_value()) {
        diagnostics.add(member.error());
        continue;
      }
      cohort.members.push_back(member.take());
    }
  }

  read_optional_identifier(reader, "plan", cohort.plan, diagnostics);
  read_timestamp(reader, "created_at", cohort.created_at, diagnostics);
  read_timestamp(reader, "stage_entered_at", cohort.stage_entered_at, diagnostics);
  read_optional_timestamp(reader, "last_promoted_at", cohort.last_promoted_at, diagnostics);
  if (const json::Value* note_value = reader.optional("note", json::Type::String);
      note_value != nullptr) {
    cohort.note = note_value->as_string();
  }

  reader.finish();
  if (diagnostics.empty()) {
    // The state-dependent required and forbidden members are enforced by
    // validate(), so there is a single source of truth for them.
    cohort.validate(path, diagnostics);
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return cohort;
}

std::string Cohort::to_string() const {
  std::string out{"cohort "};
  out += id.is_set() ? id.value() : std::string{"<unset>"};
  out += " state=";
  out += cohort_state_token(state);
  out += " baseline=";
  out += baseline.is_set() ? baseline.value() : std::string{"<unset>"};
  out += " generation=";
  out += scalar_text(baseline_generation.value(), baseline_generation.is_set());
  out += " revision=";
  out += scalar_text(revision.value(), revision.is_set());
  out += " stage=";
  out += scalar_text(stage.value(), stage.is_set());
  out += "/";
  out += scalar_text(required_stages.value(), required_stages.is_set());
  out += " members=";
  out += std::to_string(members.size());
  return out;
}

// --- GateCounts -------------------------------------------------------------

json::Value GateCounts::to_json() const {
  json::Value::Object object;
  object.emplace_back("total_assets", json::Value{total_assets});
  object.emplace_back("decided_assets", json::Value{decided_assets});
  object.emplace_back("conformant_assets", json::Value{conformant_assets});
  object.emplace_back("drifted_assets", json::Value{drifted_assets});
  object.emplace_back("unknown_assets", json::Value{unknown_assets});
  object.emplace_back("unsupported_assets", json::Value{unsupported_assets});
  object.emplace_back("blocked_assets", json::Value{blocked_assets});
  object.emplace_back("exception_assets", json::Value{exception_assets});
  object.emplace_back("pending_rollout_assets", json::Value{pending_rollout_assets});
  object.emplace_back("pending_rollback_assets", json::Value{pending_rollback_assets});
  object.emplace_back("conformant_basis_points", json::Value{conformant_basis_points});
  return json::Value{std::move(object)};
}

// --- GateReport -------------------------------------------------------------

json::Value GateReport::to_json() const {
  json::Value::Object object;
  object.emplace_back("satisfied", json::Value{satisfied});
  object.emplace_back("counts", counts.to_json());
  json::Value::Array unmet;
  unmet.reserve(unmet_conditions.size());
  for (const std::string& condition : unmet_conditions) {
    unmet.push_back(json::Value{condition});
  }
  object.emplace_back("unmet_conditions", json::Value{std::move(unmet)});
  object.emplace_back("soak_remaining_nanos", json::Value{soak_remaining_nanos});
  if (next_stage.is_set()) {
    object.emplace_back("next_stage", json::Value{next_stage.value()});
  }
  return json::Value{std::move(object)};
}

std::string GateReport::to_string() const {
  std::string out{satisfied ? "satisfied" : "unsatisfied"};
  out += ": total_assets=";
  out += std::to_string(counts.total_assets);
  out += " decided_assets=";
  out += std::to_string(counts.decided_assets);
  out += " conformant_assets=";
  out += std::to_string(counts.conformant_assets);
  out += " drifted_assets=";
  out += std::to_string(counts.drifted_assets);
  out += " unknown_assets=";
  out += std::to_string(counts.unknown_assets);
  out += " unsupported_assets=";
  out += std::to_string(counts.unsupported_assets);
  out += " blocked_assets=";
  out += std::to_string(counts.blocked_assets);
  out += " exception_assets=";
  out += std::to_string(counts.exception_assets);
  out += " pending_rollout_assets=";
  out += std::to_string(counts.pending_rollout_assets);
  out += " pending_rollback_assets=";
  out += std::to_string(counts.pending_rollback_assets);
  out += " conformant_basis_points=";
  out += std::to_string(counts.conformant_basis_points);
  if (unmet_conditions.empty()) {
    out += "; unmet_conditions=none";
  } else {
    out += "; unmet_conditions=";
    for (std::size_t i = 0; i < unmet_conditions.size(); ++i) {
      out += i == 0 ? "[" : "; ";
      out += unmet_conditions[i];
    }
    out += "]";
  }
  out += "; soak_remaining_nanos=";
  out += std::to_string(soak_remaining_nanos);
  out += "; next_stage=";
  out += scalar_text(next_stage.value(), next_stage.is_set());
  return out;
}

// --- CohortRegistry ---------------------------------------------------------

Status CohortRegistry::put(Cohort cohort) {
  Diagnostics diagnostics;
  if (!cohort.validate({}, diagnostics).has_value()) {
    return diagnostics.primary();
  }
  const CohortId key = cohort.id;
  items_.insert_or_assign(key, std::move(cohort));
  return ok_status();
}

bool CohortRegistry::erase(const CohortId& id) { return items_.erase(id) != 0u; }

const Cohort* CohortRegistry::find(const CohortId& id) const {
  const auto found = items_.find(id);
  return found == items_.end() ? nullptr : &found->second;
}

std::vector<const Cohort*> CohortRegistry::containing(const AssetId& asset) const {
  std::vector<const Cohort*> out;
  // items_ is ordered by cohort identity, so the result is ascending by
  // identity without any further sorting.
  for (const auto& entry : items_) {
    if (entry.second.is_member(asset)) {
      out.push_back(&entry.second);
    }
  }
  return out;
}

Status CohortRegistry::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  std::size_t index = 0;
  for (const auto& entry : items_) {
    entry.second.validate(json::join_index(path, index), local);
    ++index;
  }
  return publish(local, diagnostics);
}

json::Value CohortRegistry::to_json() const {
  json::Value::Array array;
  array.reserve(items_.size());
  for (const auto& entry : items_) {
    array.push_back(entry.second.to_json());
  }
  return json::Value{std::move(array)};
}

Result<CohortRegistry> CohortRegistry::from_json(const json::Value& value, std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_array()) {
    diagnostics.add(ErrorCode::SchemaWrongType,
                    "expected array but found " + std::string{json::type_name(value.type())},
                    std::string{path});
    return diagnostics.primary();
  }

  CohortRegistry registry;
  const json::Value::Array& elements = value.as_array();
  std::optional<CohortId> previous;
  for (std::size_t i = 0; i < elements.size(); ++i) {
    const std::string element_path = json::join_index(path, i);
    Result<Cohort> parsed = Cohort::from_json(elements[i], element_path);
    if (!parsed.has_value()) {
      diagnostics.add(parsed.error());
      continue;
    }
    Cohort cohort = parsed.take();
    if (previous.has_value()) {
      if (cohort.id == *previous) {
        diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                        "cohort \"" + cohort.id.to_string() + "\" appears more than once",
                        json::join_path(element_path, "id"));
        continue;
      }
      if (cohort.id < *previous) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "cohorts must be ascending by cohort identity",
                        json::join_path(element_path, "id"));
        continue;
      }
    }
    previous = cohort.id;
    const CohortId key = cohort.id;
    registry.items_.emplace(key, std::move(cohort));
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return registry;
}

}  // namespace summon::fbm
