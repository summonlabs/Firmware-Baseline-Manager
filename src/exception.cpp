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

#include "summon/fbm/exception.hpp"

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

// An expiry is encoded as exactly one of "expires_at" or "expires": "never".
// Neither a missing expiry nor a malformed one is ever read as "never".
bool read_expiry(json::ObjectReader& reader, Expiry& out, Diagnostics& diagnostics) {
  const bool has_instant = reader.has("expires_at");
  const bool has_never = reader.has("expires");
  const json::Value* instant_value = reader.optional("expires_at", json::Type::String);
  const json::Value* never_value = reader.optional("expires", json::Type::String);

  if (has_instant && has_never) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "expiry must state exactly one of \"expires_at\" or \"expires\"",
                    reader.path());
    return false;
  }
  if (!has_instant && !has_never) {
    diagnostics.add(ErrorCode::SchemaMissingField,
                    "expiry is required: state either \"expires_at\" or \"expires\"",
                    reader.path());
    return false;
  }
  if (has_instant) {
    if (instant_value == nullptr) {
      return false;  // the reader diagnosed the wrong JSON type
    }
    Result<Timestamp> parsed =
        Timestamp::parse_rfc3339(instant_value->as_string(), reader.child_path("expires_at"));
    if (!parsed.has_value()) {
      diagnostics.add(parsed.error());
      return false;
    }
    out = Expiry::at(parsed.take());
    return true;
  }
  if (never_value == nullptr) {
    return false;
  }
  if (never_value->as_string() != "never") {
    diagnostics.add(ErrorCode::SchemaInvalidEnumValue,
                    "field \"expires\" must be \"never\" but is \"" + never_value->as_string() +
                        "\"",
                    reader.child_path("expires"));
    return false;
  }
  out = Expiry::never();
  return true;
}

void write_expiry(json::Value::Object& object, const Expiry& expiry) {
  if (expiry.is_set() && expiry.kind() == Expiry::Kind::Never) {
    object.emplace_back("expires", json::Value{std::string{"never"}});
    return;
  }
  // An unset expiry is invalid state, and an invalid expiry is never rendered as
  // an eternal grant: the document is written so that reading it back fails.
  const std::string text = expiry.is_set() ? expiry.at().to_rfc3339() : std::string{};
  object.emplace_back("expires_at", json::Value{text});
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

template <class Id>
void validate_optional_identity(const Id& id, std::string_view path, Diagnostics& diagnostics) {
  if (!id.is_set()) {
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

// Ordering key of an expiry: earliest first, with "never" later than every
// stated instant and equal to another "never".
int compare_expiry(const Expiry& left, const Expiry& right) {
  const bool left_never = left.kind() == Expiry::Kind::Never;
  const bool right_never = right.kind() == Expiry::Kind::Never;
  if (left_never || right_never) {
    if (left_never == right_never) {
      return 0;
    }
    return left_never ? 1 : -1;
  }
  if (left.at() == right.at()) {
    return 0;
  }
  return left.at() < right.at() ? -1 : 1;
}

// True when left is the exception that must be applied: the earliest expiry
// wins, and an exact tie is broken by the lowest exception identity. The result
// is a property of the two exceptions, never of map order.
bool exception_precedes(const BaselineException& left, const BaselineException& right) {
  const int order = compare_expiry(left.expiry, right.expiry);
  if (order != 0) {
    return order < 0;
  }
  return left.id < right.id;
}

}  // namespace

// --- ExceptionState ---------------------------------------------------------

std::string_view exception_state_token(ExceptionState state) noexcept {
  switch (state) {
    case ExceptionState::Active:
      return "active";
    case ExceptionState::Revoked:
      return "revoked";
  }
  return "unknown_exception_state";
}

Result<ExceptionState> exception_state_from_token(std::string_view token) {
  if (token == "active") {
    return ExceptionState::Active;
  }
  if (token == "revoked") {
    return ExceptionState::Revoked;
  }
  return Error{ErrorCode::SchemaInvalidEnumValue,
               "unknown exception state token \"" + std::string{token} + "\"", std::string{}};
}

// --- ExceptionScope ---------------------------------------------------------

bool ExceptionScope::covers(const HardwareProfile& hardware, const AssetId& asset_id,
                            const FirmwareComponentId& component) const {
  // A scope without a hardware class covers nothing: an unset class is a missing
  // fact, never a wildcard.
  if (!hardware_class.is_set() || hardware.hardware_class != hardware_class) {
    return false;
  }
  if (model.is_set() && hardware.model != model) {
    return false;
  }
  if (asset.is_set() && asset_id != asset) {
    return false;
  }
  // An empty component list is a deliberate widening to every component in
  // scope, not a missing field.
  if (!components.empty() &&
      std::find(components.begin(), components.end(), component) == components.end()) {
    return false;
  }
  return true;
}

Status ExceptionScope::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  validate_identity(hardware_class, json::join_path(path, "hardware_class"), "hardware_class",
                    local);
  validate_optional_identity(model, json::join_path(path, "model"), local);
  validate_optional_identity(asset, json::join_path(path, "asset"), local);

  const std::string components_path = json::join_path(path, "components");
  for (std::size_t i = 0; i < components.size(); ++i) {
    const std::string element_path = json::join_index(components_path, i);
    const FirmwareComponentId& component = components[i];
    if (!component.is_set()) {
      local.add(ErrorCode::SchemaMissingField, "component identity is required", element_path);
      continue;
    }
    const Status status = validate_identifier(component.view(), element_path);
    if (!status.has_value()) {
      local.add(status.error());
      continue;
    }
    for (std::size_t j = 0; j < i; ++j) {
      if (components[j] == component) {
        local.add(ErrorCode::SchemaDuplicateIdentifier,
                  "component \"" + component.to_string() + "\" appears more than once",
                  element_path);
        break;
      }
    }
  }
  return publish(local, diagnostics);
}

json::Value ExceptionScope::to_json() const {
  json::Value::Object object;
  object.emplace_back("hardware_class", json::Value{hardware_class.value()});
  if (model.is_set()) {
    object.emplace_back("model", json::Value{model.value()});
  }
  if (asset.is_set()) {
    object.emplace_back("asset", json::Value{asset.value()});
  }
  json::Value::Array component_array;
  component_array.reserve(components.size());
  for (const FirmwareComponentId& component : components) {
    component_array.push_back(json::Value{component.value()});
  }
  object.emplace_back("components", json::Value{std::move(component_array)});
  return json::Value{std::move(object)};
}

Result<ExceptionScope> ExceptionScope::from_json(const json::Value& value, std::string_view path) {
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  ExceptionScope scope;
  read_identifier(reader, "hardware_class", scope.hardware_class, diagnostics);
  read_optional_identifier(reader, "model", scope.model, diagnostics);
  read_optional_identifier(reader, "asset", scope.asset, diagnostics);
  if (const json::Value* components_value = reader.optional("components", json::Type::Array);
      components_value != nullptr) {
    const json::Value::Array& elements = components_value->as_array();
    for (std::size_t i = 0; i < elements.size(); ++i) {
      const std::string element_path = json::join_index(reader.child_path("components"), i);
      const json::Value& element = elements[i];
      if (!element.is_string()) {
        diagnostics.add(ErrorCode::SchemaWrongType,
                        "component identity must be a string but found " +
                            std::string{json::type_name(element.type())},
                        element_path);
        continue;
      }
      Result<FirmwareComponentId> component =
          make_id<FirmwareComponentId>(element.as_string(), element_path);
      if (!component.has_value()) {
        diagnostics.add(component.error());
        continue;
      }
      scope.components.push_back(component.take());
    }
  }
  reader.finish();
  if (diagnostics.empty()) {
    scope.validate(path, diagnostics);
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return scope;
}

std::string ExceptionScope::to_string() const {
  std::string out{"hardware_class="};
  out += hardware_class.is_set() ? hardware_class.value() : std::string{"<unset>"};
  out += " model=";
  out += model.is_set() ? model.value() : std::string{"*"};
  out += " asset=";
  out += asset.is_set() ? asset.value() : std::string{"*"};
  out += " components=";
  if (components.empty()) {
    out += "*";
  } else {
    out += '[';
    for (std::size_t i = 0; i < components.size(); ++i) {
      if (i != 0) {
        out += ',';
      }
      out += components[i].is_set() ? components[i].value() : std::string{"<unset>"};
    }
    out += ']';
  }
  return out;
}

// --- BaselineException ------------------------------------------------------

Status BaselineException::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  validate_identity(id, json::join_path(path, "id"), "id", local);
  scope.validate(json::join_path(path, "scope"), local);

  const std::string expiry_path = json::join_path(path, "expires_at");
  if (!expiry.is_set()) {
    local.add(ErrorCode::SchemaMissingField,
              "expiry is required: state either \"expires_at\" or \"expires\"", expiry_path);
  } else if (expiry.kind() == Expiry::Kind::At && !expiry.at().is_set()) {
    local.add(ErrorCode::SchemaInconsistentDocument,
              "expiry states an instant but the instant is unset", expiry_path);
  }

  if (reason.empty()) {
    local.add(ErrorCode::SchemaValueOutOfRange, "reason must be non-empty",
              json::join_path(path, "reason"));
  }
  validate_identity(approval, json::join_path(path, "approval"), "approval", local);
  validate_scalar(granted_under, json::join_path(path, "granted_under"), "granted_under", local);
  validate_scalar(revision, json::join_path(path, "revision"), "revision", local);
  validate_timestamp(created_at, json::join_path(path, "created_at"), "created_at", local);

  // revoked_at is required exactly when the state is revoked and must be absent
  // otherwise; the two facts can never disagree.
  if (state == ExceptionState::Revoked) {
    validate_timestamp(revoked_at, json::join_path(path, "revoked_at"), "revoked_at", local);
  } else if (revoked_at.is_set()) {
    local.add(ErrorCode::SchemaInconsistentDocument,
              "revoked_at must be absent unless state is revoked",
              json::join_path(path, "revoked_at"));
  }
  return publish(local, diagnostics);
}

json::Value BaselineException::to_json() const {
  json::Value::Object object;
  object.emplace_back("id", json::Value{id.value()});
  object.emplace_back("scope", scope.to_json());
  write_expiry(object, expiry);
  object.emplace_back("reason", json::Value{reason});
  object.emplace_back("approval", json::Value{approval.value()});
  object.emplace_back("granted_under", json::Value{granted_under.value()});
  object.emplace_back("revision", json::Value{revision.value()});
  object.emplace_back("state", json::Value{std::string{exception_state_token(state)}});
  object.emplace_back("created_at", json::Value{created_at.to_rfc3339()});
  if (state == ExceptionState::Revoked && revoked_at.is_set()) {
    object.emplace_back("revoked_at", json::Value{revoked_at.to_rfc3339()});
  }
  return json::Value{std::move(object)};
}

Result<BaselineException> BaselineException::from_json(const json::Value& value,
                                                       std::string_view path) {
  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  BaselineException exception;
  read_identifier(reader, "id", exception.id, diagnostics);

  if (const json::Value* scope_value = reader.required("scope", json::Type::Object);
      scope_value != nullptr) {
    Result<ExceptionScope> parsed = ExceptionScope::from_json(*scope_value, reader.child_path("scope"));
    if (parsed.has_value()) {
      exception.scope = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }

  read_expiry(reader, exception.expiry, diagnostics);
  if (const json::Value* reason_value = reader.required("reason", json::Type::String);
      reason_value != nullptr) {
    exception.reason = reason_value->as_string();
  }
  read_identifier(reader, "approval", exception.approval, diagnostics);
  read_scalar(reader, "granted_under", exception.granted_under, diagnostics);
  read_scalar(reader, "revision", exception.revision, diagnostics);

  if (const json::Value* state_value = reader.required("state", json::Type::String);
      state_value != nullptr) {
    Result<ExceptionState> parsed = exception_state_from_token(state_value->as_string());
    if (parsed.has_value()) {
      exception.state = parsed.take();
    } else {
      const Error& error = parsed.error();
      diagnostics.add(Error{error.code(), error.message(), reader.child_path("state")});
    }
  }

  read_timestamp(reader, "created_at", exception.created_at, diagnostics);
  read_optional_timestamp(reader, "revoked_at", exception.revoked_at, diagnostics);

  reader.finish();
  if (diagnostics.empty()) {
    // The state-dependent rule (revoked_at present exactly when revoked) is
    // enforced by validate() so that there is a single source of truth.
    exception.validate(path, diagnostics);
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return exception;
}

std::string BaselineException::to_string() const {
  std::string out{"exception "};
  out += id.is_set() ? id.value() : std::string{"<unset>"};
  out += " state=";
  out += exception_state_token(state);
  out += " scope(";
  out += scope.to_string();
  out += ") expiry=";
  out += expiry.is_set() ? expiry.to_string() : std::string{"<unset>"};
  out += " approval=";
  out += approval.is_set() ? approval.value() : std::string{"<unset>"};
  out += " granted_under=";
  out += granted_under.is_set() ? std::to_string(granted_under.value()) : std::string{"<unset>"};
  out += " revision=";
  out += revision.is_set() ? std::to_string(revision.value()) : std::string{"<unset>"};
  out += " created_at=";
  out += created_at.is_set() ? created_at.to_rfc3339() : std::string{"<unset>"};
  if (state == ExceptionState::Revoked) {
    out += " revoked_at=";
    out += revoked_at.is_set() ? revoked_at.to_rfc3339() : std::string{"<unset>"};
  }
  return out;
}

// --- classification ---------------------------------------------------------

std::string_view exception_status_token(ExceptionStatus status) noexcept {
  switch (status) {
    case ExceptionStatus::Effective:
      return "effective";
    case ExceptionStatus::Revoked:
      return "revoked";
    case ExceptionStatus::Expired:
      return "expired";
    case ExceptionStatus::StalePolicyGeneration:
      return "stale_policy_generation";
  }
  return "unknown_exception_status";
}

ExceptionStatus classify_exception(const BaselineException& exception,
                                   PolicyGeneration current_policy_generation, Timestamp now) {
  // An unset expiry is a programming error: it would otherwise have to be read
  // either as an eternal grant or as an expired one, and both are fabrications.
  FBM_PRECONDITION(exception.expiry.is_set());

  // The order below is fixed and observable:
  //   1. a revoked grant stays revoked, even after its expiry and even after a
  //      policy change;
  //   2. an expired grant is reported as expired rather than as stale, so that
  //      the operator sees the reason that can be acted on;
  //   3. only a grant that is still live can be fenced by the policy generation.
  if (exception.state == ExceptionState::Revoked) {
    return ExceptionStatus::Revoked;
  }
  if (exception.expiry.is_expired(now)) {
    return ExceptionStatus::Expired;
  }
  if (exception.granted_under != current_policy_generation) {
    return ExceptionStatus::StalePolicyGeneration;
  }
  return ExceptionStatus::Effective;
}

// --- ExceptionRegistry ------------------------------------------------------

Status ExceptionRegistry::put(BaselineException exception) {
  Diagnostics diagnostics;
  if (!exception.validate({}, diagnostics).has_value()) {
    return diagnostics.primary();
  }
  const ExceptionId key = exception.id;
  items_.insert_or_assign(key, std::move(exception));
  return ok_status();
}

bool ExceptionRegistry::erase(const ExceptionId& id) { return items_.erase(id) != 0u; }

const BaselineException* ExceptionRegistry::find(const ExceptionId& id) const {
  const auto found = items_.find(id);
  return found == items_.end() ? nullptr : &found->second;
}

const BaselineException* ExceptionRegistry::effective_for(
    const HardwareProfile& hardware, const AssetId& asset, const FirmwareComponentId& component,
    PolicyGeneration current_policy_generation, Timestamp now) const {
  const BaselineException* best = nullptr;
  for (const auto& entry : items_) {
    const BaselineException& candidate = entry.second;
    if (classify_exception(candidate, current_policy_generation, now) !=
        ExceptionStatus::Effective) {
      continue;
    }
    if (!candidate.scope.covers(hardware, asset, component)) {
      continue;
    }
    if (best == nullptr || exception_precedes(candidate, *best)) {
      best = &candidate;
    }
  }
  return best;
}

Status ExceptionRegistry::validate(std::string_view path, Diagnostics& diagnostics) const {
  Diagnostics local;
  std::size_t index = 0;
  for (const auto& entry : items_) {
    entry.second.validate(json::join_index(path, index), local);
    ++index;
  }
  return publish(local, diagnostics);
}

json::Value ExceptionRegistry::to_json() const {
  json::Value::Array array;
  array.reserve(items_.size());
  for (const auto& entry : items_) {
    array.push_back(entry.second.to_json());
  }
  return json::Value{std::move(array)};
}

Result<ExceptionRegistry> ExceptionRegistry::from_json(const json::Value& value,
                                                       std::string_view path) {
  Diagnostics diagnostics;
  if (!value.is_array()) {
    diagnostics.add(ErrorCode::SchemaWrongType,
                    "expected array but found " + std::string{json::type_name(value.type())},
                    std::string{path});
    return diagnostics.primary();
  }

  ExceptionRegistry registry;
  const json::Value::Array& elements = value.as_array();
  std::optional<ExceptionId> previous;
  for (std::size_t i = 0; i < elements.size(); ++i) {
    const std::string element_path = json::join_index(path, i);
    Result<BaselineException> parsed = BaselineException::from_json(elements[i], element_path);
    if (!parsed.has_value()) {
      diagnostics.add(parsed.error());
      continue;
    }
    BaselineException exception = parsed.take();
    if (previous.has_value()) {
      if (exception.id == *previous) {
        diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                        "exception \"" + exception.id.to_string() + "\" appears more than once",
                        json::join_path(element_path, "id"));
        continue;
      }
      if (exception.id < *previous) {
        diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                        "exceptions must be ascending by exception identity",
                        json::join_path(element_path, "id"));
        continue;
      }
    }
    previous = exception.id;
    const ExceptionId key = exception.id;
    registry.items_.emplace(key, std::move(exception));
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return registry;
}

}  // namespace summon::fbm
