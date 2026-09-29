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

#include "summon/fbm/authority.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {
namespace {

// Paths used for the defects verify() reports. They are JSON pointers into the
// serialization produced by AuthorizationToken::to_json(), so a caller can hand
// the path straight to a human and name the exact member that failed.
constexpr std::string_view kTokenBindingPath = "token/binding";
constexpr std::string_view kTokenMacPath = "token/mac";

// A digest rendered as raw bytes for the constant-time comparison helper. The
// comparison is over the digest itself rather than over its hexadecimal
// rendering, so no encoding choice can influence the result.
std::string_view digest_bytes(const Digest& digest) noexcept {
  return std::string_view{reinterpret_cast<const char*>(digest.data()), digest.size()};
}

bool is_zero_digest(const Digest& digest) noexcept {
  for (const std::uint8_t byte : digest) {
    if (byte != 0u) {
      return false;
    }
  }
  return true;
}

std::string quoted(std::string_view text) { return "\"" + std::string{text} + "\""; }

// A counter rendered for a diagnostic. An unset counter is named as unset
// rather than being rendered as zero.
template <class ScalarT>
std::string counter_text(const ScalarT& value) {
  return value.is_set() ? std::to_string(value.value()) : std::string{"<unset>"};
}

// --- Field readers ----------------------------------------------------------
//
// Every reader records a diagnostic instead of producing a value, so a caller
// gathers every defect and then asks Diagnostics::primary() for the single
// deterministic primary error.

template <class Id>
void read_identity(json::ObjectReader& reader, std::string_view key, Id& out,
                   Diagnostics& diagnostics) {
  const json::Value* field = reader.required(key, json::Type::String);
  if (field == nullptr) {
    return;
  }
  auto parsed = make_id<Id>(field->as_string(), reader.child_path(key));
  if (parsed.has_value()) {
    out = parsed.take();
  } else {
    diagnostics.add(parsed.error());
  }
}

template <class ScalarT>
void read_counter(json::ObjectReader& reader, std::string_view key, ScalarT& out,
                  Diagnostics& diagnostics) {
  const json::Value* field = reader.required(key, json::Type::Integer);
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

void read_timestamp(json::ObjectReader& reader, std::string_view key, Timestamp& out,
                    Diagnostics& diagnostics) {
  const json::Value* field = reader.required(key, json::Type::String);
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

void read_digest(json::ObjectReader& reader, std::string_view key, Digest& out,
                 Diagnostics& diagnostics) {
  const json::Value* field = reader.required(key, json::Type::String);
  if (field == nullptr) {
    return;
  }
  auto parsed = digest_from_hex(field->as_string(), reader.child_path(key));
  if (parsed.has_value()) {
    out = parsed.take();
  } else {
    diagnostics.add(parsed.error());
  }
}

// Reads the expiry encoding: exactly one of "expires_at" and "expires".
void read_expiry(json::ObjectReader& reader, Expiry& out, Diagnostics& diagnostics) {
  // Both members are always claimed, even when one of them is rejected, so that
  // a mutually exclusive member is never also reported as an unknown field.
  const json::Value* at_field = reader.optional("expires_at", json::Type::String);
  const json::Value* never_field = reader.optional("expires", json::Type::String);

  if (at_field != nullptr && never_field != nullptr) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "fields " + quoted("expires_at") + " and " + quoted("expires") +
                        " are mutually exclusive; exactly one must be present",
                    reader.child_path("expires"));
  }

  if (at_field != nullptr) {
    auto parsed = Timestamp::parse_rfc3339(at_field->as_string(), reader.child_path("expires_at"));
    if (parsed.has_value()) {
      out = Expiry::at(parsed.take());
    } else {
      diagnostics.add(parsed.error());
    }
    return;
  }

  if (never_field != nullptr) {
    if (never_field->as_string() != "never") {
      diagnostics.add(ErrorCode::SchemaInvalidEnumValue,
                      "field " + quoted("expires") + " must be " + quoted("never") +
                          " but found " + quoted(never_field->as_string()),
                      reader.child_path("expires"));
      return;
    }
    out = Expiry::never();
    return;
  }

  diagnostics.add(ErrorCode::SchemaMissingField,
                  "one of " + quoted("expires_at") + " or " + quoted("expires") + " is required",
                  reader.child_path("expires_at"));
}

// --- Field checks -----------------------------------------------------------

template <class Id>
void check_identity(const Id& id, std::string_view key, std::string_view path,
                    Diagnostics& diagnostics) {
  const std::string field = json::join_path(path, key);
  if (!id.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField,
                    "field " + quoted(key) + " is not set", field);
    return;
  }
  Status status = validate_identifier(id.view(), field);
  if (!status.has_value()) {
    diagnostics.add(status.error());
  }
}

template <class ScalarT>
void check_counter(const ScalarT& value, std::string_view key, std::string_view path,
                   Diagnostics& diagnostics) {
  if (!value.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "field " + quoted(key) + " is not set",
                    json::join_path(path, key));
  }
}

template <class ScalarT>
void write_counter(json::Value::Object& members, std::string_view key, const ScalarT& value) {
  if (value.is_set()) {
    members.emplace_back(std::string{key}, json::Value{static_cast<std::int64_t>(value.value())});
  }
}

// The canonical serialization of a token. Used to decide whether a second
// record of the same request identity carries exactly the same content.
std::string canonical_token(const AuthorizationToken& token) {
  return json::write_canonical(token.to_json());
}

}  // namespace

// --- Signature mode tokens --------------------------------------------------

std::string_view signature_mode_token(SignatureMode mode) noexcept {
  switch (mode) {
    case SignatureMode::None:
      return "none";
    case SignatureMode::HmacSha256:
      return "hmac_sha256";
  }
  return "unknown";
}

Result<SignatureMode> signature_mode_from_token(std::string_view token) {
  if (token == "none") {
    return SignatureMode::None;
  }
  if (token == "hmac_sha256") {
    return SignatureMode::HmacSha256;
  }
  return Error{ErrorCode::SchemaInvalidEnumValue,
               "unknown signature mode token " + quoted(token), ""};
}

// --- AuthorityBinding -------------------------------------------------------

Status AuthorityBinding::validate(std::string_view path, Diagnostics& diagnostics) const {
  const std::string base{path};

  if (scope.empty()) {
    diagnostics.add(ErrorCode::SchemaValueOutOfRange, "field \"scope\" must not be empty",
                    json::join_path(base, "scope"));
  }
  check_identity(baseline, "baseline", base, diagnostics);
  check_counter(baseline_generation, "baseline_generation", base, diagnostics);
  check_counter(baseline_revision, "baseline_revision", base, diagnostics);
  check_counter(policy_generation, "policy_generation", base, diagnostics);
  check_counter(control_epoch, "control_epoch", base, diagnostics);
  check_counter(commit_sequence, "commit_sequence", base, diagnostics);
  check_identity(plan, "plan", base, diagnostics);
  check_identity(request, "request", base, diagnostics);
  check_counter(incarnation, "incarnation", base, diagnostics);
  if (!issued_at.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "field \"issued_at\" is not set",
                    json::join_path(base, "issued_at"));
  }
  if (!expiry.is_set()) {
    diagnostics.add(ErrorCode::SchemaMissingField, "no expiry is stated",
                    json::join_path(base, "expires_at"));
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value AuthorityBinding::to_json() const {
  // Written in the member order of the schema so that the writer stays readable;
  // the canonical writer sorts members, so the order here is not semantic.
  json::Value::Object members;
  members.emplace_back("scope", scope);
  if (baseline.is_set()) {
    members.emplace_back("baseline", baseline.value());
  }
  write_counter(members, "baseline_generation", baseline_generation);
  write_counter(members, "baseline_revision", baseline_revision);
  members.emplace_back("baseline_digest", digest_to_hex(baseline_digest));
  write_counter(members, "policy_generation", policy_generation);
  write_counter(members, "control_epoch", control_epoch);
  write_counter(members, "commit_sequence", commit_sequence);
  if (plan.is_set()) {
    members.emplace_back("plan", plan.value());
  }
  if (request.is_set()) {
    members.emplace_back("request", request.value());
  }
  write_counter(members, "incarnation", incarnation);
  members.emplace_back("subject_digest", digest_to_hex(subject_digest));
  if (issued_at.is_set()) {
    members.emplace_back("issued_at", issued_at.to_rfc3339());
  }
  if (expiry.is_set()) {
    if (expiry.kind() == Expiry::Kind::Never) {
      members.emplace_back("expires", std::string{"never"});
    } else {
      members.emplace_back("expires_at", expiry.at().to_rfc3339());
    }
  }
  members.emplace_back("signature_mode", std::string{signature_mode_token(mode)});
  return json::Value{std::move(members)};
}

Result<AuthorityBinding> AuthorityBinding::from_json(const json::Value& value,
                                                     std::string_view path) {
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "authority binding must be an object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }

  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  AuthorityBinding binding;

  const json::Value* scope = reader.required("scope", json::Type::String);
  if (scope != nullptr) {
    binding.scope = scope->as_string();
  }
  read_identity(reader, "baseline", binding.baseline, diagnostics);
  read_counter(reader, "baseline_generation", binding.baseline_generation, diagnostics);
  read_counter(reader, "baseline_revision", binding.baseline_revision, diagnostics);
  read_digest(reader, "baseline_digest", binding.baseline_digest, diagnostics);
  read_counter(reader, "policy_generation", binding.policy_generation, diagnostics);
  read_counter(reader, "control_epoch", binding.control_epoch, diagnostics);
  read_counter(reader, "commit_sequence", binding.commit_sequence, diagnostics);
  read_identity(reader, "plan", binding.plan, diagnostics);
  read_identity(reader, "request", binding.request, diagnostics);
  read_counter(reader, "incarnation", binding.incarnation, diagnostics);
  read_digest(reader, "subject_digest", binding.subject_digest, diagnostics);
  read_timestamp(reader, "issued_at", binding.issued_at, diagnostics);
  read_expiry(reader, binding.expiry, diagnostics);

  const json::Value* mode = reader.required("signature_mode", json::Type::String);
  if (mode != nullptr) {
    auto parsed = signature_mode_from_token(mode->as_string());
    if (parsed.has_value()) {
      binding.mode = parsed.take();
    } else {
      diagnostics.add(parsed.error().code(), parsed.error().message(),
                      reader.child_path("signature_mode"));
    }
  }

  reader.finish();
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return binding;
}

std::string AuthorityBinding::to_string() const { return json::write_canonical(to_json()); }

// --- AuthorizationToken -----------------------------------------------------

json::Value AuthorizationToken::to_json() const {
  json::Value::Object members;
  members.emplace_back("binding", binding.to_json());
  members.emplace_back("mac", digest_to_hex(mac));
  return json::Value{std::move(members)};
}

Result<AuthorizationToken> AuthorizationToken::from_json(const json::Value& value,
                                                        std::string_view path) {
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "authorization token must be an object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }

  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  AuthorizationToken token;

  const json::Value* binding = reader.required("binding", json::Type::Object);
  read_digest(reader, "mac", token.mac, diagnostics);
  if (binding != nullptr) {
    auto parsed = AuthorityBinding::from_json(*binding, reader.child_path("binding"));
    if (parsed.has_value()) {
      token.binding = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }

  if (token.binding.mode == SignatureMode::None && !is_zero_digest(token.mac)) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "an unsigned token must carry an all-zero MAC",
                    reader.child_path("mac"));
  }

  reader.finish();
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return token;
}

std::string AuthorizationToken::to_string() const { return json::write_canonical(to_json()); }

// --- AuthorizationAuthority -------------------------------------------------

AuthorizationAuthority::AuthorizationAuthority(std::string key, SignatureMode mode)
    : key_(std::move(key)), mode_(mode) {}

AuthorizationAuthority AuthorizationAuthority::hmac_authority(std::string key) {
  return AuthorizationAuthority{std::move(key), SignatureMode::HmacSha256};
}

Digest AuthorizationAuthority::compute_mac(const AuthorityBinding& binding) const {
  // The MAC covers the canonical bytes of the binding, which never contain the
  // MAC itself, so computing and verifying it is a pure function of the binding.
  return hmac_sha256(key_, json::write_canonical(binding.to_json()));
}

AuthorizationToken AuthorizationAuthority::mint(AuthorityBinding binding) const {
  AuthorizationToken token;
  token.binding = std::move(binding);
  token.binding.mode = mode_;
  if (is_signing()) {
    token.mac = compute_mac(token.binding);
  } else {
    // An unsigned token states that it is unsigned in the token itself, so a
    // verifier can never mistake it for a signed one.
    token.mac = Digest{};
  }
  return token;
}

Status AuthorizationAuthority::verify(const AuthorizationToken& token,
                                      const AuthorityBinding& expected) const {
  const AuthorityBinding& binding = token.binding;

  // 1. signature mode and MAC.
  if (binding.mode != expected.mode) {
    return Error{ErrorCode::AuthorityNotAuthorized,
                 "token signature mode " + quoted(signature_mode_token(binding.mode)) +
                     " does not match the expected mode " +
                     quoted(signature_mode_token(expected.mode)),
                 json::join_path(kTokenBindingPath, "signature_mode")};
  }
  if (is_signing()) {
    if (binding.mode != SignatureMode::HmacSha256) {
      return Error{ErrorCode::AuthorityNotAuthorized,
                   "this authority signs its tokens, so an unsigned token is not authorized",
                   json::join_path(kTokenBindingPath, "signature_mode")};
    }
    if (!constant_time_equal(digest_bytes(token.mac),
                             digest_bytes(compute_mac(binding)))) {
      return Error{ErrorCode::AuthorityNotAuthorized, "token MAC does not match the binding",
                   std::string{kTokenMacPath}};
    }
  } else if (binding.mode != SignatureMode::None) {
    return Error{ErrorCode::AuthorityNotAuthorized,
                 "this authority holds no signing key, so a signed token cannot be verified",
                 json::join_path(kTokenBindingPath, "signature_mode")};
  }

  // 2. scope.
  if (binding.scope != expected.scope) {
    return Error{ErrorCode::AuthorityForeignScope,
                 "token scope " + quoted(binding.scope) + " does not cover the expected scope " +
                     quoted(expected.scope),
                 json::join_path(kTokenBindingPath, "scope")};
  }

  // 3. baseline identity.
  if (binding.baseline != expected.baseline) {
    return Error{ErrorCode::AuthorityForeignScope,
                 "token binds baseline " + quoted(binding.baseline.to_string()) +
                     " but the expected baseline is " + quoted(expected.baseline.to_string()),
                 json::join_path(kTokenBindingPath, "baseline")};
  }

  // 4. plan identity.
  if (binding.plan != expected.plan) {
    return Error{ErrorCode::AuthorityForeignScope,
                 "token binds plan " + quoted(binding.plan.to_string()) +
                     " but the expected plan is " + quoted(expected.plan.to_string()),
                 json::join_path(kTokenBindingPath, "plan")};
  }

  // 5. baseline generation.
  if (binding.baseline_generation != expected.baseline_generation) {
    return Error{ErrorCode::AuthorityStaleGeneration,
                 "token binds baseline generation " + counter_text(binding.baseline_generation) +
                     " but the expected generation is " +
                     counter_text(expected.baseline_generation),
                 json::join_path(kTokenBindingPath, "baseline_generation")};
  }

  // 6. baseline revision.
  if (binding.baseline_revision != expected.baseline_revision) {
    return Error{ErrorCode::AuthorityStaleRevision,
                 "token binds baseline revision " + counter_text(binding.baseline_revision) +
                     " but the expected revision is " +
                     counter_text(expected.baseline_revision),
                 json::join_path(kTokenBindingPath, "baseline_revision")};
  }

  // 7. baseline digest.
  if (!constant_time_equal(digest_bytes(binding.baseline_digest),
                           digest_bytes(expected.baseline_digest))) {
    return Error{ErrorCode::AuthorityDigestMismatch,
                 "token binds baseline digest " + digest_to_hex(binding.baseline_digest) +
                     " but the expected digest is " + digest_to_hex(expected.baseline_digest),
                 json::join_path(kTokenBindingPath, "baseline_digest")};
  }

  // 8. policy generation.
  if (binding.policy_generation != expected.policy_generation) {
    return Error{ErrorCode::AuthorityStalePolicyGeneration,
                 "token binds policy generation " + counter_text(binding.policy_generation) +
                     " but the expected generation is " +
                     counter_text(expected.policy_generation),
                 json::join_path(kTokenBindingPath, "policy_generation")};
  }

  // 9. control epoch.
  if (binding.control_epoch != expected.control_epoch) {
    return Error{ErrorCode::AuthorityStaleEpoch,
                 "token binds control epoch " + counter_text(binding.control_epoch) +
                     " but the expected epoch is " + counter_text(expected.control_epoch),
                 json::join_path(kTokenBindingPath, "control_epoch")};
  }

  // 10. incarnation.
  if (binding.incarnation != expected.incarnation) {
    return Error{ErrorCode::AuthorityIncarnationMismatch,
                 "token binds incarnation " + counter_text(binding.incarnation) +
                     " but the expected incarnation is " + counter_text(expected.incarnation),
                 json::join_path(kTokenBindingPath, "incarnation")};
  }

  // 11. subject digest.
  if (!constant_time_equal(digest_bytes(binding.subject_digest),
                           digest_bytes(expected.subject_digest))) {
    return Error{ErrorCode::AuthorityDigestMismatch,
                 "token binds subject digest " + digest_to_hex(binding.subject_digest) +
                     " but the expected digest is " + digest_to_hex(expected.subject_digest),
                 json::join_path(kTokenBindingPath, "subject_digest")};
  }

  // 12. expiry. Expiry is exclusive: the token is expired at exactly the stated
  // instant. An unstated verification time, or an unstated expiry, is never
  // read as permission.
  if (!binding.expiry.is_set()) {
    return Error{ErrorCode::AuthorityExpiredToken,
                 "the token states no expiry, so it is not accepted as an eternal grant",
                 json::join_path(kTokenBindingPath, "expires_at")};
  }
  if (!expected.issued_at.is_set()) {
    return Error{ErrorCode::AuthorityExpiredToken,
                 "the expected binding states no verification time, so expiry cannot be "
                 "established",
                 json::join_path(kTokenBindingPath, "expires_at")};
  }
  if (binding.expiry.is_expired(expected.issued_at)) {
    return Error{ErrorCode::AuthorityExpiredToken,
                 "the token expired at " + binding.expiry.to_string(),
                 json::join_path(kTokenBindingPath, "expires_at")};
  }

  return ok_status();
}

// --- AuthorizationRegistry --------------------------------------------------

Result<AuthorizationRegistry::RecordOutcome> AuthorizationRegistry::record(
    AuthorizationToken token) {
  const RequestId& request = token.binding.request;
  if (!request.is_set()) {
    return Error{ErrorCode::InvalidArgument,
                 "an authorization token must carry a request identity",
                 "authorization/request"};
  }
  if (token.binding.mode == SignatureMode::None && !is_zero_digest(token.mac)) {
    return Error{ErrorCode::SchemaInconsistentDocument,
                 "an unsigned authorization token must carry an all-zero MAC",
                 "authorization/mac"};
  }

  const auto found = items_.find(request);
  if (found != items_.end()) {
    if (canonical_token(found->second) == canonical_token(token)) {
      // The same request identity with exactly the same content is the
      // lost-response retry case.
      return RecordOutcome::IdempotentReplay;
    }
    return Error{ErrorCode::AuthorityReplayedToken,
                 "request identity " + quoted(request.to_string()) +
                     " is already recorded with a different authorization token",
                 "authorization/request"};
  }

  items_.emplace(request, std::move(token));
  return RecordOutcome::Recorded;
}

const AuthorizationToken* AuthorizationRegistry::find(const RequestId& request) const {
  const auto found = items_.find(request);
  if (found == items_.end()) {
    return nullptr;
  }
  return &found->second;
}

Status AuthorizationRegistry::validate(std::string_view path, Diagnostics& diagnostics) const {
  std::size_t index = 0;
  for (const auto& entry : items_) {
    const std::string element = json::join_index(path, index);
    const std::string binding_path = json::join_path(element, "binding");

    if (!entry.first.is_set()) {
      diagnostics.add(ErrorCode::SchemaMissingField,
                      "an authorization entry states no request identity",
                      json::join_path(binding_path, "request"));
    } else if (entry.first != entry.second.binding.request) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "authorization entry is filed under request identity " +
                          quoted(entry.first.to_string()) + " but its token states " +
                          quoted(entry.second.binding.request.to_string()),
                      json::join_path(binding_path, "request"));
    }
    if (entry.second.binding.mode == SignatureMode::None &&
        !is_zero_digest(entry.second.mac)) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "an unsigned authorization token must carry an all-zero MAC",
                      json::join_path(element, "mac"));
    }
    entry.second.binding.validate(binding_path, diagnostics);
    ++index;
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value AuthorizationRegistry::to_json() const {
  json::Value::Array out;
  out.reserve(items_.size());
  for (const auto& entry : items_) {
    out.push_back(entry.second.to_json());
  }
  return json::Value{std::move(out)};
}

Result<AuthorizationRegistry> AuthorizationRegistry::from_json(const json::Value& value,
                                                              std::string_view path) {
  if (!value.is_array()) {
    return Error{ErrorCode::SchemaWrongType,
                 "authorizations must be an array but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }

  Diagnostics diagnostics;
  AuthorizationRegistry registry;
  bool have_previous = false;
  RequestId previous;
  // Duplicates are detected against every earlier entry, not only the adjacent
  // one, so a repeat that is also out of order is still reported as a repeat.
  std::set<RequestId> seen;

  const json::Value::Array& elements = value.as_array();
  for (std::size_t index = 0; index < elements.size(); ++index) {
    const std::string element_path = json::join_index(path, index);
    const std::string request_path =
        json::join_path(json::join_path(element_path, "binding"), "request");
    auto parsed = AuthorizationToken::from_json(elements[index], element_path);
    if (!parsed.has_value()) {
      diagnostics.add(parsed.error());
      continue;
    }
    AuthorizationToken token = parsed.take();
    const RequestId& request = token.binding.request;
    if (have_previous && request < previous) {
      diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                      "authorization entries must be in ascending request identity order, but " +
                          quoted(request.to_string()) + " follows " +
                          quoted(previous.to_string()),
                      request_path);
    }
    previous = request;
    have_previous = true;
    if (!seen.insert(request).second) {
      diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                      "duplicate request identity " + quoted(request.to_string()) +
                          " in the authorization registry",
                      request_path);
      continue;
    }
    registry.items_.emplace(request, std::move(token));
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return registry;
}

}  // namespace summon::fbm
