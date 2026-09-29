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

#include "summon/fbm/policy_document.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/baseline.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/version.hpp"

namespace summon::fbm {
namespace {

// The schema marker and schema version of a detached signature document. A
// signature that states a different marker or version is a different document,
// not this one read leniently.
constexpr std::string_view kSignatureSchemaName = "summon.fbm.signature";
constexpr unsigned kSignatureSchemaVersion = 1u;

std::string quoted(std::string_view text) { return "\"" + std::string{text} + "\""; }

// A digest rendered as raw bytes for the constant-time comparison helper, so
// that no hexadecimal rendering decision can change a verification result.
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

}  // namespace

// --- PolicyDocument ---------------------------------------------------------

PolicyDocument::PolicyDocument(std::vector<Baseline> baselines)
    : baselines_(std::move(baselines)) {}

Status PolicyDocument::validate(std::string_view path, Diagnostics& diagnostics) const {
  const std::string base{path};

  // A document states the schema it was written against. The schema version is
  // fixed at construction and checked here as an invariant of the value; a
  // document read from text is rejected before it can reach this point.
  if (schema_version_ != kPolicySchemaVersion) {
    diagnostics.add(ErrorCode::FormatVersionUnsupported,
                    "policy document schema_version " + std::to_string(schema_version_) +
                        " is not supported by this build, which writes " +
                        std::to_string(kPolicySchemaVersion),
                    json::join_path(base, "schema_version"));
  }

  // Baseline identities must be unique: two definitions of one baseline would
  // make "the" baseline for an identity ambiguous. The order of the array is
  // content, not a normalized form, so it is preserved exactly as authored and
  // a repeat is detected wherever it appears, not only next to its twin.
  const std::string baselines_path = json::join_path(base, "baselines");
  std::set<BaselineId> seen;
  for (std::size_t index = 0; index < baselines_.size(); ++index) {
    const Baseline& baseline = baselines_[index];
    const std::string element_path = json::join_index(baselines_path, index);
    if (baseline.id.is_set() && !seen.insert(baseline.id).second) {
      diagnostics.add(ErrorCode::SchemaDuplicateIdentifier,
                      "baseline " + quoted(baseline.id.to_string()) +
                          " is defined more than once in this document",
                      json::join_path(element_path, "id"));
    }
    baseline.validate(element_path, diagnostics);
  }

  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return ok_status();
}

json::Value PolicyDocument::to_json() const {
  json::Value::Object members;
  members.emplace_back("schema", std::string{kSchemaName});
  members.emplace_back("schema_version", static_cast<std::int64_t>(schema_version_));
  json::Value::Array baselines;
  baselines.reserve(baselines_.size());
  for (const Baseline& baseline : baselines_) {
    baselines.push_back(baseline.to_json());
  }
  members.emplace_back("baselines", json::Value{std::move(baselines)});
  return json::Value{std::move(members)};
}

Result<PolicyDocument> PolicyDocument::from_json(const json::Value& value, std::string_view path) {
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "policy document must be an object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }

  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  PolicyDocument document;

  const json::Value* schema = reader.required("schema", json::Type::String);
  if (schema != nullptr && schema->as_string() != kSchemaName) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "policy document schema must be " + quoted(kSchemaName) + " but found " +
                        quoted(schema->as_string()),
                    reader.child_path("schema"));
  }

  const json::Value* schema_version = reader.required("schema_version", json::Type::Integer);
  if (schema_version != nullptr) {
    const std::int64_t raw = schema_version->as_integer();
    if (raw < 0 ||
        static_cast<std::uint64_t>(raw) >
            static_cast<std::uint64_t>(std::numeric_limits<unsigned>::max())) {
      diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                      "field \"schema_version\" must be a non-negative integer",
                      reader.child_path("schema_version"));
    } else if (static_cast<unsigned>(raw) != kPolicySchemaVersion) {
      diagnostics.add(ErrorCode::FormatVersionUnsupported,
                      "policy document schema_version " + std::to_string(raw) +
                          " is not supported by this build, which writes " +
                          std::to_string(kPolicySchemaVersion),
                      reader.child_path("schema_version"));
    } else {
      document.schema_version_ = static_cast<unsigned>(raw);
    }
  }

  const json::Value* baselines = reader.required("baselines", json::Type::Array);
  if (baselines != nullptr) {
    const std::string baselines_path = reader.child_path("baselines");
    const json::Value::Array& elements = baselines->as_array();
    for (std::size_t index = 0; index < elements.size(); ++index) {
      auto parsed = Baseline::from_json(elements[index], json::join_index(baselines_path, index));
      if (parsed.has_value()) {
        document.baselines_.push_back(parsed.take());
      } else {
        diagnostics.add(parsed.error());
      }
    }
  }

  reader.finish();
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }

  // The document-level rules (unique baseline identities, and every baseline's
  // own rules) are enforced by validate() so that there is a single source of
  // truth for what a valid policy document is.
  Status status = document.validate(path, diagnostics);
  if (!status.has_value()) {
    return status.error();
  }
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return document;
}

Result<PolicyDocument> PolicyDocument::parse(std::string_view text, std::string_view path) {
  auto value = json::parse(text, json::Limits{}, path);
  if (!value.has_value()) {
    return value.error();
  }
  return PolicyDocument::from_json(value.value(), path);
}

std::string PolicyDocument::canonical_bytes() const { return json::write_canonical(to_json()); }

Digest PolicyDocument::content_digest() const { return Sha256::of(canonical_bytes()); }

// --- Signatures -------------------------------------------------------------

std::string_view signature_check_token(SignatureCheck check) noexcept {
  switch (check) {
    case SignatureCheck::NotConfigured:
      return "not_configured";
    case SignatureCheck::Valid:
      return "valid";
    case SignatureCheck::Invalid:
      return "invalid";
  }
  return "unknown";
}

json::Value DetachedSignature::to_json() const {
  json::Value::Object members;
  members.emplace_back("schema", std::string{kSignatureSchemaName});
  members.emplace_back("schema_version", static_cast<std::int64_t>(kSignatureSchemaVersion));
  members.emplace_back("mode", std::string{signature_mode_token(mode)});
  members.emplace_back("mac", digest_to_hex(mac));
  return json::Value{std::move(members)};
}

Result<DetachedSignature> DetachedSignature::from_json(const json::Value& value,
                                                       std::string_view path) {
  if (!value.is_object()) {
    return Error{ErrorCode::SchemaWrongType,
                 "detached signature must be an object but found " +
                     std::string{json::type_name(value.type())},
                 std::string{path}};
  }

  Diagnostics diagnostics;
  json::ObjectReader reader(value, std::string{path}, diagnostics);
  DetachedSignature signature;

  const json::Value* schema = reader.required("schema", json::Type::String);
  if (schema != nullptr && schema->as_string() != kSignatureSchemaName) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "detached signature schema must be " + quoted(kSignatureSchemaName) +
                        " but found " + quoted(schema->as_string()),
                    reader.child_path("schema"));
  }

  const json::Value* schema_version = reader.required("schema_version", json::Type::Integer);
  if (schema_version != nullptr) {
    const std::int64_t raw = schema_version->as_integer();
    if (raw < 0 ||
        static_cast<std::uint64_t>(raw) >
            static_cast<std::uint64_t>(std::numeric_limits<unsigned>::max())) {
      diagnostics.add(ErrorCode::SchemaValueOutOfRange,
                      "field \"schema_version\" must be a non-negative integer",
                      reader.child_path("schema_version"));
    } else if (static_cast<unsigned>(raw) != kSignatureSchemaVersion) {
      diagnostics.add(ErrorCode::FormatVersionUnsupported,
                      "detached signature schema_version " + std::to_string(raw) +
                          " is not supported by this build, which writes " +
                          std::to_string(kSignatureSchemaVersion),
                      reader.child_path("schema_version"));
    }
  }

  const json::Value* mode = reader.required("mode", json::Type::String);
  if (mode != nullptr) {
    auto parsed = signature_mode_from_token(mode->as_string());
    if (parsed.has_value()) {
      signature.mode = parsed.take();
    } else {
      diagnostics.add(parsed.error().code(), parsed.error().message(),
                      reader.child_path("mode"));
    }
  }

  const json::Value* mac = reader.required("mac", json::Type::String);
  if (mac != nullptr) {
    auto parsed = digest_from_hex(mac->as_string(), reader.child_path("mac"));
    if (parsed.has_value()) {
      signature.mac = parsed.take();
    } else {
      diagnostics.add(parsed.error());
    }
  }

  // An unsigned signature document states that it signs nothing. A MAC that is
  // not all zero would be read as a signature that was never computed.
  if (signature.mode == SignatureMode::None && mac != nullptr && !is_zero_digest(signature.mac)) {
    diagnostics.add(ErrorCode::SchemaInconsistentDocument,
                    "an unsigned signature must carry an all-zero MAC",
                    reader.child_path("mac"));
  }

  reader.finish();
  if (!diagnostics.empty()) {
    return diagnostics.primary();
  }
  return signature;
}

std::string DetachedSignature::to_text() const { return json::write_canonical(to_json()); }

Result<DetachedSignature> DetachedSignature::parse(std::string_view text, std::string_view path) {
  auto value = json::parse(text, json::Limits{}, path);
  if (!value.has_value()) {
    return value.error();
  }
  return DetachedSignature::from_json(value.value(), path);
}

DetachedSignature sign_policy_document(std::string_view canonical_bytes, std::string_view key) {
  DetachedSignature signature;
  signature.mode = SignatureMode::HmacSha256;
  signature.mac = hmac_sha256(key, canonical_bytes);
  return signature;
}

SignatureCheck verify_policy_signature(std::string_view canonical_bytes,
                                       const DetachedSignature& signature,
                                       std::string_view key) {
  if (key.empty()) {
    // No key was configured, so nothing was verified. This is reported verbatim
    // and is never reported as Valid.
    return SignatureCheck::NotConfigured;
  }
  if (signature.mode != SignatureMode::HmacSha256) {
    return SignatureCheck::Invalid;
  }
  const Digest computed = hmac_sha256(key, canonical_bytes);
  if (!constant_time_equal(digest_bytes(computed), digest_bytes(signature.mac))) {
    return SignatureCheck::Invalid;
  }
  return SignatureCheck::Valid;
}

}  // namespace summon::fbm
