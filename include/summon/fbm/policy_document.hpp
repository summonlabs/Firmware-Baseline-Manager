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
#include <vector>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/baseline.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/version.hpp"

namespace summon::fbm {

// A canonical policy document: the unit of authored firmware baseline policy.
//
// The document is strict JSON with an exact schema. Its identity is the SHA-256
// of its canonical serialization, so two documents that differ only in key
// order or whitespace have the same identity, and any semantic change produces
// a different one.
//
// This repository does not own signing keys and never generates one. A detached
// HMAC-SHA256 signature is supported when the operator supplies a key at run
// time; when no key is configured, verification reports "not configured" and
// never "valid".
class PolicyDocument {
 public:
  static constexpr std::string_view kSchemaName = "summon.fbm.policy";

  PolicyDocument() = default;
  explicit PolicyDocument(std::vector<Baseline> baselines);

  unsigned schema_version() const noexcept { return schema_version_; }
  const std::vector<Baseline>& baselines() const noexcept { return baselines_; }

  Status validate(std::string_view path, Diagnostics& diagnostics) const;

  json::Value to_json() const;
  static Result<PolicyDocument> from_json(const json::Value& value, std::string_view path);

  // Strict text parse. Rejects a byte order mark, invalid UTF-8, trailing
  // content, and everything else the JSON reader rejects.
  static Result<PolicyDocument> parse(std::string_view text, std::string_view path);

  // Canonical bytes: no insignificant whitespace, sorted object members. These
  // exact bytes are what the content digest and any signature cover.
  std::string canonical_bytes() const;
  Digest content_digest() const;

 private:
  unsigned schema_version_ = kPolicySchemaVersion;
  std::vector<Baseline> baselines_;
};

enum class SignatureCheck : std::uint8_t {
  // No key was configured, so nothing was verified. This is reported verbatim
  // and is never reported as Valid.
  NotConfigured = 0,
  Valid = 1,
  Invalid = 2,
};

std::string_view signature_check_token(SignatureCheck check) noexcept;

// A detached signature over the canonical bytes of a policy document.
struct DetachedSignature {
  SignatureMode mode = SignatureMode::None;
  Digest mac{};

  json::Value to_json() const;
  static Result<DetachedSignature> from_json(const json::Value& value, std::string_view path);
  std::string to_text() const;
  static Result<DetachedSignature> parse(std::string_view text, std::string_view path);
};

// Computes the detached signature of canonical document bytes with an
// operator-supplied key.
DetachedSignature sign_policy_document(std::string_view canonical_bytes, std::string_view key);

// Verifies a detached signature. An empty key reports NotConfigured.
SignatureCheck verify_policy_signature(std::string_view canonical_bytes,
                                       const DetachedSignature& signature,
                                       std::string_view key);

}  // namespace summon::fbm
