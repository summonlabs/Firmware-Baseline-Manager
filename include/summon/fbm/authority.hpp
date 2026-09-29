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
#include <optional>
#include <string>
#include <string_view>

#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm {

enum class SignatureMode : std::uint8_t {
  // The token is content-bound and digest-bound but carries no signature. This
  // is recorded in the token itself so that a verifier can never mistake an
  // unsigned token for a signed one.
  None = 0,
  HmacSha256 = 1,
};

std::string_view signature_mode_token(SignatureMode mode) noexcept;
Result<SignatureMode> signature_mode_from_token(std::string_view token);

// Everything a token binds to. Verification compares each field against the
// state the caller is about to mutate, so a token minted against any other
// identity, generation, revision, digest, epoch, incarnation, or plan is
// rejected instead of silently inherited.
struct AuthorityBinding {
  std::string scope;
  BaselineId baseline;
  BaselineGeneration baseline_generation;
  Revision baseline_revision;
  Digest baseline_digest{};
  PolicyGeneration policy_generation;
  ControlEpoch control_epoch;
  CommitSequence commit_sequence;
  PlanId plan;
  RequestId request;
  IncarnationId incarnation;
  // Digest over the exact planned mutation, so two different mutations never
  // share a token.
  Digest subject_digest{};
  Timestamp issued_at;
  Expiry expiry;
  SignatureMode mode = SignatureMode::None;

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<AuthorityBinding> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

struct AuthorizationToken {
  AuthorityBinding binding;
  // Zero when binding.mode is None.
  Digest mac{};

  json::Value to_json() const;
  static Result<AuthorizationToken> from_json(const json::Value& value, std::string_view path);
  std::string to_string() const;
};

// Mints and verifies authorization tokens. The signing key, when one is
// configured, is supplied by the operator at run time, is never stored by the
// library, and never appears in a token, a log line, or an error message.
class AuthorizationAuthority {
 public:
  AuthorizationAuthority() = default;
  AuthorizationAuthority(std::string key, SignatureMode mode);

  // A key configured but no signature required still produces signed tokens;
  // signature mode is recorded per token.
  static AuthorizationAuthority unsigned_authority() { return AuthorizationAuthority{}; }
  static AuthorizationAuthority hmac_authority(std::string key);

  bool is_signing() const noexcept { return mode_ == SignatureMode::HmacSha256; }

  AuthorizationToken mint(AuthorityBinding binding) const;

  // Verifies a token against the state the caller holds. Checks run in a fixed
  // order and the first failure is returned, so the same token and the same
  // state always produce the same error:
  //
  //   1. signature mode / MAC                    -> AuthorityNotAuthorized
  //   2. scope                                   -> AuthorityForeignScope
  //   3. baseline identity                       -> AuthorityForeignScope
  //   4. plan identity                           -> AuthorityForeignScope
  //   5. baseline generation                     -> AuthorityStaleGeneration
  //   6. baseline revision                       -> AuthorityStaleRevision
  //   7. baseline digest                         -> AuthorityDigestMismatch
  //   8. policy generation                       -> AuthorityStalePolicyGeneration
  //   9. control epoch                           -> AuthorityStaleEpoch
  //  10. incarnation                              -> AuthorityIncarnationMismatch
  //  11. subject digest                           -> AuthorityDigestMismatch
  //  12. expiry                                   -> AuthorityExpiredToken
  Status verify(const AuthorizationToken& token, const AuthorityBinding& expected) const;

  // Recomputes the MAC over the canonical form of the binding minus the MAC.
  Digest compute_mac(const AuthorityBinding& binding) const;

 private:
  std::string key_;
  SignatureMode mode_ = SignatureMode::None;
};

// Durable record of issued tokens. Replaying the same request identity with the
// same content is an idempotent replay; replaying it with different content is
// rejected.
class AuthorizationRegistry {
 public:
  AuthorizationRegistry() = default;

  enum class RecordOutcome : std::uint8_t {
    Recorded = 0,
    IdempotentReplay = 1,
  };

  Result<RecordOutcome> record(AuthorizationToken token);
  const AuthorizationToken* find(const RequestId& request) const;
  bool contains(const RequestId& request) const { return find(request) != nullptr; }

  bool empty() const noexcept { return items_.empty(); }
  std::size_t size() const noexcept { return items_.size(); }
  const std::map<RequestId, AuthorizationToken>& items() const noexcept { return items_; }

  Status validate(std::string_view path, Diagnostics& diagnostics) const;
  json::Value to_json() const;
  static Result<AuthorizationRegistry> from_json(const json::Value& value, std::string_view path);

 private:
  std::map<RequestId, AuthorizationToken> items_;
};

}  // namespace summon::fbm
