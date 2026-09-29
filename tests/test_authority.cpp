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

#include "check.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

// json is a namespace, so it is aliased rather than imported with a
// using-declaration.
namespace json = summon::fbm::json;

namespace {

using summon::fbm::AuthorizationAuthority;
using summon::fbm::AuthorizationRegistry;
using summon::fbm::AuthorizationToken;
using summon::fbm::AuthorityBinding;
using summon::fbm::BaselineGeneration;
using summon::fbm::BaselineId;
using summon::fbm::CommitSequence;
using summon::fbm::ControlEpoch;
using summon::fbm::Digest;
using summon::fbm::digest_from_hex;
using summon::fbm::digest_to_hex;
using summon::fbm::ErrorCode;
using summon::fbm::Expiry;
using summon::fbm::IncarnationId;
using summon::fbm::PlanId;
using summon::fbm::PolicyGeneration;
using summon::fbm::RequestId;
using summon::fbm::Revision;
using summon::fbm::signature_mode_from_token;
using summon::fbm::signature_mode_token;
using summon::fbm::SignatureMode;
using summon::fbm::Timestamp;

constexpr std::string_view kBaselineDigestHex =
    "1111111111111111111111111111111111111111111111111111111111111111";
constexpr std::string_view kSubjectDigestHex =
    "2222222222222222222222222222222222222222222222222222222222222222";
constexpr std::string_view kOtherDigestHex =
    "3333333333333333333333333333333333333333333333333333333333333333";
constexpr std::string_view kKey = "operator-supplied-key";

// Fixed instants. The library never reads a clock, so every test is a pure
// function of these values.
constexpr std::uint64_t kIssuedAt = 1700000000ull;
constexpr std::uint64_t kExpiresAt = kIssuedAt + 60000000000ull;

Digest digest_of(std::string_view hex) {
  auto parsed = digest_from_hex(hex, "test");
  REQUIRE(parsed.has_value());
  return parsed.value();
}

bool mac_is_zero(const Digest& mac) { return digest_to_hex(mac) == std::string(64, '0'); }

AuthorityBinding sample_binding() {
  AuthorityBinding binding;
  binding.scope = "cohort/wave-1/rollout";
  binding.baseline = BaselineId{std::string{"gpu-h100-train"}};
  binding.baseline_generation = BaselineGeneration{3u};
  binding.baseline_revision = Revision{5u};
  binding.baseline_digest = digest_of(kBaselineDigestHex);
  binding.policy_generation = PolicyGeneration{4u};
  binding.control_epoch = ControlEpoch{9u};
  binding.commit_sequence = CommitSequence{11u};
  binding.plan = PlanId{std::string{"plan-1"}};
  binding.request = RequestId{std::string{"req-1"}};
  binding.incarnation = IncarnationId{3u};
  binding.subject_digest = digest_of(kSubjectDigestHex);
  binding.issued_at = Timestamp::from_unix_nanos(kIssuedAt);
  binding.expiry = Expiry::at(Timestamp::from_unix_nanos(kExpiresAt));
  binding.mode = SignatureMode::None;
  return binding;
}

// Wraps a set of binding members into a complete token document with an
// all-zero MAC, which is the encoding an unsigned token uses.
json::Value wrap_token(json::Value::Object binding_members) {
  json::Value::Object members;
  members.emplace_back("binding", json::Value{std::move(binding_members)});
  members.emplace_back("mac", digest_to_hex(Digest{}));
  return json::Value{std::move(members)};
}

// A token document whose binding has one member added or replaced. json::Value
// exposes only a const find(), so the members are copied out and wrapped back.
json::Value token_json_with(const AuthorityBinding& binding, std::string_view key,
                            json::Value value) {
  json::Value::Object members = binding.to_json().as_object();
  bool replaced = false;
  for (json::Value::Member& member : members) {
    if (member.first == key) {
      member.second = std::move(value);
      replaced = true;
      break;
    }
  }
  if (!replaced) {
    members.emplace_back(std::string{key}, std::move(value));
  }
  return wrap_token(std::move(members));
}

// A token document whose binding omits one member entirely.
json::Value token_json_without(const AuthorityBinding& binding, std::string_view key) {
  json::Value::Object members = binding.to_json().as_object();
  for (std::size_t index = 0; index < members.size(); ++index) {
    if (members[index].first == key) {
      members.erase(members.begin() + static_cast<std::ptrdiff_t>(index));
      break;
    }
  }
  return wrap_token(std::move(members));
}

}  // namespace

// --- Signature mode tokens --------------------------------------------------

FBM_TEST(authority_signature_mode_tokens_are_stable) {
  CHECK_EQ(signature_mode_token(SignatureMode::None), std::string_view{"none"});
  CHECK_EQ(signature_mode_token(SignatureMode::HmacSha256), std::string_view{"hmac_sha256"});
  CHECK_EQ(signature_mode_token(static_cast<SignatureMode>(9)), std::string_view{"unknown"});

  auto none = signature_mode_from_token("none");
  CHECK_OK(none);
  CHECK(none.value() == SignatureMode::None);

  auto hmac = signature_mode_from_token("hmac_sha256");
  CHECK_OK(hmac);
  CHECK(hmac.value() == SignatureMode::HmacSha256);

  auto unknown = signature_mode_from_token("hmac");
  CHECK_ERROR(unknown, ErrorCode::SchemaInvalidEnumValue);
  CHECK(unknown.error().message().find("hmac") != std::string::npos);
}

// --- Binding validation -----------------------------------------------------

FBM_TEST(authority_binding_validate_accepts_the_schema_shape) {
  const AuthorityBinding binding = sample_binding();
  summon::fbm::Diagnostics diagnostics;
  CHECK_OK(binding.validate("/binding", diagnostics));
  CHECK(diagnostics.empty());
}

FBM_TEST(authority_binding_validate_rejects_missing_and_invalid_members) {
  {
    AuthorityBinding binding = sample_binding();
    binding.scope.clear();
    summon::fbm::Diagnostics diagnostics;
    CHECK(!binding.validate("/binding", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaValueOutOfRange);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/binding/scope"});
  }
  {
    AuthorityBinding binding = sample_binding();
    binding.baseline = BaselineId::unset();
    summon::fbm::Diagnostics diagnostics;
    CHECK(!binding.validate("/binding", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaMissingField);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/binding/baseline"});
  }
  {
    AuthorityBinding binding = sample_binding();
    binding.baseline = BaselineId{std::string{"not an identifier"}};
    summon::fbm::Diagnostics diagnostics;
    CHECK(!binding.validate("/binding", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInvalidIdentifier);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/binding/baseline"});
  }
  {
    AuthorityBinding binding = sample_binding();
    binding.policy_generation = PolicyGeneration::unset();
    summon::fbm::Diagnostics diagnostics;
    CHECK(!binding.validate("/binding", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaMissingField);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/binding/policy_generation"});
  }
  {
    AuthorityBinding binding = sample_binding();
    binding.issued_at = Timestamp{};
    summon::fbm::Diagnostics diagnostics;
    CHECK(!binding.validate("/binding", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaMissingField);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/binding/issued_at"});
  }
  {
    AuthorityBinding binding = sample_binding();
    binding.expiry = Expiry{};
    summon::fbm::Diagnostics diagnostics;
    CHECK(!binding.validate("/binding", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaMissingField);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/binding/expires_at"});
  }
}

// --- Mint and verify --------------------------------------------------------

FBM_TEST(authority_mint_and_verify_a_matching_binding) {
  const AuthorityBinding binding = sample_binding();

  const AuthorizationAuthority unsigned_authority = AuthorizationAuthority::unsigned_authority();
  CHECK(!unsigned_authority.is_signing());
  const AuthorizationToken unsigned_token = unsigned_authority.mint(binding);
  CHECK(unsigned_token.binding.mode == SignatureMode::None);
  CHECK(mac_is_zero(unsigned_token.mac));
  CHECK_OK(unsigned_authority.verify(unsigned_token, binding));

  const AuthorizationAuthority signed_authority = AuthorizationAuthority::hmac_authority(std::string{kKey});
  CHECK(signed_authority.is_signing());
  const AuthorizationToken signed_token = signed_authority.mint(binding);
  CHECK(signed_token.binding.mode == SignatureMode::HmacSha256);
  CHECK(!mac_is_zero(signed_token.mac));
  CHECK_EQ(digest_to_hex(signed_token.mac),
           digest_to_hex(signed_authority.compute_mac(signed_token.binding)));

  // The signed bytes are the canonical binding, which never contains the MAC,
  // and which does contain the signature mode the authority recorded. Editing
  // the mode after minting therefore breaks the MAC rather than downgrading it.
  CHECK_EQ(digest_to_hex(signed_authority.compute_mac(signed_token.binding)),
           digest_to_hex(signed_token.mac));
  AuthorityBinding mode_edited = signed_token.binding;
  mode_edited.mode = SignatureMode::None;
  CHECK(digest_to_hex(signed_authority.compute_mac(mode_edited)) !=
        digest_to_hex(signed_token.mac));

  AuthorityBinding expected = binding;
  expected.mode = SignatureMode::HmacSha256;
  CHECK_OK(signed_authority.verify(signed_token, expected));

  // A different key produces a different MAC and cannot verify.
  const AuthorizationAuthority other_authority = AuthorizationAuthority::hmac_authority("other-key");
  CHECK(!other_authority.verify(signed_token, expected).has_value());
  CHECK_EQ(other_authority.verify(signed_token, expected).error().code(),
           ErrorCode::AuthorityNotAuthorized);
}

FBM_TEST(authority_verify_check_one_signature_mode_and_mac) {
  const AuthorityBinding binding = sample_binding();

  // An unsigned token presented where a signature is required fails check 1,
  // and it fails there before any other field is considered.
  const AuthorizationAuthority unsigned_authority = AuthorizationAuthority::unsigned_authority();
  const AuthorizationToken unsigned_token = unsigned_authority.mint(binding);
  AuthorityBinding signed_expectation = binding;
  signed_expectation.mode = SignatureMode::HmacSha256;
  signed_expectation.scope = "somewhere/else";
  signed_expectation.baseline_generation = BaselineGeneration{99u};
  signed_expectation.issued_at = Timestamp::from_unix_nanos(kExpiresAt + 1u);
  CHECK_ERROR(unsigned_authority.verify(unsigned_token, signed_expectation),
              ErrorCode::AuthorityNotAuthorized);

  // A signed token whose MAC was altered fails check 1.
  const AuthorizationAuthority signed_authority = AuthorizationAuthority::hmac_authority(std::string{kKey});
  AuthorizationToken tampered = signed_authority.mint(binding);
  tampered.mac[0] = static_cast<std::uint8_t>(tampered.mac[0] ^ 0x01u);
  AuthorityBinding expected = binding;
  expected.mode = SignatureMode::HmacSha256;
  CHECK_ERROR(signed_authority.verify(tampered, expected), ErrorCode::AuthorityNotAuthorized);

  // An authority with no key cannot verify a signed token at all.
  const AuthorizationToken signed_token = signed_authority.mint(binding);
  CHECK_ERROR(unsigned_authority.verify(signed_token, binding), ErrorCode::AuthorityNotAuthorized);
}

FBM_TEST(authority_verify_check_two_through_twelve_each_fail_alone) {
  const AuthorizationAuthority authority = AuthorizationAuthority::unsigned_authority();
  const AuthorizationToken token = authority.mint(sample_binding());
  AuthorityBinding expected = sample_binding();
  CHECK_OK(authority.verify(token, expected));

  // 2. scope
  expected = sample_binding();
  expected.scope = "cohort/wave-2/rollout";
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityForeignScope);
  CHECK_EQ(authority.verify(token, expected).error().path(), std::string{"token/binding/scope"});

  // 3. baseline identity
  expected = sample_binding();
  expected.baseline = BaselineId{std::string{"gpu-a100-train"}};
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityForeignScope);

  // 4. plan identity
  expected = sample_binding();
  expected.plan = PlanId{std::string{"plan-2"}};
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityForeignScope);

  // 5. baseline generation
  expected = sample_binding();
  expected.baseline_generation = BaselineGeneration{4u};
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStaleGeneration);

  // 6. baseline revision
  expected = sample_binding();
  expected.baseline_revision = Revision{6u};
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStaleRevision);

  // 7. baseline digest
  expected = sample_binding();
  expected.baseline_digest = digest_of(kOtherDigestHex);
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityDigestMismatch);
  CHECK_EQ(authority.verify(token, expected).error().path(),
           std::string{"token/binding/baseline_digest"});

  // 8. policy generation
  expected = sample_binding();
  expected.policy_generation = PolicyGeneration{5u};
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStalePolicyGeneration);

  // 9. control epoch
  expected = sample_binding();
  expected.control_epoch = ControlEpoch{10u};
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStaleEpoch);

  // 10. incarnation
  expected = sample_binding();
  expected.incarnation = IncarnationId{4u};
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityIncarnationMismatch);

  // 11. subject digest
  expected = sample_binding();
  expected.subject_digest = digest_of(kOtherDigestHex);
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityDigestMismatch);
  CHECK_EQ(authority.verify(token, expected).error().path(),
           std::string{"token/binding/subject_digest"});

  // 12. expiry
  expected = sample_binding();
  expected.issued_at = Timestamp::from_unix_nanos(kExpiresAt + 1u);
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityExpiredToken);
}

FBM_TEST(authority_verify_precedence_is_the_documented_order) {
  const AuthorizationAuthority authority = AuthorizationAuthority::unsigned_authority();
  const AuthorizationToken token = authority.mint(sample_binding());

  // Every field wrong at once: the earliest documented check wins.
  AuthorityBinding expected = sample_binding();
  expected.scope = "elsewhere";
  expected.baseline = BaselineId{std::string{"other-baseline"}};
  expected.plan = PlanId{std::string{"other-plan"}};
  expected.baseline_generation = BaselineGeneration{99u};
  expected.baseline_revision = Revision{99u};
  expected.baseline_digest = digest_of(kOtherDigestHex);
  expected.policy_generation = PolicyGeneration{99u};
  expected.control_epoch = ControlEpoch{99u};
  expected.incarnation = IncarnationId{99u};
  expected.subject_digest = digest_of(kOtherDigestHex);
  expected.issued_at = Timestamp::from_unix_nanos(kExpiresAt);
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityForeignScope);

  // Without the scope defect, the baseline identity is next.
  expected.scope = sample_binding().scope;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityForeignScope);
  CHECK_EQ(authority.verify(token, expected).error().path(), std::string{"token/binding/baseline"});

  // Then the plan, then generation, then revision.
  expected.baseline = sample_binding().baseline;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityForeignScope);
  expected.plan = sample_binding().plan;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStaleGeneration);
  expected.baseline_generation = sample_binding().baseline_generation;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStaleRevision);
  expected.baseline_revision = sample_binding().baseline_revision;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityDigestMismatch);
  expected.baseline_digest = sample_binding().baseline_digest;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStalePolicyGeneration);
  expected.policy_generation = sample_binding().policy_generation;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityStaleEpoch);
  expected.control_epoch = sample_binding().control_epoch;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityIncarnationMismatch);
  expected.incarnation = sample_binding().incarnation;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityDigestMismatch);
  expected.subject_digest = sample_binding().subject_digest;
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityExpiredToken);
  expected.issued_at = sample_binding().issued_at;
  CHECK_OK(authority.verify(token, expected));

  // The result is a pure function of the token and the expected binding: the
  // same inputs always produce the same error.
  AuthorityBinding first = sample_binding();
  first.control_epoch = ControlEpoch{77u};
  AuthorityBinding second = sample_binding();
  second.control_epoch = ControlEpoch{77u};
  const auto left = authority.verify(token, first);
  const auto right = authority.verify(token, second);
  REQUIRE(!left.has_value());
  REQUIRE(!right.has_value());
  CHECK_EQ(left.error().code(), right.error().code());
  CHECK_EQ(left.error().message(), right.error().message());
  CHECK_EQ(left.error().path(), right.error().path());
}

FBM_TEST(authority_expiry_is_exclusive_at_the_exact_instant) {
  const AuthorizationAuthority authority = AuthorizationAuthority::unsigned_authority();
  const AuthorizationToken token = authority.mint(sample_binding());

  // One nanosecond before the stated instant the grant still holds.
  AuthorityBinding expected = sample_binding();
  expected.issued_at = Timestamp::from_unix_nanos(kExpiresAt - 1u);
  CHECK_OK(authority.verify(token, expected));

  // At exactly the stated instant the grant is expired.
  expected.issued_at = Timestamp::from_unix_nanos(kExpiresAt);
  CHECK_ERROR(authority.verify(token, expected), ErrorCode::AuthorityExpiredToken);

  // A never-expiring grant is never expired.
  AuthorityBinding perpetual = sample_binding();
  perpetual.expiry = Expiry::never();
  const AuthorizationToken perpetual_token = authority.mint(perpetual);
  AuthorityBinding far_future = perpetual;
  far_future.issued_at = Timestamp::from_unix_nanos(kExpiresAt * 100u);
  CHECK_OK(authority.verify(perpetual_token, far_future));

  // An unstated expiry is not an eternal grant.
  AuthorityBinding unstated = sample_binding();
  unstated.expiry = Expiry{};
  const AuthorizationToken unstated_token = authority.mint(unstated);
  CHECK_ERROR(authority.verify(unstated_token, sample_binding()), ErrorCode::AuthorityExpiredToken);
}

// --- JSON round trips -------------------------------------------------------

FBM_TEST(authority_binding_json_round_trips) {
  const AuthorityBinding binding = sample_binding();
  const std::string canonical = binding.to_string();
  auto parsed = json::parse(canonical);
  CHECK_OK(parsed);
  auto decoded = AuthorityBinding::from_json(parsed.value(), "/binding");
  CHECK_OK(decoded);
  CHECK_EQ(decoded.value().to_string(), canonical);
  CHECK_EQ(decoded.value().scope, binding.scope);
  CHECK_EQ(decoded.value().baseline.value(), binding.baseline.value());
  CHECK_EQ(decoded.value().expiry, binding.expiry);
  CHECK(decoded.value().mode == SignatureMode::None);

  // A never-expiring binding writes "expires": "never" and reads it back.
  AuthorityBinding perpetual = sample_binding();
  perpetual.expiry = Expiry::never();
  const std::string perpetual_text = perpetual.to_string();
  CHECK(perpetual_text.find("\"expires\":\"never\"") != std::string::npos);
  auto perpetual_parsed = json::parse(perpetual_text);
  CHECK_OK(perpetual_parsed);
  auto perpetual_decoded = AuthorityBinding::from_json(perpetual_parsed.value(), "/binding");
  CHECK_OK(perpetual_decoded);
  CHECK_EQ(perpetual_decoded.value().to_string(), perpetual_text);
  CHECK(perpetual_decoded.value().expiry == Expiry::never());
}

FBM_TEST(authority_token_json_round_trips_for_both_modes) {
  const AuthorityBinding binding = sample_binding();

  const AuthorizationToken unsigned_token =
      AuthorizationAuthority::unsigned_authority().mint(binding);
  const std::string unsigned_text = unsigned_token.to_string();
  auto unsigned_parsed = json::parse(unsigned_text);
  CHECK_OK(unsigned_parsed);
  auto unsigned_decoded = AuthorizationToken::from_json(unsigned_parsed.value(), "/token");
  CHECK_OK(unsigned_decoded);
  CHECK_EQ(unsigned_decoded.value().to_string(), unsigned_text);
  CHECK(unsigned_decoded.value().binding.mode == SignatureMode::None);
  CHECK(mac_is_zero(unsigned_decoded.value().mac));

  const AuthorizationToken signed_token =
      AuthorizationAuthority::hmac_authority(std::string{kKey}).mint(binding);
  const std::string signed_text = signed_token.to_string();
  auto signed_parsed = json::parse(signed_text);
  CHECK_OK(signed_parsed);
  auto signed_decoded = AuthorizationToken::from_json(signed_parsed.value(), "/token");
  CHECK_OK(signed_decoded);
  CHECK_EQ(signed_decoded.value().to_string(), signed_text);
  CHECK(signed_decoded.value().binding.mode == SignatureMode::HmacSha256);
  CHECK_EQ(digest_to_hex(signed_decoded.value().mac), digest_to_hex(signed_token.mac));
}

FBM_TEST(authority_json_rejects_missing_unknown_and_impossible_members) {
  const AuthorityBinding binding = sample_binding();
  const AuthorizationToken token =
      AuthorizationAuthority::unsigned_authority().mint(binding);

  // Missing MAC.
  json::Value without_mac = token.to_json();
  CHECK(without_mac.erase("mac"));
  CHECK_ERROR(AuthorizationToken::from_json(without_mac, "/token"), ErrorCode::SchemaMissingField);

  // Unknown member.
  json::Value with_unknown = token.to_json();
  with_unknown.set("signature", json::Value{"deadbeef"});
  CHECK_ERROR(AuthorizationToken::from_json(with_unknown, "/token"), ErrorCode::SchemaUnknownField);

  // Missing nested member.
  CHECK_ERROR(AuthorizationToken::from_json(token_json_without(binding, "baseline_revision"),
                                            "/token"),
              ErrorCode::SchemaMissingField);

  // Missing binding.
  json::Value without_binding = token.to_json();
  CHECK(without_binding.erase("binding"));
  CHECK_ERROR(AuthorizationToken::from_json(without_binding, "/token"),
              ErrorCode::SchemaMissingField);

  // Wrong type for a counter.
  CHECK_ERROR(AuthorizationToken::from_json(
                  token_json_with(binding, "policy_generation", json::Value{"four"}), "/token"),
              ErrorCode::SchemaWrongType);

  // Negative counter.
  CHECK_ERROR(AuthorizationToken::from_json(
                  token_json_with(binding, "control_epoch", json::Value{-1}), "/token"),
              ErrorCode::SchemaValueOutOfRange);

  // Invalid enum token.
  CHECK_ERROR(AuthorizationToken::from_json(
                  token_json_with(binding, "signature_mode", json::Value{"hmac"}), "/token"),
              ErrorCode::SchemaInvalidEnumValue);

  // Both expiry forms at once.
  CHECK_ERROR(AuthorizationToken::from_json(
                  token_json_with(binding, "expires", json::Value{"never"}), "/token"),
              ErrorCode::SchemaInconsistentDocument);

  // "expires" states exactly one value; replacing the stated instant with a
  // different token leaves that token as the only defect.
  json::Value bad_never = token_json_without(binding, "expires_at");
  json::Value::Object bad_members = bad_never.find("binding")->as_object();
  bad_members.emplace_back("expires", json::Value{"sometimes"});
  bad_never.set("binding", json::Value{std::move(bad_members)});
  CHECK_ERROR(AuthorizationToken::from_json(bad_never, "/token"),
              ErrorCode::SchemaInvalidEnumValue);

  // Neither expiry form.
  json::Value no_expiry = token_json_without(binding, "expires_at");
  CHECK_ERROR(AuthorizationToken::from_json(no_expiry, "/token"), ErrorCode::SchemaMissingField);

  // A malformed timestamp is named as such.
  CHECK_ERROR(AuthorizationToken::from_json(
                  token_json_with(binding, "issued_at", json::Value{"2026-01-01"}), "/token"),
              ErrorCode::SchemaInvalidTimestampText);

  // An unsigned token with a non-zero MAC is an impossible combination.
  json::Value non_zero = token.to_json();
  non_zero.set("mac", json::Value{std::string(64, 'a')});
  CHECK_ERROR(AuthorizationToken::from_json(non_zero, "/token"),
              ErrorCode::SchemaInconsistentDocument);

  // A binding that is not an object is a wrong type, not a silent default.
  json::Value not_an_object = token.to_json();
  not_an_object.set("binding", json::Value{std::string{"binding"}});
  CHECK_ERROR(AuthorizationToken::from_json(not_an_object, "/token"), ErrorCode::SchemaWrongType);
  CHECK_ERROR(AuthorityBinding::from_json(json::Value{std::string{"x"}}, "/binding"),
              ErrorCode::SchemaWrongType);
}

// --- Registry ---------------------------------------------------------------

FBM_TEST(authority_registry_records_and_detects_replays) {
  const AuthorizationAuthority authority = AuthorizationAuthority::unsigned_authority();
  const AuthorizationToken token = authority.mint(sample_binding());

  AuthorizationRegistry registry;
  CHECK(registry.empty());

  auto first = registry.record(token);
  CHECK_OK(first);
  CHECK(first.value() == AuthorizationRegistry::RecordOutcome::Recorded);
  CHECK_EQ(registry.size(), std::size_t{1});
  REQUIRE(registry.find(token.binding.request) != nullptr);
  CHECK(registry.contains(token.binding.request));
  CHECK(registry.find(RequestId{std::string{"req-2"}}) == nullptr);

  // The same request identity with exactly the same content is the
  // lost-response retry case.
  auto replay = registry.record(token);
  CHECK_OK(replay);
  CHECK(replay.value() == AuthorizationRegistry::RecordOutcome::IdempotentReplay);
  CHECK_EQ(registry.size(), std::size_t{1});

  // The same request identity with different content is rejected.
  AuthorityBinding different = sample_binding();
  different.subject_digest = digest_of(kOtherDigestHex);
  auto conflicting = registry.record(authority.mint(different));
  CHECK_ERROR(conflicting, ErrorCode::AuthorityReplayedToken);
  CHECK_EQ(registry.size(), std::size_t{1});
  CHECK_EQ(registry.find(token.binding.request)->binding.subject_digest,
           digest_of(kSubjectDigestHex));

  // A second, different request is recorded.
  AuthorityBinding other = sample_binding();
  other.request = RequestId{std::string{"req-2"}};
  auto second = registry.record(authority.mint(other));
  CHECK_OK(second);
  CHECK(second.value() == AuthorizationRegistry::RecordOutcome::Recorded);
  CHECK_EQ(registry.size(), std::size_t{2});

  // A token without a request identity cannot be filed.
  AuthorityBinding anonymous = sample_binding();
  anonymous.request = RequestId::unset();
  CHECK_ERROR(registry.record(authority.mint(anonymous)), ErrorCode::InvalidArgument);
}

FBM_TEST(authority_registry_json_round_trips_and_enforces_order) {
  const AuthorizationAuthority authority = AuthorizationAuthority::unsigned_authority();
  AuthorizationRegistry registry;
  CHECK_OK(registry.record(authority.mint(sample_binding())));
  AuthorityBinding second = sample_binding();
  second.request = RequestId{std::string{"req-2"}};
  CHECK_OK(registry.record(authority.mint(second)));

  const json::Value encoded = registry.to_json();
  CHECK(encoded.is_array());
  CHECK_EQ(encoded.size(), std::size_t{2});

  auto decoded = AuthorizationRegistry::from_json(encoded, "/authorizations");
  CHECK_OK(decoded);
  CHECK_EQ(decoded.value().size(), std::size_t{2});
  CHECK_EQ(json::write_canonical(decoded.value().to_json()), json::write_canonical(encoded));

  summon::fbm::Diagnostics diagnostics;
  CHECK_OK(decoded.value().validate("/authorizations", diagnostics));
  CHECK(diagnostics.empty());

  // A duplicate request identity is rejected.
  json::Value duplicate = encoded;
  duplicate.push_back(encoded.as_array().front());
  CHECK_ERROR(AuthorizationRegistry::from_json(duplicate, "/authorizations"),
              ErrorCode::SchemaDuplicateIdentifier);

  // Entries that are not in ascending request identity order are rejected: the
  // registry is keyed by request identity, so silently reordering would change
  // the canonical bytes of the document that contained this array.
  json::Value reversed = encoded;
  json::Value::Array& elements = reversed.as_array();
  std::swap(elements[0], elements[1]);
  CHECK_ERROR(AuthorizationRegistry::from_json(reversed, "/authorizations"),
              ErrorCode::SchemaInconsistentDocument);

  // A registry that is not an array is a wrong type.
  CHECK_ERROR(AuthorizationRegistry::from_json(json::Value{std::string{"x"}}, "/authorizations"),
              ErrorCode::SchemaWrongType);

  // An entry whose token is not an object is a wrong type.
  json::Value not_an_entry = json::Value::make_array();
  not_an_entry.push_back(json::Value{std::string{"token"}});
  CHECK_ERROR(AuthorizationRegistry::from_json(not_an_entry, "/authorizations"),
              ErrorCode::SchemaWrongType);

  // An entry with an unknown member is rejected rather than ignored.
  json::Value entry_with_unknown = encoded;
  json::Value::Array& entries = entry_with_unknown.as_array();
  json::Value::Object entry_members = entries.front().as_object();
  entry_members.emplace_back("note", json::Value{"extra"});
  entries.front() = json::Value{std::move(entry_members)};
  CHECK_ERROR(AuthorizationRegistry::from_json(entry_with_unknown, "/authorizations"),
              ErrorCode::SchemaUnknownField);
}
