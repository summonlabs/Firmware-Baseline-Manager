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

#include "summon/fbm/error.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>

#include "summon/fbm/strong_types.hpp"

namespace summon::fbm {
namespace {

// Every declared code has exactly one token. Tokens are part of the published
// CLI contract: a token is never renamed and never reused for a new meaning.
// A numeric value that is not a declared code has no meaning to report, so it
// is named as unknown rather than being folded into a neighbouring code.
std::string_view token_for(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::Ok:
      return "ok";

    // 1xx - durable record framing and integrity.
    case ErrorCode::FormatMagicMismatch:
      return "format_magic_mismatch";
    case ErrorCode::FormatVersionUnsupported:
      return "format_version_unsupported";
    case ErrorCode::FormatTruncated:
      return "format_truncated";
    case ErrorCode::FormatLengthOutOfRange:
      return "format_length_out_of_range";
    case ErrorCode::FormatReservedFieldNonZero:
      return "format_reserved_field_non_zero";
    case ErrorCode::FormatChecksumMismatch:
      return "format_checksum_mismatch";
    case ErrorCode::FormatTrailingBytes:
      return "format_trailing_bytes";
    case ErrorCode::FormatDigestMismatch:
      return "format_digest_mismatch";
    case ErrorCode::FormatImpossibleCombination:
      return "format_impossible_combination";
    case ErrorCode::FormatInvalidEnumValue:
      return "format_invalid_enum_value";
    case ErrorCode::FormatRecordKindUnknown:
      return "format_record_kind_unknown";

    // 2xx - text and JSON encoding.
    case ErrorCode::EncodingInvalidUtf8:
      return "encoding_invalid_utf8";
    case ErrorCode::EncodingUnexpectedByte:
      return "encoding_unexpected_byte";
    case ErrorCode::EncodingUnexpectedEnd:
      return "encoding_unexpected_end";
    case ErrorCode::EncodingTrailingContent:
      return "encoding_trailing_content";
    case ErrorCode::EncodingDepthExceeded:
      return "encoding_depth_exceeded";
    case ErrorCode::EncodingSizeExceeded:
      return "encoding_size_exceeded";
    case ErrorCode::EncodingNumberOutOfRange:
      return "encoding_number_out_of_range";
    case ErrorCode::EncodingDuplicateKey:
      return "encoding_duplicate_key";
    case ErrorCode::EncodingInvalidEscape:
      return "encoding_invalid_escape";
    case ErrorCode::EncodingInvalidSurrogate:
      return "encoding_invalid_surrogate";
    case ErrorCode::EncodingUnescapedControl:
      return "encoding_unescaped_control";
    case ErrorCode::EncodingByteOrderMark:
      return "encoding_byte_order_mark";

    // 3xx - schema shape of a document.
    case ErrorCode::SchemaMissingField:
      return "schema_missing_field";
    case ErrorCode::SchemaUnknownField:
      return "schema_unknown_field";
    case ErrorCode::SchemaWrongType:
      return "schema_wrong_type";
    case ErrorCode::SchemaValueOutOfRange:
      return "schema_value_out_of_range";
    case ErrorCode::SchemaInvalidEnumValue:
      return "schema_invalid_enum_value";
    case ErrorCode::SchemaInvalidIdentifier:
      return "schema_invalid_identifier";
    case ErrorCode::SchemaEmptyCollection:
      return "schema_empty_collection";
    case ErrorCode::SchemaDuplicateIdentifier:
      return "schema_duplicate_identifier";
    case ErrorCode::SchemaInconsistentDocument:
      return "schema_inconsistent_document";
    case ErrorCode::SchemaTooManyElements:
      return "schema_too_many_elements";
    case ErrorCode::SchemaInvalidVersionText:
      return "schema_invalid_version_text";
    case ErrorCode::SchemaInvalidTimestampText:
      return "schema_invalid_timestamp_text";

    // 4xx - resolution of identities referenced by a request.
    case ErrorCode::IdentityUnknownBaseline:
      return "identity_unknown_baseline";
    case ErrorCode::IdentityUnknownCohort:
      return "identity_unknown_cohort";
    case ErrorCode::IdentityUnknownException:
      return "identity_unknown_exception";
    case ErrorCode::IdentityUnknownAsset:
      return "identity_unknown_asset";
    case ErrorCode::IdentityAmbiguousBaseline:
      return "identity_ambiguous_baseline";
    case ErrorCode::IdentityUnknownComponent:
      return "identity_unknown_component";
    case ErrorCode::IdentityUnknownHardwareClass:
      return "identity_unknown_hardware_class";

    // 5xx - authority, generations, and fencing.
    case ErrorCode::AuthorityStaleGeneration:
      return "authority_stale_generation";
    case ErrorCode::AuthorityStalePolicyGeneration:
      return "authority_stale_policy_generation";
    case ErrorCode::AuthorityStaleEpoch:
      return "authority_stale_epoch";
    case ErrorCode::AuthorityStaleRevision:
      return "authority_stale_revision";
    case ErrorCode::AuthorityForeignScope:
      return "authority_foreign_scope";
    case ErrorCode::AuthorityExpiredToken:
      return "authority_expired_token";
    case ErrorCode::AuthorityDigestMismatch:
      return "authority_digest_mismatch";
    case ErrorCode::AuthorityNotAuthorized:
      return "authority_not_authorized";
    case ErrorCode::AuthorityMissingToken:
      return "authority_missing_token";
    case ErrorCode::AuthorityIncarnationMismatch:
      return "authority_incarnation_mismatch";
    case ErrorCode::AuthorityReplayedToken:
      return "authority_replayed_token";

    // 6xx - policy semantics.
    case ErrorCode::PolicyNoApplicableBaseline:
      return "policy_no_applicable_baseline";
    case ErrorCode::PolicySelectorOutOfScope:
      return "policy_selector_out_of_scope";
    case ErrorCode::PolicyIncompatibleCombination:
      return "policy_incompatible_combination";
    case ErrorCode::PolicyRuleViolation:
      return "policy_rule_violation";
    case ErrorCode::PolicySelfContradiction:
      return "policy_self_contradiction";
    case ErrorCode::PolicyDuplicateRule:
      return "policy_duplicate_rule";
    case ErrorCode::PolicyGateNotSatisfied:
      return "policy_gate_not_satisfied";
    case ErrorCode::PolicyRollbackTargetUnknown:
      return "policy_rollback_target_unknown";
    case ErrorCode::PolicyRollbackTargetIncompatible:
      return "policy_rollback_target_incompatible";
    case ErrorCode::PolicyExceptionCoversResidual:
      return "policy_exception_covers_residual";

    // 7xx - evidence.
    case ErrorCode::EvidenceMissing:
      return "evidence_missing";
    case ErrorCode::EvidenceStale:
      return "evidence_stale";
    case ErrorCode::EvidenceOutOfOrder:
      return "evidence_out_of_order";
    case ErrorCode::EvidenceConflicting:
      return "evidence_conflicting";
    case ErrorCode::EvidenceUnknownVersion:
      return "evidence_unknown_version";

    // 8xx - operational failures against the host.
    case ErrorCode::IoFailure:
      return "io_failure";
    case ErrorCode::IoNotFound:
      return "io_not_found";
    case ErrorCode::IoPermissionDenied:
      return "io_permission_denied";
    case ErrorCode::IoLockBusy:
      return "io_lock_busy";
    case ErrorCode::IoLockFailed:
      return "io_lock_failed";
    case ErrorCode::IoAtomicReplaceFailed:
      return "io_atomic_replace_failed";
    case ErrorCode::IoFlushFailed:
      return "io_flush_failed";
    case ErrorCode::IoUnexpectedEntry:
      return "io_unexpected_entry";
    case ErrorCode::RecoveryInconsistentState:
      return "recovery_inconsistent_state";
    case ErrorCode::RecoveryNoAuthoritativeGeneration:
      return "recovery_no_authoritative_generation";
    case ErrorCode::InternalInvariantViolation:
      return "internal_invariant_violation";
    case ErrorCode::InvalidArgument:
      return "invalid_argument";
    case ErrorCode::NotSupported:
      return "not_supported";
  }
  return "unknown_error";
}

}  // namespace

std::string_view error_code_token(ErrorCode code) { return token_for(code); }

std::uint16_t error_precedence(ErrorCode code) noexcept {
  const std::uint16_t raw = static_cast<std::uint16_t>(code);
  if (raw == 0u) {
    return 0u;
  }
  const std::uint16_t category = static_cast<std::uint16_t>(raw / 100u);
  const std::uint16_t member = static_cast<std::uint16_t>(raw % 100u);
  return static_cast<std::uint16_t>(category * 100u + member);
}

std::uint16_t error_category(ErrorCode code) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(code) / 100u);
}

Error::Error(ErrorCode code, std::string message, std::string path)
    : code_(code), message_(std::move(message)), path_(std::move(path)) {}

std::string Error::to_string() const {
  std::string out{error_code_token(code_)};
  out += ": ";
  out += message_;
  if (!path_.empty()) {
    out += " (at ";
    out += path_;
    out += ')';
  }
  return out;
}

bool error_less(const Error& a, const Error& b) noexcept {
  const std::uint16_t a_rank = error_precedence(a.code());
  const std::uint16_t b_rank = error_precedence(b.code());
  if (a_rank != b_rank) {
    return a_rank < b_rank;
  }
  if (a.path() != b.path()) {
    return a.path() < b.path();
  }
  if (a.message() != b.message()) {
    return a.message() < b.message();
  }
  return static_cast<std::uint16_t>(a.code()) < static_cast<std::uint16_t>(b.code());
}

void Diagnostics::add(Error error) { errors_.push_back(std::move(error)); }

void Diagnostics::add(ErrorCode code, std::string message, std::string path) {
  errors_.emplace_back(code, std::move(message), std::move(path));
}

Error Diagnostics::primary() const {
  if (errors_.empty()) {
    return Error{};
  }
  std::size_t best = 0;
  for (std::size_t i = 1; i < errors_.size(); ++i) {
    // error_less is a total order, so the minimum is unique up to errors that
    // are equal in every observable field; insertion order cannot change it.
    if (error_less(errors_[i], errors_[best])) {
      best = i;
    }
  }
  return errors_[best];
}

[[noreturn]] void precondition_failed(const char* expression, const char* file, int line) {
  std::fprintf(stderr, "fbm: precondition failed: %s at %s:%d\n",
               expression != nullptr ? expression : "<null>",
               file != nullptr ? file : "<unknown>", line);
  std::abort();
}

}  // namespace summon::fbm
