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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/error.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/version.hpp"

namespace {

using summon::fbm::BaselineId;
using summon::fbm::build_info;
using summon::fbm::Diagnostics;
using summon::fbm::Error;
using summon::fbm::ErrorCode;
using summon::fbm::error_category;
using summon::fbm::error_code_token;
using summon::fbm::error_less;
using summon::fbm::error_precedence;
using summon::fbm::FirmwareGeneration;
using summon::fbm::HardwareRevision;
using summon::fbm::is_valid_identifier;
using summon::fbm::make_id;
using summon::fbm::RackId;
using summon::fbm::SiteId;
using summon::fbm::validate_identifier;
using summon::fbm::version_string;

// Every declared code with its published token. A change to any token, or the
// reuse of a token for a second code, breaks this table on purpose.
struct CodeToken {
  ErrorCode code;
  std::string_view token;
};

constexpr CodeToken kCodeTokens[] = {
    {ErrorCode::Ok, "ok"},

    // 1xx - durable record framing and integrity.
    {ErrorCode::FormatMagicMismatch, "format_magic_mismatch"},
    {ErrorCode::FormatVersionUnsupported, "format_version_unsupported"},
    {ErrorCode::FormatTruncated, "format_truncated"},
    {ErrorCode::FormatLengthOutOfRange, "format_length_out_of_range"},
    {ErrorCode::FormatReservedFieldNonZero, "format_reserved_field_non_zero"},
    {ErrorCode::FormatChecksumMismatch, "format_checksum_mismatch"},
    {ErrorCode::FormatTrailingBytes, "format_trailing_bytes"},
    {ErrorCode::FormatDigestMismatch, "format_digest_mismatch"},
    {ErrorCode::FormatImpossibleCombination, "format_impossible_combination"},
    {ErrorCode::FormatInvalidEnumValue, "format_invalid_enum_value"},
    {ErrorCode::FormatRecordKindUnknown, "format_record_kind_unknown"},

    // 2xx - text and JSON encoding.
    {ErrorCode::EncodingInvalidUtf8, "encoding_invalid_utf8"},
    {ErrorCode::EncodingUnexpectedByte, "encoding_unexpected_byte"},
    {ErrorCode::EncodingUnexpectedEnd, "encoding_unexpected_end"},
    {ErrorCode::EncodingTrailingContent, "encoding_trailing_content"},
    {ErrorCode::EncodingDepthExceeded, "encoding_depth_exceeded"},
    {ErrorCode::EncodingSizeExceeded, "encoding_size_exceeded"},
    {ErrorCode::EncodingNumberOutOfRange, "encoding_number_out_of_range"},
    {ErrorCode::EncodingDuplicateKey, "encoding_duplicate_key"},
    {ErrorCode::EncodingInvalidEscape, "encoding_invalid_escape"},
    {ErrorCode::EncodingInvalidSurrogate, "encoding_invalid_surrogate"},
    {ErrorCode::EncodingUnescapedControl, "encoding_unescaped_control"},
    {ErrorCode::EncodingByteOrderMark, "encoding_byte_order_mark"},

    // 3xx - schema shape of a document.
    {ErrorCode::SchemaMissingField, "schema_missing_field"},
    {ErrorCode::SchemaUnknownField, "schema_unknown_field"},
    {ErrorCode::SchemaWrongType, "schema_wrong_type"},
    {ErrorCode::SchemaValueOutOfRange, "schema_value_out_of_range"},
    {ErrorCode::SchemaInvalidEnumValue, "schema_invalid_enum_value"},
    {ErrorCode::SchemaInvalidIdentifier, "schema_invalid_identifier"},
    {ErrorCode::SchemaEmptyCollection, "schema_empty_collection"},
    {ErrorCode::SchemaDuplicateIdentifier, "schema_duplicate_identifier"},
    {ErrorCode::SchemaInconsistentDocument, "schema_inconsistent_document"},
    {ErrorCode::SchemaTooManyElements, "schema_too_many_elements"},
    {ErrorCode::SchemaInvalidVersionText, "schema_invalid_version_text"},
    {ErrorCode::SchemaInvalidTimestampText, "schema_invalid_timestamp_text"},

    // 4xx - identity resolution.
    {ErrorCode::IdentityUnknownBaseline, "identity_unknown_baseline"},
    {ErrorCode::IdentityUnknownCohort, "identity_unknown_cohort"},
    {ErrorCode::IdentityUnknownException, "identity_unknown_exception"},
    {ErrorCode::IdentityUnknownAsset, "identity_unknown_asset"},
    {ErrorCode::IdentityAmbiguousBaseline, "identity_ambiguous_baseline"},
    {ErrorCode::IdentityUnknownComponent, "identity_unknown_component"},
    {ErrorCode::IdentityUnknownHardwareClass, "identity_unknown_hardware_class"},

    // 5xx - authority, generations, and fencing.
    {ErrorCode::AuthorityStaleGeneration, "authority_stale_generation"},
    {ErrorCode::AuthorityStalePolicyGeneration, "authority_stale_policy_generation"},
    {ErrorCode::AuthorityStaleEpoch, "authority_stale_epoch"},
    {ErrorCode::AuthorityStaleRevision, "authority_stale_revision"},
    {ErrorCode::AuthorityForeignScope, "authority_foreign_scope"},
    {ErrorCode::AuthorityExpiredToken, "authority_expired_token"},
    {ErrorCode::AuthorityDigestMismatch, "authority_digest_mismatch"},
    {ErrorCode::AuthorityNotAuthorized, "authority_not_authorized"},
    {ErrorCode::AuthorityMissingToken, "authority_missing_token"},
    {ErrorCode::AuthorityIncarnationMismatch, "authority_incarnation_mismatch"},
    {ErrorCode::AuthorityReplayedToken, "authority_replayed_token"},

    // 6xx - policy semantics.
    {ErrorCode::PolicyNoApplicableBaseline, "policy_no_applicable_baseline"},
    {ErrorCode::PolicySelectorOutOfScope, "policy_selector_out_of_scope"},
    {ErrorCode::PolicyIncompatibleCombination, "policy_incompatible_combination"},
    {ErrorCode::PolicyRuleViolation, "policy_rule_violation"},
    {ErrorCode::PolicySelfContradiction, "policy_self_contradiction"},
    {ErrorCode::PolicyDuplicateRule, "policy_duplicate_rule"},
    {ErrorCode::PolicyGateNotSatisfied, "policy_gate_not_satisfied"},
    {ErrorCode::PolicyRollbackTargetUnknown, "policy_rollback_target_unknown"},
    {ErrorCode::PolicyRollbackTargetIncompatible, "policy_rollback_target_incompatible"},
    {ErrorCode::PolicyExceptionCoversResidual, "policy_exception_covers_residual"},

    // 7xx - evidence.
    {ErrorCode::EvidenceMissing, "evidence_missing"},
    {ErrorCode::EvidenceStale, "evidence_stale"},
    {ErrorCode::EvidenceOutOfOrder, "evidence_out_of_order"},
    {ErrorCode::EvidenceConflicting, "evidence_conflicting"},
    {ErrorCode::EvidenceUnknownVersion, "evidence_unknown_version"},

    // 8xx - operational failures against the host.
    {ErrorCode::IoFailure, "io_failure"},
    {ErrorCode::IoNotFound, "io_not_found"},
    {ErrorCode::IoPermissionDenied, "io_permission_denied"},
    {ErrorCode::IoLockBusy, "io_lock_busy"},
    {ErrorCode::IoLockFailed, "io_lock_failed"},
    {ErrorCode::IoAtomicReplaceFailed, "io_atomic_replace_failed"},
    {ErrorCode::IoFlushFailed, "io_flush_failed"},
    {ErrorCode::IoUnexpectedEntry, "io_unexpected_entry"},
    {ErrorCode::RecoveryInconsistentState, "recovery_inconsistent_state"},
    {ErrorCode::RecoveryNoAuthoritativeGeneration, "recovery_no_authoritative_generation"},
    {ErrorCode::InternalInvariantViolation, "internal_invariant_violation"},
    {ErrorCode::InvalidArgument, "invalid_argument"},
    {ErrorCode::NotSupported, "not_supported"},
};

}  // namespace

// --- StrongId ---------------------------------------------------------------

FBM_TEST(strong_id_missing_is_not_empty) {
  const SiteId unset = SiteId::unset();
  CHECK(!unset.is_set());
  CHECK_EQ(unset.to_string(), std::string{"<unset>"});
  CHECK_EQ(unset.value(), std::string{});

  const SiteId empty{std::string{}};
  CHECK(empty.is_set());
  CHECK_EQ(empty.value(), std::string{});
  CHECK_EQ(empty.to_string(), std::string{});

  // A set identity that carries an empty string is a real value and is not the
  // missing identity.
  CHECK_NE(unset, empty);
  CHECK_LT(unset, empty);

  const SiteId named{std::string{"rack-1"}};
  CHECK(unset < named);
  CHECK(empty < named);
  CHECK_NE(unset, named);
  CHECK_EQ(named.to_string(), std::string{"rack-1"});

  // Distinct tag types are distinct identities even with equal text.
  const RackId rack_a{std::string{"a"}};
  const RackId rack_b{std::string{"b"}};
  CHECK_LT(rack_a, rack_b);
}

// --- Scalar -----------------------------------------------------------------

FBM_TEST(scalar_unset_precedes_first_and_overflow_is_reported) {
  const FirmwareGeneration unset = FirmwareGeneration::unset();
  CHECK(!unset.is_set());
  CHECK_LT(unset, FirmwareGeneration::first());
  CHECK(!(FirmwareGeneration::first() < unset));
  CHECK_EQ(FirmwareGeneration::first().value(), std::uint64_t{1});
  CHECK_EQ(unset.value_or(7u), std::uint64_t{7});

  // An unset scalar has no successor at all.
  FirmwareGeneration no_successor;
  CHECK(!unset.checked_next(no_successor));
  CHECK(!no_successor.is_set());

  // 64-bit instantiation: the maximum value reports overflow instead of wrapping.
  const FirmwareGeneration max64{std::numeric_limits<std::uint64_t>::max()};
  FirmwareGeneration next64;
  CHECK(!max64.checked_next(next64));
  CHECK(!next64.is_set());
  CHECK_EQ(max64.value(), std::numeric_limits<std::uint64_t>::max());

  // uint32_t instantiation: same obligation, different representation.
  const HardwareRevision max32{std::numeric_limits<std::uint32_t>::max()};
  HardwareRevision next32;
  CHECK(!max32.checked_next(next32));
  CHECK(!next32.is_set());

  // Ordinary successors still work and stay set.
  FirmwareGeneration two;
  CHECK(FirmwareGeneration::first().checked_next(two));
  CHECK(two.is_set());
  CHECK_EQ(two.value(), std::uint64_t{2});

  const HardwareRevision revision{41u};
  CHECK(revision.is_set());
  HardwareRevision revision_next;
  CHECK(revision.checked_next(revision_next));
  CHECK_EQ(revision_next.value(), std::uint32_t{42});
}

// --- Identifiers ------------------------------------------------------------

FBM_TEST(identifier_accepts_documented_forms) {
  CHECK(is_valid_identifier("a"));
  CHECK(is_valid_identifier("A0"));
  CHECK(is_valid_identifier("rack-1"));
  CHECK(is_valid_identifier("n1.2_x"));
  CHECK(is_valid_identifier(std::string(128, 'a')));
  CHECK(!is_valid_identifier(std::string(129, 'a')));

  CHECK_OK(validate_identifier("a", "site.id"));
  CHECK_OK(validate_identifier("A0", "site.id"));
  CHECK_OK(validate_identifier("rack-1", "rack.id"));
  CHECK_OK(validate_identifier("n1.2_x", "asset.id"));
  CHECK_OK(validate_identifier(std::string(128, 'a'), "identifier"));
}

FBM_TEST(identifier_rejects_documented_forms_with_exact_reasons) {
  const std::string e_acute = "\xC3\xA9";  // two-byte UTF-8 sequence for e-acute
  CHECK_EQ(e_acute.size(), std::size_t{2});

  CHECK(!is_valid_identifier(""));
  CHECK(!is_valid_identifier("-lead"));
  CHECK(!is_valid_identifier(".lead"));
  CHECK(!is_valid_identifier("with space"));
  CHECK(!is_valid_identifier("with:colon"));
  CHECK(!is_valid_identifier("with/slash"));
  CHECK(!is_valid_identifier("with\\backslash"));
  CHECK(!is_valid_identifier(e_acute));
  CHECK(!is_valid_identifier(std::string(129, 'a')));

  // Empty identifier.
  auto empty_status = validate_identifier("", "policy.rule.id");
  REQUIRE(!empty_status.has_value());
  CHECK_EQ(empty_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(empty_status.error().path(), std::string{"policy.rule.id"});

  // Too long: 129 bytes.
  auto long_status = validate_identifier(std::string(129, 'a'), "policy.rule.id");
  REQUIRE(!long_status.has_value());
  CHECK_EQ(long_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(long_status.error().path(), std::string{"policy.rule.id"});
  CHECK(long_status.error().message().find("129") != std::string::npos);

  // A disallowed first byte names the byte and its zero-based offset.
  auto dash_status = validate_identifier("-lead", "policy.rule.id");
  REQUIRE(!dash_status.has_value());
  CHECK_EQ(dash_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(dash_status.error().path(), std::string{"policy.rule.id"});
  CHECK(dash_status.error().message().find("0x2D") != std::string::npos);
  CHECK(dash_status.error().message().find("offset 0") != std::string::npos);

  auto dot_status = validate_identifier(".lead", "policy.rule.id");
  REQUIRE(!dot_status.has_value());
  CHECK_EQ(dot_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK(dot_status.error().message().find("0x2E") != std::string::npos);

  // A disallowed byte after the first names the byte and its offset.
  auto space_status = validate_identifier("with space", "policy.rule.id");
  REQUIRE(!space_status.has_value());
  CHECK_EQ(space_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK(space_status.error().message().find("0x20") != std::string::npos);
  CHECK(space_status.error().message().find("offset 4") != std::string::npos);

  auto colon_status = validate_identifier("with:colon", "policy.rule.id");
  REQUIRE(!colon_status.has_value());
  CHECK_EQ(colon_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK(colon_status.error().message().find("0x3A") != std::string::npos);

  auto slash_status = validate_identifier("with/slash", "policy.rule.id");
  REQUIRE(!slash_status.has_value());
  CHECK_EQ(slash_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK(slash_status.error().message().find("0x2F") != std::string::npos);

  auto backslash_status = validate_identifier("with\\backslash", "policy.rule.id");
  REQUIRE(!backslash_status.has_value());
  CHECK_EQ(backslash_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK(backslash_status.error().message().find("0x5C") != std::string::npos);

  // A non-ASCII byte is named by its byte value, not silently accepted.
  auto utf8_status = validate_identifier(e_acute, "policy.rule.id");
  REQUIRE(!utf8_status.has_value());
  CHECK_EQ(utf8_status.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(utf8_status.error().path(), std::string{"policy.rule.id"});
  CHECK(utf8_status.error().message().find("0xC3") != std::string::npos);
}

FBM_TEST(make_id_propagates_the_exact_error_code) {
  auto good = make_id<BaselineId>("baseline-7", "baseline.id");
  CHECK_OK(good);
  CHECK(good.value().is_set());
  CHECK_EQ(good.value().value(), std::string{"baseline-7"});

  auto bad = make_id<BaselineId>("baseline 7", "baseline.id");
  REQUIRE(!bad.has_value());
  CHECK_EQ(bad.error().code(), ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(bad.error().path(), std::string{"baseline.id"});

  auto empty = make_id<RackId>("", "rack.id");
  CHECK_ERROR(empty, ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(empty.error().path(), std::string{"rack.id"});

  auto too_long = make_id<RackId>(std::string(129, 'a'), "rack.id");
  CHECK_ERROR(too_long, ErrorCode::SchemaInvalidIdentifier);
  CHECK_EQ(too_long.error().path(), std::string{"rack.id"});
}

// --- Error codes and tokens -------------------------------------------------

FBM_TEST(error_code_tokens_are_stable_and_unique) {
  std::size_t counted = 0;
  for (const CodeToken& entry : kCodeTokens) {
    ++counted;
    CHECK_EQ(error_code_token(entry.code), entry.token);
    // Every token is lower_snake_case: [a-z][a-z0-9_]* with no double or
    // trailing underscore.
    bool shape_ok = !entry.token.empty();
    for (std::size_t i = 0; i < entry.token.size(); ++i) {
      const char c = entry.token[i];
      const bool lower = c >= 'a' && c <= 'z';
      const bool digit = c >= '0' && c <= '9';
      if (i == 0 && !lower) {
        shape_ok = false;
      }
      if (!lower && !digit && c != '_') {
        shape_ok = false;
      }
      if (c == '_' && (i == 0 || i + 1 == entry.token.size())) {
        shape_ok = false;
      }
      if (c == '_' && i > 0 && entry.token[i - 1] == '_') {
        shape_ok = false;
      }
    }
    CHECK_MSG(shape_ok, "token is not lower_snake_case: " << entry.token);
  }
  CHECK_EQ(counted, std::size_t{82});

  bool unique = true;
  std::string_view duplicate{};
  for (std::size_t i = 0; i < counted && unique; ++i) {
    for (std::size_t j = i + 1; j < counted && unique; ++j) {
      if (kCodeTokens[i].token == kCodeTokens[j].token) {
        duplicate = kCodeTokens[i].token;
        unique = false;
      }
    }
  }
  CHECK_MSG(unique, "duplicate token: " << duplicate);

  // A numeric value that is not a declared code is not silently folded into a
  // neighbouring code.
  CHECK_EQ(error_code_token(static_cast<ErrorCode>(9999)), std::string_view{"unknown_error"});
  CHECK_EQ(error_code_token(static_cast<ErrorCode>(0)), std::string_view{"ok"});
}

FBM_TEST(error_precedence_orders_categories_and_error_less_is_total) {
  CHECK_EQ(error_precedence(ErrorCode::Ok), std::uint16_t{0});
  CHECK_EQ(error_precedence(ErrorCode::FormatChecksumMismatch), std::uint16_t{105});
  CHECK_EQ(error_precedence(ErrorCode::IoFailure), std::uint16_t{800});

  CHECK_LT(error_precedence(ErrorCode::FormatChecksumMismatch),
           error_precedence(ErrorCode::EncodingInvalidUtf8));
  CHECK_LT(error_precedence(ErrorCode::EncodingInvalidUtf8),
           error_precedence(ErrorCode::SchemaMissingField));
  CHECK_LT(error_precedence(ErrorCode::SchemaMissingField),
           error_precedence(ErrorCode::AuthorityStaleGeneration));
  CHECK_LT(error_precedence(ErrorCode::AuthorityStaleGeneration),
           error_precedence(ErrorCode::IoFailure));

  CHECK_EQ(error_category(ErrorCode::FormatChecksumMismatch), std::uint16_t{1});
  CHECK_EQ(error_category(ErrorCode::EncodingUnexpectedByte), std::uint16_t{2});
  CHECK_EQ(error_category(ErrorCode::SchemaValueOutOfRange), std::uint16_t{3});
  CHECK_EQ(error_category(ErrorCode::IdentityUnknownBaseline), std::uint16_t{4});
  CHECK_EQ(error_category(ErrorCode::AuthorityStaleGeneration), std::uint16_t{5});
  CHECK_EQ(error_category(ErrorCode::PolicyGateNotSatisfied), std::uint16_t{6});
  CHECK_EQ(error_category(ErrorCode::EvidenceMissing), std::uint16_t{7});
  CHECK_EQ(error_category(ErrorCode::IoLockBusy), std::uint16_t{8});
  CHECK_EQ(error_category(ErrorCode::Ok), std::uint16_t{0});

  std::vector<Error> forward{
      Error{ErrorCode::IoFailure, "io", "store.path"},
      Error{ErrorCode::SchemaMissingField, "missing", "policy.rules"},
      Error{ErrorCode::FormatChecksumMismatch, "checksum", "artifact.digest"},
      Error{ErrorCode::FormatChecksumMismatch, "checksum", "artifact.body"},
      Error{ErrorCode::FormatChecksumMismatch, "checksum", "artifact.body"},
      Error{ErrorCode::EncodingInvalidUtf8, "utf8", "policy.title"},
  };
  std::vector<Error> backward(forward.rbegin(), forward.rend());

  for (const Error& error : forward) {
    CHECK(!error_less(error, error));
  }

  std::sort(forward.begin(), forward.end(), error_less);
  std::sort(backward.begin(), backward.end(), error_less);
  CHECK_EQ(forward.size(), backward.size());
  for (std::size_t i = 0; i < forward.size() && i < backward.size(); ++i) {
    CHECK_EQ(forward[i].code(), backward[i].code());
    CHECK_EQ(forward[i].path(), backward[i].path());
    CHECK_EQ(forward[i].message(), backward[i].message());
  }
  REQUIRE(!forward.empty());
  CHECK_EQ(forward.front().code(), ErrorCode::FormatChecksumMismatch);
  CHECK_EQ(forward.front().path(), std::string{"artifact.body"});
}

FBM_TEST(diagnostics_primary_is_independent_of_insertion_order) {
  Diagnostics forward;
  forward.add(ErrorCode::IoFailure, "io failed", "store.path");
  forward.add(ErrorCode::SchemaMissingField, "missing field", "policy.rules");
  forward.add(ErrorCode::FormatChecksumMismatch, "checksum mismatch", "policy.rules");
  forward.add(Error{ErrorCode::EncodingInvalidUtf8, "invalid utf8", "policy.title"});

  Diagnostics backward;
  backward.add(Error{ErrorCode::EncodingInvalidUtf8, "invalid utf8", "policy.title"});
  backward.add(ErrorCode::FormatChecksumMismatch, "checksum mismatch", "policy.rules");
  backward.add(ErrorCode::SchemaMissingField, "missing field", "policy.rules");
  backward.add(ErrorCode::IoFailure, "io failed", "store.path");

  CHECK_EQ(forward.size(), std::size_t{4});
  CHECK_EQ(backward.size(), std::size_t{4});

  const Error forward_primary = forward.primary();
  const Error backward_primary = backward.primary();
  CHECK_EQ(forward_primary.code(), backward_primary.code());
  CHECK_EQ(forward_primary.path(), backward_primary.path());
  CHECK_EQ(forward_primary.message(), backward_primary.message());
  CHECK_EQ(forward_primary.code(), ErrorCode::FormatChecksumMismatch);
  CHECK_EQ(forward_primary.path(), std::string{"policy.rules"});
  CHECK(!error_less(forward_primary, backward_primary));
  CHECK(!error_less(backward_primary, forward_primary));

  // Ties break on path, then message, then code - never on insertion order.
  Diagnostics ties_forward;
  ties_forward.add(ErrorCode::SchemaMissingField, "zzz", "b");
  ties_forward.add(ErrorCode::SchemaMissingField, "aaa", "b");
  ties_forward.add(ErrorCode::SchemaMissingField, "aaa", "a");
  Diagnostics ties_backward;
  ties_backward.add(ErrorCode::SchemaMissingField, "aaa", "a");
  ties_backward.add(ErrorCode::SchemaMissingField, "aaa", "b");
  ties_backward.add(ErrorCode::SchemaMissingField, "zzz", "b");
  CHECK_EQ(ties_forward.primary().path(), std::string{"a"});
  CHECK_EQ(ties_backward.primary().path(), std::string{"a"});
  CHECK_EQ(ties_forward.primary().message(), std::string{"aaa"});
  CHECK_EQ(ties_backward.primary().message(), std::string{"aaa"});

  // The same code and path with different messages breaks on message text.
  Diagnostics messages;
  messages.add(ErrorCode::PolicyGateNotSatisfied, "zulu", "policy.gate");
  messages.add(ErrorCode::PolicyGateNotSatisfied, "alpha", "policy.gate");
  CHECK_EQ(messages.primary().message(), std::string{"alpha"});

  // An empty accumulator has no primary defect; it reports Ok rather than
  // inventing a failure.
  const Diagnostics none;
  CHECK(none.empty());
  const Error default_error = none.primary();
  CHECK(default_error.is_ok());
  CHECK_EQ(default_error.code(), ErrorCode::Ok);
  CHECK_EQ(default_error.message(), std::string{});
  CHECK_EQ(default_error.path(), std::string{});

  // clear() empties the accumulator.
  Diagnostics cleared;
  cleared.add(ErrorCode::IoFailure, "io failed", "store.path");
  CHECK(!cleared.empty());
  cleared.clear();
  CHECK(cleared.empty());
  CHECK(cleared.primary().is_ok());
}

FBM_TEST(error_to_string_renders_token_message_and_path) {
  const Error with_path{ErrorCode::PolicyGateNotSatisfied, "gate is not satisfied", "policy.gate"};
  CHECK_EQ(with_path.to_string(),
           std::string{"policy_gate_not_satisfied: gate is not satisfied (at policy.gate)"});

  const Error without_path{ErrorCode::IoLockBusy, "lock is busy"};
  CHECK_EQ(without_path.to_string(), std::string{"io_lock_busy: lock is busy"});

  const Error format{ErrorCode::FormatChecksumMismatch, "checksum mismatch", "artifact.frame"};
  CHECK_EQ(format.to_string(),
           std::string{"format_checksum_mismatch: checksum mismatch (at artifact.frame)"});

  const Error default_error{};
  CHECK(default_error.is_ok());
  CHECK_EQ(default_error.to_string(), std::string{"ok: "});
}

// --- Version ----------------------------------------------------------------

FBM_TEST(version_string_matches_the_build_definition) {
  const std::string version = version_string();
  CHECK(!version.empty());
  CHECK_EQ(version, std::string{FBM_VERSION_STRING});
  CHECK_EQ(version_string(), version);

  const std::string info = build_info();
  CHECK(!info.empty());
  CHECK_EQ(build_info(), info);
  // The description names a compiler and a configuration and contains no
  // machine-specific absolute path.
  CHECK(info.find('(') != std::string::npos);
  CHECK(info.find(')') != std::string::npos);
  CHECK(info.find(":\\") == std::string::npos);
  CHECK(info.find(":/") == std::string::npos);
}
