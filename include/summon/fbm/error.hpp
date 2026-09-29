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

namespace summon::fbm {

enum class ErrorCode : std::uint16_t {
  Ok = 0,

  // 1xx - durable record framing and integrity. Structural integrity of a
  // durable record outranks every other class of defect: a record whose bytes
  // cannot be trusted cannot be interpreted at all.
  FormatMagicMismatch = 100,
  FormatVersionUnsupported = 101,
  FormatTruncated = 102,
  FormatLengthOutOfRange = 103,
  FormatReservedFieldNonZero = 104,
  FormatChecksumMismatch = 105,
  FormatTrailingBytes = 106,
  FormatDigestMismatch = 107,
  FormatImpossibleCombination = 108,
  FormatInvalidEnumValue = 109,
  FormatRecordKindUnknown = 110,

  // 2xx - text and JSON encoding.
  EncodingInvalidUtf8 = 200,
  EncodingUnexpectedByte = 201,
  EncodingUnexpectedEnd = 202,
  EncodingTrailingContent = 203,
  EncodingDepthExceeded = 204,
  EncodingSizeExceeded = 205,
  EncodingNumberOutOfRange = 206,
  EncodingDuplicateKey = 207,
  EncodingInvalidEscape = 208,
  EncodingInvalidSurrogate = 209,
  EncodingUnescapedControl = 210,
  EncodingByteOrderMark = 211,

  // 3xx - schema shape of a document.
  SchemaMissingField = 300,
  SchemaUnknownField = 301,
  SchemaWrongType = 302,
  SchemaValueOutOfRange = 303,
  SchemaInvalidEnumValue = 304,
  SchemaInvalidIdentifier = 305,
  SchemaEmptyCollection = 306,
  SchemaDuplicateIdentifier = 307,
  SchemaInconsistentDocument = 308,
  SchemaTooManyElements = 309,
  SchemaInvalidVersionText = 310,
  SchemaInvalidTimestampText = 311,

  // 4xx - resolution of identities referenced by a request.
  IdentityUnknownBaseline = 400,
  IdentityUnknownCohort = 401,
  IdentityUnknownException = 402,
  IdentityUnknownAsset = 403,
  IdentityAmbiguousBaseline = 404,
  IdentityUnknownComponent = 405,
  IdentityUnknownHardwareClass = 406,

  // 5xx - authority, generations, and fencing.
  AuthorityStaleGeneration = 500,
  AuthorityStalePolicyGeneration = 501,
  AuthorityStaleEpoch = 502,
  AuthorityStaleRevision = 503,
  AuthorityForeignScope = 504,
  AuthorityExpiredToken = 505,
  AuthorityDigestMismatch = 506,
  AuthorityNotAuthorized = 507,
  AuthorityMissingToken = 508,
  AuthorityIncarnationMismatch = 509,
  AuthorityReplayedToken = 510,

  // 6xx - policy semantics.
  PolicyNoApplicableBaseline = 600,
  PolicySelectorOutOfScope = 601,
  PolicyIncompatibleCombination = 602,
  PolicyRuleViolation = 603,
  PolicySelfContradiction = 604,
  PolicyDuplicateRule = 605,
  PolicyGateNotSatisfied = 606,
  PolicyRollbackTargetUnknown = 607,
  PolicyRollbackTargetIncompatible = 608,
  PolicyExceptionCoversResidual = 609,

  // 7xx - evidence.
  EvidenceMissing = 700,
  EvidenceStale = 701,
  EvidenceOutOfOrder = 702,
  EvidenceConflicting = 703,
  EvidenceUnknownVersion = 704,

  // 8xx - operational failures against the host.
  IoFailure = 800,
  IoNotFound = 801,
  IoPermissionDenied = 802,
  IoLockBusy = 803,
  IoLockFailed = 804,
  IoAtomicReplaceFailed = 805,
  IoFlushFailed = 806,
  IoUnexpectedEntry = 807,
  RecoveryInconsistentState = 808,
  RecoveryNoAuthoritativeGeneration = 809,
  InternalInvariantViolation = 810,
  InvalidArgument = 811,
  NotSupported = 812,
};

// Stable lowercase token for an error code. Tokens are part of the CLI
// contract and are never reused for a different meaning.
std::string_view error_code_token(ErrorCode code);

// Deterministic precedence rank. Smaller ranks are more primary. Two runs of
// the same invalid request always select the same primary error because the
// rank depends only on the code, and ties are broken by field path and then by
// message text - never by map iteration order, allocation address, thread
// scheduling, or the order in which defects happened to be discovered.
std::uint16_t error_precedence(ErrorCode code) noexcept;

// Category number of an error code (the hundreds digit group).
std::uint16_t error_category(ErrorCode code) noexcept;

// A single diagnosed defect: a code, a human-readable message, and the field
// path within the request or document where the defect was found.
class Error {
 public:
  Error() = default;
  Error(ErrorCode code, std::string message, std::string path = {});

  ErrorCode code() const noexcept { return code_; }
  const std::string& message() const noexcept { return message_; }
  const std::string& path() const noexcept { return path_; }
  bool is_ok() const noexcept { return code_ == ErrorCode::Ok; }

  // "token: message" with an "(at path)" suffix when a path is present.
  std::string to_string() const;

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string message_;
  std::string path_;
};

// Deterministic ordering: precedence, then path, then message, then code.
bool error_less(const Error& a, const Error& b) noexcept;

// Accumulates every defect found while validating one request so that the
// caller can report a single, deterministic primary error while retaining the
// complete picture for diagnostics.
class Diagnostics {
 public:
  Diagnostics() = default;

  void add(Error error);
  void add(ErrorCode code, std::string message, std::string path = {});

  bool empty() const noexcept { return errors_.empty(); }
  std::size_t size() const noexcept { return errors_.size(); }
  const std::vector<Error>& errors() const noexcept { return errors_; }

  // The error with the lowest precedence rank. Ties break on path, then
  // message, then code, so the result is independent of insertion order.
  Error primary() const;

  void clear() { errors_.clear(); }

 private:
  std::vector<Error> errors_;
};

}  // namespace summon::fbm
