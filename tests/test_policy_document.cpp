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
#include <vector>

#include "summon/fbm/baseline.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/policy_document.hpp"
#include "summon/fbm/result.hpp"

// json is a namespace, so it is aliased rather than imported with a
// using-declaration.
namespace json = summon::fbm::json;

namespace {

using summon::fbm::Baseline;
using summon::fbm::DetachedSignature;
using summon::fbm::Diagnostics;
using summon::fbm::digest_to_hex;
using summon::fbm::ErrorCode;
using summon::fbm::PolicyDocument;
using summon::fbm::Sha256;
using summon::fbm::sign_policy_document;
using summon::fbm::SignatureCheck;
using summon::fbm::signature_check_token;
using summon::fbm::SignatureMode;
using summon::fbm::verify_policy_signature;

constexpr std::string_view kKey = "operator-supplied-policy-key";

// A complete, schema-conformant policy document: two baselines, one published
// with a compatibility rule and one draft.
constexpr const char* kDocumentText = R"json({
  "schema": "summon.fbm.policy",
  "schema_version": 1,
  "baselines": [
    {
      "id": "bios-train",
      "generation": 2,
      "revision": 4,
      "state": "published",
      "title": "BIOS training baseline",
      "selectors": [
        {
          "hardware_class": "server",
          "model": "r760",
          "minimum_revision": 2,
          "maximum_revision": 6
        }
      ],
      "components": [
        {
          "component": "bios",
          "approved": "3.1.0",
          "conformant": ["3.0.0", "3.1.0"],
          "rollback_targets": ["2.9.0"],
          "freshness": {"max_age_nanos": 43200000000000}
        }
      ],
      "rules": [
        {
          "id": "r-bios-bmc",
          "when_component": "bmc",
          "when_versions": {"min": "2.4.0", "min_inclusive": true},
          "requirement": {
            "kind": "component_version_in_range",
            "component": "bios",
            "versions": {
              "min": "3.0.0",
              "min_inclusive": true,
              "max": "3.2.0",
              "max_inclusive": false
            }
          },
          "reason": "BMC 2.4 requires BIOS 3.x"
        }
      ],
      "gate": {
        "minimum_conformant_basis_points": 9900,
        "minimum_decided_assets": 2,
        "minimum_conformant_assets": 2,
        "soak_nanos": 0,
        "required_stages": 2
      },
      "created_at": "2026-01-01T00:00:00.000000000Z",
      "published_at": "2026-01-02T00:00:00.000000000Z"
    },
    {
      "id": "gpu-h100-train",
      "generation": 3,
      "revision": 5,
      "state": "draft",
      "title": "H100 training baseline",
      "selectors": [{"hardware_class": "gpu", "model": "h100"}],
      "components": [
        {
          "component": "bmc",
          "approved": "2.4.1",
          "conformant": ["2.4.0", "2.4.1"],
          "rollback_targets": ["2.3.9"],
          "freshness": {"unbounded": true}
        }
      ],
      "rules": [],
      "gate": {
        "minimum_conformant_basis_points": 10000,
        "minimum_decided_assets": 1,
        "minimum_conformant_assets": 1,
        "soak_nanos": 0,
        "required_stages": 1
      },
      "created_at": "2026-01-03T00:00:00.000000000Z"
    }
  ]
})json";

// The same document with every object's members written in a different order.
// Object member order is not content: the canonical form sorts it.
constexpr const char* kReorderedDocumentText = R"json({
  "schema_version": 1,
  "baselines": [
    {
      "title": "BIOS training baseline",
      "state": "published",
      "revision": 4,
      "published_at": "2026-01-02T00:00:00.000000000Z",
      "id": "bios-train",
      "created_at": "2026-01-01T00:00:00.000000000Z",
      "generation": 2,
      "gate": {
        "soak_nanos": 0,
        "required_stages": 2,
        "minimum_decided_assets": 2,
        "minimum_conformant_basis_points": 9900,
        "minimum_conformant_assets": 2
      },
      "rules": [
        {
          "when_versions": {"min_inclusive": true, "min": "2.4.0"},
          "when_component": "bmc",
          "requirement": {
            "versions": {
              "max_inclusive": false,
              "max": "3.2.0",
              "min_inclusive": true,
              "min": "3.0.0"
            },
            "kind": "component_version_in_range",
            "component": "bios"
          },
          "reason": "BMC 2.4 requires BIOS 3.x",
          "id": "r-bios-bmc"
        }
      ],
      "components": [
        {
          "rollback_targets": ["2.9.0"],
          "freshness": {"max_age_nanos": 43200000000000},
          "conformant": ["3.0.0", "3.1.0"],
          "component": "bios",
          "approved": "3.1.0"
        }
      ],
      "selectors": [
        {
          "minimum_revision": 2,
          "model": "r760",
          "maximum_revision": 6,
          "hardware_class": "server"
        }
      ]
    },
    {
      "title": "H100 training baseline",
      "state": "draft",
      "revision": 5,
      "selectors": [{"model": "h100", "hardware_class": "gpu"}],
      "rules": [],
      "id": "gpu-h100-train",
      "gate": {
        "soak_nanos": 0,
        "required_stages": 1,
        "minimum_decided_assets": 1,
        "minimum_conformant_basis_points": 10000,
        "minimum_conformant_assets": 1
      },
      "generation": 3,
      "created_at": "2026-01-03T00:00:00.000000000Z",
      "components": [
        {
          "rollback_targets": ["2.3.9"],
          "freshness": {"unbounded": true},
          "conformant": ["2.4.0", "2.4.1"],
          "component": "bmc",
          "approved": "2.4.1"
        }
      ]
    }
  ],
  "schema": "summon.fbm.policy"
})json";

PolicyDocument must_parse(const char* text) {
  auto parsed = PolicyDocument::parse(text, "/policy");
  CHECK_OK(parsed);
  return parsed.take();
}

}  // namespace

// --- Parsing ----------------------------------------------------------------

FBM_TEST(policy_document_parses_a_valid_document) {
  const PolicyDocument document = must_parse(kDocumentText);

  CHECK_EQ(document.schema_version(), 1u);
  CHECK_EQ(document.baselines().size(), std::size_t{2});
  CHECK_EQ(document.baselines().at(0).id.value(), std::string{"bios-train"});
  CHECK_EQ(document.baselines().at(1).id.value(), std::string{"gpu-h100-train"});

  // The identity of a document is the SHA-256 of its canonical bytes, and the
  // canonical bytes are the canonical serialization of its value.
  CHECK_EQ(document.canonical_bytes(), json::write_canonical(document.to_json()));
  CHECK(document.content_digest() == Sha256::of(document.canonical_bytes()));

  Diagnostics diagnostics;
  CHECK_OK(document.validate("/policy", diagnostics));
  CHECK(diagnostics.empty());
}

FBM_TEST(policy_document_member_order_does_not_change_identity) {
  const PolicyDocument first = must_parse(kDocumentText);
  const PolicyDocument second = must_parse(kReorderedDocumentText);

  CHECK_EQ(first.canonical_bytes(), second.canonical_bytes());
  CHECK(first.content_digest() == second.content_digest());
  CHECK_EQ(digest_to_hex(first.content_digest()), digest_to_hex(second.content_digest()));

  // A round trip through JSON preserves the canonical bytes exactly.
  auto reparsed = PolicyDocument::from_json(first.to_json(), "/policy");
  CHECK_OK(reparsed);
  CHECK_EQ(reparsed.value().canonical_bytes(), first.canonical_bytes());
  CHECK(reparsed.value().content_digest() == first.content_digest());
}

FBM_TEST(policy_document_rejects_wrong_schema_and_unsupported_version) {
  const std::string wrong_schema = R"json({
    "schema": "summon.fbm.snapshot",
    "schema_version": 1,
    "baselines": []
  })json";
  CHECK_ERROR(PolicyDocument::parse(wrong_schema, "/policy"),
              ErrorCode::SchemaInconsistentDocument);

  const std::string unsupported = R"json({
    "schema": "summon.fbm.policy",
    "schema_version": 2,
    "baselines": []
  })json";
  CHECK_ERROR(PolicyDocument::parse(unsupported, "/policy"), ErrorCode::FormatVersionUnsupported);

  const std::string negative = R"json({
    "schema": "summon.fbm.policy",
    "schema_version": -1,
    "baselines": []
  })json";
  CHECK_ERROR(PolicyDocument::parse(negative, "/policy"), ErrorCode::SchemaValueOutOfRange);

  const std::string wrong_type = R"json({
    "schema": "summon.fbm.policy",
    "schema_version": "1",
    "baselines": []
  })json";
  CHECK_ERROR(PolicyDocument::parse(wrong_type, "/policy"), ErrorCode::SchemaWrongType);
}

FBM_TEST(policy_document_rejects_missing_unknown_and_malformed_members) {
  const std::string missing_baselines = R"json({
    "schema": "summon.fbm.policy",
    "schema_version": 1
  })json";
  CHECK_ERROR(PolicyDocument::parse(missing_baselines, "/policy"), ErrorCode::SchemaMissingField);

  const std::string unknown_member = R"json({
    "schema": "summon.fbm.policy",
    "schema_version": 1,
    "baselines": [],
    "generation": 7
  })json";
  CHECK_ERROR(PolicyDocument::parse(unknown_member, "/policy"), ErrorCode::SchemaUnknownField);

  const std::string not_an_object = R"json([])json";
  CHECK_ERROR(PolicyDocument::parse(not_an_object, "/policy"), ErrorCode::SchemaWrongType);

  const std::string trailing =
      std::string{R"json({
    "schema": "summon.fbm.policy",
    "schema_version": 1,
    "baselines": []
  })json"} +
      " {}";
  CHECK_ERROR(PolicyDocument::parse(trailing, "/policy"), ErrorCode::EncodingTrailingContent);

  // A policy document with no baselines is a well-formed statement that it
  // defines nothing; it is not an error.
  const std::string empty_document = R"json({
    "schema": "summon.fbm.policy",
    "schema_version": 1,
    "baselines": []
  })json";
  auto parsed = PolicyDocument::parse(empty_document, "/policy");
  CHECK_OK(parsed);
  CHECK(parsed.value().baselines().empty());
  Diagnostics diagnostics;
  CHECK_OK(parsed.value().validate("/policy", diagnostics));
  CHECK(diagnostics.empty());
}

FBM_TEST(policy_document_rejects_duplicate_baseline_identities) {
  // A duplicate identity is rejected while parsing.
  const PolicyDocument document = must_parse(kDocumentText);
  json::Value::Object members = document.to_json().as_object();
  for (json::Value::Member& member : members) {
    if (member.first == "baselines") {
      const json::Value copy = member.second.as_array().front();
      member.second.push_back(copy);
    }
  }
  const json::Value duplicated{std::move(members)};
  auto parsed = PolicyDocument::from_json(duplicated, "/policy");
  CHECK_ERROR(parsed, ErrorCode::SchemaDuplicateIdentifier);
  CHECK_EQ(parsed.error().path(), std::string{"/policy/baselines/2/id"});

  // The same rule holds for a document built in memory.
  std::vector<Baseline> baselines{document.baselines().at(0), document.baselines().at(0)};
  const PolicyDocument in_memory{std::move(baselines)};
  Diagnostics diagnostics;
  CHECK(!in_memory.validate("/policy", diagnostics).has_value());
  CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaDuplicateIdentifier);
  CHECK_EQ(diagnostics.primary().path(), std::string{"/policy/baselines/1/id"});

  // A baseline that violates its own schema is reported with its exact path.
  std::vector<Baseline> broken{document.baselines().at(1)};
  broken.front().selectors.clear();
  const PolicyDocument broken_document{std::move(broken)};
  Diagnostics broken_diagnostics;
  CHECK(!broken_document.validate("/policy", broken_diagnostics).has_value());
  CHECK_EQ(broken_diagnostics.primary().code(), ErrorCode::SchemaEmptyCollection);
  CHECK_EQ(broken_diagnostics.primary().path(), std::string{"/policy/baselines/0/selectors"});
}

// --- Signatures -------------------------------------------------------------

FBM_TEST(policy_document_signature_checks_are_deterministic) {
  const PolicyDocument document = must_parse(kDocumentText);
  const std::string bytes = document.canonical_bytes();

  // No key was configured, so nothing was verified and the result is reported
  // verbatim rather than as "valid".
  const DetachedSignature signed_document = sign_policy_document(bytes, kKey);
  CHECK(signed_document.mode == SignatureMode::HmacSha256);
  CHECK_EQ(verify_policy_signature(bytes, signed_document, std::string_view{}),
           SignatureCheck::NotConfigured);
  CHECK_EQ(signature_check_token(SignatureCheck::NotConfigured),
           std::string_view{"not_configured"});

  // The correct key verifies.
  CHECK_EQ(verify_policy_signature(bytes, signed_document, kKey), SignatureCheck::Valid);
  CHECK_EQ(signature_check_token(SignatureCheck::Valid), std::string_view{"valid"});

  // A different key does not.
  CHECK_EQ(verify_policy_signature(bytes, signed_document, "another-key"), SignatureCheck::Invalid);
  CHECK_EQ(signature_check_token(SignatureCheck::Invalid), std::string_view{"invalid"});

  // A tampered document does not verify, even under the right key.
  const std::string tampered = bytes + " ";
  CHECK_EQ(verify_policy_signature(tampered, signed_document, kKey), SignatureCheck::Invalid);

  // A tampered MAC does not verify.
  DetachedSignature altered = signed_document;
  altered.mac[31] = static_cast<std::uint8_t>(altered.mac[31] ^ 0x01u);
  CHECK_EQ(verify_policy_signature(bytes, altered, kKey), SignatureCheck::Invalid);

  // An unsigned signature verifies nothing, even with a key configured.
  DetachedSignature unsigned_signature;
  CHECK(unsigned_signature.mode == SignatureMode::None);
  CHECK_EQ(verify_policy_signature(bytes, unsigned_signature, kKey), SignatureCheck::Invalid);

  // The detached signature document round trips through its own text form.
  const std::string text = signed_document.to_text();
  CHECK(text.find("\"schema\":\"summon.fbm.signature\"") != std::string::npos);
  auto parsed = DetachedSignature::parse(text, "/signature");
  CHECK_OK(parsed);
  CHECK(parsed.value().mode == SignatureMode::HmacSha256);
  CHECK_EQ(digest_to_hex(parsed.value().mac), digest_to_hex(signed_document.mac));
  CHECK_EQ(parsed.value().to_text(), text);
  CHECK_EQ(verify_policy_signature(bytes, parsed.value(), kKey), SignatureCheck::Valid);
}

FBM_TEST(policy_document_signature_document_is_strict) {
  const PolicyDocument document = must_parse(kDocumentText);
  const DetachedSignature signature = sign_policy_document(document.canonical_bytes(), kKey);

  json::Value::Object members = signature.to_json().as_object();
  for (json::Value::Member& member : members) {
    if (member.first == "schema") {
      member.second = json::Value{"summon.fbm.policy"};
    }
  }
  const json::Value wrong_schema{std::move(members)};
  CHECK_ERROR(DetachedSignature::from_json(wrong_schema, "/signature"),
              ErrorCode::SchemaInconsistentDocument);

  json::Value::Object unsupported_members = signature.to_json().as_object();
  for (json::Value::Member& member : unsupported_members) {
    if (member.first == "schema_version") {
      member.second = json::Value{2};
    }
  }
  const json::Value unsupported{std::move(unsupported_members)};
  CHECK_ERROR(DetachedSignature::from_json(unsupported, "/signature"),
              ErrorCode::FormatVersionUnsupported);

  json::Value::Object missing_members = signature.to_json().as_object();
  for (std::size_t index = 0; index < missing_members.size(); ++index) {
    if (missing_members[index].first == "mac") {
      missing_members.erase(missing_members.begin() + static_cast<std::ptrdiff_t>(index));
      break;
    }
  }
  const json::Value missing{std::move(missing_members)};
  CHECK_ERROR(DetachedSignature::from_json(missing, "/signature"), ErrorCode::SchemaMissingField);

  json::Value::Object unknown_members = signature.to_json().as_object();
  unknown_members.emplace_back("key", json::Value{"secret"});
  const json::Value unknown{std::move(unknown_members)};
  CHECK_ERROR(DetachedSignature::from_json(unknown, "/signature"), ErrorCode::SchemaUnknownField);

  json::Value::Object bad_mode_members = signature.to_json().as_object();
  for (json::Value::Member& member : bad_mode_members) {
    if (member.first == "mode") {
      member.second = json::Value{"hmac"};
    }
  }
  const json::Value bad_mode{std::move(bad_mode_members)};
  CHECK_ERROR(DetachedSignature::from_json(bad_mode, "/signature"),
              ErrorCode::SchemaInvalidEnumValue);

  json::Value::Object bad_mac_members = signature.to_json().as_object();
  for (json::Value::Member& member : bad_mac_members) {
    if (member.first == "mac") {
      member.second = json::Value{"not-a-digest"};
    }
  }
  const json::Value bad_mac{std::move(bad_mac_members)};
  CHECK_ERROR(DetachedSignature::from_json(bad_mac, "/signature"), ErrorCode::SchemaValueOutOfRange);
}
