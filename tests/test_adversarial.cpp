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

// Adversarial tests. Each one attacks the runtime with hostile, truncated, or
// inconsistent input and fails if the library crashes, accepts something it
// must reject, or reports a different error for identical input on a second
// run.
//
// There are deliberately no timeouts anywhere in this file: a hang is a defect
// to be diagnosed, not to be papered over, so the suite cannot mask one.
//
// Cases that this host cannot produce are skipped explicitly, in place, with a
// comment saying why; nothing here is pretended to have passed.

#include "check.hpp"
#include "support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/cohort.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/exception.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/manager.hpp"
#include "summon/fbm/observation.hpp"
#include "summon/fbm/platform.hpp"
#include "summon/fbm/policy_document.hpp"
#include "summon/fbm/snapshot.hpp"
#include "summon/fbm/store.hpp"

using namespace summon::fbm;
using namespace fbm_test;

namespace json = summon::fbm::json;

namespace {

// --- byte helpers -----------------------------------------------------------

std::string read_bytes(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

void write_bytes(const std::filesystem::path& path, std::string_view data) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::uint16_t read_u16(std::string_view bytes, std::size_t offset) {
  std::uint16_t value = 0;
  for (unsigned index = 0; index < 2; ++index) {
    value |= static_cast<std::uint16_t>(
                 static_cast<unsigned char>(bytes[offset + index]))
             << (8u * index);
  }
  return value;
}

std::uint32_t read_u32(std::string_view bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (unsigned index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(
                 static_cast<unsigned char>(bytes[offset + index]))
             << (8u * index);
  }
  return value;
}

void write_u16(std::string& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<char>(value & 0xFFu);
  bytes[offset + 1] = static_cast<char>((value >> 8) & 0xFFu);
}

void write_u32(std::string& bytes, std::size_t offset, std::uint32_t value) {
  for (unsigned index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<char>((value >> (8u * index)) & 0xFFu);
  }
}

// Recomputes a frame's own checksum, so that a test can attack a later layer
// without the checksum catching the edit first.
void reseal_frame(std::string& bytes) {
  const std::size_t frame_crc_offset = bytes.size() - kRecordTrailerBytes;
  write_u32(bytes, frame_crc_offset, Crc32c::of(bytes.data(), frame_crc_offset));
}

std::string hex_of(std::string_view text) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(text.size() * 2u);
  for (const char raw : text) {
    const auto byte = static_cast<unsigned char>(raw);
    out.push_back(kDigits[(byte >> 4u) & 0x0Fu]);
    out.push_back(kDigits[byte & 0x0Fu]);
  }
  return out;
}

std::string quoted_text(std::string_view text) { return "\"" + std::string{text} + "\""; }

// A cheap, complete description of an outcome, used to prove that identical
// input produces identical errors on a second run.
template <class T>
std::string outcome_signature(const Result<T>& result) {
  return result.has_value() ? std::string{"ok"} : result.error().to_string();
}

// --- fixtures ---------------------------------------------------------------

StoreOptions writable_store_options(const std::filesystem::path& directory,
                                    bool create_if_missing) {
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = create_if_missing;
  options.take_writer_lock = true;
  return options;
}

struct CommittedRecord {
  std::string bytes;
  unsigned slot = 0;
  Digest digest{};
  bool valid = false;
};

// Commits exactly one generation into a fresh scratch directory and returns the
// raw bytes of the slot that became authoritative.
CommittedRecord commit_one_generation(const std::filesystem::path& directory) {
  CommittedRecord record;
  auto store = DurableStore::open(writable_store_options(directory, true));
  REQUIRE(store.has_value());
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{1};
  auto outcome = store.value()->commit(std::move(next));
  REQUIRE(outcome.has_value());
  record.slot = outcome.value().slot;
  record.digest = outcome.value().digest;
  store.value().reset();
  record.bytes = read_bytes(StorePaths::for_directory(directory).slot_file(record.slot));
  record.valid = true;
  return record;
}

// A complete, valid small policy document: one published baseline.
PolicyDocument small_policy_document() {
  Baseline baseline;
  baseline.id = BaselineId{"pol-base"};
  baseline.generation = BaselineGeneration{3};
  baseline.revision = Revision{5};
  baseline.state = BaselineState::Published;
  baseline.title = "small policy";
  HardwareSelector selector;
  selector.hardware_class = HardwareClassId{"gpu"};
  selector.model = HardwareModelId{"h100"};
  selector.minimum_revision = HardwareRevision{1};
  selector.maximum_revision = HardwareRevision{4};
  baseline.selectors.push_back(selector);
  baseline.components.push_back(ComponentRequirement{
      .component = FirmwareComponentId{"bmc"},
      .approved_version = version("2.4.1"),
      .conformant_versions = {version("2.4.0"), version("2.4.1")},
      .rollback_targets = {version("2.3.9")},
      .freshness = FreshnessBound::within(86400000000000ull)});
  baseline.gate.minimum_conformant_basis_points = 9900u;
  baseline.gate.minimum_decided_assets = 2u;
  baseline.gate.minimum_conformant_assets = 2u;
  baseline.gate.required_stages = StageIndex{2};
  baseline.created_at = base_time();
  baseline.published_at = base_time();
  Diagnostics diagnostics;
  Status valid = baseline.validate("/baseline", diagnostics);
  REQUIRE(valid.has_value());
  std::vector<Baseline> baselines;
  baselines.push_back(std::move(baseline));
  return PolicyDocument{std::move(baselines)};
}

void require_valid_snapshot_text(const std::string& text) {
  auto parsed = json::parse(text, json::Limits{}, "/snapshot");
  REQUIRE(parsed.has_value());
  auto decoded = Snapshot::from_json(parsed.value(), "/snapshot");
  REQUIRE(decoded.has_value());
}

// Every byte of a single-byte corruption must be accounted for: either the text
// no longer parses, or the value is rejected by the schema, or the corruption
// changed the document's canonical bytes. A corruption that leaves the parsed
// value byte-identical to the original would mean a byte was silently dropped.
std::string corruption_report(const char* kind, std::size_t index, unsigned mask,
                              std::string_view original, std::string_view corrupted) {
  return std::string{kind} + " single-byte corruption was ignored at index " +
         std::to_string(index) + " mask=0x" + [mask]() {
           constexpr char kDigits[] = "0123456789abcdef";
           std::string text{"0x"};
           text.push_back(kDigits[(mask >> 4u) & 0x0Fu]);
           text.push_back(kDigits[mask & 0x0Fu]);
           return text;
         }() +
         " original_byte=0x" + hex_of(original.substr(index, 1)) +
         " replacement_byte=0x" + hex_of(corrupted.substr(index, 1)) +
         " corrupted_document=" + std::string{corrupted};
}

}  // namespace

// ---------------------------------------------------------------------------
// Policy documents
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_policy_document_prefixes_are_always_rejected) {
  const PolicyDocument document = small_policy_document();
  const std::string text = document.canonical_bytes();
  CHECK_GT(text.size(), std::size_t{100});

  auto parsed = PolicyDocument::parse(text, "/policy");
  REQUIRE(parsed.has_value());
  CHECK_EQ(parsed.value().canonical_bytes(), text);
  CHECK(parsed.value().content_digest() == document.content_digest());

  // Every strict prefix of the document is rejected. A truncated document is
  // never completed by guessing the missing bytes.
  std::string first_failure;
  for (std::size_t length = 0; length < text.size(); ++length) {
    auto truncated = PolicyDocument::parse(text.substr(0, length), "/policy");
    if (truncated.has_value()) {
      first_failure = "prefix of " + std::to_string(length) + " of " +
                      std::to_string(text.size()) +
                      " bytes parsed as a complete policy document: " + text.substr(0, length);
      break;
    }
  }
  CHECK_MSG(first_failure.empty(), first_failure);
}

FBM_TEST(adversarial_policy_document_corruptions_are_never_ignored) {
  const PolicyDocument document = small_policy_document();
  const std::string original = document.canonical_bytes();
  const unsigned masks[] = {0x01u, 0x80u, 0xFFu};
  constexpr std::size_t kMaskCount = 3;

  std::string first_failure;
  std::size_t ignored = 0;
  for (std::size_t index = 0; index < original.size(); ++index) {
    for (std::size_t mask_index = 0; mask_index < kMaskCount; ++mask_index) {
      const unsigned mask = masks[mask_index];
      std::string corrupted = original;
      corrupted[index] = static_cast<char>(static_cast<unsigned char>(corrupted[index]) ^ mask);

      auto parsed_value = json::parse(corrupted, json::Limits{}, "/policy");
      if (!parsed_value.has_value()) {
        continue;  // the text is no longer JSON at all
      }
      auto decoded = PolicyDocument::from_json(parsed_value.value(), "/policy");
      if (!decoded.has_value()) {
        continue;  // the schema rejected it
      }
      if (decoded.value().canonical_bytes() != original) {
        continue;  // a different, but well-formed, document
      }
      ++ignored;
      if (first_failure.empty()) {
        first_failure = corruption_report("policy document", index, mask, original, corrupted);
      }
    }
  }
  CHECK_MSG(ignored == 0u, first_failure);
}

FBM_TEST(adversarial_policy_document_shape_defects_are_specific) {
  const PolicyDocument document = small_policy_document();
  const std::string text = document.canonical_bytes();
  auto parsed = json::parse(text, json::Limits{}, "/policy");
  REQUIRE(parsed.has_value());
  const json::Value value = parsed.value();

  // Wrong schema marker.
  {
    json::Value altered = value;
    altered.set("schema", json::Value{"summon.fbm.policy.v2"});
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"),
                ErrorCode::SchemaInconsistentDocument);
  }
  // Unsupported schema version.
  {
    json::Value altered = value;
    altered.set("schema_version", json::Value{std::int64_t{2}});
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"),
                ErrorCode::FormatVersionUnsupported);
  }
  // Negative schema version.
  {
    json::Value altered = value;
    altered.set("schema_version", json::Value{std::int64_t{-1}});
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"), ErrorCode::SchemaValueOutOfRange);
  }
  // Missing required members.
  {
    json::Value altered = value;
    CHECK(altered.erase("schema"));
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value altered = value;
    CHECK(altered.erase("baselines"));
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"), ErrorCode::SchemaMissingField);
  }
  // Unknown member.
  {
    json::Value altered = value;
    altered.set("extra", json::Value{"x"});
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"), ErrorCode::SchemaUnknownField);
  }
  // Wrong type for a member.
  {
    json::Value altered = value;
    altered.set("schema_version", json::Value{"one"});
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"), ErrorCode::SchemaWrongType);
  }
  // A document that is not an object at all.
  CHECK_ERROR(PolicyDocument::from_json(json::Value{std::string{"x"}}, "/policy"),
              ErrorCode::SchemaWrongType);
  // Empty baselines array is a document that approves nothing.
  {
    json::Value altered = value;
    altered.set("baselines", json::Value::make_array());
    auto decoded = PolicyDocument::from_json(altered, "/policy");
    CHECK_OK(decoded);
    CHECK_EQ(decoded.value().baselines().size(), std::size_t{0});
  }
  // Two baselines with the same identity are ambiguous and rejected.
  {
    json::Value altered = value;
    const json::Value* baselines = altered.find("baselines");
    REQUIRE(baselines != nullptr);
    json::Value doubled = json::Value::make_array();
    for (const json::Value& element : baselines->as_array()) {
      doubled.push_back(element);
    }
    for (const json::Value& element : baselines->as_array()) {
      doubled.push_back(element);
    }
    altered.set("baselines", std::move(doubled));
    CHECK_ERROR(PolicyDocument::from_json(altered, "/policy"),
                ErrorCode::SchemaDuplicateIdentifier);
  }

  // Every prefix of the malformed variants is rejected as well.
  const std::string truncated = text.substr(0, text.size() / 2u);
  auto truncated_parse = PolicyDocument::parse(truncated, "/policy");
  CHECK(!truncated_parse.has_value());
  CHECK(!PolicyDocument::parse("", "/policy").has_value());
  CHECK(!PolicyDocument::parse("{", "/policy").has_value());
  CHECK(!PolicyDocument::parse("[]", "/policy").has_value());
  // Insignificant trailing whitespace is not a defect.
  CHECK(PolicyDocument::parse(text + " ", "/policy").has_value());
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_snapshot_document_prefixes_are_always_rejected) {
  const std::filesystem::path directory = scratch_directory("adversarial-snapshot-prefix");
  Fixture fixture = publish_fixture(directory);
  const std::string text =
      json::write_canonical(fixture.manager->snapshot().to_json());
  require_valid_snapshot_text(text);

  std::string first_failure;
  for (std::size_t length = 0; length < text.size(); ++length) {
    auto parsed = json::parse(text.substr(0, length), json::Limits{}, "/snapshot");
    if (parsed.has_value()) {
      auto decoded = Snapshot::from_json(parsed.value(), "/snapshot");
      if (decoded.has_value()) {
        first_failure = "snapshot prefix of " + std::to_string(length) + " bytes decoded";
        break;
      }
    }
  }
  CHECK_MSG(first_failure.empty(), first_failure);
}

FBM_TEST(adversarial_snapshot_document_corruptions_are_never_ignored) {
  const std::filesystem::path directory = scratch_directory("adversarial-snapshot-corrupt");
  Fixture fixture = publish_fixture(directory);
  make_conformant(*fixture.manager, fixture.asset, fixture.now);
  const std::string original =
      json::write_canonical(fixture.manager->snapshot().to_json());
  require_valid_snapshot_text(original);

  const unsigned masks[] = {0x01u, 0x80u, 0xFFu};
  constexpr std::size_t kMaskCount = 3;
  std::string first_failure;
  std::size_t ignored = 0;
  for (std::size_t index = 0; index < original.size(); ++index) {
    for (std::size_t mask_index = 0; mask_index < kMaskCount; ++mask_index) {
      const unsigned mask = masks[mask_index];
      std::string corrupted = original;
      corrupted[index] = static_cast<char>(static_cast<unsigned char>(corrupted[index]) ^ mask);
      auto parsed_value = json::parse(corrupted, json::Limits{}, "/snapshot");
      if (!parsed_value.has_value()) {
        continue;
      }
      auto decoded = Snapshot::from_json(parsed_value.value(), "/snapshot");
      if (!decoded.has_value()) {
        continue;
      }
      if (json::write_canonical(decoded.value().to_json()) != original) {
        continue;
      }
      ++ignored;
      if (first_failure.empty()) {
        first_failure = corruption_report("snapshot document", index, mask, original, corrupted);
      }
    }
  }
  CHECK_MSG(ignored == 0u, first_failure);
}

FBM_TEST(adversarial_snapshot_document_shape_defects_are_specific) {
  const std::filesystem::path directory = scratch_directory("adversarial-snapshot-shape");
  Fixture fixture = publish_fixture(directory);
  auto parsed = json::parse(json::write_canonical(fixture.manager->snapshot().to_json()),
                            json::Limits{}, "/snapshot");
  REQUIRE(parsed.has_value());
  const json::Value value = parsed.value();

  // A different format marker is a different format, not this one read loosely.
  {
    json::Value altered = value;
    altered.set("format", json::Value{"summon.fbm.snapshot.v2"});
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::FormatMagicMismatch);
  }
  {
    json::Value altered = value;
    altered.set("format_version", json::Value{std::int64_t{2}});
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::FormatVersionUnsupported);
  }
  {
    json::Value altered = value;
    altered.set("format_version", json::Value{std::int64_t{-1}});
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::SchemaValueOutOfRange);
  }
  {
    json::Value altered = value;
    CHECK(altered.erase("format"));
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value altered = value;
    CHECK(altered.erase("baselines"));
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value altered = value;
    altered.set("note", json::Value{"extra"});
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::SchemaUnknownField);
  }
  {
    json::Value altered = value;
    altered.set("observations", json::Value::make_array());
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::SchemaWrongType);
  }
  CHECK_ERROR(Snapshot::from_json(json::Value{std::string{"x"}}, "/snapshot"),
              ErrorCode::SchemaWrongType);
  // A snapshot whose revision is the largest integer JSON can carry is accepted;
  // a negative counter is not.
  {
    json::Value altered = value;
    altered.set("revision", json::Value{std::int64_t{9223372036854775807LL}});
    auto decoded = Snapshot::from_json(altered, "/snapshot");
    CHECK_OK(decoded);
    CHECK_EQ(decoded.value().revision.value(), std::uint64_t{9223372036854775807ull});
  }
  {
    json::Value altered = value;
    altered.set("revision", json::Value{std::int64_t{-1}});
    CHECK_ERROR(Snapshot::from_json(altered, "/snapshot"), ErrorCode::SchemaValueOutOfRange);
  }
  // A counter one past the largest integer that fits std::int64_t is never
  // silently wrapped: the reader turns the literal into a real value, and the
  // counter reader then rejects it as the wrong JSON type for a counter.
  {
    const std::string beyond =
        "{" + std::string{"\"format\":\"summon.fbm.snapshot\",\"format_version\":1,"} +
        "\"revision\":9223372036854775808,\"baselines\":[],"
        "\"observations\":{\"profiles\":[],\"components\":[]},"
        "\"exceptions\":[],\"cohorts\":[],\"authorizations\":[]}";
    auto parsed_beyond = json::parse(beyond, json::Limits{}, "/snapshot");
    REQUIRE(parsed_beyond.has_value());
    const json::Value* revision = parsed_beyond.value().find("revision");
    REQUIRE(revision != nullptr);
    CHECK(revision->is_real());
    CHECK_ERROR(Snapshot::from_json(parsed_beyond.value(), "/snapshot"),
                ErrorCode::SchemaWrongType);
  }
  // A number that is not representable at all is reported by the reader.
  {
    CHECK_ERROR(json::parse("1e999", json::Limits{}, "/doc"),
                ErrorCode::EncodingNumberOutOfRange);
  }
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_frame_single_byte_corruptions_are_all_rejected) {
  const std::filesystem::path directory = scratch_directory("adversarial-frame-corrupt");
  const CommittedRecord record = commit_one_generation(directory);
  REQUIRE(record.valid);
  REQUIRE(read_bytes(StorePaths::for_directory(directory).slot_file(record.slot)) == record.bytes);

  std::string first_failure;
  for (std::size_t index = 0; index < record.bytes.size(); ++index) {
    std::string corrupted = record.bytes;
    corrupted[index] = static_cast<char>(static_cast<unsigned char>(corrupted[index]) ^ 0xFFu);
    auto frame = decode_record(corrupted, "/frame");
    if (frame.has_value()) {
      first_failure = "frame byte " + std::to_string(index) + " could be corrupted with 0xFF " +
                      "and still decoded (size=" + std::to_string(record.bytes.size()) + ")";
      break;
    }
  }
  CHECK_MSG(first_failure.empty(), first_failure);
}

FBM_TEST(adversarial_frame_truncations_and_extensions_are_rejected) {
  const std::filesystem::path directory = scratch_directory("adversarial-frame-truncate");
  const CommittedRecord record = commit_one_generation(directory);
  REQUIRE(record.valid);

  // Every prefix, including the empty one, and every suffix removal.
  std::string first_failure;
  for (std::size_t length = 0; length < record.bytes.size(); ++length) {
    auto frame = decode_record(std::string_view{record.bytes}.substr(0, length), "/prefix");
    if (frame.has_value()) {
      first_failure = "a prefix of " + std::to_string(length) + " bytes decoded as a frame";
      break;
    }
  }
  if (first_failure.empty()) {
    for (std::size_t removed = 1; removed <= record.bytes.size(); ++removed) {
      auto frame = decode_record(
          std::string_view{record.bytes}.substr(0, record.bytes.size() - removed), "/suffix");
      if (frame.has_value()) {
        first_failure = "removing the last " + std::to_string(removed) + " bytes left a frame";
        break;
      }
    }
  }
  CHECK_MSG(first_failure.empty(), first_failure);

  // Trailing bytes after a complete frame are never tolerated.
  CHECK_ERROR(decode_record(record.bytes + "x", "/trailing"), ErrorCode::FormatTrailingBytes);
  CHECK_ERROR(decode_record("", "/empty"), ErrorCode::FormatTruncated);

  // A declared payload larger than the configured maximum is rejected by the
  // limit check before any buffer is sized from it. This is the snapshot size
  // limit: the length in the frame header is attacker-controlled.
  {
    std::string oversized = record.bytes;
    write_u32(oversized, 36, kMaxRecordPayloadBytes + 1u);
    CHECK_ERROR(decode_record(oversized, "/oversized"), ErrorCode::FormatLengthOutOfRange);
  }
  {
    std::string maximal = record.bytes;
    write_u32(maximal, 36, 0xFFFFFFFFu);
    CHECK_ERROR(decode_record(maximal, "/maximum"), ErrorCode::FormatLengthOutOfRange);
  }
  {
    std::string zero_length = record.bytes;
    write_u32(zero_length, 36, 0u);
    CHECK_ERROR(decode_record(zero_length, "/zero"), ErrorCode::FormatTrailingBytes);
  }

  // Header fields are checked in a fixed order, so each defect is named exactly.
  {
    std::string bytes = record.bytes;
    write_u32(bytes, 0, 0xDEADBEEFu);
    CHECK_ERROR(decode_record(bytes, "/magic"), ErrorCode::FormatMagicMismatch);
  }
  {
    std::string bytes = record.bytes;
    write_u16(bytes, 4, 99);
    CHECK_ERROR(decode_record(bytes, "/version"), ErrorCode::FormatVersionUnsupported);
  }
  {
    std::string bytes = record.bytes;
    write_u16(bytes, 6, 77);
    CHECK_ERROR(decode_record(bytes, "/kind"), ErrorCode::FormatRecordKindUnknown);
  }
  {
    std::string bytes = record.bytes;
    write_u32(bytes, 8, 1);
    CHECK_ERROR(decode_record(bytes, "/reserved"), ErrorCode::FormatReservedFieldNonZero);
  }
  {
    std::string bytes = record.bytes;
    bytes[kRecordHeaderBytes + 3u] = static_cast<char>(
        static_cast<unsigned char>(bytes[kRecordHeaderBytes + 3u]) ^ 0x40u);
    CHECK_ERROR(decode_record(bytes, "/payload"), ErrorCode::FormatChecksumMismatch);
  }
  {
    // The payload byte is changed, the payload checksum is corrected, and the
    // frame checksum is resealed: only the payload digest can catch this.
    std::string bytes = record.bytes;
    bytes[kRecordHeaderBytes + 3u] = static_cast<char>(
        static_cast<unsigned char>(bytes[kRecordHeaderBytes + 3u]) ^ 0x40u);
    const std::string_view payload{bytes.data() + kRecordHeaderBytes,
                                   bytes.size() - kRecordOverheadBytes};
    write_u32(bytes, 40, Crc32c::of(payload.data(), payload.size()));
    reseal_frame(bytes);
    CHECK_ERROR(decode_record(bytes, "/digest"), ErrorCode::FormatDigestMismatch);
  }
}

FBM_TEST(adversarial_frame_decode_is_a_pure_function_of_its_bytes) {
  const std::filesystem::path directory = scratch_directory("adversarial-frame-determinism");
  const CommittedRecord record = commit_one_generation(directory);
  REQUIRE(record.valid);

  std::string first_failure;
  for (std::size_t index = 0; index + 3u < record.bytes.size(); index += 3u) {
    std::string corrupted = record.bytes;
    corrupted[index] = static_cast<char>(static_cast<unsigned char>(corrupted[index]) ^ 0x5Au);
    const std::string first = outcome_signature(decode_record(corrupted, "/frame"));
    const std::string second = outcome_signature(decode_record(corrupted, "/frame"));
    if (first != second) {
      first_failure = "decode_record returned two different outcomes for one input at index " +
                      std::to_string(index) + ": " + first + " vs " + second;
      break;
    }
    if (!decode_record(record.bytes, "/frame").has_value()) {
      first_failure = "an untouched committed frame no longer decodes";
      break;
    }
  }
  CHECK_MSG(first_failure.empty(), first_failure);
}

// ---------------------------------------------------------------------------
// Absurd values and counters
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_absurd_numeric_values_are_rejected_by_the_schema) {
  const PolicyDocument document = small_policy_document();
  auto parsed = json::parse(document.canonical_bytes(), json::Limits{}, "/policy");
  REQUIRE(parsed.has_value());

  const auto with_gate_field = [&parsed](const char* field, std::int64_t raw) {
    json::Value altered = parsed.value();
    const json::Value* baselines = altered.find("baselines");
    json::Value::Array elements = baselines->as_array();
    json::Value::Object baseline_members = elements.front().as_object();
    for (json::Value::Member& member : baseline_members) {
      if (member.first == "gate") {
        json::Value::Object gate_members = member.second.as_object();
        bool replaced = false;
        for (json::Value::Member& gate_member : gate_members) {
          if (gate_member.first == field) {
            gate_member.second = json::Value{raw};
            replaced = true;
          }
        }
        if (!replaced) {
          gate_members.emplace_back(field, json::Value{raw});
        }
        member.second = json::Value{std::move(gate_members)};
      }
    }
    elements.front() = json::Value{std::move(baseline_members)};
    altered.set("baselines", json::Value{std::move(elements)});
    return altered;
  };

  // At the documented maximum the gate is accepted; one past it is not.
  {
    auto decoded = PolicyDocument::from_json(with_gate_field("minimum_conformant_basis_points",
                                                             10000),
                                             "/policy");
    CHECK_OK(decoded);
  }
  CHECK_ERROR(PolicyDocument::from_json(with_gate_field("minimum_conformant_basis_points", 10001),
                                        "/policy"),
              ErrorCode::SchemaValueOutOfRange);
  {
    auto decoded = PolicyDocument::from_json(
        with_gate_field("minimum_conformant_basis_points", 4294967295LL), "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaValueOutOfRange);
  }
  {
    // Zero stages is not "no stages required"; it is an empty requirement.
    auto decoded =
        PolicyDocument::from_json(with_gate_field("required_stages", 0), "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaValueOutOfRange);
  }
  {
    auto decoded = PolicyDocument::from_json(with_gate_field("required_stages", -1), "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaValueOutOfRange);
  }
  {
    auto decoded = PolicyDocument::from_json(with_gate_field("soak_nanos", -1), "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaValueOutOfRange);
  }
  {
    // A gate is allowed to demand no conformant assets at all. The decided
    // minimum is what keeps a gate from promoting on nothing, and the gate
    // evaluator independently reports every unknown, unsupported, or blocked
    // member as an unmet condition rather than counting it.
    auto decoded = PolicyDocument::from_json(with_gate_field("minimum_conformant_assets", 0),
                                             "/policy");
    CHECK_OK(decoded);
  }
  {
    auto decoded = PolicyDocument::from_json(with_gate_field("minimum_decided_assets", 0),
                                             "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaValueOutOfRange);
  }
  {
    // A decided minimum below the conformant minimum is a contradiction.
    auto decoded = PolicyDocument::from_json(with_gate_field("minimum_decided_assets", 1),
                                             "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaInconsistentDocument);
  }
  {
    auto decoded =
        PolicyDocument::from_json(with_gate_field("required_stages", 4294967296LL), "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaValueOutOfRange);
  }
  {
    auto decoded = PolicyDocument::from_json(with_gate_field("minimum_conformant_basis_points",
                                                             9223372036854775807LL),
                                             "/policy");
    CHECK_ERROR(decoded, ErrorCode::SchemaValueOutOfRange);
  }

  // A baseline generation at the largest value JSON can carry is a legal
  // counter; one past it does not fit and is reported by the reader.
  const auto with_baseline_field = [&parsed](const char* field, std::int64_t raw) {
    json::Value altered = parsed.value();
    const json::Value* baselines = altered.find("baselines");
    json::Value::Array elements = baselines->as_array();
    json::Value::Object baseline_members = elements.front().as_object();
    bool replaced = false;
    for (json::Value::Member& member : baseline_members) {
      if (member.first == field) {
        member.second = json::Value{raw};
        replaced = true;
      }
    }
    if (!replaced) {
      baseline_members.emplace_back(field, json::Value{raw});
    }
    elements.front() = json::Value{std::move(baseline_members)};
    altered.set("baselines", json::Value{std::move(elements)});
    return altered;
  };
  {
    auto decoded = PolicyDocument::from_json(
        with_baseline_field("generation", 9223372036854775807LL), "/policy");
    CHECK_OK(decoded);
    CHECK_EQ(decoded.value().baselines().front().generation.value(),
             std::uint64_t{9223372036854775807ull});
  }
  CHECK_ERROR(
      PolicyDocument::from_json(with_baseline_field("generation", -1), "/policy"),
      ErrorCode::SchemaValueOutOfRange);
  {
    // Zero is a legal non-negative counter and stays a stated zero rather than
    // becoming an absent value.
    auto decoded = PolicyDocument::from_json(with_baseline_field("generation", 0), "/policy");
    CHECK_OK(decoded);
    CHECK(decoded.value().baselines().front().generation.is_set());
    CHECK_EQ(decoded.value().baselines().front().generation.value(), std::uint64_t{0});
  }
}

FBM_TEST(adversarial_counter_overflow_is_reported_never_wrapped) {
  // The counter type itself reports exhaustion instead of wrapping.
  Revision revision{std::numeric_limits<std::uint64_t>::max()};
  Revision next_revision;
  CHECK(!revision.checked_next(next_revision));
  CHECK(!next_revision.is_set());

  BaselineGeneration generation{std::numeric_limits<std::uint64_t>::max()};
  BaselineGeneration next_generation;
  CHECK(!generation.checked_next(next_generation));

  CommitSequence sequence{std::numeric_limits<std::uint64_t>::max()};
  CommitSequence next_sequence;
  CHECK(!sequence.checked_next(next_sequence));

  ControlEpoch epoch{std::numeric_limits<std::uint64_t>::max()};
  ControlEpoch next_epoch;
  CHECK(!epoch.checked_next(next_epoch));

  IncarnationId incarnation{std::numeric_limits<std::uint64_t>::max()};
  IncarnationId next_incarnation;
  CHECK(!incarnation.checked_next(next_incarnation));

  PolicyGeneration policy{std::numeric_limits<std::uint64_t>::max()};
  PolicyGeneration next_policy;
  CHECK(!policy.checked_next(next_policy));

  ObservationSequence observation{std::numeric_limits<std::uint64_t>::max()};
  ObservationSequence next_observation;
  CHECK(!observation.checked_next(next_observation));

  StageIndex stage{std::numeric_limits<std::uint32_t>::max()};
  StageIndex next_stage;
  CHECK(!stage.checked_next(next_stage));

  // An unset counter is not zero, and has no successor to take.
  Revision unset_revision;
  Revision after_unset;
  CHECK(!unset_revision.is_set());
  CHECK(!unset_revision.checked_next(after_unset));

  // A durable publication of an exhausted counter is refused, and the refusal
  // leaves the previously committed generation authoritative.
  const std::filesystem::path directory = scratch_directory("adversarial-counter-overflow");
  const StoreOptions options = writable_store_options(directory, true);
  Digest committed_digest{};
  Revision committed_revision{};
  {
    auto store = DurableStore::open(options);
    REQUIRE(store.has_value());
    Snapshot next = store.value()->snapshot();
    next.revision = Revision{7};
    auto outcome = store.value()->commit(std::move(next));
    REQUIRE(outcome.has_value());
    committed_digest = outcome.value().digest;
    committed_revision = store.value()->snapshot().revision;
    CHECK(committed_revision == Revision{7});

    // The revision cannot be represented in the durable encoding, so the commit
    // must be refused rather than silently published as a wrapped value.
    Snapshot exhausted = store.value()->snapshot();
    exhausted.revision = Revision{std::numeric_limits<std::uint64_t>::max()};
    auto refused = store.value()->commit(std::move(exhausted));
    CHECK(!refused.has_value());
    CHECK(refused.error().code() == ErrorCode::SchemaValueOutOfRange ||
          refused.error().code() == ErrorCode::InternalInvariantViolation);
    // The in-memory generation is untouched by the refusal.
    CHECK(store.value()->snapshot().revision == committed_revision);
    CHECK(store.value()->published_digest() == committed_digest);
    store.value().reset();
  }
  {
    auto reopened = DurableStore::open(options);
    CHECK_OK(reopened);
    CHECK(reopened.value()->snapshot().revision == committed_revision);
    CHECK(reopened.value()->published_digest() == committed_digest);
    CHECK(reopened.value()->recovery().outcome == RecoveryOutcome::Recovered);
  }
}

// ---------------------------------------------------------------------------
// Duplicate identifiers
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_duplicate_identifiers_are_rejected_at_every_level) {
  const std::filesystem::path directory = scratch_directory("adversarial-duplicates");
  const Timestamp start = base_time();
  Fixture fixture = publish_fixture(directory, start);
  BaselineManager& manager = *fixture.manager;

  // Components: two adjacent requirements for the same component identity.
  {
    BaselineDraft draft = standard_draft();
    const ComponentRequirement duplicate = draft.components.front();
    draft.components.insert(draft.components.begin() + 1, duplicate);
    CHECK_ERROR(manager.define_baseline(draft, context_at(start, "req-dup-component")),
                ErrorCode::SchemaDuplicateIdentifier);
    CHECK(manager.snapshot().baselines.find(fixture.baseline) != nullptr);
  }
  // Components out of ascending order are a different, equally specific defect.
  {
    BaselineDraft draft = standard_draft();
    const ComponentRequirement first = draft.components.front();
    draft.components.push_back(first);
    CHECK_ERROR(manager.define_baseline(draft, context_at(start, "req-order-component")),
                ErrorCode::SchemaInconsistentDocument);
  }
  // Selectors: the same selector twice.
  {
    BaselineDraft draft = standard_draft();
    draft.selectors.push_back(draft.selectors.front());
    CHECK_ERROR(manager.define_baseline(draft, context_at(start, "req-dup-selector")),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  // Rules: the same rule identity twice.
  {
    BaselineDraft draft = standard_draft();
    auto added = draft.rules.add(draft.rules.rules().front());
    CHECK_ERROR(added, ErrorCode::SchemaDuplicateIdentifier);
    CHECK_EQ(draft.rules.size(), std::size_t{1});
  }
  // Baselines: the same identity twice in one policy document.
  {
    PolicyDocument document = manager.export_policy_document();
    std::vector<Baseline> doubled = document.baselines();
    for (const Baseline& baseline : document.baselines()) {
      doubled.push_back(baseline);
    }
    PolicyDocument duplicated{doubled};
    Diagnostics diagnostics;
    CHECK(!duplicated.validate("/policy", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaDuplicateIdentifier);
    CHECK_ERROR(manager.apply_policy_document(duplicated, context_at(start, "req-dup-policy")),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  // Exceptions: the same exception identity twice.
  {
    ExceptionDraft draft;
    draft.id = ExceptionId{"exc-1"};
    draft.scope.hardware_class = HardwareClassId{"gpu"};
    draft.scope.asset = fixture.asset;
    draft.expiry = Expiry::at(at(1769904000ull + 3600ull));
    draft.reason = "window";
    auto granted = manager.grant_exception(draft, context_at(start, "req-exc-1"));
    CHECK_OK(granted);
    CHECK_ERROR(manager.grant_exception(draft, context_at(start, "req-exc-1-again")),
                ErrorCode::SchemaDuplicateIdentifier);
    CHECK_EQ(manager.exceptions().size(), std::size_t{1});
  }
  // Observational evidence: the same asset twice in one observation document.
  {
    ObservationLog log;
    HardwareObservation observation;
    observation.id = ObservationId{"obs-1"};
    observation.evidence = EvidenceId{"ev-1"};
    observation.asset = fixture.asset;
    observation.hardware = profile_of();
    observation.hardware_generation = HardwareGeneration{1};
    observation.sequence = ObservationSequence{1};
    observation.observed_at = start;
    observation.reporter = IncarnationId{1};
    CHECK_OK(log.record(observation));
    const json::Value encoded = log.to_json();
    json::Value doubled = json::Value::make_object();
    json::Value::Object members = encoded.as_object();
    for (json::Value::Member& member : members) {
      if (member.first == "profiles") {
        json::Value::Array profiles = member.second.as_array();
        json::Value copy = profiles.front();
        profiles.push_back(std::move(copy));
        member.second = json::Value{std::move(profiles)};
      }
    }
    doubled = json::Value{std::move(members)};
    CHECK_ERROR(ObservationLog::from_json(doubled, "/observations"),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  // Cohorts: the same cohort identity twice. This block and the authorization
  // block below are last because both need a cohort to exist first.
  {
    CohortDraft draft;
    draft.id = CohortId{"wave-1"};
    draft.baseline = fixture.baseline;
    draft.baseline_generation = fixture.generation;
    draft.members = {fixture.asset};
    auto created = manager.create_cohort(draft, context_at(start, "req-cohort-1"));
    CHECK_MSG(created.has_value(), created.error().to_string());
    REQUIRE(created.has_value());
    CHECK_ERROR(manager.create_cohort(draft, context_at(start, "req-cohort-1-again")),
                ErrorCode::SchemaDuplicateIdentifier);
    CHECK_EQ(manager.cohorts().size(), std::size_t{1});
  }
  // Authorizations: the same request identity twice in one registry.
  {
    CohortDraft draft;
    draft.id = CohortId{"wave-2"};
    draft.baseline = fixture.baseline;
    draft.baseline_generation = fixture.generation;
    draft.members = {fixture.asset};
    auto created = manager.create_cohort(draft, context_at(start, "req-cohort-2"));
    CHECK_MSG(created.has_value(), created.error().to_string());
    REQUIRE(created.has_value());
    auto authorized = manager.authorize_cohort(created.value().id, created.value().revision,
                                               context_at(start, "req-authorize-2"));
    REQUIRE(authorized.has_value());
    CHECK_OK(manager.authorize_rollout(created.value().id, authorized.value().revision,
                                       context_at(start, "req-rollout-2")));
    const json::Value encoded = manager.snapshot().authorizations.to_json();
    REQUIRE(encoded.is_array());
    REQUIRE(encoded.size() == std::size_t{1});
    json::Value doubled = encoded;
    doubled.push_back(encoded.as_array().front());
    CHECK_ERROR(AuthorizationRegistry::from_json(doubled, "/authorizations"),
                ErrorCode::SchemaDuplicateIdentifier);
  }
}

// ---------------------------------------------------------------------------
// Stale generations, revisions, and authority
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_stale_generation_and_revision_are_fenced) {
  const std::filesystem::path directory = scratch_directory("adversarial-stale");
  const Timestamp start = base_time();
  Fixture fixture = publish_fixture(directory, start);
  BaselineManager& manager = *fixture.manager;

  // Publishing against the wrong generation.
  CHECK_ERROR(manager.publish_baseline(fixture.baseline,
                                       BaselineGeneration{fixture.generation.value() + 1u},
                                       context_at(start, "req-publish-stale")),
              ErrorCode::AuthorityStaleGeneration);
  CHECK_ERROR(manager.retire_baseline(fixture.baseline,
                                      BaselineGeneration{fixture.generation.value() + 1u},
                                      context_at(start, "req-retire-stale")),
              ErrorCode::AuthorityStaleGeneration);
  // An unknown baseline is an identity failure, not a stale one.
  CHECK_ERROR(manager.publish_baseline(BaselineId{"never-defined"}, BaselineGeneration{1},
                                       context_at(start, "req-publish-unknown")),
              ErrorCode::IdentityUnknownBaseline);

  // Revoking against the wrong revision.
  ExceptionDraft draft;
  draft.id = ExceptionId{"exc-stale"};
  draft.scope.hardware_class = HardwareClassId{"gpu"};
  draft.scope.asset = fixture.asset;
  draft.expiry = Expiry::at(at(1769904000ull + 3600ull));
  draft.reason = "window";
  auto granted = manager.grant_exception(draft, context_at(start, "req-exc"));
  REQUIRE(granted.has_value());
  const Revision granted_revision = granted.value().revision;
  CHECK_ERROR(manager.revoke_exception(granted.value().id, Revision{granted_revision.value() + 1u},
                                       context_at(start, "req-revoke-stale")),
              ErrorCode::AuthorityStaleRevision);
  CHECK_ERROR(manager.revoke_exception(ExceptionId{"never-granted"}, Revision{1},
                                       context_at(start, "req-revoke-unknown")),
              ErrorCode::IdentityUnknownException);
  // The correct revision still works, and a second revocation with the same
  // revision is stale rather than a second revocation.
  auto revoked = manager.revoke_exception(granted.value().id, granted_revision,
                                          context_at(start, "req-revoke"));
  CHECK_OK(revoked);
  CHECK_ERROR(manager.revoke_exception(granted.value().id, granted_revision,
                                       context_at(start, "req-revoke-again")),
              ErrorCode::AuthorityStaleRevision);

  // A cohort transition against a stale revision.
  CohortDraft cohort_draft;
  cohort_draft.id = CohortId{"wave-stale"};
  cohort_draft.baseline = fixture.baseline;
  cohort_draft.baseline_generation = fixture.generation;
  cohort_draft.members = {fixture.asset};
  auto created = manager.create_cohort(cohort_draft, context_at(start, "req-cohort"));
  CHECK_MSG(created.has_value(), created.error().to_string());
  REQUIRE(created.has_value());
  CHECK_ERROR(manager.authorize_cohort(created.value().id,
                                       Revision{created.value().revision.value() + 1u},
                                       context_at(start, "req-authorize-stale")),
              ErrorCode::AuthorityStaleRevision);
  CHECK_ERROR(manager.pause_cohort(created.value().id,
                                   Revision{created.value().revision.value() + 1u},
                                   context_at(start, "req-pause-stale")),
              ErrorCode::AuthorityStaleRevision);
  CHECK_ERROR(manager.authorize_rollout(created.value().id,
                                        Revision{created.value().revision.value() + 1u},
                                        context_at(start, "req-token-stale")),
              ErrorCode::AuthorityStaleRevision);

  // A cohort created against a generation the baseline has already left is
  // rejected at creation, so a stale cohort cannot even be formed.
  CohortDraft stale_draft = cohort_draft;
  stale_draft.id = CohortId{"wave-never"};
  stale_draft.baseline_generation = BaselineGeneration{fixture.generation.value() + 5u};
  CHECK_ERROR(manager.create_cohort(stale_draft, context_at(start, "req-cohort-stale")),
              ErrorCode::AuthorityStaleGeneration);
}

FBM_TEST(adversarial_cohort_promotion_is_fenced_by_a_moved_baseline) {
  const std::filesystem::path directory = scratch_directory("adversarial-cohort-fence");
  const Timestamp start = base_time();
  Fixture fixture = publish_fixture(directory, start);
  BaselineManager& manager = *fixture.manager;
  make_conformant(manager, fixture.asset, start);

  CohortDraft draft;
  draft.id = CohortId{"wave-1"};
  draft.baseline = fixture.baseline;
  draft.baseline_generation = fixture.generation;
  draft.members = {fixture.asset};
  auto created = manager.create_cohort(draft, context_at(start, "req-cohort"));
  CHECK_MSG(created.has_value(), created.error().to_string());
  REQUIRE(created.has_value());
  auto authorized = manager.authorize_cohort(created.value().id, created.value().revision,
                                             context_at(start, "req-authorize"));
  CHECK_MSG(authorized.has_value(), authorized.error().to_string());
  REQUIRE(authorized.has_value());
  const Revision authorized_revision = authorized.value().revision;

  // The baseline moves to a new generation: every authorization that bound the
  // old generation is fenced from that moment on.
  auto redefined = manager.define_baseline(standard_draft(), context_at(start, "req-redefine"));
  REQUIRE(redefined.has_value());
  CHECK(redefined.value().generation ==
        BaselineGeneration{fixture.generation.value() + 1u});
  auto republished = manager.publish_baseline(redefined.value().id, redefined.value().generation,
                                              context_at(start, "req-republish"));
  REQUIRE(republished.has_value());

  // Minting a fresh rollout token is refused for the fenced cohort.
  CHECK_ERROR(manager.authorize_rollout(created.value().id, authorized_revision,
                                        context_at(start, "req-rollout")),
              ErrorCode::AuthorityStaleGeneration);

  // Promotion of the same cohort must be refused as well: the cohort may not be
  // advanced on an authorization that the baseline move has already voided.
  EvaluationRequest request;
  request.asset = fixture.asset;
  request.now = start;
  request.gates = open_gates();
  auto promoted = manager.promote_cohort(created.value().id, authorized_revision, request,
                                         context_at(start, "req-promote"));
  const Cohort* stored = manager.snapshot().cohorts.find(created.value().id);
  REQUIRE(stored != nullptr);
  const CohortState state_after = stored->state;
  const Revision revision_after = stored->revision;
  CHECK_MSG(state_after == CohortState::Authorized,
            "a fenced cohort was promoted: state is now " +
                std::string{cohort_state_token(state_after)} + " at revision " +
                std::to_string(revision_after.value_or(0u)));
  CHECK(revision_after == authorized_revision);
  if (promoted.has_value()) {
    CHECK_MSG(false, "promote_cohort accepted a cohort whose baseline generation moved: " +
                         promoted.value().to_string());
  } else {
    CHECK_EQ(promoted.error().code(), ErrorCode::AuthorityStaleGeneration);
  }
}

FBM_TEST(adversarial_token_minted_before_a_policy_change_never_verifies) {
  const std::filesystem::path directory = scratch_directory("adversarial-token-policy");
  const Timestamp start = base_time();
  Fixture fixture = publish_fixture(directory, start);
  BaselineManager& manager = *fixture.manager;
  make_conformant(manager, fixture.asset, start);

  CohortDraft draft;
  draft.id = CohortId{"wave-1"};
  draft.baseline = fixture.baseline;
  draft.baseline_generation = fixture.generation;
  draft.members = {fixture.asset};
  auto created = manager.create_cohort(draft, context_at(start, "req-cohort"));
  CHECK_MSG(created.has_value(), created.error().to_string());
  REQUIRE(created.has_value());
  auto authorized = manager.authorize_cohort(created.value().id, created.value().revision,
                                             context_at(start, "req-authorize"));
  CHECK_MSG(authorized.has_value(), authorized.error().to_string());
  REQUIRE(authorized.has_value());
  auto token = manager.authorize_rollout(created.value().id, authorized.value().revision,
                                         context_at(start, "req-rollout"));
  REQUIRE(token.has_value());
  const std::string scope = "cohort/wave-1/rollout";
  const PlanId plan = authorized.value().plan;
  // A token that was just minted verifies against the state the manager holds.
  CHECK_OK(manager.verify_token(token.value(), scope, plan, start));

  // A policy change that leaves the bound baseline's generation, revision, and
  // content alone still fences the token through the policy generation.
  // Defining a further baseline is exactly such a change.
  const PolicyGeneration before = token.value().binding.policy_generation;
  BaselineDraft other = standard_draft("other-baseline");
  auto defined = manager.define_baseline(other, context_at(start, "req-other"));
  REQUIRE(defined.has_value());
  CHECK(manager.policy_generation().value() > before.value());
  // The token is fenced. Every commit advances the control epoch as well, and
  // the check order documented in authority.hpp places the epoch check before
  // the policy-generation check, so either stale-authority code is a correct
  // rejection here. A success would not be.
  const Status fenced = manager.verify_token(token.value(), scope, plan, start);
  CHECK(!fenced.has_value());
  if (!fenced.has_value()) {
    CHECK_MSG(fenced.error().code() == ErrorCode::AuthorityStalePolicyGeneration ||
                  fenced.error().code() == ErrorCode::AuthorityStaleEpoch,
              "a token minted before a policy change verified: " + fenced.error().to_string());
  }

  // The token is also fenced across an authority restart, because a new
  // incarnation begins a new control epoch. The documented check order places
  // the policy-generation check (8) before the control-epoch check (9), so a
  // token that a policy change already fenced reports the policy generation.
  // Either code is a correct rejection; a success would not be.
  const Digest old_mac = token.value().mac;
  const RequestId old_request = token.value().binding.request;
  fixture.manager.reset();
  auto reopened = BaselineManager::open(manager_options(directory, false, start));
  REQUIRE(reopened.has_value());
  AuthorizationToken stale = token.value();
  const Status across_restart = reopened.value()->verify_token(stale, scope, plan, start);
  CHECK(!across_restart.has_value());
  if (!across_restart.has_value()) {
    CHECK_MSG(across_restart.error().code() == ErrorCode::AuthorityStalePolicyGeneration ||
                  across_restart.error().code() == ErrorCode::AuthorityStaleEpoch,
              "a token survived an authority restart: " + across_restart.error().to_string());
  }
  // The recorded authorization is still durable, and its MAC is unchanged, so
  // the rejection is about fencing and not about a lost record.
  const AuthorizationToken* recorded =
      reopened.value()->snapshot().authorizations.find(old_request);
  REQUIRE(recorded != nullptr);
  CHECK(recorded->mac == old_mac);
}

FBM_TEST(adversarial_an_authority_restart_fences_a_token_through_the_control_epoch) {
  const std::filesystem::path directory = scratch_directory("adv-restart-epoch");
  Fixture fixture = publish_fixture(directory);
  make_conformant(*fixture.manager, fixture.asset, fixture.now);

  CohortDraft draft;
  draft.id = CohortId{"wave-restart"};
  draft.baseline = fixture.baseline;
  draft.baseline_generation = fixture.generation;
  draft.members = {fixture.asset};
  auto created = fixture.manager->create_cohort(draft, context_at(fixture.now, "req-cohort"));
  REQUIRE(created.has_value());
  auto authorized = fixture.manager->authorize_cohort(created.value().id, created.value().revision,
                                                      context_at(fixture.now, "req-authorize"));
  REQUIRE(authorized.has_value());
  auto token = fixture.manager->authorize_rollout(created.value().id, authorized.value().revision,
                                                  context_at(fixture.now, "req-rollout"));
  REQUIRE(token.has_value());

  const std::string scope = "cohort/wave-restart/rollout";
  const PlanId plan = authorized.value().plan;
  CHECK_OK(fixture.manager->verify_token(token.value(), scope, plan, fixture.now));

  // Restart the authority without changing any policy. The only fence that has
  // moved is the control epoch minted by the new incarnation, and the token's
  // incarnation is provenance rather than a fence.
  fixture.manager.reset();
  auto reopened = BaselineManager::open(manager_options(directory, false, fixture.now));
  REQUIRE(reopened.has_value());
  AuthorizationToken stale = token.value();
  CHECK_ERROR(reopened.value()->verify_token(stale, scope, plan, fixture.now),
              ErrorCode::AuthorityStaleEpoch);
}

// ---------------------------------------------------------------------------
// Evidence ordering
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_reordered_evidence_is_fenced) {
  const std::filesystem::path directory = scratch_directory("adversarial-evidence");
  const Timestamp start = base_time();
  Fixture fixture = publish_fixture(directory, start);
  BaselineManager& manager = *fixture.manager;
  const AssetId asset{"node-01"};
  const Timestamp observed = at(1769904000ull + 10ull);

  auto recorded = observe_profile(manager, asset, profile_of("gpu", "h100", 2),
                                  ObservationSequence{5}, observed, "ev-p5");
  REQUIRE(recorded.has_value());
  CHECK(recorded.value() == ObservationOutcome::Recorded);
  const CommitSequence after_first = manager.commit_sequence();

  // An exactly identical replay at the same sequence is the lost-response case
  // and must be accepted without writing anything.
  auto replay = observe_profile(manager, asset, profile_of("gpu", "h100", 2),
                                ObservationSequence{5}, observed, "ev-p5");
  CHECK_OK(replay);
  CHECK(replay.value() == ObservationOutcome::IdempotentReplay);
  CHECK(manager.commit_sequence() == after_first);

  // A differing replay at the same sequence is a conflict, not a replacement.
  auto conflicting = observe_profile(manager, asset, profile_of("gpu", "h100", 3),
                                     ObservationSequence{5}, observed, "ev-p5");
  CHECK_ERROR(conflicting, ErrorCode::EvidenceConflicting);
  CHECK(manager.commit_sequence() == after_first);

  // A lower sequence must never replace newer evidence.
  auto stale = observe_profile(manager, asset, profile_of("gpu", "h100", 4),
                               ObservationSequence{3}, observed, "ev-p3");
  CHECK_ERROR(stale, ErrorCode::EvidenceOutOfOrder);
  CHECK(manager.commit_sequence() == after_first);

  const HardwareObservation* stored = manager.snapshot().observations.profile(asset);
  REQUIRE(stored != nullptr);
  CHECK(stored->sequence == ObservationSequence{5});
  CHECK(stored->hardware.revision == HardwareRevision{2});
  CHECK(stored->evidence == EvidenceId{"ev-p5"});

  // The same rules hold for component evidence.
  auto component_recorded = observe_component(manager, asset, "bmc", version("2.4.1"),
                                              ObservationSequence{9}, observed, "ev-bmc-9");
  CHECK_OK(component_recorded);
  auto component_replay = observe_component(manager, asset, "bmc", version("2.4.1"),
                                            ObservationSequence{9}, observed, "ev-bmc-9");
  CHECK_OK(component_replay);
  CHECK(component_replay.value() == ObservationOutcome::IdempotentReplay);
  auto component_conflict = observe_component(manager, asset, "bmc", version("2.4.0"),
                                              ObservationSequence{9}, observed, "ev-bmc-9");
  CHECK_ERROR(component_conflict, ErrorCode::EvidenceConflicting);
  // A lower sequence must never replace newer component evidence either. The
  // first observation of a component is not "out of order": ordering is only
  // defined against evidence that already exists.
  const CommitSequence after_component = manager.commit_sequence();
  auto component_stale = observe_component(manager, asset, "bmc", version("1.0.0"),
                                           ObservationSequence{4}, observed, "ev-bmc-4");
  CHECK_ERROR(component_stale, ErrorCode::EvidenceOutOfOrder);
  CHECK(manager.commit_sequence() == after_component);
  const FirmwareObservation* bmc = manager.snapshot().observations.component(
      asset, FirmwareComponentId{"bmc"});
  REQUIRE(bmc != nullptr);
  CHECK(bmc->sequence == ObservationSequence{9});
  CHECK(bmc->version.has_value() && bmc->version->to_string() == std::string{"2.4.1"});
  // An observation of a component whose version was not determined is a
  // different fact from a version, and is recorded as such.
  auto undetermined = observe_component(manager, asset, "bios", std::nullopt,
                                        ObservationSequence{10}, observed, "ev-bios-10");
  CHECK_OK(undetermined);
  const FirmwareObservation* bios = manager.snapshot().observations.component(asset,
                                                                            FirmwareComponentId{"bios"});
  REQUIRE(bios != nullptr);
  CHECK(!bios->version.has_value());
  // Re-observing the undetermined version at a higher sequence stays undetermined
  // rather than becoming the approved version.
  auto still_undetermined = observe_component(manager, asset, "bios", std::nullopt,
                                              ObservationSequence{11}, observed, "ev-bios-11");
  CHECK_OK(still_undetermined);
  const FirmwareObservation* bios_again = manager.snapshot().observations.component(
      asset, FirmwareComponentId{"bios"});
  REQUIRE(bios_again != nullptr);
  CHECK(!bios_again->version.has_value());
  CHECK(bios_again->sequence == ObservationSequence{11});
}

// ---------------------------------------------------------------------------
// Hostile identities, paths, and text
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_hostile_identities_are_rejected) {
  const std::filesystem::path directory = scratch_directory("adversarial-identities");
  const Timestamp start = base_time();
  Fixture fixture = publish_fixture(directory, start);
  BaselineManager& manager = *fixture.manager;

  const std::string traversal[] = {"..", ".", "../x", "..\\x", "a/../b", "a/b", "a\\b"};
  for (const std::string& text : traversal) {
    CHECK_MSG(!is_valid_identifier(text), "traversal form accepted: " + quoted_text(text));
    CHECK_ERROR(validate_identifier(text, "/id"), ErrorCode::SchemaInvalidIdentifier);
  }
  const std::string streams[] = {"a:b", "ads:stream", "file.txt:$DATA", "C:x"};
  for (const std::string& text : streams) {
    CHECK_MSG(!is_valid_identifier(text), "colon form accepted: " + quoted_text(text));
    CHECK_ERROR(validate_identifier(text, "/id"), ErrorCode::SchemaInvalidIdentifier);
  }
  CHECK(!is_valid_identifier(""));
  CHECK(!is_valid_identifier(std::string(129, 'a')));
  CHECK(is_valid_identifier(std::string(128, 'a')));
  CHECK(!is_valid_identifier(std::string_view{"a\0b", 3}));
  CHECK(!is_valid_identifier("caf\xC3\xA9"));
  CHECK(!is_valid_identifier("\xFF"));
  // Only ASCII is accepted, so a valid UTF-8 sequence is still not an identity.
  CHECK(!is_valid_identifier("\xE2\x86\x92"));

  // The manager rejects every hostile identity through the real mutation path
  // and leaves the state untouched.
  const std::size_t baselines_before = manager.baselines().size();
  for (const std::string& text : traversal) {
    BaselineDraft draft = standard_draft();
    draft.id = BaselineId{text};
    CHECK_ERROR(manager.define_baseline(draft, context_at(start, "req-hostile")),
                ErrorCode::SchemaInvalidIdentifier);
  }
  for (const std::string& text : streams) {
    BaselineDraft draft = standard_draft();
    draft.id = BaselineId{text};
    CHECK_ERROR(manager.define_baseline(draft, context_at(start, "req-hostile")),
                ErrorCode::SchemaInvalidIdentifier);
  }
  CHECK_EQ(manager.baselines().size(), baselines_before);

  // Hostile asset identities inside a cohort member list.
  {
    CohortDraft draft;
    draft.id = CohortId{"wave-hostile"};
    draft.baseline = fixture.baseline;
    draft.baseline_generation = fixture.generation;
    draft.members = {AssetId{"../evil"}, AssetId{"node-01"}};
    CHECK_ERROR(manager.create_cohort(draft, context_at(start, "req-cohort-hostile")),
                ErrorCode::SchemaInvalidIdentifier);
    CHECK(manager.snapshot().cohorts.find(CohortId{"wave-hostile"}) == nullptr);
  }
  // Hostile asset identities inside an exception scope.
  {
    ExceptionDraft draft;
    draft.id = ExceptionId{"exc-hostile"};
    draft.scope.hardware_class = HardwareClassId{"gpu"};
    draft.scope.asset = AssetId{"..\\evil"};
    draft.expiry = Expiry::at(at(1769904000ull + 60ull));
    draft.reason = "hostile";
    CHECK_ERROR(manager.grant_exception(draft, context_at(start, "req-exc-hostile")),
                ErrorCode::SchemaInvalidIdentifier);
    CHECK(manager.snapshot().exceptions.find(ExceptionId{"exc-hostile"}) == nullptr);
  }
  // A component identity carrying a colon.
  {
    BaselineDraft draft = standard_draft();
    draft.components.front().component = FirmwareComponentId{"bmc:stream"};
    CHECK_ERROR(manager.define_baseline(draft, context_at(start, "req-hostile-component")),
                ErrorCode::SchemaInvalidIdentifier);
  }

  // No identity is ever used as a path component, so nothing was created
  // outside the store directory: the directory holds only the fixed names.
  const auto entries = platform::list_directory(directory);
  REQUIRE(entries.has_value());
  for (const std::string& entry : entries.value()) {
    CHECK_MSG(entry.rfind("store.", 0) == 0,
              "an unexpected entry appeared in the store directory: " + quoted_text(entry));
  }
}

FBM_TEST(adversarial_invalid_encoding_defects_are_named) {
  // A byte order mark is named as such rather than being skipped.
  CHECK_ERROR(json::parse("\xEF\xBB\xBF{}", json::Limits{}, "/doc"),
              ErrorCode::EncodingByteOrderMark);
  // A lone surrogate is not a character.
  CHECK_ERROR(json::parse("\"\\uD800\"", json::Limits{}, "/doc"),
              ErrorCode::EncodingInvalidSurrogate);
  CHECK_ERROR(json::parse("\"\\uDC00\"", json::Limits{}, "/doc"),
              ErrorCode::EncodingInvalidSurrogate);
  // Overlong and truncated UTF-8 sequences are rejected.
  CHECK_ERROR(json::parse("\"\xC0\x80\"", json::Limits{}, "/doc"),
              ErrorCode::EncodingInvalidUtf8);
  CHECK_ERROR(json::parse("\"\xC3\x28\"", json::Limits{}, "/doc"),
              ErrorCode::EncodingInvalidUtf8);
  CHECK_ERROR(json::parse("\"\xFF\"", json::Limits{}, "/doc"), ErrorCode::EncodingInvalidUtf8);
  // A raw control character inside a string must be escaped.
  CHECK_ERROR(json::parse("\"a\x01b\"", json::Limits{}, "/doc"),
              ErrorCode::EncodingUnescapedControl);
  // An unknown escape is not a character either.
  CHECK_ERROR(json::parse("\"a\\qb\"", json::Limits{}, "/doc"),
              ErrorCode::EncodingInvalidEscape);
  // Duplicate object keys are rejected, not last-wins.
  CHECK_ERROR(json::parse("{\"a\":1,\"a\":2}", json::Limits{}, "/doc"),
              ErrorCode::EncodingDuplicateKey);
  // Trailing content after the top-level value.
  CHECK_ERROR(json::parse("{} {}", json::Limits{}, "/doc"),
              ErrorCode::EncodingTrailingContent);
  // A truncated document is reported as an unexpected end.
  CHECK_ERROR(json::parse("{\"a\":", json::Limits{}, "/doc"), ErrorCode::EncodingUnexpectedEnd);
  // The literals NaN and Infinity are not JSON numbers.
  CHECK(!json::parse("NaN", json::Limits{}, "/doc").has_value());
  CHECK(!json::parse("Infinity", json::Limits{}, "/doc").has_value());
  CHECK(!json::parse("01", json::Limits{}, "/doc").has_value());

  // A valid multi-byte UTF-8 string is text, but never an identifier.
  auto valid_utf8 = json::parse("\"caf\xC3\xA9\"", json::Limits{}, "/doc");
  CHECK_OK(valid_utf8);
  CHECK_EQ(valid_utf8.value().as_string(), std::string{"caf\xC3\xA9"});
  CHECK(!is_valid_identifier(valid_utf8.value().as_string()));
  // An embedded NUL inside a JSON string survives the round trip exactly.
  auto with_nul = json::parse("\"a\\u0000b\"", json::Limits{}, "/doc");
  CHECK_OK(with_nul);
  CHECK_EQ(with_nul.value().as_string(), std::string("a\x00" "b", 3));
  CHECK(!is_valid_identifier(with_nul.value().as_string()));

  // A very long string is accepted as text and rejected as an identity.
  const std::string long_text(5000, 'x');
  CHECK(!is_valid_identifier(long_text));
  auto long_json = json::parse("\"" + long_text + "\"", json::Limits{}, "/doc");
  CHECK_OK(long_json);
  CHECK_EQ(long_json.value().as_string().size(), long_text.size());
}

FBM_TEST(adversarial_long_paths_do_not_crash_or_leak) {
  const std::filesystem::path root = scratch_directory("adversarial-long-paths");

  // A path longer than the classic Windows maximum. The library must either
  // create and use it or return a documented Io error; both are acceptable, a
  // crash or a silent success with no store is not.
  std::filesystem::path deep = root;
  for (int index = 0; index < 8; ++index) {
    deep /= std::string(38, static_cast<char>('a' + index));
  }
  StoreOptions options = writable_store_options(deep, true);
  auto first = DurableStore::open(options);
  const std::string first_outcome = outcome_signature(first);
  if (first.has_value()) {
    CHECK(first.value()->holds_writer_lock());
    Snapshot next = first.value()->snapshot();
    next.revision = Revision{1};
    auto committed = first.value()->commit(std::move(next));
    CHECK_OK(committed);
    first.value().reset();
    auto reopened = DurableStore::open(options);
    CHECK_OK(reopened);
    CHECK(reopened.value()->snapshot().revision == Revision{1});
  } else {
    CHECK(first.error().code() == ErrorCode::IoNotFound ||
          first.error().code() == ErrorCode::IoPermissionDenied ||
          first.error().code() == ErrorCode::IoFailure);
  }
  // The same call twice is the same outcome, whatever the host decided.
  auto second = DurableStore::open(options);
  CHECK_EQ(outcome_signature(second), first_outcome);
  if (second.has_value()) {
    second.value().reset();
  }

  // A path component that Windows reads as an alternate data stream is never a
  // directory, so the store reports a missing directory rather than writing
  // into a stream attached to another file.
  std::error_code ec;
  const std::filesystem::path host = root / "host.txt";
  write_bytes(host, "host file");
  const std::filesystem::path stream_path = root / "host.txt:stream";
  auto stream_store = DurableStore::open(writable_store_options(stream_path, false));
  CHECK_ERROR(stream_store, ErrorCode::IoNotFound);
  CHECK(std::filesystem::is_regular_file(host, ec));
  CHECK_EQ(read_bytes(host), std::string{"host file"});
}

// ---------------------------------------------------------------------------
// Store lifecycle, locking, and disk failures
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_store_open_close_cycles_and_second_writer) {
  const std::filesystem::path directory = scratch_directory("adversarial-lifecycle");
  const StoreOptions options = writable_store_options(directory, true);

  for (int cycle = 0; cycle < 3; ++cycle) {
    auto store = DurableStore::open(options);
    REQUIRE(store.has_value());
    Snapshot next = store.value()->snapshot();
    next.revision = Revision{static_cast<std::uint64_t>(cycle + 1)};
    auto committed = store.value()->commit(std::move(next));
    REQUIRE(committed.has_value());

    // A second writer in the same process is refused, and the refusal does not
    // disturb the first writer.
    auto second = DurableStore::open(options);
    CHECK_ERROR(second, ErrorCode::IoLockBusy);
    auto inspect = DurableStore::inspect(directory);
    CHECK_OK(inspect);
    CHECK(inspect.value().commit_sequence == committed.value().commit_sequence);
    CHECK(inspect.value().control_epoch == committed.value().control_epoch);
    store.value().reset();

    auto third = DurableStore::open(options);
    CHECK_OK(third);
    CHECK_EQ(third.value()->snapshot().revision.value_or(0u),
             static_cast<std::uint64_t>(cycle + 1));
    third.value().reset();
  }

  // The manager holds the same lock for its lifetime, so two managers can never
  // interleave writes to one directory.
  auto first_manager = BaselineManager::open(manager_options(directory, true, base_time()));
  CHECK_OK(first_manager);
  auto second_manager = BaselineManager::open(manager_options(directory, true, base_time()));
  CHECK_ERROR(second_manager, ErrorCode::IoLockBusy);
  first_manager.value().reset();
  auto third_manager = BaselineManager::open(manager_options(directory, false, base_time()));
  CHECK_OK(third_manager);
  third_manager.value().reset();
}

FBM_TEST(adversarial_disk_failures_return_specific_errors) {
  const std::filesystem::path root = scratch_directory("adversarial-disk");

  // A path that is a regular file rather than a directory.
  const std::filesystem::path plain_file = root / "plain-file";
  write_bytes(plain_file, "not a directory");
  CHECK(std::filesystem::is_regular_file(plain_file));
  {
    auto opened = DurableStore::open(writable_store_options(plain_file, false));
    CHECK_ERROR(opened, ErrorCode::IoNotFound);
  }
  {
    auto opened = DurableStore::open(writable_store_options(plain_file, true));
    CHECK(!opened.has_value());
    CHECK(opened.error().code() == ErrorCode::IoFailure ||
          opened.error().code() == ErrorCode::IoPermissionDenied ||
          opened.error().code() == ErrorCode::IoNotFound);
  }
  // The file was not replaced by a directory.
  CHECK(std::filesystem::is_regular_file(plain_file));
  CHECK_EQ(read_bytes(plain_file), std::string{"not a directory"});

  // A directory that cannot be created because a parent is a file.
  {
    auto opened = DurableStore::open(writable_store_options(plain_file / "child", true));
    CHECK(!opened.has_value());
    CHECK(opened.error().code() == ErrorCode::IoFailure ||
          opened.error().code() == ErrorCode::IoPermissionDenied ||
          opened.error().code() == ErrorCode::IoNotFound);
  }
  // A missing directory without permission to create one.
  {
    auto opened = DurableStore::open(
        writable_store_options(root / "does-not-exist" / "deeper", false));
    CHECK_ERROR(opened, ErrorCode::IoNotFound);
  }
  // Read-only inspection of a directory that does not exist.
  CHECK_ERROR(DurableStore::inspect(root / "never-created"), ErrorCode::IoNotFound);

  // A read-only directory. On Windows the read-only attribute on a directory
  // does not deny file creation inside it, so this host cannot produce the
  // denial; the case is skipped explicitly rather than asserted. On a host that
  // does deny it, the open must fail with a documented Io error.
  {
    const std::filesystem::path read_only = root / "read-only";
    std::error_code ec;
    std::filesystem::create_directories(read_only, ec);
    CHECK(!ec);
    std::filesystem::permissions(read_only,
                                 std::filesystem::perms::owner_write |
                                     std::filesystem::perms::group_write |
                                     std::filesystem::perms::others_write,
                                 std::filesystem::perm_options::remove, ec);
    auto opened = DurableStore::open(writable_store_options(read_only, true));
    if (!opened.has_value()) {
      CHECK(opened.error().code() == ErrorCode::IoPermissionDenied ||
            opened.error().code() == ErrorCode::IoFailure ||
            opened.error().code() == ErrorCode::IoNotFound);
    } else {
      // Explicit skip: this platform does not enforce it.
      opened.value().reset();
    }
    std::filesystem::permissions(read_only,
                                 std::filesystem::perms::owner_write |
                                     std::filesystem::perms::group_write |
                                     std::filesystem::perms::others_write,
                                 std::filesystem::perm_options::add, ec);
  }

  // A torn slot is never adopted: recovery reports an inconsistent state
  // instead of guessing which half of a record is real.
  {
    const std::filesystem::path directory = root / "torn-slot";
    const CommittedRecord record = commit_one_generation(directory);
    REQUIRE(record.valid);
    const std::filesystem::path slot =
        StorePaths::for_directory(directory).slot_file(record.slot);
    write_bytes(slot, record.bytes.substr(0, record.bytes.size() / 2u));
    auto reopened = DurableStore::open(writable_store_options(directory, true));
    CHECK_ERROR(reopened, ErrorCode::RecoveryInconsistentState);
  }
  // A slot replaced by garbage of a plausible length is refused as well.
  {
    const std::filesystem::path directory = root / "garbage-slot";
    const CommittedRecord record = commit_one_generation(directory);
    REQUIRE(record.valid);
    const std::filesystem::path slot =
        StorePaths::for_directory(directory).slot_file(record.slot);
    std::string garbage(record.bytes.size(), 'x');
    write_bytes(slot, garbage);
    auto reopened = DurableStore::open(writable_store_options(directory, true));
    CHECK_ERROR(reopened, ErrorCode::RecoveryInconsistentState);
  }
  // A fence that names a slot which is no longer present is refused: the fence
  // is authoritative about which generation exists, and a missing slot is not
  // silently treated as an empty one.
  {
    const std::filesystem::path directory = root / "missing-slot";
    const CommittedRecord record = commit_one_generation(directory);
    REQUIRE(record.valid);
    const StorePaths paths = StorePaths::for_directory(directory);
    std::error_code removal_error;
    std::filesystem::remove(paths.slot_file(record.slot), removal_error);
    CHECK(!removal_error);
    auto reopened = DurableStore::open(writable_store_options(directory, true));
    CHECK_ERROR(reopened, ErrorCode::RecoveryInconsistentState);
  }
  // A frame whose payload digest disagrees with its own payload is refused by
  // the decoder before any document is interpreted.
  {
    const std::filesystem::path directory = root / "digest-mismatch";
    const CommittedRecord record = commit_one_generation(directory);
    REQUIRE(record.valid);
    const StorePaths paths = StorePaths::for_directory(directory);
    std::string slot_bytes = read_bytes(paths.slot_file(record.slot));
    slot_bytes[44u] = static_cast<char>(static_cast<unsigned char>(slot_bytes[44u]) ^ 0x11u);
    reseal_frame(slot_bytes);
    write_bytes(paths.slot_file(record.slot), slot_bytes);
    auto frame = decode_record(slot_bytes, "/slot");
    CHECK_ERROR(frame, ErrorCode::FormatDigestMismatch);
    auto reopened = DurableStore::open(writable_store_options(directory, true));
    CHECK_ERROR(reopened, ErrorCode::RecoveryInconsistentState);
  }
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_resource_limits_reject_oversized_documents) {
  // The configured limits are enforced before the document is interpreted, so
  // a hostile document is rejected instead of being materialized.
  {
    json::Limits limits;
    limits.max_bytes = 1024u;
    const std::string document(2048u, ' ');
    CHECK_ERROR(json::parse(document, limits, "/doc"), ErrorCode::EncodingSizeExceeded);
  }
  {
    json::Limits limits;
    limits.max_depth = 4u;
    std::string document;
    for (int index = 0; index < 8; ++index) {
      document.push_back('[');
    }
    document += "1";
    for (int index = 0; index < 8; ++index) {
      document.push_back(']');
    }
    CHECK_ERROR(json::parse(document, limits, "/doc"), ErrorCode::EncodingDepthExceeded);
  }
  {
    json::Limits limits;
    limits.max_string_bytes = 8u;
    CHECK_ERROR(json::parse("\"0123456789\"", limits, "/doc"), ErrorCode::EncodingSizeExceeded);
  }
  {
    json::Limits limits;
    limits.max_nodes = 3u;
    CHECK_ERROR(json::parse("[[[[1]]]]", limits, "/doc"), ErrorCode::EncodingSizeExceeded);
  }
  {
    json::Limits limits;
    limits.max_array_elements = 2u;
    CHECK_ERROR(json::parse("[1,2,3]", limits, "/doc"), ErrorCode::EncodingSizeExceeded);
  }
  {
    json::Limits limits;
    limits.max_object_members = 1u;
    CHECK_ERROR(json::parse("{\"a\":1,\"b\":2}", limits, "/doc"),
                ErrorCode::EncodingSizeExceeded);
  }

  // The real configured policy limit: a document larger than the reader's
  // maximum is refused by the limit check, and never by exhausting memory.
  {
    const std::string oversized(64u * 1024u * 1024u + 1u, 'x');
    auto parsed = PolicyDocument::parse(oversized, "/policy");
    CHECK_ERROR(parsed, ErrorCode::EncodingSizeExceeded);
  }
  // A snapshot payload larger than the record limit is refused from the header
  // alone, before any buffer is sized from the attacker-controlled length.
  {
    std::string header(kRecordOverheadBytes, '\0');
    write_u32(header, 0, kRecordMagic);
    write_u16(header, 4, kDurableFormatVersion);
    write_u16(header, 6, kRecordKindSnapshot);
    write_u32(header, 8, 0u);
    write_u32(header, 36, kMaxRecordPayloadBytes + 1u);
    CHECK_ERROR(decode_record(header, "/header"), ErrorCode::FormatLengthOutOfRange);
  }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

FBM_TEST(adversarial_repeated_runs_return_identical_errors) {
  // The same malformed input must produce the same code, message, and path on
  // every run, and the primary error must not depend on discovery order.
  const std::string documents[] = {
      "",
      "{",
      "}",
      "[]",
      "{\"a\":1,\"a\":2}",
      "\xEF\xBB\xBF{}",
      "\"\\uD800\"",
      "\"\xC0\x80\"",
      "{\"format\":\"summon.fbm.snapshot\",\"format_version\":2}",
      "{\"schema\":\"summon.fbm.policy\",\"schema_version\":1,\"baselines\":[{}]}",
      "{\"schema\":\"summon.fbm.policy\",\"schema_version\":9,\"baselines\":[]}",
      "{\"schema\":\"summon.fbm.policy\",\"schema_version\":1,\"baselines\":[],\"x\":1}",
      "{\"format\":\"other\",\"format_version\":1,\"baselines\":[],\"observations\":{},"
      "\"exceptions\":[],\"cohorts\":[],\"authorizations\":[]}"};
  std::string first_failure;
  for (const std::string& document : documents) {
    const std::string first_json = outcome_signature(json::parse(document));
    const std::string second_json = outcome_signature(json::parse(document));
    if (first_json != second_json) {
      first_failure = "json::parse disagreed with itself for " + quoted_text(document) + ": " +
                      first_json + " vs " + second_json;
      break;
    }
    auto first_policy = PolicyDocument::parse(document, "/policy");
    auto second_policy = PolicyDocument::parse(document, "/policy");
    if (outcome_signature(first_policy) != outcome_signature(second_policy)) {
      first_failure = "PolicyDocument::parse disagreed with itself for " + quoted_text(document);
      break;
    }
    auto first_value = json::parse(document, json::Limits{}, "/snapshot");
    if (first_value.has_value()) {
      auto first_snapshot = Snapshot::from_json(first_value.value(), "/snapshot");
      auto second_snapshot = Snapshot::from_json(first_value.value(), "/snapshot");
      if (outcome_signature(first_snapshot) != outcome_signature(second_snapshot)) {
        first_failure = "Snapshot::from_json disagreed with itself for " + quoted_text(document);
        break;
      }
    }
  }
  CHECK_MSG(first_failure.empty(), first_failure);

  // The primary error is selected by a documented precedence, not by the order
  // in which the defects happened to be discovered.
  Diagnostics forward;
  forward.add(ErrorCode::SchemaUnknownField, "unknown member", "/z");
  forward.add(ErrorCode::EncodingInvalidUtf8, "bad byte", "/a");
  forward.add(ErrorCode::SchemaMissingField, "missing", "/m");
  Diagnostics backward;
  backward.add(ErrorCode::SchemaMissingField, "missing", "/m");
  backward.add(ErrorCode::EncodingInvalidUtf8, "bad byte", "/a");
  backward.add(ErrorCode::SchemaUnknownField, "unknown member", "/z");
  CHECK_EQ(forward.primary().to_string(), backward.primary().to_string());
  CHECK_EQ(forward.primary().code(), ErrorCode::EncodingInvalidUtf8);

  // Identical rejected mutations produce identical errors on a second call.
  const std::filesystem::path directory = scratch_directory("adversarial-repeat");
  const Timestamp start = base_time();
  Fixture fixture = publish_fixture(directory, start);
  BaselineManager& manager = *fixture.manager;
  for (const char* identity : {"..", "a:b", "a/b", "C:\\x"}) {
    BaselineDraft draft = standard_draft();
    draft.id = BaselineId{identity};
    const std::string first = outcome_signature(
        manager.define_baseline(draft, context_at(start, "req-repeat")));
    const std::string second = outcome_signature(
        manager.define_baseline(draft, context_at(start, "req-repeat")));
    CHECK_MSG(first == second, "define_baseline disagreed with itself for " + quoted_text(identity) +
                                   ": " + first + " vs " + second);
    CHECK(first.rfind("schema_invalid_identifier", 0) == 0);
  }
  for (const auto generation : {BaselineGeneration{99}, BaselineGeneration{100}}) {
    const std::string first = outcome_signature(manager.publish_baseline(
        fixture.baseline, generation, context_at(start, "req-repeat")));
    const std::string second = outcome_signature(manager.publish_baseline(
        fixture.baseline, generation, context_at(start, "req-repeat")));
    CHECK_MSG(first == second, "publish_baseline disagreed with itself: " + first + " vs " +
                                   second);
    CHECK(first.rfind("authority_stale_generation", 0) == 0);
  }
}
