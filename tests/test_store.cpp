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

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "check.hpp"
#include "support.hpp"

using namespace summon::fbm;
using namespace fbm_test;

namespace {

std::string read_bytes(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

void write_bytes(const std::filesystem::path& path, const std::string& data) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::uint32_t read_u32(const std::string& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (unsigned index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + index]))
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

// Recomputes the frame checksum so that a test can attack a later layer without
// the checksum catching the edit first.
void reseal_frame(std::string& bytes) {
  const std::size_t frame_crc_offset = bytes.size() - kRecordTrailerBytes;
  write_u32(bytes, frame_crc_offset, Crc32c::of(bytes.data(), frame_crc_offset));
}

// Restores both integrity fields a legitimate writer would have produced, so a
// test can reach the digest check that sits behind them.
void reseal_all(std::string& bytes) {
  const std::uint32_t payload_length = read_u32(bytes, 36);
  const std::string_view payload(bytes.data() + kRecordHeaderBytes, payload_length);
  write_u32(bytes, 40, Crc32c::of(payload.data(), payload.size()));
  reseal_frame(bytes);
}

// Commits once and returns the on-disk bytes of the active slot.
std::string committed_slot_bytes(const std::filesystem::path& directory) {
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  options.take_writer_lock = true;
  auto store = DurableStore::open(options);
  if (!store.has_value()) {
    ::fbm_test::report_failure(__FILE__, __LINE__, "could not open the store for the fixture");
    throw ::fbm_test::Abort{};
  }
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{1};
  next.policy_generation = PolicyGeneration{3};
  auto outcome = store.value()->commit(std::move(next));
  if (!outcome.has_value()) {
    ::fbm_test::report_failure(__FILE__, __LINE__, "fixture commit failed");
    throw ::fbm_test::Abort{};
  }
  const std::filesystem::path slot = StorePaths::for_directory(directory).slot_file(outcome.value().slot);
  store.value().reset();
  return read_bytes(slot);
}

}  // namespace

FBM_TEST(store_fresh_directory_reports_no_authoritative_generation) {
  const std::filesystem::path directory = scratch_directory("store-fresh");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;

  auto store = DurableStore::open(options);
  CHECK_OK(store);
  CHECK(store.value()->recovery().outcome == RecoveryOutcome::Empty);
  CHECK(!store.value()->recovery().fence_present);
  CHECK(!store.value()->snapshot().commit_sequence.is_set());
  CHECK(store.value()->holds_writer_lock());
}

FBM_TEST(store_missing_directory_without_create_is_an_error) {
  const std::filesystem::path directory = scratch_directory("store-missing") / "absent";
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = false;
  auto store = DurableStore::open(options);
  CHECK_ERROR(store, ErrorCode::IoNotFound);
}

FBM_TEST(store_commit_advances_sequence_and_epoch_and_ignores_caller_values) {
  const std::filesystem::path directory = scratch_directory("store-advance");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);

  // The commit sequence is the store's own counter, so the caller's value is
  // ignored and the store starts at one. The control epoch belongs to the
  // control plane: an unset value is defaulted to one and an explicit value is
  // preserved across commits rather than advanced.
  Snapshot next = store.value()->snapshot();
  next.commit_sequence = CommitSequence{9999};
  auto first = store.value()->commit(std::move(next));
  CHECK_OK(first);
  CHECK_EQ(first.value().commit_sequence.value(), 1u);
  CHECK_EQ(first.value().control_epoch.value(), 1u);

  Snapshot second_next = store.value()->snapshot();
  second_next.commit_sequence = CommitSequence{1};
  auto second = store.value()->commit(std::move(second_next));
  CHECK_OK(second);
  CHECK_EQ(second.value().commit_sequence.value(), 2u);
  CHECK_EQ(second.value().control_epoch.value(), 1u);
  CHECK_NE(first.value().slot, second.value().slot);

  // An epoch that would move the control plane backwards is refused.
  Snapshot backwards = store.value()->snapshot();
  backwards.control_epoch = ControlEpoch{0};
  auto rejected = store.value()->commit(std::move(backwards));
  CHECK_ERROR(rejected, ErrorCode::AuthorityStaleEpoch);

  Snapshot forwards = store.value()->snapshot();
  forwards.control_epoch = ControlEpoch{5};
  auto advanced = store.value()->commit(std::move(forwards));
  CHECK_OK(advanced);
  CHECK_EQ(advanced.value().control_epoch.value(), 5u);
}

FBM_TEST(store_alternates_slots_and_keeps_the_previous_generation_readable) {
  const std::filesystem::path directory = scratch_directory("store-slots");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);

  std::vector<unsigned> slots;
  for (int index = 0; index < 4; ++index) {
    Snapshot next = store.value()->snapshot();
    next.revision = Revision{static_cast<std::uint64_t>(index + 1)};
    auto outcome = store.value()->commit(std::move(next));
    CHECK_OK(outcome);
    slots.push_back(outcome.value().slot);
  }
  CHECK_EQ(slots.size(), 4u);
  CHECK_NE(slots[0], slots[1]);
  CHECK_EQ(slots[0], slots[2]);
  CHECK_EQ(slots[1], slots[3]);

  // Reopening recovers exactly the newest fenced generation, and the inactive
  // slot holding the previous generation is not reported as an unpublished
  // commit.
  store.value().reset();
  auto reopened = DurableStore::open(options);
  CHECK_OK(reopened);
  CHECK(reopened.value()->recovery().outcome == RecoveryOutcome::Recovered);
  CHECK(!reopened.value()->recovery().unpublished_slot_present);
  CHECK_EQ(reopened.value()->snapshot().commit_sequence.value(), 4u);
  CHECK_EQ(reopened.value()->snapshot().revision.value(), 4u);
}

FBM_TEST(store_writer_lock_excludes_a_second_writer_in_the_same_process) {
  const std::filesystem::path directory = scratch_directory("store-lock");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;

  auto first = DurableStore::open(options);
  CHECK_OK(first);
  auto second = DurableStore::open(options);
  CHECK_ERROR(second, ErrorCode::IoLockBusy);
  first.value().reset();
  auto third = DurableStore::open(options);
  CHECK_OK(third);
}

FBM_TEST(store_inspect_never_creates_or_modifies_anything) {
  const std::filesystem::path directory = scratch_directory("store-inspect");
  // The directory exists but the store directory named does not.
  auto report = DurableStore::inspect(directory / "absent");
  CHECK_ERROR(report, ErrorCode::IoNotFound);

  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{5};
  CHECK_OK(store.value()->commit(std::move(next)));
  store.value().reset();

  const auto count_entries = [&directory]() {
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
      (void)entry;
      ++count;
    }
    return count;
  };
  const std::size_t before = count_entries();
  auto inspected = DurableStore::inspect(directory);
  CHECK_OK(inspected);
  CHECK(inspected.value().outcome == RecoveryOutcome::Recovered);
  CHECK_EQ(inspected.value().commit_sequence.value(), 1u);
  CHECK_EQ(count_entries(), before);
}

FBM_TEST(store_removes_stale_staging_files_and_never_adopts_them) {
  const std::filesystem::path directory = scratch_directory("store-staging");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{2};
  CHECK_OK(store.value()->commit(std::move(next)));
  store.value().reset();

  const StorePaths paths = StorePaths::for_directory(directory);
  write_bytes(paths.staging_file(0), "not a record at all");
  write_bytes(paths.staging_file(1), "also not a record");
  auto reopened = DurableStore::open(options);
  CHECK_OK(reopened);
  CHECK(!std::filesystem::exists(paths.staging_file(0)));
  CHECK(!std::filesystem::exists(paths.staging_file(1)));
  CHECK_EQ(reopened.value()->snapshot().revision.value(), 2u);
}

FBM_TEST(store_without_a_fence_has_no_authoritative_generation) {
  const std::filesystem::path directory = scratch_directory("store-nofence");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{7};
  CHECK_OK(store.value()->commit(std::move(next)));
  store.value().reset();

  const StorePaths paths = StorePaths::for_directory(directory);
  std::filesystem::remove(paths.fence_file);

  auto reopened = DurableStore::open(options);
  CHECK_OK(reopened);
  CHECK(reopened.value()->recovery().outcome == RecoveryOutcome::Empty);
  CHECK(!reopened.value()->snapshot().revision.is_set());
  bool mentioned = false;
  for (const std::string& note : reopened.value()->recovery().notes) {
    if (note.find("not adopted") != std::string::npos) {
      mentioned = true;
    }
  }
  CHECK(mentioned);
}

FBM_TEST(store_with_a_torn_fence_refuses_to_guess) {
  const std::filesystem::path directory = scratch_directory("store-tornfence");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{3};
  CHECK_OK(store.value()->commit(std::move(next)));
  store.value().reset();

  const StorePaths paths = StorePaths::for_directory(directory);
  std::string fence = read_bytes(paths.fence_file);
  CHECK_GT(fence.size(), 10u);
  fence[80] = static_cast<char>(static_cast<unsigned char>(fence[80]) ^ 0xFFu);
  write_bytes(paths.fence_file, fence);

  auto reopened = DurableStore::open(options);
  CHECK_ERROR(reopened, ErrorCode::RecoveryInconsistentState);
}

FBM_TEST(store_with_a_corrupt_active_slot_refuses_to_guess) {
  const std::filesystem::path directory = scratch_directory("store-corruptslot");
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{3};
  auto outcome = store.value()->commit(std::move(next));
  CHECK_OK(outcome);
  store.value().reset();

  const StorePaths paths = StorePaths::for_directory(directory);
  std::string slot = read_bytes(paths.slot_file(outcome.value().slot));
  slot[100] = static_cast<char>(static_cast<unsigned char>(slot[100]) ^ 0x01u);
  write_bytes(paths.slot_file(outcome.value().slot), slot);

  auto reopened = DurableStore::open(options);
  CHECK_ERROR(reopened, ErrorCode::RecoveryInconsistentState);
}

FBM_TEST(store_frame_decoder_rejects_every_malformed_shape) {
  const std::filesystem::path directory = scratch_directory("store-frames");
  const std::string valid = committed_slot_bytes(directory);
  CHECK_GT(valid.size(), kRecordOverheadBytes + 8u);

  {
    auto frame = decode_record(valid, "/valid");
    CHECK_OK(frame);
    CHECK_EQ(frame.value().record_kind, kRecordKindSnapshot);
    CHECK(frame.value().commit_sequence.is_set());
  }
  {
    auto frame = decode_record(valid.substr(0, valid.size() - 1u), "/truncated");
    CHECK_ERROR(frame, ErrorCode::FormatTruncated);
  }
  {
    auto frame = decode_record(valid.substr(0, kRecordHeaderBytes - 1u), "/short");
    CHECK_ERROR(frame, ErrorCode::FormatTruncated);
  }
  {
    auto frame = decode_record(valid.substr(0, 4), "/tiny");
    CHECK_ERROR(frame, ErrorCode::FormatTruncated);
  }
  {
    auto frame = decode_record(valid + std::string{"x"}, "/trailing");
    CHECK_ERROR(frame, ErrorCode::FormatTrailingBytes);
  }
  {
    std::string bytes = valid;
    write_u32(bytes, 0, 0xDEADBEEFu);
    auto frame = decode_record(bytes, "/magic");
    CHECK_ERROR(frame, ErrorCode::FormatMagicMismatch);
  }
  {
    std::string bytes = valid;
    write_u16(bytes, 4, 99);
    auto frame = decode_record(bytes, "/version");
    CHECK_ERROR(frame, ErrorCode::FormatVersionUnsupported);
  }
  {
    std::string bytes = valid;
    write_u16(bytes, 6, 77);
    auto frame = decode_record(bytes, "/kind");
    CHECK_ERROR(frame, ErrorCode::FormatRecordKindUnknown);
  }
  {
    std::string bytes = valid;
    write_u32(bytes, 8, 1);
    auto frame = decode_record(bytes, "/reserved");
    CHECK_ERROR(frame, ErrorCode::FormatReservedFieldNonZero);
  }
  {
    std::string bytes = valid;
    write_u32(bytes, 36, 0xFFFFFFFFu);
    auto frame = decode_record(bytes, "/length");
    CHECK_ERROR(frame, ErrorCode::FormatLengthOutOfRange);
  }
  {
    std::string bytes = valid;
    write_u32(bytes, bytes.size() - 4u, 0x11223344u);
    auto frame = decode_record(bytes, "/trailer-magic");
    CHECK_ERROR(frame, ErrorCode::FormatMagicMismatch);
  }
  {
    std::string bytes = valid;
    const std::size_t frame_crc_offset = bytes.size() - kRecordTrailerBytes;
    write_u32(bytes, frame_crc_offset, read_u32(bytes, frame_crc_offset) ^ 0x1u);
    auto frame = decode_record(bytes, "/frame-crc");
    CHECK_ERROR(frame, ErrorCode::FormatChecksumMismatch);
  }
  {
    std::string bytes = valid;
    bytes[kRecordHeaderBytes + 3u] = static_cast<char>(
        static_cast<unsigned char>(bytes[kRecordHeaderBytes + 3u]) ^ 0x40u);
    auto frame = decode_record(bytes, "/payload");
    CHECK_ERROR(frame, ErrorCode::FormatChecksumMismatch);
  }
  {
    // Payload edited and the frame resealed, so only the payload digest can
    // catch it.
    std::string bytes = valid;
    bytes[kRecordHeaderBytes + 3u] = static_cast<char>(
        static_cast<unsigned char>(bytes[kRecordHeaderBytes + 3u]) ^ 0x40u);
    reseal_all(bytes);
    auto frame = decode_record(bytes, "/digest");
    CHECK_ERROR(frame, ErrorCode::FormatDigestMismatch);
  }
  {
    // Every possible single-byte truncation length must be rejected, and never
    // accepted as a shorter valid record.
    bool all_rejected = true;
    for (std::size_t length = 0; length < valid.size(); ++length) {
      auto frame = decode_record(valid.substr(0, length), "/prefix");
      if (frame.has_value()) {
        all_rejected = false;
        break;
      }
    }
    CHECK(all_rejected);
  }
  {
    // Sealing a random byte at every payload position must never yield a
    // successful decode.
    bool any_accepted = false;
    for (std::size_t index = kRecordHeaderBytes; index < valid.size() - kRecordTrailerBytes;
         index += 7u) {
      std::string bytes = valid;
      bytes[index] = static_cast<char>(static_cast<unsigned char>(bytes[index]) ^ 0x5Au);
      auto frame = decode_record(bytes, "/flip");
      if (frame.has_value()) {
        any_accepted = true;
        break;
      }
    }
    CHECK(!any_accepted);
  }
}

FBM_TEST(store_relocated_directory_does_not_change_the_generation) {
  const std::filesystem::path first = scratch_directory("store-relocate-a");
  const std::filesystem::path second = scratch_directory("store-relocate-b");

  StoreOptions options;
  options.directory = first;
  options.create_if_missing = true;
  auto store = DurableStore::open(options);
  CHECK_OK(store);
  Snapshot next = store.value()->snapshot();
  next.revision = Revision{11};
  auto outcome = store.value()->commit(std::move(next));
  CHECK_OK(outcome);
  const Digest digest = outcome.value().digest;
  store.value().reset();

  std::error_code ec;
  for (const auto& entry : std::filesystem::directory_iterator(first)) {
    std::filesystem::copy_file(entry.path(), second / entry.path().filename(),
                               std::filesystem::copy_options::overwrite_existing, ec);
  }
  CHECK(!ec);

  StoreOptions moved;
  moved.directory = second;
  moved.create_if_missing = false;
  auto reopened = DurableStore::open(moved);
  CHECK_OK(reopened);
  CHECK_EQ(reopened.value()->snapshot().revision.value(), 11u);
  CHECK(reopened.value()->published_digest() == digest);
}
