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
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/platform.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/snapshot.hpp"

namespace summon::fbm {

// --- Durable record framing --------------------------------------------------
//
// Every durable record is a single frame:
//
//   offset  size  field
//        0     4  magic               0x314D4246 ("FBM1" little endian)
//        4     2  format_version      must equal kDurableFormatVersion
//        6     2  record_kind         1 snapshot, 2 fence
//        8     4  reserved            must be zero
//       12     8  commit_sequence
//       20     8  control_epoch
//       28     8  slot                the slot this record occupies
//       36     4  payload_length      exact payload byte count
//       40     4  payload_crc32c      CRC-32C of the payload bytes
//       44    32  payload_digest      SHA-256 of the payload bytes
//       76    ..  payload
//      end     4  frame_crc32c        CRC-32C of bytes [0, end of payload)
//      end+4   4  trailer_magic       must equal the record magic
//
// The frame length is fully determined by payload_length, so a truncated file
// and a file with trailing bytes are both detected rather than tolerated.
inline constexpr std::uint32_t kRecordMagic = 0x314D4246u;
inline constexpr std::size_t kRecordHeaderBytes = 76u;
inline constexpr std::size_t kRecordTrailerBytes = 8u;
inline constexpr std::size_t kRecordOverheadBytes = kRecordHeaderBytes + kRecordTrailerBytes;
inline constexpr std::uint32_t kMaxRecordPayloadBytes = 64u * 1024u * 1024u;

inline constexpr std::uint16_t kRecordKindSnapshot = 1u;
inline constexpr std::uint16_t kRecordKindFence = 2u;

// Names of the files a store directory may contain. Every name is fixed, so no
// identity is ever used as a path component and no identity can escape the
// directory.
struct StorePaths {
  std::filesystem::path directory;
  std::filesystem::path lock_file;
  std::filesystem::path fence_file;

  std::filesystem::path slot_file(unsigned slot) const;
  std::filesystem::path staging_file(unsigned slot) const;

  static StorePaths for_directory(const std::filesystem::path& directory);
};

enum class CommitPoint : std::uint8_t {
  BeforeStageWrite = 0,
  AfterStageFlush = 1,
  AfterStageVerify = 2,
  AfterPublish = 3,
  BeforeFenceWrite = 4,
  AfterFenceWrite = 5,
};

std::string_view commit_point_token(CommitPoint point) noexcept;

// Durability instrumentation. Callbacks run on the committing thread while the
// store's commit sequence is in progress, so an implementation must not call
// back into the same store. The crash harness uses this to terminate the
// process at exact commit points, which is what makes crash consistency a
// measured property rather than a claim.
class ICommitObserver {
 public:
  virtual ~ICommitObserver() = default;
  virtual void on_commit_point(CommitPoint point) = 0;
};

enum class RecoveryOutcome : std::uint8_t {
  // No committed generation exists yet.
  Empty = 0,
  // Exactly one authoritative generation was recovered.
  Recovered = 1,
  // A complete but never-fenced slot was present and was left unpublished; the
  // fence still names the previous generation.
  RecoveredIgnoringUnpublishedSlot = 2,
};

std::string_view recovery_outcome_token(RecoveryOutcome outcome) noexcept;

struct RecoveryReport {
  RecoveryOutcome outcome = RecoveryOutcome::Empty;
  bool fence_present = false;
  bool fence_valid = false;
  unsigned active_slot = 0;
  bool unpublished_slot_present = false;
  unsigned unpublished_slot = 0;
  CommitSequence commit_sequence;
  ControlEpoch control_epoch;
  Digest digest{};
  // Deterministic, ordered notes describing what was found and what was
  // discarded. Never empty for a non-trivial recovery.
  std::vector<std::string> notes;

  json::Value to_json() const;
  std::string to_string() const;
};

struct StoreOptions {
  std::filesystem::path directory;
  // When false, opening a non-existent directory fails instead of creating it.
  bool create_if_missing = false;
  // When false, the store is opened without the cross-process writer lock. Only
  // read-only inspection uses this.
  bool take_writer_lock = true;
};

struct CommitOutcome {
  CommitSequence commit_sequence;
  ControlEpoch control_epoch;
  unsigned slot = 0;
  Digest digest{};
  std::uint64_t payload_bytes = 0;

  json::Value to_json() const;
};

// A crash-consistent, single-writer durable store.
//
// Commit protocol, in order:
//   1. stage    - write the framed record for the inactive slot to a staging
//                 file and flush it to stable storage
//   2. verify   - read the staging file back and validate its frame, checksum,
//                 digest, and payload structure
//   3. publish  - atomically replace the inactive slot with the staging file
//   4. fence    - only after publication, atomically replace the fence record
//                 that names the active slot and its digest
//
// The fence, not the rename, decides which slot is authoritative. A crash at
// any point therefore recovers exactly one complete generation: either the
// previously fenced one, or the newly fenced one. Partially committed states
// are never merged.
class DurableStore {
 public:
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;
  ~DurableStore();

  // Opens the store, takes the writer lock, and recovers exactly one
  // authoritative generation.
  static Result<std::unique_ptr<DurableStore>> open(const StoreOptions& options,
                                                    ICommitObserver* observer = nullptr);

  // Read-only inspection without taking the writer lock and without modifying
  // anything. Used by the CLI's status and verify commands and by the recovery
  // tests to observe a store that another process still holds.
  static Result<RecoveryReport> inspect(const std::filesystem::path& directory);

  const Snapshot& snapshot() const noexcept { return snapshot_; }
  const RecoveryReport& recovery() const noexcept { return recovery_; }
  const StorePaths& paths() const noexcept { return paths_; }
  bool holds_writer_lock() const noexcept { return lock_.is_held(); }
  const Digest& published_digest() const noexcept { return published_digest_; }

  // Publishes a new generation.
  //
  // The commit sequence is the store's own counter and always advances; the
  // caller's value for it is ignored. The control epoch belongs to the owner of
  // the control plane, so the caller's value is preserved, defaulted to one when
  // the store has never had an epoch, and rejected with AuthorityStaleEpoch when
  // it would move the epoch backwards.
  Result<CommitOutcome> commit(Snapshot next);

  // Re-reads the durable state and re-derives the single authoritative
  // generation. Used to observe state written by a previous process
  // incarnation. The writer lock is already held and is not re-acquired.
  Status reload();

 private:
  DurableStore() = default;

  static Result<std::string> encode_snapshot_record(const Snapshot& snapshot, unsigned slot);
  static Result<std::string> encode_fence_record(CommitSequence sequence, ControlEpoch epoch,
                                                 unsigned slot, const Digest& snapshot_digest);

  StorePaths paths_;
  platform::FileLock lock_;
  RecoveryReport recovery_;
  Snapshot snapshot_;
  bool active_slot_known_ = false;
  unsigned active_slot_ = 0;
  Digest published_digest_{};
  ICommitObserver* observer_ = nullptr;
};

// Structural validation of one frame, exposed so that the adversarial tests can
// attack the encoding directly. Returns the parsed header fields and the
// payload on success.
struct RecordFrame {
  std::uint16_t format_version = 0;
  std::uint16_t record_kind = 0;
  CommitSequence commit_sequence;
  ControlEpoch control_epoch;
  std::uint64_t slot = 0;
  Digest payload_digest{};
  std::string payload;
};

Result<RecordFrame> decode_record(std::string_view bytes, std::string_view path);

}  // namespace summon::fbm
