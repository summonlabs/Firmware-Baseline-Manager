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

#include "summon/fbm/store.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "summon/fbm/json.hpp"
#include "summon/fbm/platform.hpp"
#include "summon/fbm/strong_types.hpp"
#include "summon/fbm/version.hpp"

namespace summon::fbm {
namespace {

constexpr char kLockFileName[] = "store.lock";
constexpr char kFenceFileName[] = "store.fence";
constexpr char kFenceStagingName[] = "store.fence.stage";

std::string slot_file_name(unsigned slot) { return "store." + std::to_string(slot) + ".slot"; }
std::string staging_file_name(unsigned slot) { return "store." + std::to_string(slot) + ".stage"; }

// --- Little-endian scalar access --------------------------------------------

void put_u16(std::string& out, std::uint16_t value) {
  out.push_back(static_cast<char>(value & 0xFFu));
  out.push_back(static_cast<char>((value >> 8) & 0xFFu));
}

void put_u32(std::string& out, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    out.push_back(static_cast<char>((value >> shift) & 0xFFu));
  }
}

void put_u64(std::string& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    out.push_back(static_cast<char>((value >> shift) & 0xFFu));
  }
}

std::uint16_t read_u16(std::string_view bytes, std::size_t offset) {
  const auto lo = static_cast<std::uint16_t>(static_cast<unsigned char>(bytes[offset]));
  const auto hi = static_cast<std::uint16_t>(static_cast<unsigned char>(bytes[offset + 1]));
  return static_cast<std::uint16_t>(lo | static_cast<std::uint16_t>(hi << 8));
}

std::uint32_t read_u32(std::string_view bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (unsigned index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + index]))
             << (8u * index);
  }
  return value;
}

std::uint64_t read_u64(std::string_view bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[offset + index]))
             << (8u * index);
  }
  return value;
}

Digest read_digest(std::string_view bytes, std::size_t offset) {
  Digest digest{};
  for (std::size_t index = 0; index < digest.size(); ++index) {
    digest[index] = static_cast<std::uint8_t>(bytes[offset + index]);
  }
  return digest;
}

Error error(ErrorCode code, std::string message, std::string path) {
  return Error{code, std::move(message), std::move(path)};
}

// --- Frame encoding ----------------------------------------------------------

std::string encode_frame(std::uint16_t kind, CommitSequence sequence, ControlEpoch epoch,
                         std::uint64_t slot, std::string_view payload) {
  const std::uint32_t payload_crc = Crc32c::of(payload.data(), payload.size());
  const Digest payload_digest = Sha256::of(payload.data(), payload.size());

  std::string frame;
  frame.reserve(kRecordOverheadBytes + payload.size());
  put_u32(frame, kRecordMagic);
  put_u16(frame, static_cast<std::uint16_t>(kDurableFormatVersion));
  put_u16(frame, kind);
  put_u32(frame, 0u);  // reserved
  put_u64(frame, sequence.value_or(0u));
  put_u64(frame, epoch.value_or(0u));
  put_u64(frame, slot);
  put_u32(frame, static_cast<std::uint32_t>(payload.size()));
  put_u32(frame, payload_crc);
  for (const std::uint8_t byte : payload_digest) {
    frame.push_back(static_cast<char>(byte));
  }
  frame.append(payload.data(), payload.size());

  const std::uint32_t frame_crc = Crc32c::of(frame.data(), frame.size());
  put_u32(frame, frame_crc);
  put_u32(frame, kRecordMagic);
  return frame;
}

}  // namespace

std::string_view commit_point_token(CommitPoint point) noexcept {
  switch (point) {
    case CommitPoint::BeforeStageWrite:
      return "before_stage_write";
    case CommitPoint::AfterStageFlush:
      return "after_stage_flush";
    case CommitPoint::AfterStageVerify:
      return "after_stage_verify";
    case CommitPoint::AfterPublish:
      return "after_publish";
    case CommitPoint::BeforeFenceWrite:
      return "before_fence_write";
    case CommitPoint::AfterFenceWrite:
      return "after_fence_write";
  }
  return "unknown";
}

std::string_view recovery_outcome_token(RecoveryOutcome outcome) noexcept {
  switch (outcome) {
    case RecoveryOutcome::Empty:
      return "empty";
    case RecoveryOutcome::Recovered:
      return "recovered";
    case RecoveryOutcome::RecoveredIgnoringUnpublishedSlot:
      return "recovered_ignoring_unpublished_slot";
  }
  return "unknown";
}

std::filesystem::path StorePaths::slot_file(unsigned slot) const {
  return directory / slot_file_name(slot);
}

std::filesystem::path StorePaths::staging_file(unsigned slot) const {
  return directory / staging_file_name(slot);
}

StorePaths StorePaths::for_directory(const std::filesystem::path& directory) {
  StorePaths paths;
  paths.directory = directory;
  paths.lock_file = directory / kLockFileName;
  paths.fence_file = directory / kFenceFileName;
  return paths;
}

Result<RecordFrame> decode_record(std::string_view bytes, std::string_view path) {
  const std::string where{path};

  if (bytes.size() < kRecordOverheadBytes) {
    return error(ErrorCode::FormatTruncated,
                 "record is " + std::to_string(bytes.size()) + " bytes, shorter than the minimum of " +
                     std::to_string(kRecordOverheadBytes),
                 where);
  }

  if (read_u32(bytes, 0) != kRecordMagic) {
    return error(ErrorCode::FormatMagicMismatch, "record magic does not match", where);
  }

  const std::uint16_t format_version = read_u16(bytes, 4);
  if (format_version != static_cast<std::uint16_t>(kDurableFormatVersion)) {
    return error(ErrorCode::FormatVersionUnsupported,
                 "record format version " + std::to_string(format_version) +
                     " is not supported by this build, which writes version " +
                     std::to_string(kDurableFormatVersion),
                 std::string{where});
  }

  const std::uint16_t kind = read_u16(bytes, 6);
  if (kind != kRecordKindSnapshot && kind != kRecordKindFence) {
    return error(ErrorCode::FormatRecordKindUnknown,
                 "record kind " + std::to_string(kind) + " is not a known record kind", where);
  }

  if (read_u32(bytes, 8) != 0u) {
    return error(ErrorCode::FormatReservedFieldNonZero,
                 "reserved header field must be zero", where);
  }

  const std::uint32_t payload_length = read_u32(bytes, 36);
  if (payload_length > kMaxRecordPayloadBytes) {
    return error(ErrorCode::FormatLengthOutOfRange,
                 "payload length " + std::to_string(payload_length) + " exceeds the maximum of " +
                     std::to_string(kMaxRecordPayloadBytes),
                 where);
  }

  const std::size_t available = bytes.size() - kRecordOverheadBytes;
  if (payload_length > available) {
    return error(ErrorCode::FormatTruncated,
                 "record claims " + std::to_string(payload_length) + " payload bytes but only " +
                     std::to_string(available) + " are present",
                 where);
  }
  if (payload_length < available) {
    return error(ErrorCode::FormatTrailingBytes,
                 "record has " + std::to_string(available - payload_length) +
                     " trailing bytes after the declared payload",
                 where);
  }

  if (read_u32(bytes, bytes.size() - 4) != kRecordMagic) {
    return error(ErrorCode::FormatMagicMismatch, "record trailer magic does not match", where);
  }

  const std::size_t frame_crc_offset = bytes.size() - kRecordTrailerBytes;
  const std::uint32_t stored_frame_crc = read_u32(bytes, frame_crc_offset);
  const std::uint32_t computed_frame_crc = Crc32c::of(bytes.data(), frame_crc_offset);
  if (stored_frame_crc != computed_frame_crc) {
    return error(ErrorCode::FormatChecksumMismatch,
                 "frame checksum mismatch: stored " + std::to_string(stored_frame_crc) +
                     ", computed " + std::to_string(computed_frame_crc),
                 where);
  }

  const std::uint32_t stored_payload_crc = read_u32(bytes, 40);
  const std::string_view payload = bytes.substr(kRecordHeaderBytes, payload_length);
  const std::uint32_t computed_payload_crc = Crc32c::of(payload.data(), payload.size());
  if (stored_payload_crc != computed_payload_crc) {
    return error(ErrorCode::FormatChecksumMismatch,
                 "payload checksum mismatch: stored " + std::to_string(stored_payload_crc) +
                     ", computed " + std::to_string(computed_payload_crc),
                 where);
  }

  const Digest stored_digest = read_digest(bytes, 44);
  const Digest computed_digest = Sha256::of(payload.data(), payload.size());
  if (!(stored_digest == computed_digest)) {
    return error(ErrorCode::FormatDigestMismatch,
                 "payload digest mismatch: stored " + digest_to_hex(stored_digest) +
                     ", computed " + digest_to_hex(computed_digest),
                 where);
  }

  RecordFrame frame;
  frame.format_version = format_version;
  frame.record_kind = kind;
  frame.commit_sequence = CommitSequence{read_u64(bytes, 12)};
  frame.control_epoch = ControlEpoch{read_u64(bytes, 20)};
  frame.slot = read_u64(bytes, 28);
  frame.payload_digest = stored_digest;
  frame.payload.assign(payload.data(), payload.size());
  return frame;
}

namespace {

std::string fence_payload(const Digest& digest) {
  std::string payload;
  payload.reserve(digest.size());
  for (const std::uint8_t byte : digest) {
    payload.push_back(static_cast<char>(byte));
  }
  return payload;
}

Digest digest_from_fence_payload(std::string_view payload) {
  Digest digest{};
  for (std::size_t index = 0; index < digest.size(); ++index) {
    digest[index] = static_cast<std::uint8_t>(payload[index]);
  }
  return digest;
}

// Decodes one snapshot payload. Every durable read goes through here so that
// framing, JSON strictness, and schema validation are applied uniformly.
Result<Snapshot> parse_snapshot_payload(std::string_view payload, const std::string& path) {
  auto value = json::parse(payload, json::Limits{}, path);
  if (!value.has_value()) {
    return value.error();
  }
  return Snapshot::from_json(value.value(), path);
}

struct RecoveryInternal {
  // Value-initialized: a Digest is an aggregate of scalars, so a member left
  // without an initializer would hold indeterminate bytes.
  RecoveryReport report{};
  Snapshot snapshot{};
  Digest digest{};
  bool has_generation = false;
};

// Reads the fence and the slot it names. The fence is the only thing that makes
// a slot authoritative; a complete slot that no fence names is never adopted.
Result<RecoveryInternal> recover_state(const StorePaths& paths, bool repair) {
  RecoveryInternal out{};

  std::array<bool, 2> slot_present{false, false};
  std::array<RecordFrame, 2> slot_frames{};
  std::array<bool, 2> slot_valid{false, false};

  for (unsigned slot = 0; slot < 2; ++slot) {
    const std::filesystem::path file = paths.slot_file(slot);
    if (!platform::is_regular_file(file)) {
      continue;
    }
    slot_present[slot] = true;
    auto bytes = platform::read_file(file, kMaxRecordPayloadBytes + kRecordOverheadBytes);
    if (!bytes.has_value()) {
      out.report.notes.push_back("slot " + std::to_string(slot) + " could not be read: " +
                                 bytes.error().message());
      continue;
    }
    auto frame = decode_record(bytes.value(), file.string());
    if (!frame.has_value()) {
      out.report.notes.push_back("slot " + std::to_string(slot) + " is not a valid record: " +
                                 frame.error().to_string());
      continue;
    }
    if (frame.value().record_kind != kRecordKindSnapshot) {
      out.report.notes.push_back("slot " + std::to_string(slot) + " holds record kind " +
                                 std::to_string(frame.value().record_kind) +
                                 ", not a snapshot");
      continue;
    }
    slot_frames[slot] = frame.take();
    slot_valid[slot] = true;
  }

  for (unsigned slot = 0; slot < 2; ++slot) {
    if (repair) {
      const std::filesystem::path staging = paths.staging_file(slot);
      if (platform::path_exists(staging)) {
        platform::remove_file(staging);
        out.report.notes.push_back("removed staging file for slot " + std::to_string(slot) +
                                   "; staging files are never authoritative");
      }
    }
  }

  const bool fence_exists = platform::is_regular_file(paths.fence_file);
  out.report.fence_present = fence_exists;

  if (fence_exists) {
    auto fence_bytes =
        platform::read_file(paths.fence_file, kMaxRecordPayloadBytes + kRecordOverheadBytes);
    if (!fence_bytes.has_value()) {
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fence file exists but could not be read: " +
                       fence_bytes.error().message(),
                   paths.fence_file.string());
    }
    auto fence = decode_record(fence_bytes.value(), paths.fence_file.string());
    if (!fence.has_value()) {
      out.report.notes.push_back("fence is not a valid record: " + fence.error().to_string());
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fence record is not decodable, so no generation can be established: " +
                       fence.error().to_string(),
                   paths.fence_file.string());
    }
    if (fence.value().record_kind != kRecordKindFence) {
      out.report.notes.push_back("fence holds record kind " +
                                 std::to_string(fence.value().record_kind) + ", not a fence");
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fence file does not hold a fence record",
                   paths.fence_file.string());
    }
    if (fence.value().payload.size() != kSha256DigestBytes) {
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fence payload is " + std::to_string(fence.value().payload.size()) +
                       " bytes, expected " + std::to_string(kSha256DigestBytes),
                   paths.fence_file.string());
    }

    out.report.fence_valid = true;
    const unsigned active = static_cast<unsigned>(fence.value().slot);
    if (fence.value().slot > 1u) {
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fence names slot " + std::to_string(fence.value().slot) +
                       ", which is not one of the two slots",
                   paths.fence_file.string());
    }
    out.report.active_slot = active;

    const Digest expected = digest_from_fence_payload(fence.value().payload);
    if (!slot_valid[active]) {
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fence names slot " + std::to_string(active) +
                       " but that slot does not hold a valid snapshot",
                   paths.fence_file.string());
    }

    const RecordFrame& frame = slot_frames[active];
    if (!(frame.payload_digest == expected)) {
      return error(ErrorCode::FormatDigestMismatch,
                   "the fenced digest " + digest_to_hex(expected) +
                       " does not match slot " + std::to_string(active) + " digest " +
                       digest_to_hex(frame.payload_digest),
                   paths.fence_file.string());
    }
    if (!(frame.commit_sequence == fence.value().commit_sequence) ||
        !(frame.control_epoch == fence.value().control_epoch)) {
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fence and slot " + std::to_string(active) +
                       " disagree about the commit sequence or control epoch",
                   paths.fence_file.string());
    }

    auto snapshot = parse_snapshot_payload(frame.payload, paths.slot_file(active).string());
    if (!snapshot.has_value()) {
      return error(ErrorCode::RecoveryInconsistentState,
                   "the fenced snapshot payload is not a valid snapshot: " +
                       snapshot.error().to_string(),
                   paths.slot_file(active).string());
    }

    // The inactive slot normally holds the previous generation, which is a
    // complete and valid record. Only a slot whose commit sequence is AHEAD of
    // the fence is a commit that was published but never fenced.
    const unsigned other = 1u - active;
    if (slot_valid[other] && slot_frames[other].commit_sequence > frame.commit_sequence) {
      out.report.unpublished_slot_present = true;
      out.report.unpublished_slot = other;
      out.report.notes.push_back(
          "slot " + std::to_string(other) + " holds commit sequence " +
          std::to_string(slot_frames[other].commit_sequence.value_or(0u)) +
          " which is ahead of the fenced sequence " +
          std::to_string(frame.commit_sequence.value_or(0u)) +
          "; it is not authoritative and was not adopted");
    }

    out.report.outcome = out.report.unpublished_slot_present
                             ? RecoveryOutcome::RecoveredIgnoringUnpublishedSlot
                             : RecoveryOutcome::Recovered;
    out.report.commit_sequence = frame.commit_sequence;
    out.report.control_epoch = frame.control_epoch;
    out.report.digest = expected;
    out.snapshot = snapshot.take();
    out.digest = expected;
    out.has_generation = true;
    return out;
  }

  // No fence has ever been published, so no generation has ever been
  // authoritative. Anything present is discarded rather than adopted: a slot
  // that no fence names never becomes authority by being first on disk.
  bool discarded = false;
  for (unsigned slot = 0; slot < 2; ++slot) {
    if (slot_valid[slot]) {
      discarded = true;
      out.report.notes.push_back("slot " + std::to_string(slot) +
                                 " holds a record but no fence has ever named it; it was not "
                                 "adopted");
    } else if (slot_present[slot]) {
      discarded = true;
      out.report.notes.push_back("slot " + std::to_string(slot) +
                                 " holds an unreadable file; it was not adopted");
    }
  }
  if (discarded) {
    out.report.notes.push_back("no fence is present, so the store has no authoritative generation");
  } else {
    out.report.notes.push_back("no fence and no slot records are present");
  }
  // No generation exists, so no sequence and no epoch are reported. Reporting
  // zero here would be exactly the "missing becomes zero" conversion this
  // system refuses to make.
  out.report.outcome = RecoveryOutcome::Empty;
  out.snapshot = Snapshot::empty();
  out.has_generation = false;
  return out;
}

}  // namespace

Result<std::unique_ptr<DurableStore>> DurableStore::open(const StoreOptions& options,
                                                         ICommitObserver* observer) {
  if (options.directory.empty()) {
    return error(ErrorCode::InvalidArgument, "store directory must not be empty", "");
  }

  std::unique_ptr<DurableStore> store(new DurableStore());
  store->paths_ = StorePaths::for_directory(options.directory);
  store->observer_ = observer;

  if (!platform::is_directory(store->paths_.directory)) {
    if (!options.create_if_missing) {
      return error(ErrorCode::IoNotFound,
                   "store directory does not exist and create_if_missing is false",
                   store->paths_.directory.string());
    }
    Status created = platform::ensure_directory(store->paths_.directory);
    if (!created.has_value()) {
      return created.error();
    }
  }

  if (options.take_writer_lock) {
    auto lock = platform::FileLock::acquire(store->paths_.lock_file);
    if (!lock.has_value()) {
      return lock.error();
    }
    store->lock_ = lock.take();
  }

  auto recovered = recover_state(store->paths_, true);
  if (!recovered.has_value()) {
    return recovered.error();
  }
  store->recovery_ = recovered.value().report;
  store->snapshot_ = std::move(recovered.value().snapshot);
  store->published_digest_ = recovered.value().digest;
  store->active_slot_known_ = recovered.value().has_generation;
  store->active_slot_ = recovered.value().report.active_slot;

  return std::move(store);
}

Result<RecoveryReport> DurableStore::inspect(const std::filesystem::path& directory) {
  const StorePaths paths = StorePaths::for_directory(directory);
  if (!platform::is_directory(paths.directory)) {
    return error(ErrorCode::IoNotFound, "store directory does not exist", paths.directory.string());
  }
  auto recovered = recover_state(paths, false);
  if (!recovered.has_value()) {
    return recovered.error();
  }
  return recovered.take().report;
}

DurableStore::~DurableStore() = default;

Result<CommitOutcome> DurableStore::commit(Snapshot next) {
  CommitSequence next_sequence;
  ControlEpoch next_epoch;

  if (!snapshot_.commit_sequence.is_set()) {
    // An unset sequence means this is the very first commit of the store.
    next_sequence = CommitSequence::first();
  } else if (!snapshot_.commit_sequence.checked_next(next_sequence)) {
    return error(ErrorCode::InternalInvariantViolation,
                 "the durable commit sequence has reached its maximum value", "");
  }
  // The commit sequence is the store's own counter and always advances. The
  // control epoch belongs to the owner of the control plane, so the store
  // preserves the caller's value rather than advancing it on every commit, and
  // refuses only an epoch that would move the control plane backwards. An epoch
  // that advanced on every commit could not fence anything: it would invalidate
  // every outstanding authorization the moment unrelated evidence landed.
  if (!next.control_epoch.is_set()) {
    next_epoch = snapshot_.control_epoch.is_set() ? snapshot_.control_epoch : ControlEpoch::first();
  } else if (snapshot_.control_epoch.is_set() && next.control_epoch < snapshot_.control_epoch) {
    return error(ErrorCode::AuthorityStaleEpoch,
                 "the requested control epoch is older than the durable control epoch", "");
  } else {
    next_epoch = next.control_epoch;
  }

  next.commit_sequence = next_sequence;
  next.control_epoch = next_epoch;

  const unsigned slot = active_slot_known_ ? (1u - active_slot_) : 0u;
  const std::filesystem::path staging = paths_.staging_file(slot);
  const std::filesystem::path target = paths_.slot_file(slot);

  if (observer_ != nullptr) {
    observer_->on_commit_point(CommitPoint::BeforeStageWrite);
  }

  const std::string payload = next.canonical_bytes();
  const Digest digest = Sha256::of(payload.data(), payload.size());
  const std::string frame =
      encode_frame(kRecordKindSnapshot, next_sequence, next_epoch, slot, payload);

  Status staged = platform::write_file_flushed(staging, frame);
  if (!staged.has_value()) {
    return staged.error();
  }

  if (observer_ != nullptr) {
    observer_->on_commit_point(CommitPoint::AfterStageFlush);
  }

  // Read the staging file back and prove it decodes to exactly the snapshot we
  // intended to write. Nothing is published before this succeeds.
  auto staged_bytes = platform::read_file(staging, kMaxRecordPayloadBytes + kRecordOverheadBytes);
  if (!staged_bytes.has_value()) {
    return staged_bytes.error();
  }
  auto staged_frame = decode_record(staged_bytes.value(), staging.string());
  if (!staged_frame.has_value()) {
    return staged_frame.error();
  }
  if (!(staged_frame.value().payload_digest == digest)) {
    return error(ErrorCode::FormatDigestMismatch,
                 "staged record digest does not match the snapshot being committed",
                 staging.string());
  }
  {
    auto staged_snapshot = parse_snapshot_payload(staged_frame.value().payload, staging.string());
    if (!staged_snapshot.has_value()) {
      return staged_snapshot.error();
    }
  }

  if (observer_ != nullptr) {
    observer_->on_commit_point(CommitPoint::AfterStageVerify);
  }

  Status published = platform::atomic_replace(staging, target);
  if (!published.has_value()) {
    return published.error();
  }

  if (observer_ != nullptr) {
    observer_->on_commit_point(CommitPoint::AfterPublish);
  }

  // Re-read the published slot. A publication that cannot be read back is not a
  // publication.
  auto published_bytes =
      platform::read_file(target, kMaxRecordPayloadBytes + kRecordOverheadBytes);
  if (!published_bytes.has_value()) {
    return published_bytes.error();
  }
  auto published_frame = decode_record(published_bytes.value(), target.string());
  if (!published_frame.has_value()) {
    return published_frame.error();
  }
  if (!(published_frame.value().payload_digest == digest)) {
    return error(ErrorCode::FormatDigestMismatch,
                 "published record digest does not match the snapshot being committed",
                 target.string());
  }

  if (observer_ != nullptr) {
    observer_->on_commit_point(CommitPoint::BeforeFenceWrite);
  }

  const std::string fence_staging_path = (paths_.directory / kFenceStagingName).string();
  const std::string fence_payload_bytes = fence_payload(digest);
  const std::string fence_frame =
      encode_frame(kRecordKindFence, next_sequence, next_epoch, slot, fence_payload_bytes);

  Status fence_staged = platform::write_file_flushed(fence_staging_path, fence_frame);
  if (!fence_staged.has_value()) {
    return fence_staged.error();
  }
  Status fence_published =
      platform::atomic_replace(fence_staging_path, paths_.fence_file);
  if (!fence_published.has_value()) {
    return fence_published.error();
  }

  if (observer_ != nullptr) {
    observer_->on_commit_point(CommitPoint::AfterFenceWrite);
  }

  snapshot_ = std::move(next);
  active_slot_known_ = true;
  active_slot_ = slot;
  published_digest_ = digest;
  recovery_.outcome = RecoveryOutcome::Recovered;
  recovery_.active_slot = slot;
  recovery_.commit_sequence = next_sequence;
  recovery_.control_epoch = next_epoch;
  recovery_.digest = digest;
  recovery_.fence_present = true;
  recovery_.fence_valid = true;
  recovery_.unpublished_slot_present = false;
  recovery_.notes.clear();

  CommitOutcome outcome;
  outcome.commit_sequence = next_sequence;
  outcome.control_epoch = next_epoch;
  outcome.slot = slot;
  outcome.digest = digest;
  outcome.payload_bytes = static_cast<std::uint64_t>(payload.size());
  return outcome;
}

Status DurableStore::reload() {
  auto recovered = recover_state(paths_, true);
  if (!recovered.has_value()) {
    return recovered.error();
  }
  recovery_ = recovered.value().report;
  snapshot_ = std::move(recovered.value().snapshot);
  published_digest_ = recovered.value().digest;
  active_slot_known_ = recovered.value().has_generation;
  active_slot_ = recovered.value().report.active_slot;
  return ok_status();
}

json::Value CommitOutcome::to_json() const {
  json::Value::Object members;
  members.emplace_back("commit_sequence", json::Value{commit_sequence.value_or(0u)});
  members.emplace_back("control_epoch", json::Value{control_epoch.value_or(0u)});
  members.emplace_back("slot", json::Value{static_cast<std::int64_t>(slot)});
  members.emplace_back("digest", json::Value{digest_to_hex(digest)});
  members.emplace_back("payload_bytes", json::Value{static_cast<std::int64_t>(payload_bytes)});
  return json::Value{std::move(members)};
}

json::Value RecoveryReport::to_json() const {
  json::Value::Object members;
  members.emplace_back("outcome", json::Value{std::string{recovery_outcome_token(outcome)}});
  members.emplace_back("fence_present", json::Value{fence_present});
  members.emplace_back("fence_valid", json::Value{fence_valid});
  members.emplace_back("active_slot", json::Value{static_cast<std::int64_t>(active_slot)});
  members.emplace_back("unpublished_slot_present", json::Value{unpublished_slot_present});
  members.emplace_back("unpublished_slot",
                       json::Value{static_cast<std::int64_t>(unpublished_slot)});
  if (commit_sequence.is_set()) {
    members.emplace_back("commit_sequence", json::Value{commit_sequence.value()});
  }
  if (control_epoch.is_set()) {
    members.emplace_back("control_epoch", json::Value{control_epoch.value()});
  }
  if (!(digest == Digest{})) {
    members.emplace_back("digest", json::Value{digest_to_hex(digest)});
  }
  json::Value::Array rendered_notes;
  rendered_notes.reserve(notes.size());
  for (const std::string& note : notes) {
    rendered_notes.emplace_back(note);
  }
  members.emplace_back("notes", json::Value{std::move(rendered_notes)});
  return json::Value{std::move(members)};
}

std::string RecoveryReport::to_string() const { return json::write_canonical(to_json()); }

}  // namespace summon::fbm
