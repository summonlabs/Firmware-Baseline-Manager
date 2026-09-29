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
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/result.hpp"

// Host primitives: file durability, atomic publication, cross-process
// exclusion, and child processes. Everything in this header is a thin, honest
// wrapper over the operating system. Nothing here emulates a guarantee the
// platform does not provide.
namespace summon::fbm::platform {

// --- Filesystem -------------------------------------------------------------

bool path_exists(const std::filesystem::path& path) noexcept;
bool is_regular_file(const std::filesystem::path& path) noexcept;
bool is_directory(const std::filesystem::path& path) noexcept;

Result<std::uint64_t> file_size(const std::filesystem::path& path);

// Creates the directory and every missing parent.
Status ensure_directory(const std::filesystem::path& path);

// Reads a whole file. Fails with EncodingSizeExceeded when the file is larger
// than max_bytes, so a runaway file cannot exhaust memory.
Result<std::string> read_file(const std::filesystem::path& path, std::uint64_t max_bytes);

// Creates or truncates the file, writes every byte, and flushes the file's
// contents to stable storage before returning.
Status write_file_flushed(const std::filesystem::path& path, std::string_view data);

// Flushes an already written file to stable storage without modifying it.
Status sync_file(const std::filesystem::path& path);

// Flushes a directory entry. A real fsync of the directory on POSIX; on Windows
// the platform offers no supported directory flush, so this is a documented
// no-op that returns success. Callers must not depend on it for correctness:
// the store's A/B slot scheme keeps a rename that was not yet durable from
// becoming authoritative, because the fence, not the rename, selects the
// generation.
Status flush_directory(const std::filesystem::path& directory);

// Atomically replaces destination with source. On success the destination
// either has its previous contents or the new contents and never a mixture.
Status atomic_replace(const std::filesystem::path& source, const std::filesystem::path& destination);

Status remove_file(const std::filesystem::path& path) noexcept;

// Removes a directory tree, tolerating absence.
Status remove_tree(const std::filesystem::path& path) noexcept;

// Lists the entries of a directory in ascending name order. Deterministic, so
// that a recovery scan never depends on directory enumeration order.
Result<std::vector<std::string>> list_directory(const std::filesystem::path& directory);

// --- Cross-process exclusion -------------------------------------------------

// A real operating-system exclusive lock on a file. The lock is released by the
// kernel when the holding process exits, however it exits, which is what makes
// the single-writer claim provable under process termination.
class FileLock {
 public:
  FileLock() = default;
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;
  FileLock(FileLock&& other) noexcept;
  FileLock& operator=(FileLock&& other) noexcept;
  ~FileLock();

  // Acquires the lock without waiting. Returns IoLockBusy when another process
  // or another lock object in this process already holds it.
  static Result<FileLock> acquire(const std::filesystem::path& path);

  bool is_held() const noexcept { return handle_ != nullptr; }
  void release() noexcept;

 private:
  void* handle_ = nullptr;
};

// --- Child processes ---------------------------------------------------------

struct ChildProcess {
  void* handle = nullptr;
  std::uint64_t process_id = 0;
  std::filesystem::path standard_output_path;
  std::filesystem::path standard_error_path;

  bool is_valid() const noexcept { return handle != nullptr; }
};

// Starts a child process whose standard output and standard error are written
// directly to the given files by the operating system. No pipe is used, so a
// child that writes a large amount of output can never block on a full pipe.
Result<ChildProcess> spawn_process(const std::filesystem::path& executable,
                                    const std::vector<std::string>& arguments,
                                    const std::filesystem::path& working_directory,
                                    const std::filesystem::path& standard_output_path,
                                    const std::filesystem::path& standard_error_path);

// Waits for the child to exit and returns its exit code. There is no timeout:
// a child that never exits is a defect to diagnose, not to paper over.
Result<int> wait_for_exit(ChildProcess& child);

// Terminates the child immediately and waits for it. The child runs no cleanup,
// no destructor, and no atexit handler, which is exactly what makes it a real
// abrupt-termination test.
Status terminate_immediately(ChildProcess& child);

// Releases the process handle without waiting. The child keeps running.
void abandon_process(ChildProcess& child) noexcept;

std::uint64_t current_process_id() noexcept;

// Sleeps the calling thread. Used by process harnesses only; library logic
// never sleeps.
void sleep_millis(std::uint64_t milliseconds);

}  // namespace summon::fbm::platform
