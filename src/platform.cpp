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

// The library target defines NOMINMAX and WIN32_LEAN_AND_MEAN. Defining them
// here as well keeps a standalone compile of this translation unit identical to
// the library build and keeps the min/max macros out of the standard headers.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "summon/fbm/platform.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)

#include <windows.h>

#else

#include <cerrno>
#include <csignal>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#endif

// Host primitives implemented directly on the operating system. Nothing in this
// file emulates a guarantee the platform does not provide: a flush is a real
// flush, a lock is a real kernel lock, and an atomic replace is a real rename.
namespace summon::fbm::platform {

namespace {

// Ascending order over the unsigned byte value of every character, then by
// length for prefixes. Directory enumeration order is not stable across hosts
// or runs, so callers sort through this total order and never observe it.
bool byte_less(std::string_view left, std::string_view right) noexcept {
  const std::size_t shared = std::min(left.size(), right.size());
  for (std::size_t index = 0; index < shared; ++index) {
    const auto left_byte = static_cast<unsigned char>(left[index]);
    const auto right_byte = static_cast<unsigned char>(right[index]);
    if (left_byte != right_byte) {
      return left_byte < right_byte;
    }
  }
  return left.size() < right.size();
}

// The UTF-8 rendering of a path, used for Error::path so that diagnostics are
// encoded the same way on every host.
std::string path_to_utf8(const std::filesystem::path& path) {
  const std::u8string text = path.u8string();
  std::string out;
  out.reserve(text.size());
  for (const char8_t unit : text) {
    out.push_back(static_cast<char>(unit));
  }
  return out;
}

#if defined(_WIN32)

// Exit code used when a child is terminated abruptly, so that an abrupt death
// is distinguishable from any orderly exit the child could perform.
constexpr UINT kImmediateTerminationExitCode = 0xDEADu;

// Read and write requests are capped so that a size_t never narrows into the
// DWORD the Win32 API takes.
constexpr std::size_t kIoChunkBytes = std::size_t{1} << 30;

// Owns a Win32 handle and closes it exactly once.
class HandleGuard {
 public:
  HandleGuard() noexcept = default;
  explicit HandleGuard(HANDLE handle) noexcept : handle_(handle) {}
  ~HandleGuard() { reset(); }

  HandleGuard(const HandleGuard&) = delete;
  HandleGuard& operator=(const HandleGuard&) = delete;
  HandleGuard(HandleGuard&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
  HandleGuard& operator=(HandleGuard&& other) noexcept {
    if (this != &other) {
      reset();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }

  HANDLE get() const noexcept { return handle_; }
  explicit operator bool() const noexcept {
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
  }

  void reset() noexcept {
    if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
      ::CloseHandle(handle_);
    }
    handle_ = nullptr;
  }

 private:
  HANDLE handle_ = nullptr;
};

std::string wide_to_utf8(std::wstring_view text) {
  if (text.empty()) {
    return std::string();
  }
  const int length = static_cast<int>(text.size());
  const int needed =
      ::WideCharToMultiByte(CP_UTF8, 0, text.data(), length, nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    return std::string();
  }
  std::string out(static_cast<std::size_t>(needed), '\0');
  const int written =
      ::WideCharToMultiByte(CP_UTF8, 0, text.data(), length, out.data(), needed, nullptr, nullptr);
  if (written <= 0) {
    return std::string();
  }
  out.resize(static_cast<std::size_t>(written));
  return out;
}

std::wstring utf8_to_wide(std::string_view text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int length = static_cast<int>(text.size());
  const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), length, nullptr, 0);
  if (needed <= 0) {
    return std::wstring();
  }
  std::wstring out(static_cast<std::size_t>(needed), L'\0');
  const int written = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), length, out.data(), needed);
  if (written <= 0) {
    return std::wstring();
  }
  out.resize(static_cast<std::size_t>(written));
  return out;
}

// The operating system's own text for a Win32 error code, or an empty string
// when the system has no text for it. The decimal code is always reported by
// the caller, so a missing description never hides the cause.
std::string system_error_text(int system_error) {
  LPWSTR buffer = nullptr;
  const DWORD length = ::FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, static_cast<DWORD>(system_error), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
  if (length == 0 || buffer == nullptr) {
    if (buffer != nullptr) {
      ::LocalFree(buffer);
    }
    return std::string();
  }
  std::wstring text(buffer, length);
  ::LocalFree(buffer);
  while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' ||
                           text.back() == L'\t')) {
    text.pop_back();
  }
  return wide_to_utf8(text);
}

ErrorCode classify_system_error(int system_error) noexcept {
  switch (system_error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
    case ERROR_BAD_NETPATH:
    case ERROR_BAD_NET_NAME:
      return ErrorCode::IoNotFound;
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
    case ERROR_WRITE_PROTECT:
      return ErrorCode::IoPermissionDenied;
    default:
      return ErrorCode::IoFailure;
  }
}

// Every host failure carries the decimal Win32 error code, the system's own
// description when it has one, and the path the operation was aimed at.
Error make_error(ErrorCode code, std::string_view operation, int system_error,
                 const std::filesystem::path& path = {}) {
  std::string message(operation);
  message.append(" failed: windows error ");
  message.append(std::to_string(system_error));
  const std::string detail = system_error_text(system_error);
  if (!detail.empty()) {
    message.append(" (");
    message.append(detail);
    message.append(")");
  }
  return Error{code, std::move(message), path_to_utf8(path)};
}

Error make_system_error(std::string_view operation, int system_error,
                        const std::filesystem::path& path = {}) {
  return make_error(classify_system_error(system_error), operation, system_error, path);
}

// Quotes one argument using the standard Windows rules, including the
// backslash-before-quote rule, so that arguments containing spaces, embedded
// quotes, or trailing backslashes survive the round trip through the child's
// command line parser.
std::wstring quote_argument(const std::wstring& argument) {
  if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return argument;
  }
  std::wstring quoted;
  quoted.push_back(L'"');
  std::size_t index = 0;
  while (true) {
    std::size_t backslashes = 0;
    while (index < argument.size() && argument[index] == L'\\') {
      ++index;
      ++backslashes;
    }
    if (index == argument.size()) {
      // Backslashes before the closing quote must be doubled.
      quoted.append(backslashes * 2, L'\\');
      break;
    }
    if (argument[index] == L'"') {
      // Backslashes before an embedded quote must be doubled, and the quote
      // itself escaped.
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(L'"');
    } else {
      quoted.append(backslashes, L'\\');
      quoted.push_back(argument[index]);
    }
    ++index;
  }
  quoted.push_back(L'"');
  return quoted;
}

#endif  // defined(_WIN32)

#if !defined(_WIN32)

ErrorCode classify_system_error(int system_error) noexcept {
  switch (system_error) {
    case ENOENT:
    case ENOTDIR:
      return ErrorCode::IoNotFound;
    case EACCES:
    case EPERM:
    case EROFS:
      return ErrorCode::IoPermissionDenied;
    default:
      return ErrorCode::IoFailure;
  }
}

Error make_error(ErrorCode code, std::string_view operation, int system_error,
                 const std::filesystem::path& path = {}) {
  std::string message(operation);
  message.append(" failed: errno ");
  message.append(std::to_string(system_error));
  const char* detail = std::strerror(system_error);
  if (detail != nullptr && detail[0] != '\0') {
    message.append(" (");
    message.append(detail);
    message.append(")");
  }
  return Error{code, std::move(message), path_to_utf8(path)};
}

Error make_system_error(std::string_view operation, int system_error,
                        const std::filesystem::path& path = {}) {
  return make_error(classify_system_error(system_error), operation, system_error, path);
}

// The descriptor is stored biased by one so that descriptor zero is never
// confused with the null handle that marks a released lock.
void* descriptor_to_handle(int descriptor) noexcept {
  return reinterpret_cast<void*>(static_cast<std::intptr_t>(descriptor) + 1);
}

int handle_to_descriptor(void* handle) noexcept {
  return static_cast<int>(reinterpret_cast<std::intptr_t>(handle) - 1);
}

pid_t process_handle_to_pid(void* handle) noexcept {
  return static_cast<pid_t>(reinterpret_cast<std::intptr_t>(handle));
}

void* pid_to_process_handle(pid_t pid) noexcept {
  return reinterpret_cast<void*>(static_cast<std::intptr_t>(pid));
}

#endif  // !defined(_WIN32)

}  // namespace

// --- Filesystem -------------------------------------------------------------

bool path_exists(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  return ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
#else
  struct stat information {};
  return ::stat(path.c_str(), &information) == 0;
#endif
}

bool is_regular_file(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  const DWORD attributes = ::GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
  struct stat information {};
  if (::stat(path.c_str(), &information) != 0) {
    return false;
  }
  return S_ISREG(information.st_mode);
#endif
}

bool is_directory(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  const DWORD attributes = ::GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
  struct stat information {};
  if (::stat(path.c_str(), &information) != 0) {
    return false;
  }
  return S_ISDIR(information.st_mode);
#endif
}

Result<std::uint64_t> file_size(const std::filesystem::path& path) {
#if defined(_WIN32)
  HandleGuard file(::CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (!file) {
    const int error = static_cast<int>(::GetLastError());
    return make_system_error("file_size: CreateFileW", error, path);
  }
  LARGE_INTEGER size{};
  if (::GetFileSizeEx(file.get(), &size) == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "file_size: GetFileSizeEx", error, path);
  }
  if (size.QuadPart < 0) {
    return Error{ErrorCode::IoFailure, "file_size: the host reported a negative size",
                 path_to_utf8(path)};
  }
  return static_cast<std::uint64_t>(size.QuadPart);
#else
  struct stat information {};
  if (::stat(path.c_str(), &information) != 0) {
    const int error = errno;
    return make_system_error("file_size: stat", error, path);
  }
  if (information.st_size < 0) {
    return Error{ErrorCode::IoFailure, "file_size: the host reported a negative size",
                 path_to_utf8(path)};
  }
  return static_cast<std::uint64_t>(information.st_size);
#endif
}

Status ensure_directory(const std::filesystem::path& path) {
  std::error_code error;
  const bool created = std::filesystem::create_directories(path, error);
  static_cast<void>(created);
  if (!error) {
    return ok_status();
  }
  // Qualified so that argument-dependent lookup cannot select the standard
  // library's is_directory instead of this one.
  if (summon::fbm::platform::is_directory(path)) {
    return ok_status();
  }
  return make_system_error("ensure_directory: create_directories", error.value(), path);
}

Result<std::string> read_file(const std::filesystem::path& path, std::uint64_t max_bytes) {
#if defined(_WIN32)
  HandleGuard file(::CreateFileW(path.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file) {
    const int error = static_cast<int>(::GetLastError());
    return make_system_error("read_file: CreateFileW", error, path);
  }

  LARGE_INTEGER size{};
  if (::GetFileSizeEx(file.get(), &size) == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "read_file: GetFileSizeEx", error, path);
  }
  if (size.QuadPart < 0) {
    return Error{ErrorCode::IoFailure, "read_file: the host reported a negative size",
                 path_to_utf8(path)};
  }
  const std::uint64_t total = static_cast<std::uint64_t>(size.QuadPart);

  if (total > max_bytes ||
      total > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    std::string message = "read_file: the file holds ";
    message.append(std::to_string(total));
    message.append(" bytes, which exceeds the ");
    message.append(std::to_string(max_bytes));
    message.append(" byte limit");
    return Error{ErrorCode::EncodingSizeExceeded, std::move(message), path_to_utf8(path)};
  }

  std::string data(static_cast<std::size_t>(total), '\0');
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    const DWORD request = static_cast<DWORD>(std::min<std::size_t>(remaining, kIoChunkBytes));
    DWORD read = 0;
    if (::ReadFile(file.get(), data.data() + offset, request, &read, nullptr) == 0) {
      const int error = static_cast<int>(::GetLastError());
      return make_error(ErrorCode::IoFailure, "read_file: ReadFile", error, path);
    }
    if (read == 0) {
      std::string message = "read_file: the file ended after ";
      message.append(std::to_string(offset));
      message.append(" of ");
      message.append(std::to_string(total));
      message.append(" bytes");
      return Error{ErrorCode::IoFailure, std::move(message), path_to_utf8(path)};
    }
    offset += static_cast<std::size_t>(read);
  }
  return data;
#else
  const int descriptor = ::open(path.c_str(), O_RDONLY);
  if (descriptor < 0) {
    const int error = errno;
    return make_system_error("read_file: open", error, path);
  }

  struct stat information {};
  if (::fstat(descriptor, &information) != 0) {
    const int error = errno;
    ::close(descriptor);
    return make_error(ErrorCode::IoFailure, "read_file: fstat", error, path);
  }
  if (!S_ISREG(information.st_mode)) {
    ::close(descriptor);
    return Error{ErrorCode::IoFailure, "read_file: the path is not a regular file",
                 path_to_utf8(path)};
  }
  if (information.st_size < 0) {
    ::close(descriptor);
    return Error{ErrorCode::IoFailure, "read_file: the host reported a negative size",
                 path_to_utf8(path)};
  }
  const std::uint64_t total = static_cast<std::uint64_t>(information.st_size);
  if (total > max_bytes ||
      total > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    ::close(descriptor);
    std::string message = "read_file: the file holds ";
    message.append(std::to_string(total));
    message.append(" bytes, which exceeds the ");
    message.append(std::to_string(max_bytes));
    message.append(" byte limit");
    return Error{ErrorCode::EncodingSizeExceeded, std::move(message), path_to_utf8(path)};
  }

  std::string data(static_cast<std::size_t>(total), '\0');
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    const ssize_t read =
        ::read(descriptor, data.data() + offset, static_cast<std::size_t>(remaining));
    if (read < 0) {
      const int error = errno;
      if (error == EINTR) {
        continue;
      }
      ::close(descriptor);
      return make_error(ErrorCode::IoFailure, "read_file: read", error, path);
    }
    if (read == 0) {
      ::close(descriptor);
      std::string message = "read_file: the file ended after ";
      message.append(std::to_string(offset));
      message.append(" of ");
      message.append(std::to_string(total));
      message.append(" bytes");
      return Error{ErrorCode::IoFailure, std::move(message), path_to_utf8(path)};
    }
    offset += static_cast<std::size_t>(read);
  }
  ::close(descriptor);
  return data;
#endif
}

Status write_file_flushed(const std::filesystem::path& path, std::string_view data) {
#if defined(_WIN32)
  HandleGuard file(::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                 nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "write_file_flushed: CreateFileW", error, path);
  }

  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    const DWORD request = static_cast<DWORD>(std::min<std::size_t>(remaining, kIoChunkBytes));
    DWORD written = 0;
    if (::WriteFile(file.get(), data.data() + offset, request, &written, nullptr) == 0) {
      const int error = static_cast<int>(::GetLastError());
      return make_error(ErrorCode::IoFailure, "write_file_flushed: WriteFile", error, path);
    }
    if (written == 0) {
      return Error{ErrorCode::IoFailure, "write_file_flushed: WriteFile accepted no bytes",
                   path_to_utf8(path)};
    }
    offset += static_cast<std::size_t>(written);
  }

  if (::FlushFileBuffers(file.get()) == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFlushFailed, "write_file_flushed: FlushFileBuffers", error, path);
  }
  return ok_status();
#else
  const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (descriptor < 0) {
    const int error = errno;
    return make_error(ErrorCode::IoFailure, "write_file_flushed: open", error, path);
  }

  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    const ssize_t written = ::write(descriptor, data.data() + offset, remaining);
    if (written < 0) {
      const int error = errno;
      if (error == EINTR) {
        continue;
      }
      ::close(descriptor);
      return make_error(ErrorCode::IoFailure, "write_file_flushed: write", error, path);
    }
    if (written == 0) {
      ::close(descriptor);
      return Error{ErrorCode::IoFailure, "write_file_flushed: write accepted no bytes",
                   path_to_utf8(path)};
    }
    offset += static_cast<std::size_t>(written);
  }

  if (::fsync(descriptor) != 0) {
    const int error = errno;
    ::close(descriptor);
    return make_error(ErrorCode::IoFlushFailed, "write_file_flushed: fsync", error, path);
  }
  ::close(descriptor);
  return ok_status();
#endif
}

Status sync_file(const std::filesystem::path& path) {
#if defined(_WIN32)
  HandleGuard file(::CreateFileW(path.c_str(), GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file) {
    const int error = static_cast<int>(::GetLastError());
    return make_system_error("sync_file: CreateFileW", error, path);
  }
  if (::FlushFileBuffers(file.get()) == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFlushFailed, "sync_file: FlushFileBuffers", error, path);
  }
  return ok_status();
#else
  const int descriptor = ::open(path.c_str(), O_WRONLY);
  if (descriptor < 0) {
    const int error = errno;
    return make_system_error("sync_file: open", error, path);
  }
  if (::fsync(descriptor) != 0) {
    const int error = errno;
    ::close(descriptor);
    return make_error(ErrorCode::IoFlushFailed, "sync_file: fsync", error, path);
  }
  ::close(descriptor);
  return ok_status();
#endif
}

Status flush_directory(const std::filesystem::path& directory) {
#if defined(_WIN32)
  // Windows offers no supported flush of a directory entry: there is no handle
  // to fsync and FlushFileBuffers has no meaning for a directory. This is a
  // documented no-op, and correctness never depends on it. The store's A/B slot
  // scheme keeps a rename that was not yet durable from becoming authoritative,
  // because the fence - not the rename - selects the generation.
  static_cast<void>(directory);
  return ok_status();
#else
  const int descriptor = ::open(directory.c_str(), O_RDONLY);
  if (descriptor < 0) {
    const int error = errno;
    return make_system_error("flush_directory: open", error, directory);
  }
  if (::fsync(descriptor) != 0) {
    const int error = errno;
    ::close(descriptor);
    return make_error(ErrorCode::IoFlushFailed, "flush_directory: fsync", error, directory);
  }
  ::close(descriptor);
  return ok_status();
#endif
}

Status atomic_replace(const std::filesystem::path& source,
                      const std::filesystem::path& destination) {
#if defined(_WIN32)
  // MoveFileExW with both flags is a same-volume rename: the destination either
  // holds its previous contents or the new contents and never a mixture, and it
  // works whether or not the destination already exists.
  if (::MoveFileExW(source.c_str(), destination.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoAtomicReplaceFailed, "atomic_replace: MoveFileExW", error,
                      destination);
  }
  return ok_status();
#else
  if (::rename(source.c_str(), destination.c_str()) != 0) {
    const int error = errno;
    return make_error(ErrorCode::IoAtomicReplaceFailed, "atomic_replace: rename", error,
                      destination);
  }
  return ok_status();
#endif
}

Status remove_file(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
  if (::DeleteFileW(path.c_str()) != 0) {
    return ok_status();
  }
  const int error = static_cast<int>(::GetLastError());
  return make_error(classify_system_error(error), "remove_file: DeleteFileW", error, path);
#else
  if (::unlink(path.c_str()) == 0) {
    return ok_status();
  }
  const int error = errno;
  return make_error(classify_system_error(error), "remove_file: unlink", error, path);
#endif
}

Status remove_tree(const std::filesystem::path& path) noexcept {
  std::error_code error;
  std::filesystem::remove_all(path, error);
  if (error) {
    return make_system_error("remove_tree: remove_all", error.value(), path);
  }
  return ok_status();
}

Result<std::vector<std::string>> list_directory(const std::filesystem::path& directory) {
#if defined(_WIN32)
  const std::filesystem::path pattern = directory / L"*";
  WIN32_FIND_DATAW entry{};
  HANDLE search = ::FindFirstFileW(pattern.c_str(), &entry);
  if (search == INVALID_HANDLE_VALUE) {
    const int error = static_cast<int>(::GetLastError());
    return make_system_error("list_directory: FindFirstFileW", error, directory);
  }

  std::vector<std::string> names;
  bool more = true;
  while (more) {
    const wchar_t* name = entry.cFileName;
    const bool is_current = name[0] == L'.' && name[1] == L'\0';
    const bool is_parent = name[0] == L'.' && name[1] == L'.' && name[2] == L'\0';
    if (!is_current && !is_parent) {
      names.push_back(wide_to_utf8(name));
    }
    more = ::FindNextFileW(search, &entry) != 0;
  }
  const int error = static_cast<int>(::GetLastError());
  ::FindClose(search);
  if (error != ERROR_NO_MORE_FILES) {
    return make_error(ErrorCode::IoFailure, "list_directory: FindNextFileW", error, directory);
  }

  std::sort(names.begin(), names.end(), byte_less);
  return names;
#else
  DIR* stream = ::opendir(directory.c_str());
  if (stream == nullptr) {
    const int error = errno;
    return make_system_error("list_directory: opendir", error, directory);
  }

  std::vector<std::string> names;
  while (true) {
    errno = 0;
    const struct dirent* entry = ::readdir(stream);
    if (entry == nullptr) {
      break;
    }
    const char* name = entry->d_name;
    const bool is_current = name[0] == '.' && name[1] == '\0';
    const bool is_parent = name[0] == '.' && name[1] == '.' && name[2] == '\0';
    if (!is_current && !is_parent) {
      names.push_back(std::string(name));
    }
  }
  const int error = errno;
  ::closedir(stream);
  if (error != 0) {
    return make_error(ErrorCode::IoFailure, "list_directory: readdir", error, directory);
  }

  std::sort(names.begin(), names.end(), byte_less);
  return names;
#endif
}

// --- Cross-process exclusion -------------------------------------------------

FileLock::FileLock(FileLock&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    release();
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

FileLock::~FileLock() { release(); }

void FileLock::release() noexcept {
  if (handle_ == nullptr) {
    return;
  }
#if defined(_WIN32)
  const HANDLE handle = static_cast<HANDLE>(handle_);
  handle_ = nullptr;
  OVERLAPPED overlapped{};
  ::UnlockFileEx(handle, 0, MAXDWORD, MAXDWORD, &overlapped);
  ::CloseHandle(handle);
#else
  const int descriptor = handle_to_descriptor(handle_);
  handle_ = nullptr;
  ::flock(descriptor, LOCK_UN);
  ::close(descriptor);
#endif
}

Result<FileLock> FileLock::acquire(const std::filesystem::path& path) {
#if defined(_WIN32)
  // The lock file is opened non-inheritable (a null security descriptor) so a
  // child process never inherits the parent's claim, and with sharing enabled
  // so every other process can open the same file and contend for the lock.
  const HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoLockFailed, "FileLock::acquire: CreateFileW", error, path);
  }

  OVERLAPPED overlapped{};
  const DWORD flags = static_cast<DWORD>(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY);
  if (::LockFileEx(handle, flags, 0, MAXDWORD, MAXDWORD, &overlapped) == 0) {
    const int error = static_cast<int>(::GetLastError());
    ::CloseHandle(handle);
    if (error == ERROR_LOCK_VIOLATION) {
      return make_error(ErrorCode::IoLockBusy, "FileLock::acquire: LockFileEx", error, path);
    }
    return make_error(ErrorCode::IoLockFailed, "FileLock::acquire: LockFileEx", error, path);
  }

  FileLock lock;
  lock.handle_ = handle;
  return lock;
#else
  int flags = O_RDWR | O_CREAT;
#if defined(O_CLOEXEC)
  // A child process must not inherit the parent's lock descriptor.
  flags |= O_CLOEXEC;
#endif
  const int descriptor = ::open(path.c_str(), flags, 0644);
  if (descriptor < 0) {
    const int error = errno;
    return make_error(ErrorCode::IoLockFailed, "FileLock::acquire: open", error, path);
  }

  if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    const int error = errno;
    ::close(descriptor);
    if (error == EWOULDBLOCK || error == EAGAIN) {
      return make_error(ErrorCode::IoLockBusy, "FileLock::acquire: flock", error, path);
    }
    return make_error(ErrorCode::IoLockFailed, "FileLock::acquire: flock", error, path);
  }

  FileLock lock;
  lock.handle_ = descriptor_to_handle(descriptor);
  return lock;
#endif
}

// --- Child processes ---------------------------------------------------------

Result<ChildProcess> spawn_process(const std::filesystem::path& executable,
                                   const std::vector<std::string>& arguments,
                                   const std::filesystem::path& working_directory,
                                   const std::filesystem::path& standard_output_path,
                                   const std::filesystem::path& standard_error_path) {
#if defined(_WIN32)
  if (executable.empty()) {
    return Error{ErrorCode::InvalidArgument, "spawn_process: the executable path is empty",
                 path_to_utf8(executable)};
  }

  // The command line is a single properly quoted string: the executable itself
  // first, then one quoted token per argument.
  std::wstring command_line = quote_argument(executable.native());
  for (const std::string& argument : arguments) {
    command_line.push_back(L' ');
    command_line.append(quote_argument(utf8_to_wide(argument)));
  }
  std::vector<wchar_t> mutable_command_line(command_line.begin(), command_line.end());
  mutable_command_line.push_back(L'\0');

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.lpSecurityDescriptor = nullptr;
  attributes.bInheritHandle = TRUE;

  const std::filesystem::path null_device = L"NUL";
  HandleGuard standard_input(::CreateFileW(null_device.c_str(), GENERIC_READ,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!standard_input) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "spawn_process: open the null device", error,
                      null_device);
  }

  // Real inheritable file handles, never pipes: a chatty child fills a file and
  // can never block on a full pipe.
  HandleGuard output_file(::CreateFileW(standard_output_path.c_str(), GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_DELETE, &attributes,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!output_file) {
    const int error = static_cast<int>(::GetLastError());
    return make_system_error("spawn_process: create standard output", error, standard_output_path);
  }

  HandleGuard error_file(::CreateFileW(standard_error_path.c_str(), GENERIC_WRITE,
                                       FILE_SHARE_READ | FILE_SHARE_DELETE, &attributes,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!error_file) {
    const int error = static_cast<int>(::GetLastError());
    return make_system_error("spawn_process: create standard error", error, standard_error_path);
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = standard_input.get();
  startup.hStdOutput = output_file.get();
  startup.hStdError = error_file.get();

  PROCESS_INFORMATION process{};
  const wchar_t* working = working_directory.empty() ? nullptr : working_directory.c_str();
  const BOOL created = ::CreateProcessW(executable.c_str(), mutable_command_line.data(), nullptr,
                                        nullptr, TRUE, 0, nullptr, working, &startup, &process);
  if (created == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_system_error("spawn_process: CreateProcessW", error, executable);
  }
  ::CloseHandle(process.hThread);

  ChildProcess child;
  child.handle = process.hProcess;
  child.process_id = static_cast<std::uint64_t>(process.dwProcessId);
  child.standard_output_path = standard_output_path;
  child.standard_error_path = standard_error_path;
  return child;
#else
  if (executable.empty()) {
    return Error{ErrorCode::InvalidArgument, "spawn_process: the executable path is empty",
                 path_to_utf8(executable)};
  }

  std::vector<std::string> storage;
  storage.reserve(arguments.size() + 1);
  storage.push_back(executable.string());
  for (const std::string& argument : arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (std::string& text : storage) {
    argv.push_back(text.data());
  }
  argv.push_back(nullptr);

  const int input_descriptor = ::open("/dev/null", O_RDONLY);
  if (input_descriptor < 0) {
    const int error = errno;
    return make_error(ErrorCode::IoFailure, "spawn_process: open /dev/null", error,
                      std::filesystem::path("/dev/null"));
  }
  const int output_descriptor =
      ::open(standard_output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (output_descriptor < 0) {
    const int error = errno;
    ::close(input_descriptor);
    return make_system_error("spawn_process: open standard output", error, standard_output_path);
  }
  const int error_descriptor =
      ::open(standard_error_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (error_descriptor < 0) {
    const int error = errno;
    ::close(input_descriptor);
    ::close(output_descriptor);
    return make_system_error("spawn_process: open standard error", error, standard_error_path);
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    const int error = errno;
    ::close(input_descriptor);
    ::close(output_descriptor);
    ::close(error_descriptor);
    return make_error(ErrorCode::IoFailure, "spawn_process: fork", error, executable);
  }
  if (pid == 0) {
    if (::dup2(input_descriptor, STDIN_FILENO) < 0 || ::dup2(output_descriptor, STDOUT_FILENO) < 0 ||
        ::dup2(error_descriptor, STDERR_FILENO) < 0) {
      ::_exit(127);
    }
    ::close(input_descriptor);
    ::close(output_descriptor);
    ::close(error_descriptor);
    if (!working_directory.empty() && ::chdir(working_directory.c_str()) != 0) {
      ::_exit(127);
    }
    ::execv(executable.c_str(), argv.data());
    ::_exit(127);
  }
  ::close(input_descriptor);
  ::close(output_descriptor);
  ::close(error_descriptor);

  ChildProcess child;
  child.handle = pid_to_process_handle(pid);
  child.process_id = static_cast<std::uint64_t>(pid);
  child.standard_output_path = standard_output_path;
  child.standard_error_path = standard_error_path;
  return child;
#endif
}

Result<int> wait_for_exit(ChildProcess& child) {
  if (child.handle == nullptr) {
    return Error{ErrorCode::InvalidArgument, "wait_for_exit: the process handle is not open", {}};
  }
#if defined(_WIN32)
  const HANDLE handle = static_cast<HANDLE>(child.handle);
  if (::WaitForSingleObject(handle, INFINITE) == WAIT_FAILED) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "wait_for_exit: WaitForSingleObject", error);
  }
  DWORD exit_code = 0;
  if (::GetExitCodeProcess(handle, &exit_code) == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "wait_for_exit: GetExitCodeProcess", error);
  }
  return static_cast<int>(exit_code);
#else
  const pid_t pid = process_handle_to_pid(child.handle);
  int status = 0;
  pid_t waited = 0;
  do {
    waited = ::waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited < 0) {
    const int error = errno;
    return make_error(ErrorCode::IoFailure, "wait_for_exit: waitpid", error);
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    // A child killed by a signal has no exit code; the conventional 128 plus
    // the signal number is reported instead.
    return 128 + WTERMSIG(status);
  }
  return 128;
#endif
}

Status terminate_immediately(ChildProcess& child) {
  if (child.handle == nullptr) {
    return Error{ErrorCode::InvalidArgument, "terminate_immediately: the process handle is not open",
                 {}};
  }
#if defined(_WIN32)
  const HANDLE handle = static_cast<HANDLE>(child.handle);
  if (::TerminateProcess(handle, kImmediateTerminationExitCode) == 0) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "terminate_immediately: TerminateProcess", error);
  }
  if (::WaitForSingleObject(handle, INFINITE) == WAIT_FAILED) {
    const int error = static_cast<int>(::GetLastError());
    return make_error(ErrorCode::IoFailure, "terminate_immediately: WaitForSingleObject", error);
  }
  return ok_status();
#else
  const pid_t pid = process_handle_to_pid(child.handle);
  if (::kill(pid, SIGKILL) != 0) {
    const int error = errno;
    return make_error(ErrorCode::IoFailure, "terminate_immediately: kill", error);
  }
  int status = 0;
  pid_t waited = 0;
  do {
    waited = ::waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited < 0) {
    const int error = errno;
    return make_error(ErrorCode::IoFailure, "terminate_immediately: waitpid", error);
  }
  return ok_status();
#endif
}

void abandon_process(ChildProcess& child) noexcept {
#if defined(_WIN32)
  if (child.handle != nullptr) {
    ::CloseHandle(static_cast<HANDLE>(child.handle));
    child.handle = nullptr;
  }
#else
  // The child keeps running. The host reaps it once this process exits, so
  // nothing is closed here beyond forgetting the handle.
  child.handle = nullptr;
#endif
}

std::uint64_t current_process_id() noexcept {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

void sleep_millis(std::uint64_t milliseconds) {
#if defined(_WIN32)
  // Sleep is capped below INFINITE so a long request stays a plain sleep.
  constexpr std::uint64_t kMaxChunk = 0xFFFFFFFEull;
  while (milliseconds > 0) {
    const std::uint64_t chunk = milliseconds < kMaxChunk ? milliseconds : kMaxChunk;
    ::Sleep(static_cast<DWORD>(chunk));
    milliseconds -= chunk;
  }
#else
  constexpr std::uint64_t kMaxChunk = 0xFFFFFFFEull;
  while (milliseconds > 0) {
    const std::uint64_t chunk = milliseconds < kMaxChunk ? milliseconds : kMaxChunk;
    struct timespec request {};
    request.tv_sec = static_cast<time_t>(chunk / 1000);
    request.tv_nsec = static_cast<long>((chunk % 1000) * 1000000ull);
    while (::nanosleep(&request, &request) != 0 && errno == EINTR) {
    }
    milliseconds -= chunk;
  }
#endif
}

}  // namespace summon::fbm::platform
