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

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "summon/fbm/result.hpp"

namespace summon::fbm {

inline constexpr std::size_t kSha256DigestBytes = 32u;
using Digest = std::array<std::uint8_t, kSha256DigestBytes>;

// Lower-case hexadecimal rendering of a digest; always 64 characters.
std::string digest_to_hex(const Digest& digest);

// Strict parse of exactly 64 lower-case or upper-case hexadecimal characters.
// All other lengths, characters, and prefixes are rejected.
Result<Digest> digest_from_hex(std::string_view text, std::string_view path);

// Lower-case, exactly 64 hexadecimal characters.
bool is_hex_digest_text(std::string_view text) noexcept;

// Streaming SHA-256 (FIPS 180-4). Single-threaded, allocation-free.
class Sha256 {
 public:
  Sha256() noexcept;

  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept { update(text.data(), text.size()); }

  // Finalizes and returns the digest. The object must not be updated again.
  Digest finish() noexcept;

  static Digest of(std::string_view text) noexcept;
  static Digest of(const void* data, std::size_t size) noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t total_bytes_ = 0;
  std::size_t buffered_ = 0;
  bool finalized_ = false;
};

// Detached HMAC-SHA256 (RFC 2104) over a caller-supplied key. The library never
// stores, defaults, or logs a key; a key is either supplied by the operator at
// run time or signature checking is reported as not configured.
Digest hmac_sha256(std::string_view key, std::string_view message) noexcept;

// Length-independent comparison, so that verification does not leak the number
// of leading matching bytes through timing.
bool constant_time_equal(std::string_view a, std::string_view b) noexcept;

// CRC-32C (Castagnoli polynomial 0x1EDC6F41, reflected). Used as the cheap
// frame integrity check on durable records; SHA-256 remains the authority for
// content identity.
class Crc32c {
 public:
  Crc32c() noexcept = default;

  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept { update(text.data(), text.size()); }

  // May be called at any time; further updates continue from the same state.
  std::uint32_t value() const noexcept;

  static std::uint32_t of(std::string_view text) noexcept;
  static std::uint32_t of(const void* data, std::size_t size) noexcept;

 private:
  std::uint32_t state_ = 0xFFFFFFFFu;
};

}  // namespace summon::fbm
