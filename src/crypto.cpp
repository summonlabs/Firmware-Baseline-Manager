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

#include "summon/fbm/crypto.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "summon/fbm/error.hpp"

namespace summon::fbm {
namespace {

constexpr std::size_t kSha256BlockBytes = 64u;
constexpr std::size_t kSha256HexChars = kSha256DigestBytes * 2u;
constexpr std::size_t kHmacBlockBytes = 64u;

// FIPS 180-4 round constants: the first 32 bits of the fractional parts of the
// cube roots of the first 64 primes.
constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

// SHA-256 initial hash value: the first 32 bits of the fractional parts of the
// square roots of the first 8 primes.
constexpr std::array<std::uint32_t, 8> kSha256InitialState = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32u - shift));
}

constexpr std::uint32_t big_sigma0(std::uint32_t x) noexcept {
  return rotate_right(x, 2u) ^ rotate_right(x, 13u) ^ rotate_right(x, 22u);
}

constexpr std::uint32_t big_sigma1(std::uint32_t x) noexcept {
  return rotate_right(x, 6u) ^ rotate_right(x, 11u) ^ rotate_right(x, 25u);
}

constexpr std::uint32_t small_sigma0(std::uint32_t x) noexcept {
  return rotate_right(x, 7u) ^ rotate_right(x, 18u) ^ (x >> 3u);
}

constexpr std::uint32_t small_sigma1(std::uint32_t x) noexcept {
  return rotate_right(x, 17u) ^ rotate_right(x, 19u) ^ (x >> 10u);
}

constexpr std::uint32_t choose_bit(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (~x & z);
}

constexpr std::uint32_t majority_bit(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (x & z) ^ (y & z);
}

// Big-endian load, so the digest is identical on every host byte order.
constexpr std::uint32_t load_be32(const std::uint8_t* bytes) noexcept {
  return (static_cast<std::uint32_t>(bytes[0]) << 24u) |
         (static_cast<std::uint32_t>(bytes[1]) << 16u) |
         (static_cast<std::uint32_t>(bytes[2]) << 8u) | static_cast<std::uint32_t>(bytes[3]);
}

constexpr int hex_digit_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

std::string hex_byte(unsigned char byte) {
  constexpr char kDigits[] = "0123456789ABCDEF";
  std::string out{"0x"};
  out += kDigits[(byte >> 4) & 0x0Fu];
  out += kDigits[byte & 0x0Fu];
  return out;
}

// Reflected Castagnoli table. Computed at compile time from the polynomial, so
// there is no lazily initialized mutable state anywhere in the CRC path.
constexpr std::array<std::uint32_t, 256> make_crc32c_table() noexcept {
  std::array<std::uint32_t, 256> table{};
  for (std::size_t i = 0; i < table.size(); ++i) {
    std::uint32_t crc = static_cast<std::uint32_t>(i);
    for (unsigned bit = 0; bit < 8u; ++bit) {
      if ((crc & 1u) != 0u) {
        crc = (crc >> 1u) ^ 0x82F63B78u;
      } else {
        crc >>= 1u;
      }
    }
    table[i] = crc;
  }
  return table;
}

constexpr std::array<std::uint32_t, 256> kCrc32cTable = make_crc32c_table();

}  // namespace

// --- SHA-256 ---------------------------------------------------------------

Sha256::Sha256() noexcept : state_(kSha256InitialState) {}

void Sha256::update(const void* data, std::size_t size) noexcept {
  if (size == 0 || finalized_) {
    return;
  }
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  total_bytes_ += static_cast<std::uint64_t>(size);
  std::size_t offset = 0;
  if (buffered_ != 0) {
    const std::size_t space = kSha256BlockBytes - buffered_;
    const std::size_t take = size < space ? size : space;
    std::memcpy(buffer_.data() + buffered_, bytes, take);
    buffered_ += take;
    offset += take;
    if (buffered_ == kSha256BlockBytes) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
  while (size - offset >= kSha256BlockBytes) {
    compress(bytes + offset);
    offset += kSha256BlockBytes;
  }
  const std::size_t remaining = size - offset;
  if (remaining != 0) {
    std::memcpy(buffer_.data(), bytes + offset, remaining);
    buffered_ = remaining;
  }
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t i = 0; i < 16u; ++i) {
    schedule[i] = load_be32(block + i * 4u);
  }
  for (std::size_t i = 16u; i < schedule.size(); ++i) {
    schedule[i] = small_sigma1(schedule[i - 2u]) + schedule[i - 7u] +
                  small_sigma0(schedule[i - 15u]) + schedule[i - 16u];
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < schedule.size(); ++i) {
    const std::uint32_t t1 =
        h + big_sigma1(e) + choose_bit(e, f, g) + kSha256RoundConstants[i] + schedule[i];
    const std::uint32_t t2 = big_sigma0(a) + majority_bit(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

Digest Sha256::finish() noexcept {
  const std::uint64_t total_bits = total_bytes_ * 8u;

  buffer_[buffered_] = 0x80u;
  ++buffered_;
  if (buffered_ > 56u) {
    while (buffered_ < kSha256BlockBytes) {
      buffer_[buffered_] = 0u;
      ++buffered_;
    }
    compress(buffer_.data());
    buffered_ = 0;
  }
  while (buffered_ < 56u) {
    buffer_[buffered_] = 0u;
    ++buffered_;
  }
  for (std::size_t i = 0; i < 8u; ++i) {
    buffer_[56u + i] = static_cast<std::uint8_t>(total_bits >> (56u - 8u * i));
  }
  compress(buffer_.data());
  buffered_ = 0;
  finalized_ = true;

  Digest digest{};
  for (std::size_t i = 0; i < state_.size(); ++i) {
    digest[i * 4u] = static_cast<std::uint8_t>(state_[i] >> 24u);
    digest[i * 4u + 1u] = static_cast<std::uint8_t>(state_[i] >> 16u);
    digest[i * 4u + 2u] = static_cast<std::uint8_t>(state_[i] >> 8u);
    digest[i * 4u + 3u] = static_cast<std::uint8_t>(state_[i]);
  }
  return digest;
}

Digest Sha256::of(std::string_view text) noexcept { return of(text.data(), text.size()); }

Digest Sha256::of(const void* data, std::size_t size) noexcept {
  Sha256 hasher;
  hasher.update(data, size);
  return hasher.finish();
}

std::string digest_to_hex(const Digest& digest) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(kSha256HexChars);
  for (std::size_t i = 0; i < digest.size(); ++i) {
    out[i * 2u] = kDigits[(digest[i] >> 4) & 0x0Fu];
    out[i * 2u + 1u] = kDigits[digest[i] & 0x0Fu];
  }
  return out;
}

Result<Digest> digest_from_hex(std::string_view text, std::string_view path) {
  if (text.size() != kSha256HexChars) {
    return Error{ErrorCode::SchemaValueOutOfRange,
                 "hex digest must be exactly " + std::to_string(kSha256HexChars) +
                     " characters but is " + std::to_string(text.size()),
                 std::string{path}};
  }
  Digest digest{};
  for (std::size_t i = 0; i < digest.size(); ++i) {
    const char high_char = text[i * 2u];
    const char low_char = text[i * 2u + 1u];
    const int high = hex_digit_value(high_char);
    if (high < 0) {
      return Error{ErrorCode::EncodingUnexpectedByte,
                   "hex digest byte " + hex_byte(static_cast<unsigned char>(high_char)) +
                       " at offset " + std::to_string(i * 2u) + " is not a hexadecimal digit",
                   std::string{path}};
    }
    const int low = hex_digit_value(low_char);
    if (low < 0) {
      return Error{ErrorCode::EncodingUnexpectedByte,
                   "hex digest byte " + hex_byte(static_cast<unsigned char>(low_char)) +
                       " at offset " + std::to_string(i * 2u + 1u) +
                       " is not a hexadecimal digit",
                   std::string{path}};
    }
    digest[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return digest;
}

bool is_hex_digest_text(std::string_view text) noexcept {
  if (text.size() != kSha256HexChars) {
    return false;
  }
  for (const char c : text) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

// --- HMAC-SHA256 -----------------------------------------------------------

Digest hmac_sha256(std::string_view key, std::string_view message) noexcept {
  std::array<std::uint8_t, kHmacBlockBytes> key_block{};
  if (key.size() > kHmacBlockBytes) {
    const Digest hashed_key = Sha256::of(key.data(), key.size());
    for (std::size_t i = 0; i < hashed_key.size(); ++i) {
      key_block[i] = hashed_key[i];
    }
  } else {
    for (std::size_t i = 0; i < key.size(); ++i) {
      key_block[i] = static_cast<std::uint8_t>(key[i]);
    }
  }

  std::array<std::uint8_t, kHmacBlockBytes> inner_pad{};
  std::array<std::uint8_t, kHmacBlockBytes> outer_pad{};
  for (std::size_t i = 0; i < kHmacBlockBytes; ++i) {
    inner_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36u);
    outer_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5cu);
  }

  Sha256 inner;
  inner.update(inner_pad.data(), inner_pad.size());
  inner.update(message.data(), message.size());
  const Digest inner_digest = inner.finish();

  Sha256 outer;
  outer.update(outer_pad.data(), outer_pad.size());
  outer.update(inner_digest.data(), inner_digest.size());
  return outer.finish();
}

bool constant_time_equal(std::string_view a, std::string_view b) noexcept {
  // The loop runs over the longer input and never reads past the end of either
  // input; a length difference is folded into the same accumulator as a byte
  // difference so that no early exit exists.
  const std::size_t longest = a.size() > b.size() ? a.size() : b.size();
  std::size_t difference = a.size() ^ b.size();
  for (std::size_t i = 0; i < longest; ++i) {
    const auto left = static_cast<unsigned char>(i < a.size() ? a[i] : '\0');
    const auto right = static_cast<unsigned char>(i < b.size() ? b[i] : '\0');
    difference |= static_cast<std::size_t>(left ^ right);
  }
  return difference == 0;
}

// --- CRC-32C ---------------------------------------------------------------

void Crc32c::update(const void* data, std::size_t size) noexcept {
  if (size == 0) {
    return;
  }
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::uint32_t crc = state_;
  for (std::size_t i = 0; i < size; ++i) {
    crc = kCrc32cTable[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8u);
  }
  state_ = crc;
}

std::uint32_t Crc32c::value() const noexcept { return state_ ^ 0xFFFFFFFFu; }

std::uint32_t Crc32c::of(std::string_view text) noexcept { return of(text.data(), text.size()); }

std::uint32_t Crc32c::of(const void* data, std::size_t size) noexcept {
  Crc32c crc;
  crc.update(data, size);
  return crc.value();
}

}  // namespace summon::fbm
