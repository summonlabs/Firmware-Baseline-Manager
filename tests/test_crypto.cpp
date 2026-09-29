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

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"

namespace {

using summon::fbm::constant_time_equal;
using summon::fbm::Crc32c;
using summon::fbm::digest_from_hex;
using summon::fbm::digest_to_hex;
using summon::fbm::Digest;
using summon::fbm::ErrorCode;
using summon::fbm::hmac_sha256;
using summon::fbm::is_hex_digest_text;
using summon::fbm::Sha256;

// FIPS 180-4 / NIST example digests (lower-case hexadecimal).
constexpr std::string_view kSha256Empty =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
constexpr std::string_view kSha256Abc =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
constexpr std::string_view kSha256TwoBlock =
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
constexpr std::string_view kSha256MillionA =
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

std::string sha256_hex(std::string_view text) { return digest_to_hex(Sha256::of(text)); }

// Reproducible byte pattern, so "streaming in every split" is deterministic.
std::vector<std::uint8_t> pattern_bytes(std::size_t size) {
  std::vector<std::uint8_t> bytes(size);
  for (std::size_t i = 0; i < size; ++i) {
    bytes[i] = static_cast<std::uint8_t>((i * 37u + 11u) & 0xFFu);
  }
  return bytes;
}

std::string_view as_text(const std::vector<std::uint8_t>& bytes) {
  return std::string_view{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

}  // namespace

FBM_TEST(crypto_sha256_matches_fips_vectors) {
  CHECK_EQ(sha256_hex(""), std::string{kSha256Empty});
  CHECK_EQ(sha256_hex("abc"), std::string{kSha256Abc});

  const std::string two_block{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
  CHECK_EQ(two_block.size(), std::size_t{56});
  CHECK_EQ(sha256_hex(two_block), std::string{kSha256TwoBlock});

  // One million copies of 'a', streamed as 1000 chunks of 1000 bytes.
  const std::string chunk(1000, 'a');
  Sha256 hasher;
  for (int i = 0; i < 1000; ++i) {
    hasher.update(chunk);
  }
  CHECK_EQ(digest_to_hex(hasher.finish()), std::string{kSha256MillionA});
}

FBM_TEST(crypto_sha256_streaming_matches_one_shot) {
  // A zero-length update contributes nothing and must not disturb the state.
  Sha256 untouched;
  untouched.update(nullptr, 0);
  untouched.update(std::string_view{});
  CHECK_EQ(digest_to_hex(untouched.finish()), std::string{kSha256Empty});

  const std::vector<std::uint8_t> bytes = pattern_bytes(200);
  const Digest one_shot = Sha256::of(as_text(bytes));

  for (std::size_t split = 0; split <= bytes.size(); ++split) {
    Sha256 streamed;
    streamed.update(bytes.data(), split);
    streamed.update(bytes.data() + split, bytes.size() - split);
    CHECK_EQ(digest_to_hex(streamed.finish()), digest_to_hex(one_shot));
  }

  // Feeding one byte at a time visits every buffering state.
  Sha256 bytewise;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytewise.update(bytes.data() + i, 1);
  }
  CHECK_EQ(digest_to_hex(bytewise.finish()), digest_to_hex(one_shot));

  // The static overload over a raw buffer agrees with the text overload.
  CHECK_EQ(digest_to_hex(Sha256::of(bytes.data(), bytes.size())), digest_to_hex(one_shot));
}

FBM_TEST(crypto_hmac_sha256_matches_rfc4231) {
  // Case 1: 20-byte key of 0x0b, data "Hi There".
  const std::string key1(20, static_cast<char>(0x0b));
  CHECK_EQ(key1.size(), std::size_t{20});
  CHECK_EQ(digest_to_hex(hmac_sha256(key1, "Hi There")),
           std::string{"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"});

  // Case 2: short key. The published digest begins 5bdcc146; the key text and
  // the data text are reproduced exactly, because a one-character change to
  // either produces a different digest.
  CHECK_EQ(digest_to_hex(hmac_sha256("Jefe", "what do ya want for nothing?")),
           std::string{"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"});

  // Cases 6 and 7: 131-byte key, longer than the 64-byte block, so the key is
  // hashed first. The RFC data text - including the hyphens in "block-size" - is
  // reproduced exactly; the expected digest is the published one.
  const std::string long_key(131, static_cast<char>(0xaa));
  CHECK_EQ(long_key.size(), std::size_t{131});
  CHECK_EQ(digest_to_hex(hmac_sha256(
               long_key, "Test Using Larger Than Block-Size Key - Hash Key First")),
           std::string{"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"});
  CHECK_EQ(digest_to_hex(hmac_sha256(
               long_key,
               "This is a test using a larger than block-size key and a larger than block-size "
               "data. The key needs to be hashed before being used by the HMAC algorithm.")),
           std::string{"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"});

  // A key of exactly the 64-byte block size is used verbatim, and an empty key
  // and empty message are still a defined HMAC.
  const std::string block_key(64, 'k');
  CHECK_EQ(block_key.size(), std::size_t{64});
  CHECK(!digest_to_hex(hmac_sha256(block_key, "payload")).empty());
  CHECK_EQ(digest_to_hex(hmac_sha256("", "")),
           std::string{"b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"});
}

FBM_TEST(crypto_crc32c_matches_known_values) {
  CHECK_EQ(Crc32c::of("123456789"), std::uint32_t{0xE3069283u});
  CHECK_EQ(Crc32c::of(""), std::uint32_t{0x00000000u});
  CHECK_EQ(Crc32c::of("a"), std::uint32_t{0xC1D04330u});

  // Splitting the same nine characters anywhere gives the same value.
  Crc32c split;
  split.update("1234");
  split.update("56789");
  CHECK_EQ(split.value(), std::uint32_t{0xE3069283u});

  // value() is a pure observation; further updates continue from the state.
  Crc32c observed;
  observed.update("1234");
  const std::uint32_t partial = observed.value();
  CHECK_EQ(observed.value(), partial);
  CHECK_EQ(observed.value(), Crc32c::of("1234"));
  observed.update("56789");
  CHECK_EQ(observed.value(), std::uint32_t{0xE3069283u});

  // An untouched instance is the CRC of the empty input, and a zero-length
  // update changes nothing.
  Crc32c untouched;
  CHECK_EQ(untouched.value(), std::uint32_t{0x00000000u});
  untouched.update(nullptr, 0);
  untouched.update(std::string_view{});
  CHECK_EQ(untouched.value(), std::uint32_t{0x00000000u});
  CHECK_EQ(Crc32c::of(static_cast<const void*>(nullptr), 0), std::uint32_t{0x00000000u});
}

FBM_TEST(crypto_crc32c_streaming_matches_one_shot) {
  const std::vector<std::uint8_t> bytes = pattern_bytes(300);
  const std::uint32_t one_shot = Crc32c::of(as_text(bytes));
  for (std::size_t split = 0; split <= bytes.size(); ++split) {
    Crc32c streamed;
    streamed.update(bytes.data(), split);
    streamed.update(bytes.data() + split, bytes.size() - split);
    CHECK_EQ(streamed.value(), one_shot);
  }

  // Feeding one byte at a time visits every state.
  Crc32c bytewise;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytewise.update(bytes.data() + i, 1);
  }
  CHECK_EQ(bytewise.value(), one_shot);
}

FBM_TEST(crypto_digest_hex_round_trip_is_strict) {
  const Digest digest = Sha256::of("abc");
  const std::string lower = digest_to_hex(digest);
  CHECK_EQ(lower.size(), std::size_t{64});
  CHECK(is_hex_digest_text(lower));

  auto parsed_lower = digest_from_hex(lower, "artifact.digest");
  CHECK_OK(parsed_lower);
  CHECK_EQ(digest_to_hex(parsed_lower.value()), lower);

  // Upper-case input is accepted and yields the identical digest.
  std::string upper = lower;
  for (char& c : upper) {
    if (c >= 'a' && c <= 'f') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  auto parsed_upper = digest_from_hex(upper, "artifact.digest");
  CHECK_OK(parsed_upper);
  CHECK_EQ(digest_to_hex(parsed_upper.value()), lower);
  CHECK(!is_hex_digest_text(upper));
}

FBM_TEST(crypto_digest_from_hex_rejects_malformed_text) {
  const Digest digest = Sha256::of("abc");
  const std::string lower = digest_to_hex(digest);

  // Wrong lengths: 63, 65, 66, and empty.
  auto short_hex = digest_from_hex(lower.substr(0, 63), "artifact.digest");
  CHECK_ERROR(short_hex, ErrorCode::SchemaValueOutOfRange);
  CHECK_EQ(short_hex.error().path(), std::string{"artifact.digest"});

  auto long_hex = digest_from_hex(lower + "0", "artifact.digest");
  CHECK_ERROR(long_hex, ErrorCode::SchemaValueOutOfRange);
  CHECK_EQ(long_hex.error().path(), std::string{"artifact.digest"});

  auto prefixed_long = digest_from_hex("0x" + lower, "artifact.digest");
  CHECK_ERROR(prefixed_long, ErrorCode::SchemaValueOutOfRange);

  auto empty_hex = digest_from_hex("", "artifact.digest");
  CHECK_ERROR(empty_hex, ErrorCode::SchemaValueOutOfRange);
  CHECK_EQ(empty_hex.error().path(), std::string{"artifact.digest"});

  CHECK(!is_hex_digest_text(""));
  CHECK(!is_hex_digest_text(lower.substr(0, 63)));
  CHECK(!is_hex_digest_text(lower + "0"));

  // A non-hexadecimal character is reported as an unexpected byte with its
  // zero-based offset.
  std::string bad = lower;
  bad[5] = 'g';
  auto bad_hex = digest_from_hex(bad, "artifact.digest");
  CHECK_ERROR(bad_hex, ErrorCode::EncodingUnexpectedByte);
  CHECK_EQ(bad_hex.error().path(), std::string{"artifact.digest"});
  CHECK(bad_hex.error().message().find("0x67") != std::string::npos);
  CHECK(bad_hex.error().message().find("offset 5") != std::string::npos);
  CHECK(!is_hex_digest_text(bad));

  std::string bad_high = lower;
  bad_high[0] = 'z';
  auto bad_high_hex = digest_from_hex(bad_high, "artifact.digest");
  CHECK_ERROR(bad_high_hex, ErrorCode::EncodingUnexpectedByte);
  CHECK(bad_high_hex.error().message().find("0x7A") != std::string::npos);
  CHECK(bad_high_hex.error().message().find("offset 0") != std::string::npos);

  // A 0x prefix inside a 64-character string is a byte defect, not a length
  // defect.
  std::string prefixed = lower;
  prefixed[1] = 'x';
  auto prefixed_exact = digest_from_hex(prefixed, "artifact.digest");
  CHECK_ERROR(prefixed_exact, ErrorCode::EncodingUnexpectedByte);
  CHECK(prefixed_exact.error().message().find("offset 1") != std::string::npos);

  // Separators and signs are not hexadecimal digits either.
  std::string separated = lower;
  separated[10] = '-';
  auto separated_hex = digest_from_hex(separated, "artifact.digest");
  CHECK_ERROR(separated_hex, ErrorCode::EncodingUnexpectedByte);
  CHECK(separated_hex.error().message().find("offset 10") != std::string::npos);
  CHECK(!is_hex_digest_text(separated));
}

FBM_TEST(crypto_constant_time_equal) {
  CHECK(constant_time_equal("", ""));
  CHECK(constant_time_equal("abc", "abc"));
  CHECK(constant_time_equal(std::string(1024, 'x'), std::string(1024, 'x')));

  // Differing first byte, differing last byte.
  CHECK(!constant_time_equal("abc", "bbc"));
  CHECK(!constant_time_equal("abc", "abd"));

  // Differing lengths, in both directions, including a prefix relationship.
  CHECK(!constant_time_equal("abc", "abcd"));
  CHECK(!constant_time_equal("abcd", "abc"));
  CHECK(!constant_time_equal("", "a"));
  CHECK(!constant_time_equal("a", ""));
  CHECK(!constant_time_equal(std::string(1024, 'x'), std::string(1023, 'x')));

  // A length difference is reported even when the shorter input is a zero-byte
  // prefix of the longer one.
  CHECK(!constant_time_equal(std::string(64, '\0'), std::string(65, '\0')));
}
