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

#include "summon/fbm/identifier.hpp"

#include <cstddef>
#include <string>
#include <string_view>

#include "summon/fbm/error.hpp"
#include "summon/fbm/result.hpp"

namespace summon::fbm {
namespace {

constexpr bool is_ascii_alphanumeric(unsigned char byte) noexcept {
  return (byte >= static_cast<unsigned char>('0') && byte <= static_cast<unsigned char>('9')) ||
         (byte >= static_cast<unsigned char>('A') && byte <= static_cast<unsigned char>('Z')) ||
         (byte >= static_cast<unsigned char>('a') && byte <= static_cast<unsigned char>('z'));
}

constexpr bool is_continuation_byte(unsigned char byte) noexcept {
  return is_ascii_alphanumeric(byte) || byte == static_cast<unsigned char>('.') ||
         byte == static_cast<unsigned char>('_') || byte == static_cast<unsigned char>('-');
}

// Renders one byte as 0xNN with upper-case digits, matching the hexadecimal
// notation used throughout the durable format documentation.
std::string hex_byte(unsigned char byte) {
  constexpr char kDigits[] = "0123456789ABCDEF";
  std::string out{"0x"};
  out += kDigits[(byte >> 4) & 0x0Fu];
  out += kDigits[byte & 0x0Fu];
  return out;
}

}  // namespace

bool is_valid_identifier(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxIdentifierBytes) {
    return false;
  }
  if (!is_ascii_alphanumeric(static_cast<unsigned char>(text[0]))) {
    return false;
  }
  for (std::size_t i = 1; i < text.size(); ++i) {
    if (!is_continuation_byte(static_cast<unsigned char>(text[i]))) {
      return false;
    }
  }
  return true;
}

Status validate_identifier(std::string_view text, std::string_view path) {
  const std::string error_path{path};
  if (text.empty()) {
    return Error{ErrorCode::SchemaInvalidIdentifier,
                 "identifier is empty; expected 1 to " + std::to_string(kMaxIdentifierBytes) +
                     " bytes",
                 error_path};
  }
  if (text.size() > kMaxIdentifierBytes) {
    return Error{ErrorCode::SchemaInvalidIdentifier,
                 "identifier is " + std::to_string(text.size()) + " bytes; expected 1 to " +
                     std::to_string(kMaxIdentifierBytes) + " bytes",
                 error_path};
  }
  for (std::size_t i = 0; i < text.size(); ++i) {
    const unsigned char byte = static_cast<unsigned char>(text[i]);
    if (i == 0) {
      if (!is_ascii_alphanumeric(byte)) {
        return Error{ErrorCode::SchemaInvalidIdentifier,
                     "identifier begins with byte " + hex_byte(byte) +
                         " at offset 0, which is not in [A-Za-z0-9]",
                     error_path};
      }
    } else if (!is_continuation_byte(byte)) {
      return Error{ErrorCode::SchemaInvalidIdentifier,
                   "identifier byte " + hex_byte(byte) + " at offset " + std::to_string(i) +
                       " is not in [A-Za-z0-9._-]",
                   error_path};
    }
  }
  return ok_status();
}

}  // namespace summon::fbm
