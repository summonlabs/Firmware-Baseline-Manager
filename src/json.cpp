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

#include "summon/fbm/json.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "summon/fbm/strong_types.hpp"

namespace summon::fbm::json {
namespace {

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

// Unsigned byte comparison. This is the ordering canonical object members are
// written in, and it deliberately compares through "unsigned char" so the
// result never depends on whether the platform's plain "char" is signed.
bool byte_less(std::string_view left, std::string_view right) noexcept {
  const std::size_t shared = left.size() < right.size() ? left.size() : right.size();
  for (std::size_t index = 0; index < shared; ++index) {
    const unsigned char a = static_cast<unsigned char>(left[index]);
    const unsigned char b = static_cast<unsigned char>(right[index]);
    if (a != b) {
      return a < b;
    }
  }
  return left.size() < right.size();
}

struct ByteLess {
  bool operator()(std::string_view left, std::string_view right) const noexcept {
    return byte_less(left, right);
  }
};

constexpr bool is_json_digit(char c) noexcept { return c >= '0' && c <= '9'; }

constexpr bool is_hex_digit(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

constexpr unsigned hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return static_cast<unsigned>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<unsigned>(c - 'a') + 10u;
  }
  return static_cast<unsigned>(c - 'A') + 10u;
}

std::string hex_byte(unsigned char byte) {
  constexpr char kHexDigits[] = "0123456789ABCDEF";
  std::string out{"0x"};
  out.push_back(kHexDigits[(byte >> 4) & 0x0Fu]);
  out.push_back(kHexDigits[byte & 0x0Fu]);
  return out;
}

// UTF-8 length implied by a code point that has already been validated as
// non-overlong, non-surrogate, and at most U+10FFFF.
constexpr std::size_t utf8_length_of(std::uint32_t code_point) noexcept {
  if (code_point < 0x80u) {
    return 1;
  }
  if (code_point < 0x800u) {
    return 2;
  }
  if (code_point < 0x10000u) {
    return 3;
  }
  return 4;
}

// ---------------------------------------------------------------------------
// Strict recursive-descent reader
// ---------------------------------------------------------------------------
//
// The scanner walks the raw bytes exactly once, left to right, and reports the
// first defect it meets by throwing the Error it built at that position. Every
// Error carries the JSON pointer of the value being read, so identical bytes
// always yield an identical code, message, and path.
class Reader {
 public:
  Reader(std::string_view text, const Limits& limits, std::string_view path_prefix)
      : text_(text), limits_(limits), path_(path_prefix) {}

  Result<Value> run() {
    if (text_.size() > limits_.max_bytes) {
      return Error{ErrorCode::EncodingSizeExceeded,
                   "document of " + std::to_string(text_.size()) + " bytes exceeds max_bytes " +
                       std::to_string(limits_.max_bytes),
                   std::string{path_}};
    }
    try {
      skip_whitespace();
      Value root = parse_value(1);
      skip_whitespace();
      if (position_ != text_.size()) {
        throw Error{ErrorCode::EncodingTrailingContent,
                    "unexpected content after the top-level value at byte " +
                        std::to_string(position_),
                    path_};
      }
      return root;
    } catch (const Error& failure) {
      return failure;
    }
  }

 private:
  // --- byte scanning -------------------------------------------------------

  void skip_whitespace() noexcept {
    while (position_ < text_.size()) {
      const char c = text_[position_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++position_;
      } else {
        return;
      }
    }
  }

  // Validates the UTF-8 sequence starting at "at". On success the code point and
  // its encoded length are stored; on failure "problem" explains the defect.
  bool decode_utf8(std::size_t at, std::uint32_t& code_point, std::string& problem) const {
    const unsigned char lead = static_cast<unsigned char>(text_[at]);
    std::size_t length = 0;
    std::uint32_t value = 0;
    if (lead >= 0xC2u && lead <= 0xDFu) {
      length = 2;
      value = static_cast<std::uint32_t>(lead & 0x1Fu);
    } else if (lead >= 0xE0u && lead <= 0xEFu) {
      length = 3;
      value = static_cast<std::uint32_t>(lead & 0x0Fu);
    } else if (lead >= 0xF0u && lead <= 0xF4u) {
      length = 4;
      value = static_cast<std::uint32_t>(lead & 0x07u);
    } else {
      problem = "invalid UTF-8 lead byte " + hex_byte(lead) + " at byte " + std::to_string(at);
      return false;
    }
    if (at + length > text_.size()) {
      problem = "truncated UTF-8 sequence at byte " + std::to_string(at);
      return false;
    }
    for (std::size_t index = 1; index < length; ++index) {
      const unsigned char continuation = static_cast<unsigned char>(text_[at + index]);
      if (continuation < 0x80u || continuation > 0xBFu) {
        problem = "invalid UTF-8 continuation byte " + hex_byte(continuation) + " at byte " +
                  std::to_string(at + index);
        return false;
      }
      value = (value << 6) | static_cast<std::uint32_t>(continuation & 0x3Fu);
    }
    if (length == 3 && value < 0x800u) {
      problem = "overlong UTF-8 encoding at byte " + std::to_string(at);
      return false;
    }
    if (length == 4 && value < 0x10000u) {
      problem = "overlong UTF-8 encoding at byte " + std::to_string(at);
      return false;
    }
    if (value >= 0xD800u && value <= 0xDFFFu) {
      problem = "UTF-8 encodes a surrogate code point at byte " + std::to_string(at);
      return false;
    }
    if (value > 0x10FFFFu) {
      problem = "UTF-8 code point above U+10FFFF at byte " + std::to_string(at);
      return false;
    }
    code_point = value;
    return true;
  }

  // Describes the byte at the current position. Structural surprises are
  // reported as EncodingUnexpectedByte, but a byte that cannot begin valid UTF-8
  // is reported as EncodingInvalidUtf8 and a byte order mark as
  // EncodingByteOrderMark, because those are the more precise defects.
  Error unexpected_byte(std::string_view context) const {
    const unsigned char byte = static_cast<unsigned char>(text_[position_]);
    if (byte == 0xEFu && position_ + 2 < text_.size() &&
        static_cast<unsigned char>(text_[position_ + 1]) == 0xBBu &&
        static_cast<unsigned char>(text_[position_ + 2]) == 0xBFu) {
      return Error{ErrorCode::EncodingByteOrderMark,
                   "unexpected UTF-8 byte order mark at byte " + std::to_string(position_), path_};
    }
    if (byte >= 0x80u) {
      std::uint32_t discarded = 0;
      std::string problem;
      if (!decode_utf8(position_, discarded, problem)) {
        return Error{ErrorCode::EncodingInvalidUtf8, problem, path_};
      }
    }
    return Error{ErrorCode::EncodingUnexpectedByte,
                 "unexpected byte " + hex_byte(byte) + " " + std::string{context} + " at byte " +
                     std::to_string(position_),
                 path_};
  }

  [[noreturn]] void fail_unexpected_byte(std::string_view context) const {
    throw unexpected_byte(context);
  }

  // --- strings -------------------------------------------------------------

  void append_bytes(std::string& out, std::string_view bytes) const {
    if (bytes.size() > limits_.max_string_bytes ||
        out.size() > limits_.max_string_bytes - bytes.size()) {
      throw Error{ErrorCode::EncodingSizeExceeded,
                  "string exceeds max_string_bytes " + std::to_string(limits_.max_string_bytes),
                  path_};
    }
    out.append(bytes);
  }

  void append_code_point(std::string& out, std::uint32_t code_point) const {
    char encoded[4] = {};
    std::size_t length = 0;
    if (code_point < 0x80u) {
      encoded[length++] = static_cast<char>(code_point);
    } else if (code_point < 0x800u) {
      encoded[length++] = static_cast<char>(0xC0u | (code_point >> 6));
      encoded[length++] = static_cast<char>(0x80u | (code_point & 0x3Fu));
    } else if (code_point < 0x10000u) {
      encoded[length++] = static_cast<char>(0xE0u | (code_point >> 12));
      encoded[length++] = static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu));
      encoded[length++] = static_cast<char>(0x80u | (code_point & 0x3Fu));
    } else {
      encoded[length++] = static_cast<char>(0xF0u | (code_point >> 18));
      encoded[length++] = static_cast<char>(0x80u | ((code_point >> 12) & 0x3Fu));
      encoded[length++] = static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu));
      encoded[length++] = static_cast<char>(0x80u | (code_point & 0x3Fu));
    }
    append_bytes(out, std::string_view{encoded, length});
  }

  std::uint32_t read_hex4() {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "truncated \\u escape at byte " + std::to_string(position_), path_};
      }
      const char digit = text_[position_];
      if (!is_hex_digit(digit)) {
        throw Error{ErrorCode::EncodingInvalidEscape,
                    std::string{"invalid hexadecimal digit '"} + digit + "' in \\u escape at byte " +
                        std::to_string(position_),
                    path_};
      }
      value = (value << 4) | hex_value(digit);
      ++position_;
    }
    return value;
  }

  void parse_escape(std::string& out) {
    ++position_;  // consume the backslash
    if (position_ >= text_.size()) {
      throw Error{ErrorCode::EncodingUnexpectedEnd, "unterminated escape sequence", path_};
    }
    const char marker = text_[position_];
    switch (marker) {
      case '"':
        append_bytes(out, std::string_view{"\""});
        ++position_;
        return;
      case '\\':
        append_bytes(out, std::string_view{"\\"});
        ++position_;
        return;
      case '/':
        append_bytes(out, std::string_view{"/"});
        ++position_;
        return;
      case 'b':
        append_bytes(out, std::string_view{"\b"});
        ++position_;
        return;
      case 'f':
        append_bytes(out, std::string_view{"\f"});
        ++position_;
        return;
      case 'n':
        append_bytes(out, std::string_view{"\n"});
        ++position_;
        return;
      case 'r':
        append_bytes(out, std::string_view{"\r"});
        ++position_;
        return;
      case 't':
        append_bytes(out, std::string_view{"\t"});
        ++position_;
        return;
      case 'u':
        break;
      default:
        throw Error{ErrorCode::EncodingInvalidEscape,
                    std::string{"invalid escape sequence \\"} + marker + " at byte " +
                        std::to_string(position_),
                    path_};
    }
    ++position_;  // consume 'u'
    const std::uint32_t first = read_hex4();
    if (first >= 0xD800u && first <= 0xDBFFu) {
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "unterminated surrogate escape pair at byte " + std::to_string(position_), path_};
      }
      if (text_[position_] != '\\' || position_ + 1 >= text_.size() ||
          text_[position_ + 1] != 'u') {
        throw Error{ErrorCode::EncodingInvalidSurrogate,
                    "high surrogate escape is not followed by a low surrogate escape at byte " +
                        std::to_string(position_),
                    path_};
      }
      position_ += 2;
      const std::uint32_t second = read_hex4();
      if (second < 0xDC00u || second > 0xDFFFu) {
        throw Error{ErrorCode::EncodingInvalidSurrogate,
                    "high surrogate escape is not followed by a low surrogate escape at byte " +
                        std::to_string(position_),
                    path_};
      }
      const std::uint32_t combined =
          0x10000u + ((first - 0xD800u) << 10) + (second - 0xDC00u);
      append_code_point(out, combined);
      return;
    }
    if (first >= 0xDC00u && first <= 0xDFFFu) {
      throw Error{ErrorCode::EncodingInvalidSurrogate,
                  "lone low surrogate escape at byte " + std::to_string(position_), path_};
    }
    append_code_point(out, first);
  }

  // The caller has verified that the current byte is a quote.
  std::string parse_string() {
    ++position_;  // consume the opening quote
    std::string out;
    for (;;) {
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "unterminated string starting at byte " + std::to_string(position_), path_};
      }
      const unsigned char byte = static_cast<unsigned char>(text_[position_]);
      if (byte < 0x20u) {
        throw Error{ErrorCode::EncodingUnescapedControl,
                    "raw control byte " + hex_byte(byte) + " in string at byte " +
                        std::to_string(position_),
                    path_};
      }
      if (byte == '"') {
        ++position_;
        return out;
      }
      if (byte == '\\') {
        parse_escape(out);
        continue;
      }
      if (byte < 0x80u) {
        append_bytes(out, std::string_view{&text_[position_], 1});
        ++position_;
        continue;
      }
      std::uint32_t code_point = 0;
      std::string problem;
      if (!decode_utf8(position_, code_point, problem)) {
        throw Error{ErrorCode::EncodingInvalidUtf8, problem, path_};
      }
      const std::size_t length = utf8_length_of(code_point);
      append_bytes(out, text_.substr(position_, length));
      position_ += length;
    }
  }

  // --- numbers -------------------------------------------------------------

  Value parse_number() {
    const std::size_t start = position_;
    if (text_[position_] == '-') {
      ++position_;
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd, "truncated number at end of input", path_};
      }
      if (!is_json_digit(text_[position_])) {
        fail_unexpected_byte("while expecting a digit after '-'");
      }
    }
    if (text_[position_] == '0') {
      ++position_;
      if (position_ < text_.size() && is_json_digit(text_[position_])) {
        fail_unexpected_byte("after a leading zero");
      }
    } else if (is_json_digit(text_[position_])) {
      while (position_ < text_.size() && is_json_digit(text_[position_])) {
        ++position_;
      }
    } else {
      fail_unexpected_byte("while expecting a digit");
    }
    bool is_real = false;
    if (position_ < text_.size() && text_[position_] == '.') {
      is_real = true;
      ++position_;
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "truncated fraction at end of input", path_};
      }
      if (!is_json_digit(text_[position_])) {
        fail_unexpected_byte("while expecting a fraction digit");
      }
      while (position_ < text_.size() && is_json_digit(text_[position_])) {
        ++position_;
      }
    }
    if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
      is_real = true;
      ++position_;
      if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-')) {
        ++position_;
      }
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "truncated exponent at end of input", path_};
      }
      if (!is_json_digit(text_[position_])) {
        fail_unexpected_byte("while expecting an exponent digit");
      }
      while (position_ < text_.size() && is_json_digit(text_[position_])) {
        ++position_;
      }
    }
    const std::string_view token = text_.substr(start, position_ - start);
    if (!is_real) {
      std::int64_t integer = 0;
      const std::from_chars_result converted =
          std::from_chars(token.data(), token.data() + token.size(), integer);
      if (converted.ec == std::errc{} && converted.ptr == token.data() + token.size()) {
        return Value{integer};
      }
      // The literal does not fit std::int64_t, so it is a real value.
    }
    double real = 0.0;
    const std::from_chars_result converted =
        std::from_chars(token.data(), token.data() + token.size(), real, std::chars_format::general);
    if (converted.ec != std::errc{} || converted.ptr != token.data() + token.size()) {
      throw Error{ErrorCode::EncodingNumberOutOfRange,
                  "number " + std::string{token} + " is not representable as a double", path_};
    }
    return Value{real};
  }

  // --- literals and containers --------------------------------------------

  void parse_literal(std::string_view literal) {
    for (std::size_t index = 0; index < literal.size(); ++index) {
      if (position_ + index >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "truncated literal, expected \"" + std::string{literal} + "\"", path_};
      }
      if (text_[position_ + index] != literal[index]) {
        // Report the mismatching byte itself; the parser unwinds from here, so
        // advancing the cursor has no other effect.
        position_ += index;
        fail_unexpected_byte("while expecting the literal \"" + std::string{literal} + "\"");
      }
    }
    position_ += literal.size();
  }

  Value parse_object(std::size_t depth) {
    ++position_;  // consume '{'
    Value::Object members;
    std::set<std::string, ByteLess> keys;
    skip_whitespace();
    if (position_ < text_.size() && text_[position_] == '}') {
      ++position_;
      return Value{std::move(members)};
    }
    for (;;) {
      skip_whitespace();
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd, "unterminated object", path_};
      }
      if (text_[position_] != '"') {
        fail_unexpected_byte("while expecting a quoted object key");
      }
      if (members.size() >= limits_.max_object_members) {
        throw Error{ErrorCode::EncodingSizeExceeded,
                    "object exceeds max_object_members " +
                        std::to_string(limits_.max_object_members),
                    path_};
      }
      std::string key = parse_string();
      const std::size_t saved = path_.size();
      path_ = join_path(path_, key);
      if (!keys.insert(key).second) {
        throw Error{ErrorCode::EncodingDuplicateKey, "duplicate object key \"" + key + "\"", path_};
      }
      skip_whitespace();
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "unexpected end of input while expecting ':'", path_};
      }
      if (text_[position_] != ':') {
        fail_unexpected_byte("while expecting ':' after an object key");
      }
      ++position_;
      Value value = parse_value(depth + 1);
      path_.resize(saved);
      members.emplace_back(std::move(key), std::move(value));
      skip_whitespace();
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "unexpected end of input while expecting ',' or '}'", path_};
      }
      const char separator = text_[position_];
      if (separator == ',') {
        ++position_;
        continue;
      }
      if (separator == '}') {
        ++position_;
        return Value{std::move(members)};
      }
      fail_unexpected_byte("while expecting ',' or '}' in an object");
    }
  }

  Value parse_array(std::size_t depth) {
    ++position_;  // consume '['
    Value::Array elements;
    skip_whitespace();
    if (position_ < text_.size() && text_[position_] == ']') {
      ++position_;
      return Value{std::move(elements)};
    }
    std::size_t index = 0;
    for (;;) {
      if (elements.size() >= limits_.max_array_elements) {
        throw Error{ErrorCode::EncodingSizeExceeded,
                    "array exceeds max_array_elements " +
                        std::to_string(limits_.max_array_elements),
                    path_};
      }
      const std::size_t saved = path_.size();
      path_ = join_index(path_, index);
      Value element = parse_value(depth + 1);
      path_.resize(saved);
      elements.push_back(std::move(element));
      ++index;
      skip_whitespace();
      if (position_ >= text_.size()) {
        throw Error{ErrorCode::EncodingUnexpectedEnd,
                    "unexpected end of input while expecting ',' or ']'", path_};
      }
      const char separator = text_[position_];
      if (separator == ',') {
        ++position_;
        continue;
      }
      if (separator == ']') {
        ++position_;
        return Value{std::move(elements)};
      }
      fail_unexpected_byte("while expecting ',' or ']' in an array");
    }
  }

  Value parse_value(std::size_t depth) {
    skip_whitespace();
    if (position_ >= text_.size()) {
      throw Error{ErrorCode::EncodingUnexpectedEnd,
                  "unexpected end of input while expecting a value", path_};
    }
    if (depth > limits_.max_depth) {
      throw Error{ErrorCode::EncodingDepthExceeded,
                  "value at depth " + std::to_string(depth) + " exceeds max_depth " +
                      std::to_string(limits_.max_depth),
                  path_};
    }
    if (nodes_ >= limits_.max_nodes) {
      throw Error{ErrorCode::EncodingSizeExceeded,
                  "document exceeds max_nodes " + std::to_string(limits_.max_nodes), path_};
    }
    ++nodes_;
    const char c = text_[position_];
    switch (c) {
      case '{':
        return parse_object(depth);
      case '[':
        return parse_array(depth);
      case '"':
        return Value{parse_string()};
      case 't':
        parse_literal("true");
        return Value{true};
      case 'f':
        parse_literal("false");
        return Value{false};
      case 'n':
        parse_literal("null");
        return Value{nullptr};
      default:
        break;
    }
    if (c == '-' || is_json_digit(c)) {
      return parse_number();
    }
    fail_unexpected_byte("while expecting a value");
  }

  std::string_view text_;
  Limits limits_;
  std::string path_;
  std::size_t position_ = 0;
  std::size_t nodes_ = 0;
};

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

std::vector<const Value::Member*> ordered_members(const Value::Object& members) {
  std::vector<const Value::Member*> ordered;
  ordered.reserve(members.size());
  for (const Value::Member& member : members) {
    ordered.push_back(&member);
  }
  std::stable_sort(ordered.begin(), ordered.end(),
                   [](const Value::Member* left, const Value::Member* right) {
                     return byte_less(left->first, right->first);
                   });
  return ordered;
}

void append_integer(std::string& out, std::int64_t value) {
  char buffer[32] = {};
  const std::to_chars_result converted =
      std::to_chars(buffer, buffer + sizeof(buffer), value);
  if (converted.ec != std::errc{}) {
    precondition_failed("std::to_chars failed for std::int64_t", __FILE__, __LINE__);
  }
  out.append(buffer, static_cast<std::size_t>(converted.ptr - buffer));
}

// Shortest round-trip form. A dot or an exponent marker is always present so
// that the text can never be read back as a JSON integer.
void append_real(std::string& out, double value) {
  if (!std::isfinite(value)) {
    precondition_failed("write_canonical requires a finite real", __FILE__, __LINE__);
  }
  char buffer[64] = {};
  const std::to_chars_result converted = std::to_chars(buffer, buffer + sizeof(buffer), value);
  if (converted.ec != std::errc{}) {
    precondition_failed("std::to_chars failed for double", __FILE__, __LINE__);
  }
  const std::string_view text{buffer, static_cast<std::size_t>(converted.ptr - buffer)};
  out.append(text);
  if (text.find_first_of(".eE") == std::string_view::npos) {
    out += ".0";
  }
}

// Minimal escaping: only quote, backslash, and code points below 0x20 are
// escaped. Everything else, including all non-ASCII, is emitted as raw UTF-8.
void append_escaped(std::string& out, std::string_view text) {
  constexpr char kHexDigits[] = "0123456789ABCDEF";
  out.push_back('"');
  for (const char raw : text) {
    const unsigned char byte = static_cast<unsigned char>(raw);
    switch (byte) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (byte < 0x20u) {
          out += "\\u00";
          out.push_back(kHexDigits[(byte >> 4) & 0x0Fu]);
          out.push_back(kHexDigits[byte & 0x0Fu]);
        } else {
          out.push_back(raw);
        }
        break;
    }
  }
  out.push_back('"');
}

void write_canonical_value(const Value& value, std::string& out) {
  switch (value.type()) {
    case Type::Null:
      out += "null";
      return;
    case Type::Boolean:
      out += value.as_boolean() ? "true" : "false";
      return;
    case Type::Integer:
      append_integer(out, value.as_integer());
      return;
    case Type::Real:
      append_real(out, value.as_real());
      return;
    case Type::String:
      append_escaped(out, value.as_string());
      return;
    case Type::Array: {
      const Value::Array& elements = value.as_array();
      out.push_back('[');
      for (std::size_t index = 0; index < elements.size(); ++index) {
        if (index != 0) {
          out.push_back(',');
        }
        write_canonical_value(elements[index], out);
      }
      out.push_back(']');
      return;
    }
    case Type::Object: {
      const std::vector<const Value::Member*> members = ordered_members(value.as_object());
      out.push_back('{');
      for (std::size_t index = 0; index < members.size(); ++index) {
        if (index != 0) {
          out.push_back(',');
        }
        append_escaped(out, members[index]->first);
        out.push_back(':');
        write_canonical_value(members[index]->second, out);
      }
      out.push_back('}');
      return;
    }
  }
}

void write_pretty_value(const Value& value, std::string& out, unsigned indent_width,
                        std::size_t depth) {
  switch (value.type()) {
    case Type::Array: {
      const Value::Array& elements = value.as_array();
      if (elements.empty()) {
        out += "[]";
        return;
      }
      out += "[\n";
      for (std::size_t index = 0; index < elements.size(); ++index) {
        if (index != 0) {
          out += ",\n";
        }
        out.append(static_cast<std::size_t>(indent_width) * (depth + 1), ' ');
        write_pretty_value(elements[index], out, indent_width, depth + 1);
      }
      out.push_back('\n');
      out.append(static_cast<std::size_t>(indent_width) * depth, ' ');
      out.push_back(']');
      return;
    }
    case Type::Object: {
      const std::vector<const Value::Member*> members = ordered_members(value.as_object());
      if (members.empty()) {
        out += "{}";
        return;
      }
      out += "{\n";
      for (std::size_t index = 0; index < members.size(); ++index) {
        if (index != 0) {
          out += ",\n";
        }
        out.append(static_cast<std::size_t>(indent_width) * (depth + 1), ' ');
        append_escaped(out, members[index]->first);
        out += ": ";
        write_pretty_value(members[index]->second, out, indent_width, depth + 1);
      }
      out.push_back('\n');
      out.append(static_cast<std::size_t>(indent_width) * depth, ' ');
      out.push_back('}');
      return;
    }
    default:
      write_canonical_value(value, out);
      return;
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Type names
// ---------------------------------------------------------------------------

std::string_view type_name(Type type) noexcept {
  switch (type) {
    case Type::Null:
      return "null";
    case Type::Boolean:
      return "boolean";
    case Type::Integer:
      return "integer";
    case Type::Real:
      return "real";
    case Type::String:
      return "string";
    case Type::Array:
      return "array";
    case Type::Object:
      return "object";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------

Type Value::type() const noexcept {
  switch (storage_.index()) {
    case 0:
      return Type::Null;
    case 1:
      return Type::Boolean;
    case 2:
      return Type::Integer;
    case 3:
      return Type::Real;
    case 4:
      return Type::String;
    case 5:
      return Type::Array;
    case 6:
      return Type::Object;
    default:
      break;
  }
  precondition_failed("Value::type() on a disengaged value", __FILE__, __LINE__);
}

bool Value::as_boolean() const {
  FBM_PRECONDITION(is_boolean());
  return std::get<bool>(storage_);
}

std::int64_t Value::as_integer() const {
  FBM_PRECONDITION(is_integer());
  return std::get<std::int64_t>(storage_);
}

double Value::as_real() const {
  FBM_PRECONDITION(is_real());
  return std::get<double>(storage_);
}

const std::string& Value::as_string() const {
  FBM_PRECONDITION(is_string());
  return std::get<std::string>(storage_);
}

const Value::Array& Value::as_array() const {
  FBM_PRECONDITION(is_array());
  return std::get<Array>(storage_);
}

Value::Array& Value::as_array() {
  FBM_PRECONDITION(is_array());
  return std::get<Array>(storage_);
}

const Value::Object& Value::as_object() const {
  FBM_PRECONDITION(is_object());
  return std::get<Object>(storage_);
}

Value::Object& Value::as_object() {
  FBM_PRECONDITION(is_object());
  return std::get<Object>(storage_);
}

const Value* Value::find(std::string_view key) const noexcept {
  if (!is_object()) {
    return nullptr;
  }
  const Object& members = std::get<Object>(storage_);
  for (const Member& member : members) {
    if (std::string_view{member.first} == key) {
      return &member.second;
    }
  }
  return nullptr;
}

void Value::set(std::string key, Value value) {
  FBM_PRECONDITION(is_object());
  Object& members = std::get<Object>(storage_);
  for (Member& member : members) {
    if (member.first == key) {
      member.second = std::move(value);
      return;
    }
  }
  members.emplace_back(std::move(key), std::move(value));
}

bool Value::erase(std::string_view key) {
  if (!is_object()) {
    return false;
  }
  Object& members = std::get<Object>(storage_);
  for (Object::iterator it = members.begin(); it != members.end(); ++it) {
    if (std::string_view{it->first} == key) {
      members.erase(it);
      return true;
    }
  }
  return false;
}

void Value::push_back(Value value) {
  FBM_PRECONDITION(is_array());
  std::get<Array>(storage_).push_back(std::move(value));
}

// Element count for containers, byte length for a string, and zero for the
// scalar types that have no elements.
std::size_t Value::size() const noexcept {
  switch (type()) {
    case Type::String:
      return std::get<std::string>(storage_).size();
    case Type::Array:
      return std::get<Array>(storage_).size();
    case Type::Object:
      return std::get<Object>(storage_).size();
    default:
      return 0;
  }
}

// Structural equality. Types must match exactly, so Integer 1 and Real 1.0 are
// NOT equal even though they denote the same mathematical number: they are
// different JSON types, and canonical form keeps them distinct. Object members
// compare by key, so member order does not affect equality. Member keys are
// unique in every Value produced by the reader (duplicates are rejected) and by
// set(), which replaces instead of appending.
bool operator==(const Value& a, const Value& b) noexcept {
  if (a.type() != b.type()) {
    return false;
  }
  switch (a.type()) {
    case Type::Null:
      return true;
    case Type::Boolean:
      return std::get<bool>(a.storage_) == std::get<bool>(b.storage_);
    case Type::Integer:
      return std::get<std::int64_t>(a.storage_) == std::get<std::int64_t>(b.storage_);
    case Type::Real:
      return std::get<double>(a.storage_) == std::get<double>(b.storage_);
    case Type::String:
      return std::get<std::string>(a.storage_) == std::get<std::string>(b.storage_);
    case Type::Array:
      return std::get<Value::Array>(a.storage_) == std::get<Value::Array>(b.storage_);
    case Type::Object: {
      const Value::Object& left = std::get<Value::Object>(a.storage_);
      const Value::Object& right = std::get<Value::Object>(b.storage_);
      if (left.size() != right.size()) {
        return false;
      }
      for (const Value::Member& member : left) {
        const Value* other = b.find(member.first);
        if (other == nullptr || !(member.second == *other)) {
          return false;
        }
      }
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Reader entry point
// ---------------------------------------------------------------------------

Result<Value> parse(std::string_view text, const Limits& limits, std::string_view path_prefix) {
  Reader reader{text, limits, path_prefix};
  return reader.run();
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

std::string write_canonical(const Value& value) {
  std::string out;
  write_canonical_value(value, out);
  return out;
}

std::string write_pretty(const Value& value, unsigned indent_width) {
  std::string out;
  write_pretty_value(value, out, indent_width, 0);
  return out;
}

// ---------------------------------------------------------------------------
// ObjectReader
// ---------------------------------------------------------------------------

ObjectReader::ObjectReader(const Value& object, std::string path, Diagnostics& diagnostics)
    : object_(object), path_(std::move(path)), diagnostics_(diagnostics) {
  if (!object_.is_object()) {
    // A reader over a non-object is a schema defect, not a programming error:
    // it is diagnosed once here and every accessor then reports absence.
    diagnostics_.add(ErrorCode::SchemaWrongType,
                     "expected object but found " + std::string{type_name(object_.type())}, path_);
  }
}

const Value* ObjectReader::required(std::string_view key, Type expected) {
  if (!object_.is_object()) {
    return nullptr;  // the constructor already recorded the wrong type
  }
  const Value* found = object_.find(key);
  if (found == nullptr) {
    diagnostics_.add(ErrorCode::SchemaMissingField,
                     "required field \"" + std::string{key} + "\" is absent", child_path(key));
    return nullptr;
  }
  requested_.push_back(std::string{key});
  if (found->type() != expected) {
    diagnostics_.add(ErrorCode::SchemaWrongType,
                     "field \"" + std::string{key} + "\" expected " +
                         std::string{type_name(expected)} + " but found " +
                         std::string{type_name(found->type())},
                     child_path(key));
    return nullptr;
  }
  return found;
}

const Value* ObjectReader::optional(std::string_view key, Type expected) {
  if (!object_.is_object()) {
    return nullptr;  // the constructor already recorded the wrong type
  }
  const Value* found = object_.find(key);
  if (found == nullptr) {
    return nullptr;  // absence is silent for an optional field
  }
  requested_.push_back(std::string{key});
  if (found->type() != expected) {
    diagnostics_.add(ErrorCode::SchemaWrongType,
                     "field \"" + std::string{key} + "\" expected " +
                         std::string{type_name(expected)} + " but found " +
                         std::string{type_name(found->type())},
                     child_path(key));
    return nullptr;
  }
  return found;
}

bool ObjectReader::has(std::string_view key) const noexcept { return object_.find(key) != nullptr; }

void ObjectReader::finish() {
  if (!object_.is_object()) {
    return;  // the constructor already recorded the wrong type
  }
  std::vector<std::string_view> unknown;
  for (const Value::Member& member : object_.as_object()) {
    bool requested = false;
    for (const std::string& key : requested_) {
      if (key == member.first) {
        requested = true;
        break;
      }
    }
    if (!requested) {
      unknown.push_back(member.first);
    }
  }
  std::stable_sort(unknown.begin(), unknown.end(), byte_less);
  for (const std::string_view key : unknown) {
    diagnostics_.add(ErrorCode::SchemaUnknownField, "unknown field \"" + std::string{key} + "\"",
                     child_path(key));
  }
}

std::string ObjectReader::child_path(std::string_view key) const { return join_path(path_, key); }

// ---------------------------------------------------------------------------
// JSON pointers
// ---------------------------------------------------------------------------

std::string join_path(std::string_view base, std::string_view key) {
  std::string out{base};
  out.push_back('/');
  for (const char raw : key) {
    switch (raw) {
      case '~':
        out += "~0";
        break;
      case '/':
        out += "~1";
        break;
      default:
        out.push_back(raw);
        break;
    }
  }
  return out;
}

std::string join_index(std::string_view base, std::size_t index) {
  std::string out{base};
  out.push_back('/');
  char buffer[24] = {};
  const std::to_chars_result converted = std::to_chars(buffer, buffer + sizeof(buffer), index);
  if (converted.ec != std::errc{}) {
    precondition_failed("std::to_chars failed for std::size_t", __FILE__, __LINE__);
  }
  out.append(buffer, static_cast<std::size_t>(converted.ptr - buffer));
  return out;
}

}  // namespace summon::fbm::json
