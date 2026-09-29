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
#include "summon/fbm/firmware_version.hpp"

#include <compare>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "summon/fbm/error.hpp"
#include "summon/fbm/strong_types.hpp"

namespace summon::fbm {
namespace {

constexpr std::uint64_t kMaxComponent = std::numeric_limits<std::uint32_t>::max();

// The flattened (major, minor, patch, build) lattice used by version_distance
// uses radix 2^32: one step of the fourth component is one unit, one step of the
// third component is 2^32 units, and so on. The fourth component has one extra
// slot below zero for the absent build component, which is why the slot value is
// build + 1 for a present build and 0 for an absent one: absent orders before
// 0.0.0.0, exactly as the documented ordering extension requires.
constexpr std::int64_t kLatticeRadix = 4294967296;  // 2^32

bool is_ascii_digit(char c) noexcept { return c >= '0' && c <= '9'; }

bool is_ascii_alpha(char c) noexcept { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

bool is_identifier_char(char c) noexcept { return is_ascii_digit(c) || is_ascii_alpha(c) || c == '-'; }

bool is_ascii_whitespace(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

bool is_all_digits(std::string_view text) noexcept {
  if (text.empty()) {
    return false;
  }
  for (const char c : text) {
    if (!is_ascii_digit(c)) {
      return false;
    }
  }
  return true;
}

// Renders one byte for a diagnostic. Printable ASCII is quoted; every other
// byte, including every non-ASCII byte, is shown as an uppercase hex value, so
// the message is stable and locale independent.
std::string describe_byte(char c) {
  const unsigned char value = static_cast<unsigned char>(c);
  if (value >= 0x20u && value < 0x7Fu) {
    return std::string{"'"} + c + "'";
  }
  constexpr char kHexDigits[] = "0123456789ABCDEF";
  std::string out = "0x";
  out += kHexDigits[(value >> 4u) & 0x0Fu];
  out += kHexDigits[value & 0x0Fu];
  return out;
}

// Echoes at most sixteen bytes of a fragment so that diagnostics stay bounded
// even for a pathologically long input.
std::string quote_fragment(std::string_view text) {
  constexpr std::size_t kLimit = 16u;
  if (text.size() <= kLimit) {
    return "\"" + std::string{text} + "\"";
  }
  return "\"" + std::string{text.substr(0u, kLimit)} + "...\"";
}

Error invalid_version(std::string message, std::string_view path) {
  return Error{ErrorCode::SchemaInvalidVersionText, std::move(message), std::string{path}};
}

void append_uint(std::string& out, std::uint32_t value) {
  char digits[10] = {};
  std::size_t count = 0;
  do {
    digits[count] = static_cast<char>('0' + static_cast<int>(value % 10u));
    ++count;
    value /= 10u;
  } while (value != 0u);
  for (std::size_t i = count; i > 0u; --i) {
    out += digits[i - 1u];
  }
}

// A cursor over the version grammar. Defects are reported left to right, so the
// first component that cannot be interpreted exactly decides the message: the
// same text always yields the same code, message and path.
class VersionCursor {
 public:
  VersionCursor(std::string_view text, std::string_view path) noexcept : text_(text), path_(path) {}

  bool at_end() const noexcept { return index_ >= text_.size(); }
  std::size_t index() const noexcept { return index_; }
  char peek() const noexcept { return text_[index_]; }
  void advance() noexcept { ++index_; }

  Error error() const { return invalid_version(message_, path_); }

  // Reads one numeric component: one or more decimal digits with no leading
  // zero and a value that fits std::uint32_t.
  bool read_component(const char* what, std::uint32_t& out) {
    if (at_end()) {
      return fail(std::string{"version "} + what + " component is missing: the text ends at offset " +
                  std::to_string(index_));
    }
    const std::size_t start = index_;
    while (!at_end() && is_ascii_digit(peek())) {
      advance();
    }
    if (index_ == start) {
      return fail(std::string{"version "} + what + " component must be a non-empty decimal digit string; found " +
                  describe_byte(peek()) + " at offset " + std::to_string(start));
    }
    const std::string_view digits = text_.substr(start, index_ - start);
    if (digits.size() > 1u && digits.front() == '0') {
      return fail(std::string{"version "} + what + " component " + quote_fragment(digits) +
                  " has a leading zero");
    }
    if (digits.size() > 10u) {
      return fail(std::string{"version "} + what + " component " + quote_fragment(digits) +
                  " does not fit in a 32-bit unsigned integer");
    }
    std::uint64_t value = 0;
    for (const char c : digits) {
      value = value * 10u + static_cast<std::uint64_t>(c - '0');
    }
    if (value > kMaxComponent) {
      return fail(std::string{"version "} + what + " component " + quote_fragment(digits) +
                  " does not fit in a 32-bit unsigned integer (maximum 4294967295)");
    }
    out = static_cast<std::uint32_t>(value);
    return true;
  }

  bool read_literal(char expected, const char* requirement) {
    if (at_end()) {
      return fail(std::string{"version is truncated: it requires "} + requirement +
                  " but the text ends at offset " + std::to_string(index_));
    }
    if (text_[index_] != expected) {
      return fail(std::string{"version requires "} + requirement + "; found " +
                  describe_byte(text_[index_]) + " at offset " + std::to_string(index_));
    }
    ++index_;
    return true;
  }

  // Reads a dot-separated identifier list after a '-' or '+' marker. The marker
  // itself has already been consumed by the caller.
  bool read_identifier_list(char marker, const char* what, bool reject_numeric_leading_zero,
                            std::string& out) {
    if (at_end() || peek() == '.' || peek() == '+') {
      return fail(std::string{"version "} + what + " is empty: no identifier follows '" + marker + "'");
    }
    while (true) {
      const std::size_t identifier_start = index_;
      while (!at_end() && is_identifier_char(peek())) {
        advance();
      }
      const std::string_view identifier = text_.substr(identifier_start, index_ - identifier_start);
      if (identifier.empty()) {
        return fail(std::string{"version "} + what + " contains an empty identifier at offset " +
                    std::to_string(identifier_start));
      }
      if (reject_numeric_leading_zero && is_all_digits(identifier) && identifier.size() > 1u &&
          identifier.front() == '0') {
        return fail(std::string{"version "} + what + " identifier " + quote_fragment(identifier) +
                    " is numeric and has a leading zero");
      }
      out.append(identifier);
      if (!at_end() && peek() == '.') {
        advance();
        out += '.';
        continue;
      }
      return true;
    }
  }

 private:
  bool fail(std::string message) {
    if (message_.empty()) {
      message_ = std::move(message);
    }
    return false;
  }

  std::string_view text_;
  std::string_view path_;
  std::size_t index_ = 0;
  std::string message_;
};

int compare_numeric_identifiers(std::string_view left, std::string_view right) {
  // Neither identifier has a leading zero, so the longer digit string is the
  // larger number and equal lengths compare lexicographically.
  if (left.size() != right.size()) {
    return left.size() < right.size() ? -1 : 1;
  }
  if (left == right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

int compare_ascii(std::string_view left, std::string_view right) {
  const std::size_t common = left.size() < right.size() ? left.size() : right.size();
  for (std::size_t i = 0; i < common; ++i) {
    const unsigned char a = static_cast<unsigned char>(left[i]);
    const unsigned char b = static_cast<unsigned char>(right[i]);
    if (a != b) {
      return a < b ? -1 : 1;
    }
  }
  if (left.size() == right.size()) {
    return 0;
  }
  return left.size() < right.size() ? -1 : 1;
}

std::string_view next_identifier(std::string_view text, std::size_t& index) {
  const std::size_t start = index;
  while (index < text.size() && text[index] != '.') {
    ++index;
  }
  const std::string_view identifier = text.substr(start, index - start);
  if (index < text.size()) {
    ++index;  // consume the '.'
  }
  return identifier;
}

// Semantic Versioning 2.0 prerelease precedence. A version without a prerelease
// outranks the same version with one; identifiers are compared left to right; a
// numeric identifier compares numerically and ranks below an alphanumeric one;
// and a longer identifier list wins when every preceding identifier is equal.
int compare_prerelease(std::string_view left, std::string_view right) {
  if (left.empty() || right.empty()) {
    if (left.empty() && right.empty()) {
      return 0;
    }
    return left.empty() ? 1 : -1;
  }
  std::size_t left_index = 0;
  std::size_t right_index = 0;
  while (left_index < left.size() && right_index < right.size()) {
    const std::string_view left_identifier = next_identifier(left, left_index);
    const std::string_view right_identifier = next_identifier(right, right_index);
    const bool left_numeric = is_all_digits(left_identifier);
    const bool right_numeric = is_all_digits(right_identifier);
    if (left_numeric && right_numeric) {
      const int order = compare_numeric_identifiers(left_identifier, right_identifier);
      if (order != 0) {
        return order;
      }
    } else if (left_numeric != right_numeric) {
      return left_numeric ? -1 : 1;
    } else {
      const int order = compare_ascii(left_identifier, right_identifier);
      if (order != 0) {
        return order;
      }
    }
  }
  if (left_index >= left.size() && right_index >= right.size()) {
    return 0;
  }
  return left_index >= left.size() ? -1 : 1;
}

std::int64_t saturating_add(std::int64_t left, std::int64_t right) noexcept {
  constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
  constexpr std::int64_t kMin = std::numeric_limits<std::int64_t>::min();
  if (right > 0 && left > kMax - right) {
    return kMax;
  }
  if (right < 0 && left < kMin - right) {
    return kMin;
  }
  return left + right;
}

// Multiplies by the lattice radix, saturating instead of overflowing. Saturation
// is monotone and preserves the sign, so a saturated intermediate can only lead
// to a saturated final value in the same direction.
std::int64_t saturating_scale(std::int64_t value) noexcept {
  constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
  constexpr std::int64_t kMin = std::numeric_limits<std::int64_t>::min();
  if (value > kMax / kLatticeRadix) {
    return kMax;
  }
  if (value < kMin / kLatticeRadix) {
    return kMin;
  }
  return value * kLatticeRadix;
}

std::int64_t component_difference(std::uint32_t left, std::uint32_t right) noexcept {
  return static_cast<std::int64_t>(left) - static_cast<std::int64_t>(right);
}

// The fourth component as a lattice digit: an absent build occupies its own slot
// immediately below '.0'.
std::int64_t build_slot(const FirmwareVersion& version) noexcept {
  return version.has_build() ? static_cast<std::int64_t>(version.build()) + 1 : 0;
}

}  // namespace

Result<FirmwareVersion> FirmwareVersion::parse(std::string_view text, std::string_view path) {
  if (text.empty()) {
    return invalid_version("version text is empty; expected major.minor.patch", path);
  }
  for (std::size_t i = 0; i < text.size(); ++i) {
    const unsigned char byte = static_cast<unsigned char>(text[i]);
    if (byte >= 0x80u) {
      return invalid_version("version text contains non-ASCII byte " + describe_byte(text[i]) +
                                 " at offset " + std::to_string(i) + "; only ASCII is accepted",
                             path);
    }
    if (is_ascii_whitespace(text[i])) {
      return invalid_version("version text contains whitespace " + describe_byte(text[i]) +
                                 " at offset " + std::to_string(i) + "; whitespace is not accepted",
                             path);
    }
  }

  VersionCursor cursor{text, path};
  FirmwareVersion version;
  if (!cursor.read_component("major", version.major_)) {
    return cursor.error();
  }
  if (!cursor.read_literal('.', "'.' between the major and minor components")) {
    return cursor.error();
  }
  if (!cursor.read_component("minor", version.minor_)) {
    return cursor.error();
  }
  if (!cursor.read_literal('.', "'.' between the minor and patch components")) {
    return cursor.error();
  }
  if (!cursor.read_component("patch", version.patch_)) {
    return cursor.error();
  }

  if (!cursor.at_end() && cursor.peek() == '.') {
    cursor.advance();
    if (cursor.at_end()) {
      return invalid_version("version has a trailing '.' with no build component", path);
    }
    std::uint32_t build = 0;
    if (!cursor.read_component("build", build)) {
      return cursor.error();
    }
    version.build_ = build;
  }

  if (!cursor.at_end() && cursor.peek() == '-') {
    cursor.advance();
    if (!cursor.read_identifier_list('-', "prerelease", true, version.prerelease_)) {
      return cursor.error();
    }
  }
  if (!cursor.at_end() && cursor.peek() == '+') {
    cursor.advance();
    if (!cursor.read_identifier_list('+', "metadata", false, version.metadata_)) {
      return cursor.error();
    }
  }
  if (!cursor.at_end()) {
    if (cursor.peek() == '.') {
      return invalid_version("version has more than four numeric components; found '.' at offset " +
                                 std::to_string(cursor.index()),
                             path);
    }
    return invalid_version("version has an unexpected byte " + describe_byte(cursor.peek()) +
                               " at offset " + std::to_string(cursor.index()),
                           path);
  }

  version.raw_ = std::string{text};
  return version;
}

std::uint32_t FirmwareVersion::build() const noexcept {
  FBM_PRECONDITION(build_.has_value());
  return *build_;
}

std::string FirmwareVersion::to_string() const {
  std::string out;
  append_uint(out, major_);
  out += '.';
  append_uint(out, minor_);
  out += '.';
  append_uint(out, patch_);
  if (build_.has_value()) {
    out += '.';
    append_uint(out, *build_);
  }
  if (!prerelease_.empty()) {
    out += '-';
    out += prerelease_;
  }
  if (!metadata_.empty()) {
    out += '+';
    out += metadata_;
  }
  return out;
}

// Precedence comparison, and the comparison every range operation uses. Note
// that the header declares operator== as defaulted, so it compares every member
// including metadata_ and raw_ and is therefore the exact-text comparison, not
// the precedence comparison; raw() and metadata() are available for exact text
// comparison, and (a <=> b) == 0 states precedence equivalence. Metadata never
// affects precedence, so two versions that differ only in metadata are
// equivalent under this order while remaining distinguishable by ==.
std::strong_ordering operator<=>(const FirmwareVersion& left, const FirmwareVersion& right) {
  if (const std::strong_ordering order = left.major_ <=> right.major_; order != 0) {
    return order;
  }
  if (const std::strong_ordering order = left.minor_ <=> right.minor_; order != 0) {
    return order;
  }
  if (const std::strong_ordering order = left.patch_ <=> right.patch_; order != 0) {
    return order;
  }
  // Documented extension: an absent fourth component is unset and orders before
  // every present fourth component, including '.0'. It is never read as zero.
  if (left.build_.has_value() != right.build_.has_value()) {
    return left.build_.has_value() ? std::strong_ordering::greater : std::strong_ordering::less;
  }
  if (left.build_.has_value()) {
    if (const std::strong_ordering order = *left.build_ <=> *right.build_; order != 0) {
      return order;
    }
  }
  const int prerelease_order = compare_prerelease(left.prerelease_, right.prerelease_);
  if (prerelease_order < 0) {
    return std::strong_ordering::less;
  }
  if (prerelease_order > 0) {
    return std::strong_ordering::greater;
  }
  return std::strong_ordering::equal;
}

Result<VersionRange> VersionRange::make(std::optional<FirmwareVersion> minimum, bool minimum_inclusive,
                                        std::optional<FirmwareVersion> maximum, bool maximum_inclusive,
                                        std::string_view path) {
  VersionRange range;
  range.minimum_ = std::move(minimum);
  range.maximum_ = std::move(maximum);
  range.minimum_inclusive_ = minimum_inclusive;
  range.maximum_inclusive_ = maximum_inclusive;
  if (range.is_empty()) {
    std::string message = "version range " + range.to_string() + " is empty: ";
    if (*range.minimum_ > *range.maximum_) {
      message += "the minimum is greater than the maximum";
    } else {
      message += "the minimum equals the maximum and at least one bound is exclusive";
    }
    return Error{ErrorCode::SchemaInconsistentDocument, std::move(message), std::string{path}};
  }
  return range;
}

bool VersionRange::contains(const FirmwareVersion& version) const {
  if (minimum_.has_value()) {
    const std::strong_ordering order = version <=> *minimum_;
    if (order == std::strong_ordering::less) {
      return false;
    }
    if (order == std::strong_ordering::equal && !minimum_inclusive_) {
      return false;
    }
  }
  if (maximum_.has_value()) {
    const std::strong_ordering order = version <=> *maximum_;
    if (order == std::strong_ordering::greater) {
      return false;
    }
    if (order == std::strong_ordering::equal && !maximum_inclusive_) {
      return false;
    }
  }
  return true;
}

bool VersionRange::is_empty() const {
  if (!minimum_.has_value() || !maximum_.has_value()) {
    return false;  // an unbounded side always admits members
  }
  const std::strong_ordering order = *minimum_ <=> *maximum_;
  if (order == std::strong_ordering::greater) {
    return true;
  }
  if (order == std::strong_ordering::less) {
    return false;
  }
  return !minimum_inclusive_ || !maximum_inclusive_;
}

std::string VersionRange::to_string() const {
  std::string out;
  out += (minimum_.has_value() && minimum_inclusive_) ? '[' : '(';
  out += minimum_.has_value() ? minimum_->to_string() : std::string{"-inf"};
  out += ", ";
  out += maximum_.has_value() ? maximum_->to_string() : std::string{"+inf"};
  out += (maximum_.has_value() && maximum_inclusive_) ? ']' : ')';
  return out;
}

// Precedence equivalence, the relation the range and conformance logic uses.
// FirmwareVersion::operator== remains the exact-text comparison declared in the
// header, so a build-metadata-only difference is not equal but does share
// precedence.
bool same_precedence(const FirmwareVersion& a, const FirmwareVersion& b) noexcept {
  return (a <=> b) == 0;
}

std::int64_t version_distance(const FirmwareVersion& lower, const FirmwareVersion& higher) {
  // Horner evaluation of the flattened index difference
  //   ((major * R + minor) * R + patch) * R + build_slot
  // computed in std::int64_t and saturated rather than wrapped. A saturated
  // intermediate keeps its sign, so the final value is saturated in the same
  // direction as the exact difference.
  std::int64_t distance = component_difference(lower.major(), higher.major());
  distance = saturating_add(saturating_scale(distance), component_difference(lower.minor(), higher.minor()));
  distance = saturating_add(saturating_scale(distance), component_difference(lower.patch(), higher.patch()));
  distance = saturating_add(saturating_scale(distance), build_slot(lower) - build_slot(higher));
  if (distance == 0) {
    const bool same_numeric_point = lower.major() == higher.major() && lower.minor() == higher.minor() &&
                                    lower.patch() == higher.patch() &&
                                    build_slot(lower) == build_slot(higher);
    if (!same_numeric_point) {
      // The only inexact point of the flattened index: a present build of
      // 4294967295 (slot 2^32) and the absent slot of the next patch release
      // share an index. The two versions still differ in precedence, so the
      // distance is reported as the adjacent step in the direction of the
      // order, which keeps the sign exact. A difference that lives only in the
      // prerelease identifiers is not a lattice difference at all and stays 0.
      return (lower <=> higher) == std::strong_ordering::less ? -1 : 1;
    }
  }
  return distance;
}

}  // namespace summon::fbm
