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
#include "summon/fbm/timestamp.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "summon/fbm/error.hpp"
#include "summon/fbm/strong_types.hpp"

namespace summon::fbm {
namespace {

// ---------------------------------------------------------------------------
// Storage convention
//
// Timestamp holds a 64-bit two's-complement pattern interpreted as a signed
// nanosecond offset from the Unix epoch. RFC 3339 text is not restricted to the
// post-epoch era and a rendering such as 1900-03-01T00:00:00.000000000Z has to
// round trip exactly, so the parser, the renderer and delta_nanos() all read and
// write that signed offset. unix_nanos() exposes the raw pattern, which means an
// instant before 1970 appears there as a value greater than or equal to 2^63.
// An instant that cannot be represented exactly is rejected with a diagnostic
// instead of being wrapped.
//
// The representable range is therefore
//   1677-09-21T00:12:43.145224192Z .. 2262-04-11T23:47:16.854775807Z.
// ---------------------------------------------------------------------------

constexpr std::int64_t kNanosPerSecond = 1'000'000'000;
constexpr std::int64_t kSecondsPerDay = 86'400;
constexpr std::int64_t kNanosPerDay = kNanosPerSecond * kSecondsPerDay;

// Proleptic Gregorian conversion: Howard Hinnant's days_from_civil and
// civil_from_days (public domain), used verbatim apart from naming and the
// explicit unsigned arithmetic that keeps the conversion warning free.
//
// days_from_civil: number of days from 1970-01-01 to y-m-d.
constexpr std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) noexcept {
  y -= (m <= 2u) ? 1 : 0;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);  // [0, 399]
  const unsigned mp = (m > 2u) ? (m - 3u) : (m + 9u);         // [0, 11]
  const unsigned doy = (153u * mp + 2u) / 5u + d - 1u;        // [0, 365]
  const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;  // [0, 146096]
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

// civil_from_days: the exact inverse of days_from_civil.
constexpr void civil_from_days(std::int64_t z, std::int64_t& y, unsigned& m, unsigned& d) noexcept {
  z += 719468;
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);  // [0, 146096]
  const unsigned yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;  // [0, 399]
  const std::int64_t yy = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);  // [0, 365]
  const unsigned mp = (5u * doy + 2u) / 153u;                       // [0, 11]
  const unsigned dd = doy - (153u * mp + 2u) / 5u + 1u;             // [1, 31]
  const unsigned mm = mp + ((mp < 10u) ? 3u : static_cast<unsigned>(-9));  // [1, 12]
  y = yy + ((mm <= 2u) ? 1 : 0);
  m = mm;
  d = dd;
}

constexpr bool is_leap_year(std::int64_t year) noexcept {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

// Number of days in a month of a proleptic Gregorian year. The month itself is
// already range checked by the caller.
constexpr unsigned days_in_month(std::int64_t year, unsigned month) noexcept {
  switch (month) {
    case 2u:
      return is_leap_year(year) ? 29u : 28u;
    case 4u:
    case 6u:
    case 9u:
    case 11u:
      return 30u;
    default:
      return 31u;
  }
}

bool is_ascii_digit(char c) noexcept { return c >= '0' && c <= '9'; }

bool is_ascii_whitespace(char c) noexcept {
  return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
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

Error invalid_timestamp(std::string message, std::string_view path) {
  return Error{ErrorCode::SchemaInvalidTimestampText, std::move(message), std::string{path}};
}

// Converts (days since the epoch, nanoseconds within the day) into the signed
// nanosecond offset and reports whether that offset is representable. The
// modular 64-bit product is verified by recovering the pair from the candidate,
// so a value outside the signed range is reported instead of wrapped.
bool to_signed_nanos(std::int64_t days, std::int64_t nanos_of_day, std::int64_t& out) noexcept {
  const std::uint64_t wrapped =
      static_cast<std::uint64_t>(days) * static_cast<std::uint64_t>(kNanosPerDay) +
      static_cast<std::uint64_t>(nanos_of_day);
  const std::int64_t candidate = static_cast<std::int64_t>(wrapped);
  std::int64_t check_days = candidate / kNanosPerDay;
  std::int64_t check_nanos = candidate % kNanosPerDay;
  if (check_nanos < 0) {
    check_nanos += kNanosPerDay;
    check_days -= 1;
  }
  if (check_days != days || check_nanos != nanos_of_day) {
    return false;
  }
  out = candidate;
  return true;
}

// A cursor over strict RFC 3339 text. Defects are reported left to right, so the
// first field that cannot be interpreted exactly decides the message: the same
// text always yields the same code, message and path.
class TimestampCursor {
 public:
  TimestampCursor(std::string_view text, std::string_view path) noexcept : text_(text), path_(path) {}

  bool at_end() const noexcept { return index_ >= text_.size(); }
  std::size_t index() const noexcept { return index_; }
  char peek() const noexcept { return text_[index_]; }
  void advance() noexcept { ++index_; }

  Error error() const { return invalid_timestamp(message_, path_); }

  // Reads exactly the given number of decimal digits.
  bool read_digits(std::size_t width, const char* what, unsigned& out) {
    const std::size_t available = text_.size() - index_;
    if (available < width) {
      return fail(std::string{"timestamp "} + what + " is truncated: expected " + std::to_string(width) +
                  " decimal digits but only " + std::to_string(available) + " byte(s) remain (at offset " +
                  std::to_string(index_) + ")");
    }
    unsigned value = 0;
    for (std::size_t i = 0; i < width; ++i) {
      const char c = text_[index_ + i];
      if (!is_ascii_digit(c)) {
        return fail(std::string{"timestamp "} + what + " must be exactly " + std::to_string(width) +
                    " decimal digits; found " + describe_byte(c) + " at offset " +
                    std::to_string(index_ + i));
      }
      value = value * 10u + static_cast<unsigned>(c - '0');
    }
    index_ += width;
    out = value;
    return true;
  }

  // Requires the literal byte expected; requirement names what that byte is for,
  // for example "'-' between the year and the month".
  bool read_literal(char expected, const char* requirement) {
    if (at_end()) {
      return fail(std::string{"timestamp is truncated: it requires "} + requirement +
                  " but the text ends at offset " + std::to_string(index_));
    }
    if (text_[index_] != expected) {
      return fail(std::string{"timestamp requires "} + requirement + "; found " +
                  describe_byte(text_[index_]) + " at offset " + std::to_string(index_));
    }
    ++index_;
    return true;
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

void append_padded(std::string& out, std::int64_t value, std::size_t width) {
  const std::string digits = std::to_string(value);
  for (std::size_t i = digits.size(); i < width; ++i) {
    out += '0';
  }
  out += digits;
}

}  // namespace

Timestamp Timestamp::system_now() {
  const std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  const std::chrono::nanoseconds since_epoch =
      std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
  return Timestamp::from_unix_nanos(static_cast<nanos_type>(since_epoch.count()));
}

Result<Timestamp> Timestamp::parse_rfc3339(std::string_view text, std::string_view path) {
  if (text.empty()) {
    return invalid_timestamp("timestamp text is empty; expected YYYY-MM-DDTHH:MM:SS[.fffffffff]Z", path);
  }
  if (text.front() == '+' || text.front() == '-') {
    return invalid_timestamp("timestamp must not begin with " + describe_byte(text.front()) +
                                 "; a signed year is not accepted (the year is four unsigned decimal digits)",
                             path);
  }
  for (std::size_t i = 0; i < text.size(); ++i) {
    const unsigned char byte = static_cast<unsigned char>(text[i]);
    if (byte >= 0x80u) {
      return invalid_timestamp("timestamp text contains non-ASCII byte " + describe_byte(text[i]) +
                                   " at offset " + std::to_string(i) + "; only ASCII is accepted",
                               path);
    }
    if (is_ascii_whitespace(text[i])) {
      return invalid_timestamp("timestamp text contains whitespace " + describe_byte(text[i]) +
                                   " at offset " + std::to_string(i) + "; whitespace is not accepted",
                               path);
    }
  }

  TimestampCursor cursor{text, path};
  unsigned year = 0;
  unsigned month = 0;
  unsigned day = 0;
  unsigned hour = 0;
  unsigned minute = 0;
  unsigned second = 0;
  unsigned nanos = 0;

  if (!cursor.read_digits(4u, "year", year)) {
    return cursor.error();
  }
  if (year < 1u) {
    return invalid_timestamp("timestamp year 0000 is out of range 1..9999", path);
  }
  if (!cursor.read_literal('-', "'-' between the year and the month")) {
    return cursor.error();
  }
  if (!cursor.read_digits(2u, "month", month)) {
    return cursor.error();
  }
  if (month < 1u || month > 12u) {
    return invalid_timestamp("timestamp month " + std::to_string(month) + " is out of range 1..12", path);
  }
  if (!cursor.read_literal('-', "'-' between the month and the day")) {
    return cursor.error();
  }
  if (!cursor.read_digits(2u, "day", day)) {
    return cursor.error();
  }
  if (day < 1u) {
    return invalid_timestamp("timestamp day 0 is out of range 1..31", path);
  }
  if (day > days_in_month(static_cast<std::int64_t>(year), month)) {
    if (month == 2u) {
      return invalid_timestamp("timestamp day " + std::to_string(day) + " is out of range for February " +
                                   std::to_string(year) + ": " + std::to_string(year) +
                                   " is not a leap year",
                               path);
    }
    return invalid_timestamp("timestamp day " + std::to_string(day) + " is out of range for month " +
                                 std::to_string(month) + ": that month has " +
                                 std::to_string(days_in_month(static_cast<std::int64_t>(year), month)) +
                                 " days",
                             path);
  }
  if (!cursor.read_literal('T', "uppercase 'T' between the date and the time")) {
    return cursor.error();
  }
  if (!cursor.read_digits(2u, "hour", hour)) {
    return cursor.error();
  }
  if (hour > 23u) {
    return invalid_timestamp("timestamp hour " + std::to_string(hour) + " is out of range 0..23", path);
  }
  if (!cursor.read_literal(':', "':' between the hour and the minute")) {
    return cursor.error();
  }
  if (!cursor.read_digits(2u, "minute", minute)) {
    return cursor.error();
  }
  if (minute > 59u) {
    return invalid_timestamp("timestamp minute " + std::to_string(minute) + " is out of range 0..59", path);
  }
  if (!cursor.read_literal(':', "':' (the seconds field is mandatory) after the minute")) {
    return cursor.error();
  }
  if (!cursor.read_digits(2u, "second", second)) {
    return cursor.error();
  }
  if (second > 59u) {
    return invalid_timestamp("timestamp second " + std::to_string(second) +
                                 " is out of range 0..59 (a leap second is not accepted)",
                             path);
  }

  if (!cursor.at_end() && cursor.peek() == '.') {
    cursor.advance();
    unsigned fraction = 0;
    std::size_t digits = 0;
    while (!cursor.at_end() && is_ascii_digit(cursor.peek())) {
      if (digits < 9u) {
        fraction = fraction * 10u + static_cast<unsigned>(cursor.peek() - '0');
      }
      ++digits;
      cursor.advance();
    }
    if (digits == 0u) {
      return invalid_timestamp("timestamp fraction must have at least one digit after '.'", path);
    }
    if (digits > 9u) {
      return invalid_timestamp("timestamp fraction has " + std::to_string(digits) +
                                   " digits; at most nine fractional digits are accepted",
                               path);
    }
    for (std::size_t pad = digits; pad < 9u; ++pad) {
      fraction *= 10u;
    }
    nanos = fraction;
  }

  if (cursor.at_end()) {
    return invalid_timestamp("timestamp must end with uppercase 'Z' but the text ends at offset " +
                                 std::to_string(cursor.index()),
                             path);
  }
  const char terminator = cursor.peek();
  if (terminator == 'z') {
    return invalid_timestamp("timestamp must end with uppercase 'Z'; lowercase 'z' at offset " +
                                 std::to_string(cursor.index()) + " is not accepted",
                             path);
  }
  if (terminator == '+' || terminator == '-') {
    return invalid_timestamp("timestamp must be UTC: an explicit numeric offset " +
                                 describe_byte(terminator) + " at offset " +
                                 std::to_string(cursor.index()) + " is not accepted",
                             path);
  }
  if (terminator != 'Z') {
    return invalid_timestamp("timestamp must end with uppercase 'Z'; found " + describe_byte(terminator) +
                                 " at offset " + std::to_string(cursor.index()),
                             path);
  }
  cursor.advance();
  if (!cursor.at_end()) {
    return invalid_timestamp("timestamp has " + std::to_string(text.size() - cursor.index()) +
                                 " trailing byte(s) after the terminating 'Z'; found " +
                                 describe_byte(cursor.peek()) + " at offset " +
                                 std::to_string(cursor.index()),
                             path);
  }

  const std::int64_t days = days_from_civil(static_cast<std::int64_t>(year), month, day);
  const std::int64_t seconds_of_day = static_cast<std::int64_t>(hour) * 3600 +
                                      static_cast<std::int64_t>(minute) * 60 +
                                      static_cast<std::int64_t>(second);
  const std::int64_t nanos_of_day = seconds_of_day * kNanosPerSecond + static_cast<std::int64_t>(nanos);
  std::int64_t offset = 0;
  if (!to_signed_nanos(days, nanos_of_day, offset)) {
    if (days < 0) {
      return invalid_timestamp(
          "timestamp is before 1677-09-21T00:12:43.145224192Z, the earliest instant representable as "
          "signed nanoseconds since the Unix epoch",
          path);
    }
    return invalid_timestamp(
        "timestamp is after 2262-04-11T23:47:16.854775807Z, the latest instant representable as "
        "signed nanoseconds since the Unix epoch",
        path);
  }
  return Timestamp::from_unix_nanos(static_cast<nanos_type>(offset));
}

// Equality and ordering compare the signed instant, not the raw bit pattern.
// Comparing the pattern would order every pre-1970 instant after every
// post-1970 instant, which is exactly the kind of silent inversion this project
// refuses to ship.
bool operator==(const Timestamp& a, const Timestamp& b) noexcept {
  if (a.set_ != b.set_) {
    return false;
  }
  return !a.set_ || a.value_ == b.value_;
}

std::strong_ordering operator<=>(const Timestamp& a, const Timestamp& b) noexcept {
  if (a.set_ != b.set_) {
    return a.set_ ? std::strong_ordering::greater : std::strong_ordering::less;
  }
  if (!a.set_) {
    return std::strong_ordering::equal;
  }
  const auto left = static_cast<std::int64_t>(a.value_);
  const auto right = static_cast<std::int64_t>(b.value_);
  return left <=> right;
}

std::string Timestamp::to_rfc3339() const {
  FBM_PRECONDITION(set_);
  const std::int64_t offset = static_cast<std::int64_t>(value_);
  std::int64_t seconds = offset / kNanosPerSecond;
  std::int64_t nanos = offset % kNanosPerSecond;
  if (nanos < 0) {
    nanos += kNanosPerSecond;
    seconds -= 1;
  }
  std::int64_t days = seconds / kSecondsPerDay;
  std::int64_t second_of_day = seconds % kSecondsPerDay;
  if (second_of_day < 0) {
    second_of_day += kSecondsPerDay;
    days -= 1;
  }
  std::int64_t year = 0;
  unsigned month = 0;
  unsigned day = 0;
  civil_from_days(days, year, month, day);
  const std::int64_t hour = second_of_day / 3600;
  const std::int64_t minute = (second_of_day % 3600) / 60;
  const std::int64_t second = second_of_day % 60;

  // Canonical rendering: four-digit year, two-digit fields, exactly nine
  // fractional digits and an uppercase Z, so two renderings of the same instant
  // are byte identical.
  std::string out;
  out.reserve(30u);
  append_padded(out, year, 4u);
  out += '-';
  append_padded(out, static_cast<std::int64_t>(month), 2u);
  out += '-';
  append_padded(out, static_cast<std::int64_t>(day), 2u);
  out += 'T';
  append_padded(out, hour, 2u);
  out += ':';
  append_padded(out, minute, 2u);
  out += ':';
  append_padded(out, second, 2u);
  out += '.';
  append_padded(out, nanos, 9u);
  out += 'Z';
  return out;
}

std::int64_t Timestamp::delta_nanos(const Timestamp& other) const noexcept {
  // Both operands must be set: an unset timestamp is not the epoch, and reading
  // it as one would silently turn missing into zero.
  FBM_PRECONDITION(is_set());
  FBM_PRECONDITION(other.is_set());
  const std::int64_t left = static_cast<std::int64_t>(value_);
  const std::int64_t right = static_cast<std::int64_t>(other.value_);
  constexpr std::uint64_t kPositiveLimit =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  constexpr std::uint64_t kNegativeLimit = kPositiveLimit + 1u;
  if (left >= right) {
    const std::uint64_t magnitude = static_cast<std::uint64_t>(left) - static_cast<std::uint64_t>(right);
    if (magnitude > kPositiveLimit) {
      return std::numeric_limits<std::int64_t>::max();
    }
    return static_cast<std::int64_t>(magnitude);
  }
  const std::uint64_t magnitude = static_cast<std::uint64_t>(right) - static_cast<std::uint64_t>(left);
  if (magnitude >= kNegativeLimit) {
    return std::numeric_limits<std::int64_t>::min();
  }
  return -static_cast<std::int64_t>(magnitude);
}

bool Expiry::is_expired(Timestamp now) const {
  // An unset Expiry is a programming error and must never read as unexpired.
  FBM_PRECONDITION(set_);
  if (kind_ == Kind::Never) {
    return false;
  }
  if (!at_.is_set()) {
    // An At grant with no stated instant cannot be shown to be valid.
    return true;
  }
  if (!now.is_set()) {
    // An unknown now cannot establish that the grant is still valid.
    return true;
  }
  // Expiry is exclusive: the grant is expired at exactly the stated instant,
  // and the signed difference is the same order delta_nanos() reports.
  return now.delta_nanos(at_) >= 0;
}

std::string Expiry::to_string() const {
  if (!set_) {
    return "<unset>";
  }
  if (kind_ == Kind::Never) {
    return "never";
  }
  return at_.is_set() ? at_.to_rfc3339() : std::string{"<unset instant>"};
}

bool FreshnessBound::is_stale(Timestamp observed_at, Timestamp now) const {
  // An unknown age is not a fresh age: this rule is the first one, so an unset
  // observation time is stale even when the window is unbounded.
  if (!observed_at.is_set()) {
    return true;
  }
  // A window that was never stated is not a licence to call evidence fresh.
  if (!set_) {
    return true;
  }
  // An explicitly unbounded window accepts evidence of any age.
  if (is_unbounded()) {
    return false;
  }
  if (!now.is_set()) {
    // The age cannot be measured, so freshness cannot be asserted.
    return true;
  }
  // Evidence observed in the future is not stale under this rule: a negative
  // age is a clock-skew question for a different check, not an age question.
  const std::int64_t age = now.delta_nanos(observed_at);
  if (age <= 0) {
    return false;
  }
  return static_cast<std::uint64_t>(age) > max_age_nanos_;
}

}  // namespace summon::fbm
