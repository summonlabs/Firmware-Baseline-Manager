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

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "summon/fbm/result.hpp"

namespace summon::fbm {

// A point in time expressed as nanoseconds since the Unix epoch, UTC. A
// Timestamp is either set or unset; an unset timestamp is never equal to any
// set timestamp, orders before every set timestamp, and never compares as "now"
// or as the epoch.
//
// The stored offset is a signed quantity, so instants before 1970 are
// representable and order before the epoch. unix_nanos() returns that signed
// offset reinterpreted as an unsigned value, which means a pre-1970 instant
// reports a value at or above 2^63. Ordering, difference, expiry, and freshness
// all use the signed interpretation; comparisons written by hand on
// unix_nanos() must not.
//
// The library never reads a clock implicitly. Every operation that depends on
// the current time takes the time as an argument so that evaluation is
// reproducible and testable.
class Timestamp {
 public:
  using nanos_type = std::uint64_t;

  constexpr Timestamp() noexcept = default;
  static constexpr Timestamp from_unix_nanos(nanos_type value) noexcept {
    return Timestamp{value};
  }

  // Unix epoch, spelled out so that "the epoch" is always an explicit choice.
  static constexpr Timestamp unix_epoch() noexcept { return Timestamp{0u}; }

  // Reads the system clock. The only place in the library that does so.
  static Timestamp system_now();

  // Strict RFC 3339 UTC parse: YYYY-MM-DDTHH:MM:SS[.fraction]Z, with exactly an
  // upper-case Z and nothing else. Rejects impossible calendar dates,
  // out-of-range fields, trailing bytes, a lowercase z, and any explicit
  // numeric UTC offset, including +00:00, because accepting offsets would make
  // two spellings of the same instant compare equal while rendering
  // differently.
  static Result<Timestamp> parse_rfc3339(std::string_view text, std::string_view path);

  bool is_set() const noexcept { return set_; }
  nanos_type unix_nanos() const noexcept { return value_; }

  // Canonical rendering: YYYY-MM-DDTHH:MM:SS.fffffffffZ with exactly nine
  // fractional digits, so that two renderings of the same instant are byte
  // identical.
  std::string to_rfc3339() const;

  // Signed difference in nanoseconds; negative when *this is earlier.
  std::int64_t delta_nanos(const Timestamp& other) const noexcept;

  // Comparison uses the signed instant, not the raw bit pattern, so a
  // pre-1970 instant orders before the epoch.
  friend bool operator==(const Timestamp& a, const Timestamp& b) noexcept;
  friend std::strong_ordering operator<=>(const Timestamp& a, const Timestamp& b) noexcept;

 private:
  constexpr explicit Timestamp(nanos_type value) noexcept : value_(value), set_(true) {}

  nanos_type value_{};
  bool set_ = false;
};

// Explicit expiry. Either the expiry instant is stated, or the document states
// that the grant never expires. There is no default, because a missing expiry
// silently read as "never" would convert an unknown into a permission.
class Expiry {
 public:
  enum class Kind : std::uint8_t { At = 0, Never = 1 };

  Expiry() = default;

  static Expiry at(Timestamp instant) { return Expiry{Kind::At, instant}; }
  static Expiry never() { return Expiry{Kind::Never, Timestamp{}}; }

  Kind kind() const noexcept { return kind_; }
  bool is_set() const noexcept { return set_; }
  const Timestamp& at() const noexcept { return at_; }

  // Expiry is exclusive: the grant is expired at exactly the stated instant.
  // A never-expiring grant is never expired.
  bool is_expired(Timestamp now) const;

  std::string to_string() const;

  friend bool operator==(const Expiry&, const Expiry&) = default;

 private:
  Expiry(Kind kind, Timestamp at) : kind_(kind), at_(at), set_(true) {}

  Kind kind_ = Kind::At;
  Timestamp at_{};
  bool set_ = false;
};

// Bounded evidence freshness window. Absence of a bound is stated explicitly
// rather than being treated as an infinite window.
class FreshnessBound {
 public:
  FreshnessBound() = default;

  static FreshnessBound within(std::uint64_t max_age_nanos) {
    return FreshnessBound{true, max_age_nanos};
  }
  static FreshnessBound unbounded() { return FreshnessBound{true, 0u}; }

  bool is_set() const noexcept { return set_; }
  bool is_unbounded() const noexcept { return set_ && max_age_nanos_ == 0u; }
  std::uint64_t max_age_nanos() const noexcept { return max_age_nanos_; }

  // True when evidence observed at observed_at is too old at now. Evidence with
  // an unset observation time is stale: an unknown age is not a fresh age.
  bool is_stale(Timestamp observed_at, Timestamp now) const;

  friend bool operator==(const FreshnessBound&, const FreshnessBound&) = default;

 private:
  FreshnessBound(bool set, std::uint64_t max_age_nanos)
      : max_age_nanos_(max_age_nanos), set_(set) {}

  std::uint64_t max_age_nanos_ = 0u;
  bool set_ = false;
};

}  // namespace summon::fbm
