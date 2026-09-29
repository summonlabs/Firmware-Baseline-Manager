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
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/result.hpp"

namespace summon::fbm {

// A firmware version.
//
// Grammar: major "." minor "." patch [ "." build ] [ "-" prerelease ] [ "+" metadata ]
//
//   * major, minor, patch, build are decimal digit strings with no leading
//     zeroes (except the single digit "0").
//   * prerelease is one or more dot-separated identifiers of [0-9A-Za-z-];
//     a purely numeric identifier carries no leading zeroes.
//   * metadata is one or more dot-separated identifiers of [0-9A-Za-z-].
//   * only ASCII is accepted; the parser never guesses an encoding.
//
// Ordering follows Semantic Versioning precedence with one documented
// extension: an absent fourth (build) component is *unset* and orders before
// every present fourth component, including ".0". It is never read as zero.
//
// Ordering is a total order over versions. It is used for reporting residuals
// and selecting rollback candidates. It never decides compatibility: newer is
// not automatically compatible.
class FirmwareVersion {
 public:
  static Result<FirmwareVersion> parse(std::string_view text, std::string_view path);

  std::uint32_t major() const noexcept { return major_; }
  std::uint32_t minor() const noexcept { return minor_; }
  std::uint32_t patch() const noexcept { return patch_; }
  bool has_build() const noexcept { return build_.has_value(); }
  std::uint32_t build() const noexcept;
  const std::string& prerelease() const noexcept { return prerelease_; }
  const std::string& metadata() const noexcept { return metadata_; }

  // The exact text this version was parsed from.
  const std::string& raw() const noexcept { return raw_; }

  // Canonical rendering: major.minor.patch[.build][-prerelease][+metadata].
  // Two versions compare equal if and only if their precedence-bearing parts
  // are equal; the canonical rendering additionally preserves metadata.
  std::string to_string() const;

  friend bool operator==(const FirmwareVersion&, const FirmwareVersion&) = default;
  friend std::strong_ordering operator<=>(const FirmwareVersion&, const FirmwareVersion&);

 private:
  FirmwareVersion() = default;

  std::uint32_t major_ = 0;
  std::uint32_t minor_ = 0;
  std::uint32_t patch_ = 0;
  std::optional<std::uint32_t> build_;
  std::string prerelease_;
  std::string metadata_;
  std::string raw_;
};

// A closed or half-open interval of versions. An unset bound is unbounded on
// that side; that is stated by leaving the bound unset, not by inventing an
// extreme version.
class VersionRange {
 public:
  VersionRange() = default;

  static VersionRange unbounded() { return VersionRange{}; }

  static Result<VersionRange> make(std::optional<FirmwareVersion> minimum, bool minimum_inclusive,
                                   std::optional<FirmwareVersion> maximum, bool maximum_inclusive,
                                   std::string_view path);

  static Result<VersionRange> exact(FirmwareVersion version) {
    return VersionRange::make(version, true, version, true, {});
  }

  bool has_minimum() const noexcept { return minimum_.has_value(); }
  bool has_maximum() const noexcept { return maximum_.has_value(); }
  bool minimum_inclusive() const noexcept { return minimum_inclusive_; }
  bool maximum_inclusive() const noexcept { return maximum_inclusive_; }
  const std::optional<FirmwareVersion>& minimum() const noexcept { return minimum_; }
  const std::optional<FirmwareVersion>& maximum() const noexcept { return maximum_; }

  // Containment. An unbounded side contains everything on that side.
  bool contains(const FirmwareVersion& version) const;

  // A range with no members: both bounds set and the interval is empty.
  bool is_empty() const;

  std::string to_string() const;

  friend bool operator==(const VersionRange&, const VersionRange&) = default;

 private:
  std::optional<FirmwareVersion> minimum_;
  std::optional<FirmwareVersion> maximum_;
  bool minimum_inclusive_ = true;
  bool maximum_inclusive_ = true;
};

// Precedence equivalence: true when two versions carry the same Semantic
// Versioning precedence, ignoring build metadata.
//
// FirmwareVersion::operator== is the EXACT-TEXT comparison, so it also compares
// metadata and the original text. same_precedence is the relation the range and
// conformance logic uses. a == b implies same_precedence(a, b), but not the
// reverse.
bool same_precedence(const FirmwareVersion& a, const FirmwareVersion& b) noexcept;

// Signed distance between two versions along the precedence order: the number
// of unit steps from lower to higher in the flattened (major, minor, patch,
// build) lattice. Reported as a residual magnitude for drift, never as an
// authorization to upgrade.
std::int64_t version_distance(const FirmwareVersion& lower, const FirmwareVersion& higher);

}  // namespace summon::fbm
