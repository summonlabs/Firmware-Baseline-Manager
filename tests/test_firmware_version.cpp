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

#include <compare>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"

namespace {

using summon::fbm::ErrorCode;
using summon::fbm::FirmwareVersion;
using summon::fbm::VersionRange;

constexpr std::string_view kPath = "spec.baseline.version";

FirmwareVersion must_parse(std::string_view text) {
  const auto parsed = FirmwareVersion::parse(text, kPath);
  if (!parsed.has_value()) {
    ::fbm_test::check_count() += 1;
    ::fbm_test::report_failure(__FILE__, __LINE__,
                               std::string{"expected \""} + std::string{text} +
                                   "\" to parse: " + parsed.error().to_string());
    throw ::fbm_test::Abort{};
  }
  return parsed.value();
}

// Asserts that text is rejected with the version code, the supplied path, and a
// message that names the defect.
void expect_rejected(std::string_view text, std::string_view needle) {
  const auto parsed = FirmwareVersion::parse(text, kPath);
  CHECK_MSG(!parsed.has_value(), "expected \"" << std::string{text} << "\" to be rejected");
  if (parsed.has_value()) {
    return;
  }
  CHECK_MSG(parsed.error().code() == ErrorCode::SchemaInvalidVersionText,
            "wrong code for \"" << std::string{text} << "\": " << parsed.error().to_string());
  CHECK_MSG(parsed.error().path() == kPath,
            "wrong path for \"" << std::string{text} << "\": \"" << parsed.error().path() << "\"");
  CHECK_MSG(parsed.error().message().find(needle) != std::string::npos,
            "message for \"" << std::string{text} << "\" was \"" << parsed.error().message()
                               << "\", which does not name \"" << needle << "\"");
}

int sign_of(std::strong_ordering order) {
  if (order == std::strong_ordering::less) {
    return -1;
  }
  if (order == std::strong_ordering::greater) {
    return 1;
  }
  return 0;
}

struct RejectCase {
  std::string_view text;
  std::string_view needle;
};

struct DistanceCase {
  std::string_view first;
  std::string_view second;
  std::int64_t expected;
};

constexpr std::int64_t kRadix = 4294967296ll;  // 2^32, the lattice radix

}  // namespace

FBM_TEST(firmware_version_parse_and_canonical_round_trip) {
  const std::string_view cases[] = {
      "0.0.0",
      "0.0.0.0",
      "1.0.0",
      "1.2.3.4",
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-0",
      "1.0.0-0.3.7",
      "1.0.0-x.7.z.92",
      "1.0.0-x-y-z.--",
      "1.0.0+build",
      "1.0.0+20130313144700",
      "1.0.0-beta+exp.sha.5114f85",
      "1.0.0-rc.1+build.1",
      "1.0.0-alpha+001",
      "10.20.30",
      "4294967295.4294967295.4294967295.4294967295",
      "2.2.2.0-rc.2+meta-1",
  };
  for (const std::string_view text : cases) {
    const auto parsed = FirmwareVersion::parse(text, kPath);
    CHECK_OK(parsed);
    const FirmwareVersion& version = parsed.value();
    CHECK_MSG(version.to_string() == text,
              "canonical rendering of \"" << std::string{text} << "\" was \"" << version.to_string() << "\"");
    CHECK_MSG(version.raw() == text, "raw text of \"" << std::string{text} << "\" was \"" << version.raw() << "\"");
    const FirmwareVersion again = must_parse(version.to_string());
    CHECK_EQ(sign_of(again <=> version), 0);
    CHECK_EQ(again.to_string(), version.to_string());
    CHECK_EQ(again.raw(), version.raw());
  }

  const FirmwareVersion full = must_parse("1.2.3.4-beta.5+build.6");
  CHECK_EQ(full.major(), std::uint32_t{1});
  CHECK_EQ(full.minor(), std::uint32_t{2});
  CHECK_EQ(full.patch(), std::uint32_t{3});
  CHECK(full.has_build());
  CHECK_EQ(full.build(), std::uint32_t{4});
  CHECK_EQ(full.prerelease(), std::string{"beta.5"});
  CHECK_EQ(full.metadata(), std::string{"build.6"});
  CHECK_EQ(full.raw(), std::string{"1.2.3.4-beta.5+build.6"});
  CHECK_EQ(full.to_string(), std::string{"1.2.3.4-beta.5+build.6"});

  const FirmwareVersion minimal = must_parse("0.0.0");
  CHECK(!minimal.has_build());
  CHECK(minimal.prerelease().empty());
  CHECK(minimal.metadata().empty());
  CHECK(minimal.raw() == minimal.to_string());
}

FBM_TEST(firmware_version_rejects_malformed_text) {
  const RejectCase cases[] = {
      {"", "empty"},
      {"1", "major"},
      {"1.0", "minor"},
      {"1.0.0.0.0", "more than four"},
      {"1.0.0.0.0.0", "more than four"},
      {"1.0.0.0.", "more than four"},
      {"1..0", "minor component"},
      {".1.0", "major component"},
      {"1.0.", "patch component"},
      {"1.0.0.", "trailing"},
      {"1.0.0-", "prerelease is empty"},
      {"1.0.0.0-", "prerelease is empty"},
      {"1.0.0-+x", "prerelease is empty"},
      {"1.0.0+", "metadata is empty"},
      {"1.0.0-a..b", "empty identifier"},
      {"1.0.0-alpha.", "empty identifier"},
      {"1.0.0+a..b", "empty identifier"},
      {"1.0.0+meta.", "empty identifier"},
      {"01.0.0", "leading zero"},
      {"1.00.0", "leading zero"},
      {"1.0.01", "leading zero"},
      {"1.0.0.01", "leading zero"},
      {"1.0.0-01", "leading zero"},
      {"1.0.0-0.1.02", "leading zero"},
      {"4294967296.0.0", "32-bit"},
      {"1.4294967296.0", "32-bit"},
      {"1.0.4294967296", "32-bit"},
      {"1.0.0.4294967296", "32-bit"},
      {"99999999999.0.0", "32-bit"},
      {"1.0.0 ", "whitespace"},
      {" 1.0.0", "whitespace"},
      {"1. 0.0", "whitespace"},
      {"1.0.0\t", "whitespace"},
      {"1.0.0\n", "whitespace"},
      {"1.0.0-\t", "whitespace"},
      {"1.0.0\xC3\xA9", "non-ASCII"},
      {"\xC3\xA9.0.0", "non-ASCII"},
      {"v1.0.0", "major component"},
      {"1.0.0-alpha_1", "unexpected byte"},
      {"1.0.0/1", "unexpected byte"},
      {"1.0.0+build+2", "unexpected byte"},
      {"1.0.0-a+b+c", "unexpected byte"},
  };
  for (const RejectCase& test_case : cases) {
    expect_rejected(test_case.text, test_case.needle);
  }
  CHECK_ERROR(FirmwareVersion::parse("1.0", kPath), ErrorCode::SchemaInvalidVersionText);
  CHECK_ERROR(FirmwareVersion::parse("1.0.0-", kPath), ErrorCode::SchemaInvalidVersionText);

  // A numeric prerelease identifier is compared numerically and is not limited
  // to 32 bits, so a long one parses and orders numerically.
  const FirmwareVersion long_numeric = must_parse("1.0.0-99999999999999999999");
  CHECK_EQ(long_numeric.prerelease(), std::string{"99999999999999999999"});
  CHECK(must_parse("1.0.0-99999999999999999999") < must_parse("1.0.0-100000000000000000000"));
}

FBM_TEST(firmware_version_ordering_table) {
  // Strictly ascending. The chain required by Semantic Versioning and the
  // absent-build extension both appear here.
  const std::string_view ascending[] = {
      "0.9.9",
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.0.0",
      "1.0.0.1",
      "1.0.2",
      "1.0.10",
      "1.1.0-alpha",
      "1.1.0",
      "1.1.0.1",
      "2.0.0-alpha",
      "2.0.0",
      "2.0.0.0",
      "2.0.0.1",
      "2.1.0",
      "10.0.0",
      "4294967295.0.0",
  };
  constexpr std::size_t kCount = sizeof(ascending) / sizeof(ascending[0]);
  for (std::size_t i = 0; i < kCount; ++i) {
    for (std::size_t j = 0; j < kCount; ++j) {
      const FirmwareVersion left = must_parse(ascending[i]);
      const FirmwareVersion right = must_parse(ascending[j]);
      const int expected = (i == j) ? 0 : ((i < j) ? -1 : 1);
      CHECK_MSG(sign_of(left <=> right) == expected,
                "expected \"" << std::string{ascending[i]} << "\" versus \"" << std::string{ascending[j]}
                                   << "\" to order as " << expected << " but it ordered as "
                                   << sign_of(left <=> right));
    }
  }

  // The individual relations the ordering contract names.
  CHECK(must_parse("1.0.0") < must_parse("1.0.1"));
  CHECK(must_parse("1.0.1") < must_parse("1.1.0"));
  CHECK(must_parse("1.1.0") < must_parse("2.0.0"));
  CHECK(must_parse("1.0.0") < must_parse("1.0.0.1"));
  CHECK(must_parse("1.0.0-alpha") < must_parse("1.0.0"));
  CHECK(must_parse("1.0.0-alpha") < must_parse("1.0.0-alpha.1"));
  CHECK(must_parse("1.0.0-alpha.1") < must_parse("1.0.0-alpha.beta"));
  CHECK(must_parse("1.0.0-alpha.beta") < must_parse("1.0.0-beta"));
  CHECK(must_parse("1.0.0-beta") < must_parse("1.0.0-beta.2"));
  CHECK(must_parse("1.0.0-beta.2") < must_parse("1.0.0-beta.11"));
  CHECK(must_parse("1.0.0-beta.11") < must_parse("1.0.0-rc.1"));
  CHECK(must_parse("1.0.0-rc.1") < must_parse("1.0.0"));
  CHECK(!(must_parse("1.0.0") < must_parse("1.0.0")));
}

FBM_TEST(firmware_version_metadata_does_not_affect_precedence) {
  const FirmwareVersion with_build_1 = must_parse("1.0.0+build.1");
  const FirmwareVersion with_build_2 = must_parse("1.0.0+build.2");
  const FirmwareVersion plain = must_parse("1.0.0");
  const FirmwareVersion prerelease_meta = must_parse("1.0.0-rc.1+meta");
  const FirmwareVersion prerelease_plain = must_parse("1.0.0-rc.1");

  // Precedence equivalence is stated with the spaceship operator, which is the
  // precedence comparison. The header declares operator== as defaulted over
  // every member, so it remains the exact-text comparison; raw() and
  // metadata() are what an exact text comparison uses.
  CHECK_EQ(sign_of(with_build_1 <=> with_build_2), 0);
  CHECK_EQ(sign_of(with_build_1 <=> plain), 0);
  CHECK_EQ(sign_of(with_build_2 <=> plain), 0);
  CHECK_EQ(sign_of(prerelease_meta <=> prerelease_plain), 0);
  CHECK(!(with_build_1 < with_build_2));
  CHECK(!(with_build_2 < with_build_1));
  CHECK(!(with_build_1 < plain));
  CHECK(prerelease_plain < plain);

  CHECK_EQ(with_build_1.metadata(), std::string{"build.1"});
  CHECK_EQ(with_build_2.metadata(), std::string{"build.2"});
  CHECK(with_build_1.metadata() != with_build_2.metadata());
  CHECK_EQ(with_build_1.to_string(), std::string{"1.0.0+build.1"});
  CHECK_EQ(with_build_2.to_string(), std::string{"1.0.0+build.2"});
  CHECK_EQ(plain.to_string(), std::string{"1.0.0"});

  // A range whose two bounds differ only in metadata is a single point.
  const auto point = VersionRange::make(with_build_1, true, with_build_2, true, kPath);
  CHECK_OK(point);
  CHECK(!point.value().is_empty());
  CHECK(point.value().contains(plain));
  CHECK(point.value().contains(with_build_1));
  CHECK(point.value().contains(with_build_2));
  CHECK(!point.value().contains(must_parse("1.0.1")));
}

FBM_TEST(firmware_version_total_order_properties) {
  const std::string_view table[] = {
      "0.0.0",
      "0.0.1",
      "0.1.0",
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
      "1.0.0.0",
      "1.0.0.1",
      "1.0.1",
      "1.0.1.0",
      "1.0.2",
      "1.0.10",
      "1.1.0-alpha",
      "1.1.0",
      "1.1.0.0",
      "1.1.0.1",
      "1.1.1",
      "2.0.0-alpha",
      "2.0.0-alpha.1",
      "2.0.0-beta",
      "2.0.0",
      "2.0.0.0",
      "2.0.0.1",
      "2.0.1",
      "2.1.0",
      "3.0.0",
      "10.0.0",
      "10.0.0.1",
      "10.0.0-rc.9",
      "100.200.300",
      "4294967295.0.0",
      "0.4294967295.4294967295",
      "1.0.0-0",
      "1.0.0-0.3.7",
      "1.0.0-x.7.z.92",
  };
  constexpr std::size_t kCount = sizeof(table) / sizeof(table[0]);
  std::vector<FirmwareVersion> versions;
  versions.reserve(kCount);
  for (const std::string_view text : table) {
    versions.push_back(must_parse(text));
  }
  REQUIRE(versions.size() == kCount);

  for (std::size_t i = 0; i < kCount; ++i) {
    CHECK_EQ(sign_of(versions[i] <=> versions[i]), 0);
    CHECK(!(versions[i] < versions[i]));
  }

  for (std::size_t i = 0; i < kCount; ++i) {
    for (std::size_t j = 0; j < kCount; ++j) {
      const int forward = sign_of(versions[i] <=> versions[j]);
      const int backward = sign_of(versions[j] <=> versions[i]);
      CHECK_MSG(forward == -backward, "antisymmetry failed for \"" << versions[i].to_string() << "\" and \""
                                          << versions[j].to_string() << "\"");
      CHECK_EQ(versions[i] < versions[j], forward < 0);
      CHECK_EQ(versions[i] > versions[j], forward > 0);
      CHECK_EQ(versions[i] <= versions[j], forward <= 0);
      CHECK_EQ(versions[i] >= versions[j], forward >= 0);
    }
  }

  for (std::size_t i = 0; i < kCount; ++i) {
    for (std::size_t j = 0; j < kCount; ++j) {
      for (std::size_t k = 0; k < kCount; ++k) {
        const bool antecedent = !(versions[i] < versions[j]) && !(versions[j] < versions[k]);
        const bool consequence = !(versions[i] < versions[k]);
        CHECK_MSG(!antecedent || consequence, "transitivity failed for \""
                                                   << versions[i].to_string() << "\", \"" << versions[j].to_string()
                                                   << "\", \"" << versions[k].to_string() << "\"");
      }
    }
  }
}

FBM_TEST(firmware_version_range_containment) {
  const FirmwareVersion below = must_parse("0.9.9");
  const FirmwareVersion low = must_parse("1.0.0");
  const FirmwareVersion mid = must_parse("1.5.0");
  const FirmwareVersion high = must_parse("2.0.0");
  const FirmwareVersion above = must_parse("2.0.1");

  const VersionRange everything = VersionRange::unbounded();
  CHECK(!everything.has_minimum());
  CHECK(!everything.has_maximum());
  CHECK(!everything.is_empty());
  CHECK(everything.contains(below));
  CHECK(everything.contains(low));
  CHECK(everything.contains(mid));
  CHECK(everything.contains(high));
  CHECK(everything.contains(above));
  CHECK_EQ(everything.to_string(), std::string{"(-inf, +inf)"});

  struct BoundedCase {
    bool minimum_inclusive;
    bool maximum_inclusive;
    bool low_inside;
    bool high_inside;
  };
  const BoundedCase bounded[] = {
      {true, true, true, true},
      {true, false, true, false},
      {false, true, false, true},
      {false, false, false, false},
  };
  for (const BoundedCase& test_case : bounded) {
    const auto made = VersionRange::make(low, test_case.minimum_inclusive, high, test_case.maximum_inclusive, kPath);
    CHECK_OK(made);
    const VersionRange& range = made.value();
    CHECK(range.has_minimum());
    CHECK(range.has_maximum());
    CHECK_EQ(range.minimum_inclusive(), test_case.minimum_inclusive);
    CHECK_EQ(range.maximum_inclusive(), test_case.maximum_inclusive);
    CHECK(!range.is_empty());
    CHECK_MSG(range.contains(mid), "mid must be inside " << range.to_string());
    CHECK_EQ(range.contains(low), test_case.low_inside);
    CHECK_EQ(range.contains(high), test_case.high_inside);
    CHECK(!range.contains(below));
    CHECK(!range.contains(above));
  }

  // One unbounded side at a time, in both inclusivities.
  const auto at_least_low = VersionRange::make(low, true, std::nullopt, true, kPath);
  CHECK_OK(at_least_low);
  CHECK(at_least_low.value().has_minimum());
  CHECK(!at_least_low.value().has_maximum());
  CHECK(at_least_low.value().contains(low));
  CHECK(at_least_low.value().contains(mid));
  CHECK(at_least_low.value().contains(above));
  CHECK(!at_least_low.value().contains(below));
  CHECK_EQ(at_least_low.value().to_string(), std::string{"[1.0.0, +inf)"});

  const auto above_low = VersionRange::make(low, false, std::nullopt, true, kPath);
  CHECK_OK(above_low);
  CHECK(!above_low.value().contains(low));
  CHECK(above_low.value().contains(mid));
  CHECK(above_low.value().contains(above));
  CHECK(!above_low.value().contains(below));
  CHECK_EQ(above_low.value().to_string(), std::string{"(1.0.0, +inf)"});

  const auto at_most_high = VersionRange::make(std::nullopt, true, high, true, kPath);
  CHECK_OK(at_most_high);
  CHECK(!at_most_high.value().has_minimum());
  CHECK(at_most_high.value().has_maximum());
  CHECK(at_most_high.value().contains(high));
  CHECK(at_most_high.value().contains(mid));
  CHECK(at_most_high.value().contains(below));
  CHECK(!at_most_high.value().contains(above));
  CHECK_EQ(at_most_high.value().to_string(), std::string{"(-inf, 2.0.0]"});

  const auto below_high = VersionRange::make(std::nullopt, true, high, false, kPath);
  CHECK_OK(below_high);
  CHECK(!below_high.value().contains(high));
  CHECK(below_high.value().contains(mid));
  CHECK(below_high.value().contains(below));
  CHECK(!below_high.value().contains(above));
  CHECK_EQ(below_high.value().to_string(), std::string{"(-inf, 2.0.0)"});

  // An unbounded side contains everything on that side, including the far ends.
  CHECK(at_least_low.value().contains(must_parse("4294967295.4294967295.4294967295")));
  CHECK(at_most_high.value().contains(must_parse("0.0.0")));
  CHECK(at_most_high.value().contains(must_parse("2.0.0-alpha")));
  CHECK(!at_least_low.value().contains(must_parse("1.0.0-alpha")));
}

FBM_TEST(firmware_version_range_make_rejects_empty_intervals) {
  const FirmwareVersion low = must_parse("1.0.0");
  const FirmwareVersion high = must_parse("2.0.0");

  CHECK_ERROR(VersionRange::make(high, true, low, true, kPath), ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(VersionRange::make(high, false, low, false, kPath), ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(VersionRange::make(high, true, low, false, kPath), ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(VersionRange::make(high, false, low, true, kPath), ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(VersionRange::make(low, true, low, false, kPath), ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(VersionRange::make(low, false, low, true, kPath), ErrorCode::SchemaInconsistentDocument);
  CHECK_ERROR(VersionRange::make(low, false, low, false, kPath), ErrorCode::SchemaInconsistentDocument);

  const auto rejected = VersionRange::make(high, true, low, true, kPath);
  REQUIRE(!rejected.has_value());
  CHECK_EQ(rejected.error().code(), ErrorCode::SchemaInconsistentDocument);
  CHECK_EQ(rejected.error().path(), std::string{kPath});
  CHECK_MSG(rejected.error().message().find("empty") != std::string::npos,
            "message did not name the empty interval: " << rejected.error().message());
  CHECK_MSG(rejected.error().message().find("greater than the maximum") != std::string::npos,
            "message did not name the direction: " << rejected.error().message());

  const auto equal_exclusive = VersionRange::make(low, true, low, false, kPath);
  REQUIRE(!equal_exclusive.has_value());
  CHECK_MSG(equal_exclusive.error().message().find("exclusive") != std::string::npos,
            "message did not name the exclusive bound: " << equal_exclusive.error().message());

  // A single point with both bounds inclusive is not empty, and is_empty()
  // agrees with make(): every interval make() accepts has at least one member.
  const auto point = VersionRange::make(low, true, low, true, kPath);
  CHECK_OK(point);
  CHECK(!point.value().is_empty());
  CHECK(point.value().contains(low));
  CHECK(!point.value().contains(high));
  CHECK_EQ(point.value().to_string(), std::string{"[1.0.0, 1.0.0]"});

  const auto exact = VersionRange::exact(low);
  CHECK_OK(exact);
  CHECK(!exact.value().is_empty());
  CHECK(exact.value().contains(low));
  CHECK(!exact.value().contains(high));

  CHECK(!VersionRange::unbounded().is_empty());
}

FBM_TEST(firmware_version_distance_table) {
  const DistanceCase cases[] = {
      {"1.0.0", "1.0.0", 0},
      {"1.0.0+a", "1.0.0+b", 0},
      {"1.0.0-alpha", "1.0.0", 0},
      {"1.0.0-alpha", "1.0.0-alpha.1", 0},
      {"2.0.0-beta", "2.0.0-alpha", 0},
      {"1.0.1", "1.0.0", kRadix},
      {"1.0.0", "1.0.1", -kRadix},
      {"1.0.100", "1.0.0", 100 * kRadix},
      {"1.0.2147483647", "1.0.0", 2147483647ll * kRadix},
      {"1.0.2147483648", "1.0.0", std::numeric_limits<std::int64_t>::max()},
      {"1.0.0.1", "1.0.0", 2},
      {"1.0.0", "1.0.0.1", -2},
      {"1.0.0.0", "1.0.0", 1},
      {"1.0.0.0", "1.0.0.1", -1},
      {"1.0.0.4294967295", "1.0.0.4294967294", 1},
      {"1.0.1.5", "1.0.0.2", kRadix + 3},
      {"1.1.0", "1.0.0", std::numeric_limits<std::int64_t>::max()},
      {"1.0.0", "1.1.0", std::numeric_limits<std::int64_t>::min()},
      {"2.0.0", "1.0.0", std::numeric_limits<std::int64_t>::max()},
      {"1.0.0", "2.0.0", std::numeric_limits<std::int64_t>::min()},
      {"1.0.0.4294967295", "1.0.1", -1},
      {"1.0.1", "1.0.0.4294967295", 1},
  };
  for (const DistanceCase& test_case : cases) {
    const FirmwareVersion first = must_parse(test_case.first);
    const FirmwareVersion second = must_parse(test_case.second);
    CHECK_MSG(version_distance(first, second) == test_case.expected,
              "distance(\"" << test_case.first << "\", \"" << test_case.second << "\") was "
                                 << version_distance(first, second) << ", expected " << test_case.expected);
    // The sign is always the precedence sign, saturated or not. Antisymmetry
    // holds for every pair whose exact distance fits in std::int64_t; at the
    // saturated extremes the two directions clamp to INT64_MAX and INT64_MIN.
    if (test_case.expected != 0) {
      const int precedence = sign_of(first <=> second);
      CHECK_EQ(sign_of(version_distance(first, second) <=> 0), precedence);
    }
    if (test_case.expected != std::numeric_limits<std::int64_t>::max() &&
        test_case.expected != std::numeric_limits<std::int64_t>::min()) {
      CHECK_EQ(version_distance(second, first), -test_case.expected);
    }
  }
}
