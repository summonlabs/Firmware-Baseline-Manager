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

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "summon/fbm/error.hpp"
#include "summon/fbm/timestamp.hpp"

namespace {

using summon::fbm::ErrorCode;
using summon::fbm::Expiry;
using summon::fbm::FreshnessBound;
using summon::fbm::Timestamp;

constexpr std::string_view kPath = "spec.observation.observed_at";

// Parses text, reporting the parse diagnostic itself when it unexpectedly
// fails. Every helper below is deterministic: no clock is consulted and no
// wall-clock duration is measured.
Timestamp must_parse(std::string_view text) {
  const auto parsed = Timestamp::parse_rfc3339(text, kPath);
  if (!parsed.has_value()) {
    ::fbm_test::check_count() += 1;
    ::fbm_test::report_failure(__FILE__, __LINE__,
                               std::string{"expected \""} + std::string{text} +
                                   "\" to parse: " + parsed.error().to_string());
    throw ::fbm_test::Abort{};
  }
  return parsed.value();
}

// Asserts that text is rejected, that the rejection code is the timestamp code,
// that the path is the supplied one, and that the message names the defect.
void expect_rejected(std::string_view text, std::string_view needle) {
  const auto parsed = Timestamp::parse_rfc3339(text, kPath);
  CHECK_MSG(!parsed.has_value(), "expected \"" << std::string{text} << "\" to be rejected");
  if (parsed.has_value()) {
    return;
  }
  CHECK_MSG(parsed.error().code() == ErrorCode::SchemaInvalidTimestampText,
            "wrong code for \"" << std::string{text} << "\": " << parsed.error().to_string());
  CHECK_MSG(parsed.error().path() == kPath,
            "wrong path for \"" << std::string{text} << "\": \"" << parsed.error().path() << "\"");
  CHECK_MSG(parsed.error().message().find(needle) != std::string::npos,
            "message for \"" << std::string{text} << "\" was \"" << parsed.error().message()
                               << "\", which does not name \"" << needle << "\"");
}

struct RejectCase {
  std::string_view text;
  std::string_view needle;
};

}  // namespace

FBM_TEST(timestamp_round_trip_table) {
  const std::string_view cases[] = {
      "1970-01-01T00:00:00.000000000Z",
      "2000-02-29T12:34:56.789012345Z",
      "1900-03-01T00:00:00.000000000Z",
      "2026-12-31T23:59:59.999999999Z",
      "2100-03-01T00:00:00.000000000Z",
  };
  for (const std::string_view text : cases) {
    const auto parsed = Timestamp::parse_rfc3339(text, kPath);
    CHECK_OK(parsed);
    const Timestamp instant = parsed.value();
    CHECK_MSG(instant.is_set(), "\"" << std::string{text} << "\" must parse to a set timestamp");
    CHECK_MSG(instant.to_rfc3339() == text,
              "round trip of \"" << std::string{text} << "\" produced \"" << instant.to_rfc3339() << "\"");
    CHECK_EQ(instant.to_rfc3339().size(), std::size_t{30});
    // Re-parsing the canonical rendering yields the same instant.
    const Timestamp again = must_parse(instant.to_rfc3339());
    CHECK_EQ(again.unix_nanos(), instant.unix_nanos());
    CHECK_EQ(again.to_rfc3339(), instant.to_rfc3339());
  }
}

FBM_TEST(timestamp_epoch_fraction_scaling_and_extremes) {
  CHECK(!Timestamp{}.is_set());
  CHECK(Timestamp::unix_epoch().is_set());
  CHECK_EQ(Timestamp::unix_epoch().unix_nanos(), std::uint64_t{0});
  CHECK_EQ(Timestamp::unix_epoch().to_rfc3339(), std::string{"1970-01-01T00:00:00.000000000Z"});
  CHECK_EQ(must_parse("1970-01-01T00:00:00Z").unix_nanos(), std::uint64_t{0});
  CHECK_EQ(must_parse("1970-01-01T00:00:01Z").unix_nanos(), std::uint64_t{1000000000});
  CHECK_EQ(must_parse("1970-01-01T00:00:00.5Z").unix_nanos(), std::uint64_t{500000000});
  CHECK_EQ(must_parse("1970-01-01T00:00:00.000000001Z").unix_nanos(), std::uint64_t{1});
  CHECK_EQ(must_parse("1970-01-01T00:00:00.123456789Z").unix_nanos(), std::uint64_t{123456789});
  CHECK_EQ(must_parse("1970-01-01T00:00:00.5Z").to_rfc3339(),
           std::string{"1970-01-01T00:00:00.500000000Z"});

  // The two ends of the signed nanosecond timeline, reached through the raw
  // storage and through text.
  const Timestamp earliest = Timestamp::from_unix_nanos(0x8000000000000000ull);
  const Timestamp latest = Timestamp::from_unix_nanos(0x7FFFFFFFFFFFFFFFull);
  CHECK_EQ(earliest.to_rfc3339(), std::string{"1677-09-21T00:12:43.145224192Z"});
  CHECK_EQ(latest.to_rfc3339(), std::string{"2262-04-11T23:47:16.854775807Z"});
  CHECK_EQ(must_parse("1677-09-21T00:12:43.145224192Z").unix_nanos(), std::uint64_t{0x8000000000000000ull});
  CHECK_EQ(must_parse("2262-04-11T23:47:16.854775807Z").unix_nanos(), std::uint64_t{0x7FFFFFFFFFFFFFFFull});
  CHECK_EQ(must_parse("1677-09-21T00:12:43.145224192Z").to_rfc3339(), std::string{"1677-09-21T00:12:43.145224192Z"});
  CHECK_EQ(must_parse("2262-04-11T23:47:16.854775807Z").to_rfc3339(), std::string{"2262-04-11T23:47:16.854775807Z"});
  CHECK_EQ(Timestamp::from_unix_nanos(0x8000000000000001ull).to_rfc3339(),
           std::string{"1677-09-21T00:12:43.145224193Z"});
  CHECK_EQ(Timestamp::from_unix_nanos(0x7FFFFFFFFFFFFFFEull).to_rfc3339(),
           std::string{"2262-04-11T23:47:16.854775806Z"});
}

FBM_TEST(timestamp_leap_year_rules) {
  // 2000 is a leap year; 1900 and 2100 are not.
  CHECK_OK(Timestamp::parse_rfc3339("2000-02-29T00:00:00.000000000Z", kPath));
  CHECK_EQ(must_parse("2000-02-29T00:00:00.000000000Z").to_rfc3339(),
           std::string{"2000-02-29T00:00:00.000000000Z"});
  CHECK_ERROR(Timestamp::parse_rfc3339("1900-02-29T00:00:00Z", kPath), ErrorCode::SchemaInvalidTimestampText);
  CHECK_ERROR(Timestamp::parse_rfc3339("2100-02-29T00:00:00Z", kPath), ErrorCode::SchemaInvalidTimestampText);
  CHECK_ERROR(Timestamp::parse_rfc3339("1900-02-30T00:00:00Z", kPath), ErrorCode::SchemaInvalidTimestampText);
  expect_rejected("1900-02-29T00:00:00Z", "not a leap year");
  expect_rejected("2100-02-29T00:00:00Z", "not a leap year");
  expect_rejected("2001-02-29T00:00:00Z", "not a leap year");
  // 1900-03-01 is a valid pre-epoch instant and must still render exactly.
  CHECK_EQ(must_parse("1900-03-01T00:00:00.000000000Z").to_rfc3339(),
           std::string{"1900-03-01T00:00:00.000000000Z"});
}

FBM_TEST(timestamp_rejects_malformed_text) {
  const RejectCase cases[] = {
      {"", "empty"},
      {"1970-01-01T00:00:00", "uppercase 'Z'"},
      {"1970-01-01T00:00:00.000000000", "uppercase 'Z'"},
      {"1970-01-01T00:00:00.Z", "at least one digit"},
      {"1970-01-01T00:00:00.1234567890Z", "at most nine"},
      {"1970-01-01 00:00:00Z", "whitespace"},
      {"1970-01-01t00:00:00Z", "uppercase 'T'"},
      {"1970/01/01T00:00:00Z", "between the year and the month"},
      {"1970-01-01T00:00Z", "seconds field is mandatory"},
      {"1970-01-01T00:00:00,5Z", "uppercase 'Z'"},
      {"70-01-01T00:00:00Z", "year"},
      {"197-01-01T00:00:00Z", "year"},
      {"1970-0-01T00:00:00Z", "month"},
      {"1970-00-01T00:00:00Z", "month"},
      {"1970-13-01T00:00:00Z", "month"},
      {"1970-01-0T00:00:00Z", "day"},
      {"1970-01-00T00:00:00Z", "day 0"},
      {"1970-01-32T00:00:00Z", "day 32"},
      {"1970-04-31T00:00:00Z", "day 31"},
      {"1970-01-01T24:00:00Z", "hour"},
      {"1970-01-01T00:60:00Z", "minute"},
      {"1970-01-01T00:00:60Z", "second"},
      {"1970-01-01T00:00:00ZZ", "trailing"},
      {"1970-01-01T00:00:00Z ", "whitespace"},
      {"+1970-01-01T00:00:00Z", "must not begin"},
      {"-1970-01-01T00:00:00Z", "must not begin"},
      {"1970-01-01T00:00:00z", "lowercase 'z'"},
      {"1970-01-01T00:00:00+00:00", "numeric offset"},
      {"1970-01-01T00:00:00-05:00", "numeric offset"},
      {"1970-01-01T00:00:00.000000000X", "uppercase 'Z'"},
      {"1970-01-01T00:00:00.0000000000Z", "at most nine"},
      {"1600-01-01T00:00:00Z", "before"},
      {"2300-01-01T00:00:00Z", "after"},
  };
  for (const RejectCase& test_case : cases) {
    expect_rejected(test_case.text, test_case.needle);
  }
}

FBM_TEST(timestamp_delta_nanos_signs_and_magnitude) {
  const Timestamp epoch = Timestamp::unix_epoch();
  const Timestamp year_1900 = must_parse("1900-03-01T00:00:00.000000000Z");
  const Timestamp year_2000 = must_parse("2000-01-01T00:00:00.000000000Z");
  const Timestamp year_2100 = must_parse("2100-03-01T00:00:00.000000000Z");

  // Equal instants.
  CHECK_EQ(epoch.delta_nanos(epoch), 0);
  CHECK_EQ(year_2000.delta_nanos(year_2000), 0);

  // Exactly 10957 days from 1970-01-01 to 2000-01-01.
  CHECK_EQ(year_2000.delta_nanos(epoch), 946684800000000000ll);
  CHECK_EQ(epoch.delta_nanos(year_2000), -946684800000000000ll);

  // Adjacent instants, one nanosecond apart.
  const Timestamp last_nanosecond = must_parse("2026-12-31T23:59:59.999999999Z");
  const Timestamp one_before = must_parse("2026-12-31T23:59:59.999999998Z");
  CHECK_EQ(last_nanosecond.delta_nanos(one_before), 1);
  CHECK_EQ(one_before.delta_nanos(last_nanosecond), -1);

  // Far-apart instants across the epoch do not wrap.
  const std::int64_t span = year_2100.delta_nanos(year_1900);
  CHECK(span > 0);
  CHECK_LT(span, std::numeric_limits<std::int64_t>::max());
  CHECK_EQ(year_1900.delta_nanos(year_2100), -span);
  CHECK_EQ(year_1900.delta_nanos(epoch) + span, year_2100.delta_nanos(epoch));
  CHECK(year_1900.delta_nanos(epoch) < 0);
  CHECK(year_2100.delta_nanos(epoch) > 0);
}

FBM_TEST(timestamp_delta_saturates_instead_of_wrapping) {
  // The endpoints of the signed timeline differ by more than INT64_MAX
  // nanoseconds; the difference saturates instead of wrapping to the wrong sign.
  const Timestamp earliest = Timestamp::from_unix_nanos(0x8000000000000000ull);
  const Timestamp latest = Timestamp::from_unix_nanos(0x7FFFFFFFFFFFFFFFull);
  CHECK_EQ(latest.delta_nanos(earliest), std::numeric_limits<std::int64_t>::max());
  CHECK_EQ(earliest.delta_nanos(latest), std::numeric_limits<std::int64_t>::min());
  CHECK_EQ(earliest.delta_nanos(Timestamp::from_unix_nanos(0x8000000000000001ull)), -1);
}

FBM_TEST(timestamp_calendar_order_agrees_with_delta) {
  const std::string_view ascending[] = {
      "1900-03-01T00:00:00.000000000Z",
      "1970-01-01T00:00:00.000000000Z",
      "2000-02-29T12:34:56.789012345Z",
      "2026-12-31T23:59:59.999999999Z",
      "2100-03-01T00:00:00.000000000Z",
  };
  constexpr std::size_t kCount = sizeof(ascending) / sizeof(ascending[0]);
  for (std::size_t i = 0; i < kCount; ++i) {
    for (std::size_t j = 0; j < kCount; ++j) {
      const std::int64_t delta = must_parse(ascending[i]).delta_nanos(must_parse(ascending[j]));
      if (i == j) {
        CHECK_EQ(delta, 0);
      } else if (i < j) {
        CHECK_MSG(delta < 0, "expected \"" << std::string{ascending[i]} << "\" to precede \""
                               << std::string{ascending[j]} << "\" but the delta was " << delta);
      } else {
        CHECK_MSG(delta > 0, "expected \"" << std::string{ascending[i]} << "\" to follow \""
                               << std::string{ascending[j]} << "\" but the delta was " << delta);
      }
    }
  }
}

FBM_TEST(timestamp_expiry_boundaries) {
  const Timestamp instant = must_parse("2026-01-01T00:00:00.000000000Z");
  const Expiry at = Expiry::at(instant);
  CHECK(at.is_set());
  CHECK(at.kind() == Expiry::Kind::At);
  CHECK(at.at() == instant);

  // Expiry is exclusive: expired at exactly the stated instant.
  CHECK(at.is_expired(instant));
  CHECK(!at.is_expired(Timestamp::from_unix_nanos(instant.unix_nanos() - 1u)));
  CHECK(at.is_expired(Timestamp::from_unix_nanos(instant.unix_nanos() + 1u)));
  CHECK(at.is_expired(must_parse("2100-03-01T00:00:00.000000000Z")));

  const Expiry never = Expiry::never();
  CHECK(never.is_set());
  CHECK(never.kind() == Expiry::Kind::Never);
  CHECK(!never.is_expired(instant));
  CHECK(!never.is_expired(Timestamp::from_unix_nanos(0x7FFFFFFFFFFFFFFFull)));
  CHECK(!never.is_expired(must_parse("2262-04-11T23:47:16.854775807Z")));

  CHECK_EQ(at.to_string(), std::string{"2026-01-01T00:00:00.000000000Z"});
  CHECK_EQ(never.to_string(), std::string{"never"});
  CHECK_EQ(Expiry{}.to_string(), std::string{"<unset>"});
  CHECK(!Expiry{}.is_set());
}

FBM_TEST(timestamp_freshness_boundaries) {
  const Timestamp observed = must_parse("2026-01-01T00:00:00.000000000Z");
  const Timestamp nine_seconds = must_parse("2026-01-01T00:00:09.999999999Z");
  const Timestamp ten_seconds = must_parse("2026-01-01T00:00:10.000000000Z");
  const Timestamp ten_seconds_and_one = Timestamp::from_unix_nanos(ten_seconds.unix_nanos() + 1u);
  const Timestamp future = must_parse("2026-01-01T00:00:20.000000000Z");

  const FreshnessBound within_ten = FreshnessBound::within(10000000000ull);
  CHECK(within_ten.is_set());
  CHECK(!within_ten.is_unbounded());
  CHECK_EQ(within_ten.max_age_nanos(), std::uint64_t{10000000000});
  CHECK(!within_ten.is_stale(observed, observed));
  CHECK(!within_ten.is_stale(observed, nine_seconds));
  // The exact boundary age is not stale; one nanosecond beyond it is.
  CHECK(!within_ten.is_stale(observed, ten_seconds));
  CHECK(within_ten.is_stale(observed, ten_seconds_and_one));

  const FreshnessBound unbounded = FreshnessBound::unbounded();
  CHECK(unbounded.is_set());
  CHECK(unbounded.is_unbounded());
  CHECK(!unbounded.is_stale(observed, must_parse("2200-01-01T00:00:00.000000000Z")));
  CHECK(!unbounded.is_stale(future, observed));

  // An unset observation time is stale: an unknown age is not a fresh age. This
  // rule comes first, so it also holds for an explicitly unbounded window.
  CHECK(within_ten.is_stale(Timestamp{}, ten_seconds));
  CHECK(unbounded.is_stale(Timestamp{}, ten_seconds));

  // Evidence observed in the future is not stale: a negative age is a
  // clock-skew question, not an age question.
  CHECK(!within_ten.is_stale(future, ten_seconds));

  // A window that was never stated is not a licence to call evidence fresh.
  CHECK(!FreshnessBound{}.is_set());
  CHECK(FreshnessBound{}.is_stale(observed, ten_seconds));
}

FBM_TEST(timestamp_system_now_is_set_and_canonical) {
  const Timestamp now = Timestamp::system_now();
  CHECK(now.is_set());
  const std::string text = now.to_rfc3339();
  CHECK_EQ(text.size(), std::size_t{30});
  const Timestamp reparsed = must_parse(text);
  CHECK_EQ(reparsed.unix_nanos(), now.unix_nanos());
  CHECK_EQ(reparsed.to_rfc3339(), text);
}
