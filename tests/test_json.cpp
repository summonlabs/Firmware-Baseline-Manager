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

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "check.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/json.hpp"

namespace json = summon::fbm::json;

using summon::fbm::Diagnostics;
using summon::fbm::Error;
using summon::fbm::ErrorCode;
using summon::fbm::Result;
using summon::fbm::json::Limits;
using summon::fbm::json::ObjectReader;
using summon::fbm::json::Type;
using summon::fbm::json::Value;

namespace {

Result<Value> parse_document(std::string_view text) {
  return json::parse(text, Limits{}, std::string{});
}

Result<Value> parse_limited(std::string_view text, const Limits& limits,
                            std::string_view prefix = std::string_view{}) {
  return json::parse(text, limits, prefix);
}

// Parses a document that the test expects to be accepted. A failure reports the
// offending bytes and the defect instead of silently continuing.
Value parse_ok(std::string_view text) {
  const Result<Value> result = parse_document(text);
  if (!result.has_value()) {
    CHECK_MSG(false, "expected a successful parse of "
                         << ::fbm_test::describe(std::string{text}) << " but got "
                         << result.error().to_string());
    throw ::fbm_test::Abort{};
  }
  return result.value();
}

std::string canonical_text(std::string_view text) {
  return json::write_canonical(parse_ok(text));
}

struct RejectionCase {
  const char* name;
  std::string_view text;
  ErrorCode expected;
};

// Asserts the exact error code with CHECK_ERROR, and additionally names the case
// so a mismatch is identifiable without counting lines.
void check_rejection(const RejectionCase& item) {
  const Result<Value> result = parse_document(item.text);
  if (!result.has_value() && result.error().code() != item.expected) {
    CHECK_MSG(false, "case " << item.name << " produced " << result.error().to_string()
                             << " but expected "
                             << summon::fbm::error_code_token(item.expected));
  }
  CHECK_ERROR(result, item.expected);
}

void check_rejections(const std::vector<RejectionCase>& cases) {
  for (const RejectionCase& item : cases) {
    check_rejection(item);
  }
}

bool is_encoding_code(ErrorCode code) {
  const unsigned value = static_cast<unsigned>(code);
  return value >= 200u && value <= 211u;
}

}  // namespace

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

FBM_TEST(json_round_trips_scalar_values) {
  CHECK_EQ(canonical_text("null"), std::string{"null"});
  CHECK_EQ(canonical_text("true"), std::string{"true"});
  CHECK_EQ(canonical_text("false"), std::string{"false"});

  CHECK(parse_ok("0").is_integer());
  CHECK_EQ(parse_ok("0").as_integer(), std::int64_t{0});
  CHECK_EQ(canonical_text("0"), std::string{"0"});
  CHECK_EQ(canonical_text("42"), std::string{"42"});
  CHECK_EQ(canonical_text("-17"), std::string{"-17"});
  CHECK_EQ(canonical_text("9223372036854775807"), std::string{"9223372036854775807"});
  CHECK_EQ(canonical_text("-9223372036854775808"), std::string{"-9223372036854775808"});
  // -0 is the integer zero, which prints as plain decimal.
  CHECK_EQ(canonical_text("-0"), std::string{"0"});

  CHECK(parse_ok("1.5").is_real());
  CHECK_EQ(parse_ok("1.5").as_real(), 1.5);
  CHECK_EQ(canonical_text("1.5"), std::string{"1.5"});
  CHECK_EQ(canonical_text("0.0"), std::string{"0.0"});
  CHECK_EQ(canonical_text("-0.0"), std::string{"-0.0"});
  // A real never loses its dot or exponent, so it can never be re-read as an
  // integer.
  CHECK_EQ(canonical_text("1e3"), std::string{"1000.0"});
  CHECK_EQ(canonical_text("1E+3"), std::string{"1000.0"});
  CHECK_EQ(canonical_text("1e2"), std::string{"100.0"});
  CHECK_EQ(canonical_text("1e-5"), std::string{"1e-05"});
  CHECK_EQ(canonical_text("1e21"), std::string{"1e+21"});
  CHECK_EQ(canonical_text("5e-324"), std::string{"5e-324"});
  CHECK_EQ(canonical_text("1.7976931348623157e308"),
           std::string{"1.7976931348623157e+308"});
  CHECK_EQ(canonical_text("100000.0"), std::string{"1e+05"});
  CHECK_EQ(canonical_text("0.1"), std::string{"0.1"});

  CHECK_EQ(canonical_text("\"\""), std::string{"\"\""});
  CHECK_EQ(canonical_text("\"abc\""), std::string{"\"abc\""});
  CHECK_EQ(canonical_text("\"a\\nb\""), std::string{"\"a\\nb\""});
  CHECK_EQ(canonical_text("\"\\u0041\""), std::string{"\"A\""});
  CHECK_EQ(canonical_text("\"\\u00e9\""), std::string{"\"\xC3\xA9\""});
  CHECK_EQ(canonical_text("\"\\uD83D\\uDE00\""), std::string{"\"\xF0\x9F\x98\x80\""});
  // Escapes are minimal: the forward slash is not escaped on output, and the
  // short forms are used for the five named control characters.
  CHECK_EQ(canonical_text("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\""),
           std::string{"\"\\\"\\\\/\\b\\f\\n\\r\\t\""});
  CHECK_EQ(canonical_text("\"\\u0000\""), std::string{"\"\\u0000\""});
  CHECK_EQ(canonical_text("\"\\u001f\""), std::string{"\"\\u001F\""});
  CHECK_EQ(canonical_text("\"\\u007f\""), std::string{"\"\x7f\""});

  // Raw UTF-8 passes through unchanged, and a raw multibyte sequence is accepted.
  CHECK_EQ(canonical_text("\"\xC3\xA9\""), std::string{"\"\xC3\xA9\""});
  CHECK_EQ(canonical_text("\"\xE2\x82\xAC\""), std::string{"\"\xE2\x82\xAC\""});
  CHECK_EQ(canonical_text("\"\xEF\xBF\xBD\""), std::string{"\"\xEF\xBF\xBD\""});
}

FBM_TEST(json_round_trips_containers) {
  CHECK_EQ(canonical_text("[]"), std::string{"[]"});
  CHECK_EQ(canonical_text("{}"), std::string{"{}"});
  CHECK_EQ(canonical_text("[ ]"), std::string{"[]"});
  CHECK_EQ(canonical_text("{ }"), std::string{"{}"});
  CHECK_EQ(canonical_text(" [ 1 , 2 , 3 ] "), std::string{"[1,2,3]"});
  CHECK_EQ(canonical_text("[true,false,null]"), std::string{"[true,false,null]"});
  CHECK_EQ(canonical_text("{\"a\":[1,2],\"b\":{\"c\":null}}"),
           std::string{"{\"a\":[1,2],\"b\":{\"c\":null}}"});
  CHECK_EQ(canonical_text("[[[[1]]]]"), std::string{"[[[[1]]]]"});
  CHECK_EQ(canonical_text("{\"\":\"\"}"), std::string{"{\"\":\"\"}"});
  CHECK_EQ(canonical_text("[\"a\",\"b\"]"), std::string{"[\"a\",\"b\"]"});
  CHECK_EQ(canonical_text("\t\r\n{\"a\"\t:\r1}"), std::string{"{\"a\":1}"});

  const Value empty_array = parse_ok("[]");
  CHECK(empty_array.is_array());
  CHECK_EQ(empty_array.size(), std::size_t{0});
  const Value empty_object = parse_ok("{}");
  CHECK(empty_object.is_object());
  CHECK_EQ(empty_object.size(), std::size_t{0});
  const Value nested = parse_ok("{\"a\":[1,2]}");
  CHECK_EQ(nested.size(), std::size_t{1});
  CHECK(nested.has("a"));
  CHECK_EQ(nested.find("a")->size(), std::size_t{2});
}

FBM_TEST(json_canonical_round_trip_is_idempotent) {
  const std::vector<std::string> documents = {
      "null",
      "true",
      "false",
      "0",
      "-0",
      "1",
      "-17",
      "9223372036854775808",
      "1.5",
      "-0.0",
      "1e3",
      "1e-5",
      "12345678901234567890",
      "\"\"",
      "\"text\"",
      "\"a\\nb\"",
      "\"\\u00e9\\uD83D\\uDE00\"",
      "\"\\u001f\"",
      "[]",
      "{}",
      "[1,2,3]",
      "{\"a\":1}",
      "{\"z\":[1,2.5,true,null,\"x\"],\"a\":{\"b\":{\"c\":[]}}}",
      "[[[[[[1]]]]]]",
      "{\"\":\"\"}",
      "[{\"k\":\"v\"},{\"k\":\"w\"}]",
      "{\"counts\":[0,-1,9223372036854775807,-9223372036854775808]}",
  };
  for (const std::string& document : documents) {
    const Value first = parse_ok(document);
    const std::string canonical = json::write_canonical(first);
    const Value second = parse_ok(canonical);
    CHECK(first == second);
    CHECK_EQ(json::write_canonical(second), canonical);
    CHECK_EQ(json::write_canonical(parse_ok(json::write_canonical(second))), canonical);
  }
}

// ---------------------------------------------------------------------------
// Equality
// ---------------------------------------------------------------------------

FBM_TEST(json_structural_equality_distinguishes_types) {
  CHECK(parse_ok("1") == parse_ok("1"));
  CHECK(parse_ok("1") != parse_ok("2"));
  CHECK(parse_ok("true") == parse_ok("true"));
  CHECK(parse_ok("true") != parse_ok("false"));
  CHECK(parse_ok("null") == parse_ok("null"));
  CHECK(parse_ok("null") != parse_ok("false"));
  CHECK(parse_ok("\"a\"") == parse_ok("\"a\""));
  CHECK(parse_ok("\"a\"") != parse_ok("\"b\""));
  CHECK(parse_ok("[1,2]") == parse_ok("[1,2]"));
  CHECK(parse_ok("[1,2]") != parse_ok("[2,1]"));
  CHECK(parse_ok("[1,2]") != parse_ok("[1,2,3]"));
  CHECK(parse_ok("{\"a\":1}") != parse_ok("{\"a\":1,\"b\":2}"));
  CHECK(parse_ok("{\"a\":1}") != parse_ok("{\"a\":2}"));
  CHECK(parse_ok("{\"a\":1}") != parse_ok("{\"b\":1}"));
  CHECK(parse_ok("{\"a\":[1,{\"b\":null}]}") == parse_ok("{\"a\":[1,{\"b\":null}]}"));
  // Object equality ignores member order but not member identity.
  CHECK(parse_ok("{\"a\":1,\"b\":2}") == parse_ok("{\"b\":2,\"a\":1}"));

  // Integer 1 and Real 1.0 are NOT equal: they are different JSON types even
  // though they denote the same mathematical number, and canonical form keeps
  // them distinct.
  CHECK(parse_ok("1").is_integer());
  CHECK(parse_ok("1.0").is_real());
  CHECK(parse_ok("1") != parse_ok("1.0"));
  CHECK(parse_ok("[1]") != parse_ok("[1.0]"));
  CHECK(parse_ok("{\"a\":1}") != parse_ok("{\"a\":1.0}"));
  CHECK_EQ(canonical_text("1"), std::string{"1"});
  CHECK_EQ(canonical_text("1.0"), std::string{"1.0"});

  // Cross-type comparisons are always unequal.
  CHECK(parse_ok("1") != parse_ok("true"));
  CHECK(parse_ok("0") != parse_ok("false"));
  CHECK(parse_ok("1") != parse_ok("\"1\""));
  CHECK(parse_ok("null") != parse_ok("\"\""));

  // Hand-built values follow the same rules.
  Value left = Value::make_object();
  left.set("a", Value{std::int64_t{1}});
  Value right = Value::make_object();
  right.set("a", Value{1.0});
  CHECK(left != right);
  CHECK_EQ(json::write_canonical(left), std::string{"{\"a\":1}"});
  CHECK_EQ(json::write_canonical(right), std::string{"{\"a\":1.0}"});
}

FBM_TEST(json_canonical_sorts_object_keys) {
  // The same members in either order produce identical canonical bytes.
  const std::string b_then_a = canonical_text("{\"b\":1,\"a\":2}");
  const std::string a_then_b = canonical_text("{\"a\":2,\"b\":1}");
  CHECK_EQ(b_then_a, a_then_b);
  CHECK_EQ(b_then_a, std::string{"{\"a\":2,\"b\":1}"});

  // Sorting is by unsigned byte value: ASCII before multi-byte UTF-8, and
  // uppercase before lowercase.
  CHECK_EQ(canonical_text("{\"a\":1,\"B\":2}"), std::string{"{\"B\":2,\"a\":1}"});
  CHECK_EQ(canonical_text("{\"z\":2,\"\xC3\xA9\":1}"), std::string{"{\"z\":2,\"\xC3\xA9\":1}"});
  CHECK_EQ(canonical_text("{\"~\":1,\"\\u0100\":2}"), std::string{"{\"~\":1,\"\xC4\x80\":2}"});
  CHECK_EQ(canonical_text("{\"b\":0,\"c\":0,\"a\":0}"), std::string{"{\"a\":0,\"b\":0,\"c\":0}"});

  // Nested objects are sorted too.
  CHECK_EQ(canonical_text("{\"m\":{\"y\":1,\"x\":2}}"), std::string{"{\"m\":{\"x\":2,\"y\":1}}"});

  // The pretty writer uses the same order.
  CHECK_EQ(json::write_pretty(parse_ok("{\"b\":1,\"a\":[2]}"), 2),
           std::string{"{\n  \"a\": [\n    2\n  ],\n  \"b\": 1\n}"});
}

// ---------------------------------------------------------------------------
// Value mutation and the pretty writer
// ---------------------------------------------------------------------------

FBM_TEST(json_value_accessors_and_mutation) {
  Value object = Value::make_object();
  CHECK(object.is_object());
  CHECK(!object.is_array());
  CHECK_EQ(object.size(), std::size_t{0});
  CHECK(object.find("absent") == nullptr);
  CHECK(!object.has("absent"));

  object.set("b", Value{std::int64_t{2}});
  object.set("a", Value{std::string{"x"}});
  CHECK_EQ(object.size(), std::size_t{2});
  CHECK(object.has("a"));
  CHECK_EQ(object.find("a")->as_string(), std::string{"x"});
  CHECK_EQ(json::write_canonical(object), std::string{"{\"a\":\"x\",\"b\":2}"});

  // set() replaces in place instead of appending a duplicate.
  object.set("a", Value{std::string{"y"}});
  CHECK_EQ(object.size(), std::size_t{2});
  CHECK_EQ(object.find("a")->as_string(), std::string{"y"});
  CHECK_EQ(json::write_canonical(object), std::string{"{\"a\":\"y\",\"b\":2}"});

  CHECK(object.erase("a"));
  CHECK(!object.erase("a"));
  CHECK_EQ(object.size(), std::size_t{1});
  CHECK_EQ(json::write_canonical(object), std::string{"{\"b\":2}"});

  Value array = Value::make_array();
  array.push_back(Value{std::int64_t{1}});
  array.push_back(Value{"two"});
  CHECK_EQ(array.size(), std::size_t{2});
  CHECK(array.as_array()[1].is_string());
  CHECK_EQ(array.as_array()[1].as_string(), std::string{"two"});
  CHECK_EQ(json::write_canonical(array), std::string{"[1,\"two\"]"});

  CHECK(Value{}.is_null());
  CHECK(Value{nullptr}.is_null());
  CHECK(Value{true}.is_boolean());
  CHECK(Value{std::int64_t{1}}.is_integer());
  CHECK(Value{1.5}.is_real());
  CHECK(Value{"text"}.is_string());
  CHECK_EQ(Value{"text"}.size(), std::size_t{4});
  CHECK_EQ(Value{std::int64_t{1}}.size(), std::size_t{0});
  CHECK(Value{std::int64_t{1}}.is_number());
  CHECK(Value{1.5}.is_number());
  CHECK(!Value{"1"}.is_number());

  CHECK_EQ(json::type_name(Type::Null), std::string_view{"null"});
  CHECK_EQ(json::type_name(Type::Boolean), std::string_view{"boolean"});
  CHECK_EQ(json::type_name(Type::Integer), std::string_view{"integer"});
  CHECK_EQ(json::type_name(Type::Real), std::string_view{"real"});
  CHECK_EQ(json::type_name(Type::String), std::string_view{"string"});
  CHECK_EQ(json::type_name(Type::Array), std::string_view{"array"});
  CHECK_EQ(json::type_name(Type::Object), std::string_view{"object"});
}

FBM_TEST(json_pretty_writer_is_deterministic) {
  const Value value = parse_ok("{\"b\":[1,2],\"a\":{\"c\":null}}");
  const std::string expected =
      "{\n  \"a\": {\n    \"c\": null\n  },\n  \"b\": [\n    1,\n    2\n  ]\n}";
  CHECK_EQ(json::write_pretty(value, 2), expected);
  CHECK_EQ(json::write_pretty(value, 2), json::write_pretty(value, 2));
  CHECK_EQ(json::write_pretty(value, 0), std::string{"{\n\"a\": {\n\"c\": null\n},\n\"b\": [\n1,\n2\n]\n}"});
  CHECK_EQ(json::write_pretty(value, 4),
           std::string{"{\n    \"a\": {\n        \"c\": null\n    },\n    \"b\": [\n        1,\n        2\n    ]\n}"});
  CHECK_EQ(json::write_pretty(parse_ok("[]"), 2), std::string{"[]"});
  CHECK_EQ(json::write_pretty(parse_ok("{}"), 2), std::string{"{}"});
  CHECK_EQ(json::write_pretty(parse_ok("[[]]"), 2), std::string{"[\n  []\n]"});
  CHECK_EQ(json::write_pretty(parse_ok("1"), 4), std::string{"1"});
  CHECK_EQ(json::write_pretty(parse_ok("\"a\\nb\""), 2), std::string{"\"a\\nb\""});
  // Pretty output re-parses to the same value as canonical output.
  CHECK(parse_ok(json::write_pretty(value, 2)) == value);
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

FBM_TEST(json_reader_rejects_byte_order_mark) {
  const std::vector<RejectionCase> cases = {
      {"bom_then_object", "\xEF\xBB\xBF{}", ErrorCode::EncodingByteOrderMark},
      {"bom_only", "\xEF\xBB\xBF", ErrorCode::EncodingByteOrderMark},
      {"bom_then_array", "\xEF\xBB\xBF[]", ErrorCode::EncodingByteOrderMark},
      {"bom_then_number", "\xEF\xBB\xBF" "1", ErrorCode::EncodingByteOrderMark},
  };
  check_rejections(cases);
  // The byte order mark is only rejected as a document prefix; U+FEFF inside a
  // string is an ordinary character.
  CHECK_EQ(canonical_text("\"\xEF\xBB\xBF\""), std::string{"\"\xEF\xBB\xBF\""});
}

FBM_TEST(json_reader_rejects_invalid_utf8) {
  const std::vector<RejectionCase> cases = {
      {"two_byte_overlong_c0", "\"\xC0\x80\"", ErrorCode::EncodingInvalidUtf8},
      {"two_byte_overlong_c1", "\"\xC1\xBF\"", ErrorCode::EncodingInvalidUtf8},
      {"three_byte_overlong", "\"\xE0\x80\x80\"", ErrorCode::EncodingInvalidUtf8},
      {"three_byte_overlong_af", "\"\xE0\x80\xAF\"", ErrorCode::EncodingInvalidUtf8},
      {"four_byte_overlong", "\"\xF0\x80\x80\x80\"", ErrorCode::EncodingInvalidUtf8},
      {"encoded_surrogate_d800", "\"\xED\xA0\x80\"", ErrorCode::EncodingInvalidUtf8},
      {"encoded_surrogate_dfff", "\"\xED\xBF\xBF\"", ErrorCode::EncodingInvalidUtf8},
      {"lead_f5", "\"\xF5\x80\x80\x80\"", ErrorCode::EncodingInvalidUtf8},
      {"lead_ff", "\"\xFF\"", ErrorCode::EncodingInvalidUtf8},
      {"lead_fe", "\"\xFE\"", ErrorCode::EncodingInvalidUtf8},
      {"stray_continuation", "\"\x80\"", ErrorCode::EncodingInvalidUtf8},
      {"above_u10ffff", "\"\xF4\x90\x80\x80\"", ErrorCode::EncodingInvalidUtf8},
      {"truncated_two_byte", "\"\xC3", ErrorCode::EncodingInvalidUtf8},
      {"truncated_three_byte", "\"\xE2\x82", ErrorCode::EncodingInvalidUtf8},
      {"missing_continuation", "\"\xC3\"", ErrorCode::EncodingInvalidUtf8},
      {"bad_continuation", "\"\xE2\x82\x41\"", ErrorCode::EncodingInvalidUtf8},
      {"bare_lead_byte", "\xFE", ErrorCode::EncodingInvalidUtf8},
      {"bare_continuation_outside_string", "\x80", ErrorCode::EncodingInvalidUtf8},
      {"invalid_utf8_as_object_key", "{\"\xC0\x80\":1}", ErrorCode::EncodingInvalidUtf8},
      {"invalid_utf8_after_valid_prefix", "{\"a\":1,\"b\":\"\xFF\"}",
       ErrorCode::EncodingInvalidUtf8},
  };
  check_rejections(cases);

  // Boundaries that are valid UTF-8 must be accepted.
  CHECK_EQ(canonical_text("\"\xC2\x80\""), std::string{"\"\xC2\x80\""});
  CHECK_EQ(canonical_text("\"\xDF\xBF\""), std::string{"\"\xDF\xBF\""});
  CHECK_EQ(canonical_text("\"\xE0\xA0\x80\""), std::string{"\"\xE0\xA0\x80\""});
  CHECK_EQ(canonical_text("\"\xED\x9F\xBF\""), std::string{"\"\xED\x9F\xBF\""});
  CHECK_EQ(canonical_text("\"\xEE\x80\x80\""), std::string{"\"\xEE\x80\x80\""});
  CHECK_EQ(canonical_text("\"\xF0\x90\x80\x80\""), std::string{"\"\xF0\x90\x80\x80\""});
  CHECK_EQ(canonical_text("\"\xF4\x8F\xBF\xBF\""), std::string{"\"\xF4\x8F\xBF\xBF\""});
}

FBM_TEST(json_reader_rejects_unescaped_control_bytes) {
  const std::vector<RejectionCase> cases = {
      {"raw_newline", "\"a\nb\"", ErrorCode::EncodingUnescapedControl},
      {"raw_carriage_return", "\"a\rb\"", ErrorCode::EncodingUnescapedControl},
      {"raw_tab", "\"a\tb\"", ErrorCode::EncodingUnescapedControl},
      {"raw_nul", std::string_view{"\"\x00\"", 3}, ErrorCode::EncodingUnescapedControl},
      {"raw_unit_separator", "\"\x1f\"", ErrorCode::EncodingUnescapedControl},
      {"raw_backspace", "\"\x08\"", ErrorCode::EncodingUnescapedControl},
      {"object_key", "{\"a\nb\":1}", ErrorCode::EncodingUnescapedControl},
      {"array_element", "[\"a\rb\"]", ErrorCode::EncodingUnescapedControl},
  };
  check_rejections(cases);
}

FBM_TEST(json_reader_rejects_invalid_escapes) {
  const std::vector<RejectionCase> cases = {
      {"unknown_letter", "\"\\x\"", ErrorCode::EncodingInvalidEscape},
      {"single_quote", "\"\\'\"", ErrorCode::EncodingInvalidEscape},
      {"space", "\"\\ \"", ErrorCode::EncodingInvalidEscape},
      {"bad_hex_digit", "\"\\u12G4\"", ErrorCode::EncodingInvalidEscape},
      {"quote_as_hex_digit", "\"\\u12\"", ErrorCode::EncodingInvalidEscape},
      {"truncated_hex", "\"\\u12", ErrorCode::EncodingUnexpectedEnd},
      {"capital_u", "\"\\U0041\"", ErrorCode::EncodingInvalidEscape},
      {"bare_backslash_at_end", "\"a\\", ErrorCode::EncodingUnexpectedEnd},
      {"invalid_escape_as_key", "{\"\\q\":1}", ErrorCode::EncodingInvalidEscape},
  };
  check_rejections(cases);

  // Every accepted escape decodes to the documented character.
  CHECK_EQ(canonical_text("\"\\\"\""), std::string{"\"\\\"\""});
  CHECK_EQ(canonical_text("\"\\\\\""), std::string{"\"\\\\\""});
  CHECK_EQ(canonical_text("\"\\/\""), std::string{"\"/\""});
  CHECK_EQ(canonical_text("\"\\b\""), std::string{"\"\\b\""});
  CHECK_EQ(canonical_text("\"\\f\""), std::string{"\"\\f\""});
  CHECK_EQ(canonical_text("\"\\n\""), std::string{"\"\\n\""});
  CHECK_EQ(canonical_text("\"\\r\""), std::string{"\"\\r\""});
  CHECK_EQ(canonical_text("\"\\t\""), std::string{"\"\\t\""});
  CHECK_EQ(canonical_text("\"\\u0041\\u00e9\""), std::string{"\"A\xC3\xA9\""});
}

FBM_TEST(json_reader_rejects_lone_surrogates) {
  const std::vector<RejectionCase> cases = {
      {"high_surrogate_alone", "\"\\uD800\"", ErrorCode::EncodingInvalidSurrogate},
      {"high_surrogate_before_text", "\"\\uD800x\"", ErrorCode::EncodingInvalidSurrogate},
      {"high_surrogate_then_plain", "\"\\uD800\\u0041\"", ErrorCode::EncodingInvalidSurrogate},
      {"high_surrogate_then_high", "\"\\uD800\\uD800\"", ErrorCode::EncodingInvalidSurrogate},
      {"high_surrogate_then_high_max", "\"\\uDBFF\\uDBFF\"", ErrorCode::EncodingInvalidSurrogate},
      {"low_surrogate_alone", "\"\\uDC00\"", ErrorCode::EncodingInvalidSurrogate},
      {"low_surrogate_max", "\"\\uDFFF\"", ErrorCode::EncodingInvalidSurrogate},
      {"low_surrogate_as_key", "{\"\\uDC00\":1}", ErrorCode::EncodingInvalidSurrogate},
      {"high_surrogate_at_end", "\"\\uD800", ErrorCode::EncodingUnexpectedEnd},
  };
  check_rejections(cases);

  // A correct surrogate pair is one code point, emitted as raw UTF-8.
  CHECK_EQ(canonical_text("\"\\uD83D\\uDE00\""), std::string{"\"\xF0\x9F\x98\x80\""});
  CHECK_EQ(canonical_text("\"\\uD800\\uDC00\""), std::string{"\"\xF0\x90\x80\x80\""});
  CHECK_EQ(canonical_text("\"\\uDBFF\\uDFFF\""), std::string{"\"\xF4\x8F\xBF\xBF\""});
}

FBM_TEST(json_reader_rejects_malformed_numbers) {
  const std::vector<RejectionCase> cases = {
      {"leading_zero", "01", ErrorCode::EncodingUnexpectedByte},
      {"leading_zero_negative", "-01", ErrorCode::EncodingUnexpectedByte},
      {"double_zero", "00", ErrorCode::EncodingUnexpectedByte},
      {"leading_zero_in_array", "[01]", ErrorCode::EncodingUnexpectedByte},
      {"leading_plus", "+1", ErrorCode::EncodingUnexpectedByte},
      {"leading_plus_in_array", "[+1]", ErrorCode::EncodingUnexpectedByte},
      {"bare_dot", ".5", ErrorCode::EncodingUnexpectedByte},
      {"trailing_dot_in_array", "[1.]", ErrorCode::EncodingUnexpectedByte},
      {"trailing_dot_then_text", "[1.x]", ErrorCode::EncodingUnexpectedByte},
      {"trailing_dot_at_end", "1.", ErrorCode::EncodingUnexpectedEnd},
      {"dot_then_end", "-.", ErrorCode::EncodingUnexpectedByte},
      {"empty_exponent_at_end", "1e", ErrorCode::EncodingUnexpectedEnd},
      {"empty_exponent_in_array", "[1e]", ErrorCode::EncodingUnexpectedByte},
      {"exponent_sign_at_end", "1e+", ErrorCode::EncodingUnexpectedEnd},
      {"exponent_sign_in_array", "[1e+]", ErrorCode::EncodingUnexpectedByte},
      {"exponent_minus_at_end", "1e-", ErrorCode::EncodingUnexpectedEnd},
      {"double_sign", "--1", ErrorCode::EncodingUnexpectedByte},
      {"minus_at_end", "-", ErrorCode::EncodingUnexpectedEnd},
      {"nan_literal", "NaN", ErrorCode::EncodingUnexpectedByte},
      {"nan_in_array", "[NaN]", ErrorCode::EncodingUnexpectedByte},
      {"infinity_literal", "Infinity", ErrorCode::EncodingUnexpectedByte},
      {"negative_infinity", "-Infinity", ErrorCode::EncodingUnexpectedByte},
      {"hex_literal", "[0x10]", ErrorCode::EncodingUnexpectedByte},
      {"underscore_separator", "[1_000]", ErrorCode::EncodingUnexpectedByte},
      {"overflow", "1e400", ErrorCode::EncodingNumberOutOfRange},
      {"negative_overflow", "-1e400", ErrorCode::EncodingNumberOutOfRange},
      {"huge_exponent", "[1e999]", ErrorCode::EncodingNumberOutOfRange},
      {"overflowing_integer", "1e309", ErrorCode::EncodingNumberOutOfRange},
  };
  check_rejections(cases);
}

FBM_TEST(json_reader_rejects_malformed_literals) {
  const std::vector<RejectionCase> cases = {
      {"capital_true", "TRUE", ErrorCode::EncodingUnexpectedByte},
      {"mixed_true", "True", ErrorCode::EncodingUnexpectedByte},
      {"truncated_true", "tru", ErrorCode::EncodingUnexpectedEnd},
      {"misspelled_true", "trux", ErrorCode::EncodingUnexpectedByte},
      {"truncated_false", "fals", ErrorCode::EncodingUnexpectedEnd},
      {"truncated_null", "nul", ErrorCode::EncodingUnexpectedEnd},
      {"misspelled_null", "nulx", ErrorCode::EncodingUnexpectedByte},
      {"capital_null", "NULL", ErrorCode::EncodingUnexpectedByte},
      {"true_then_text_in_array", "[truex]", ErrorCode::EncodingUnexpectedByte},
      {"null_then_text_in_array", "[nulll]", ErrorCode::EncodingUnexpectedByte},
      {"empty_document", "", ErrorCode::EncodingUnexpectedEnd},
      {"whitespace_only", " \t\r\n", ErrorCode::EncodingUnexpectedEnd},
      {"unterminated_string", "\"abc", ErrorCode::EncodingUnexpectedEnd},
      {"unterminated_array", "[1,", ErrorCode::EncodingUnexpectedEnd},
      {"unterminated_object", "{\"a\":1", ErrorCode::EncodingUnexpectedEnd},
      {"open_bracket_only", "[", ErrorCode::EncodingUnexpectedEnd},
      {"open_brace_only", "{", ErrorCode::EncodingUnexpectedEnd},
  };
  check_rejections(cases);
}

FBM_TEST(json_reader_rejects_malformed_structures) {
  const std::vector<RejectionCase> cases = {
      {"duplicate_key", "{\"a\":1,\"a\":2}", ErrorCode::EncodingDuplicateKey},
      {"duplicate_key_nested", "{\"a\":{\"b\":1,\"b\":2}}", ErrorCode::EncodingDuplicateKey},
      {"duplicate_empty_key", "{\"\":1,\"\":2}", ErrorCode::EncodingDuplicateKey},
      {"duplicate_key_three", "{\"a\":1,\"a\":2,\"a\":3}", ErrorCode::EncodingDuplicateKey},
      {"trailing_comma_object", "{\"a\":1,}", ErrorCode::EncodingUnexpectedByte},
      {"trailing_comma_array", "[1,2,]", ErrorCode::EncodingUnexpectedByte},
      {"comma_only_object", "{,}", ErrorCode::EncodingUnexpectedByte},
      {"comma_only_array", "[,]", ErrorCode::EncodingUnexpectedByte},
      {"unquoted_key", "{1:2}", ErrorCode::EncodingUnexpectedByte},
      {"single_quoted_key", "{'a':1}", ErrorCode::EncodingUnexpectedByte},
      {"missing_colon", "{\"a\" 1}", ErrorCode::EncodingUnexpectedByte},
      {"colon_without_value", "{\"a\":}", ErrorCode::EncodingUnexpectedByte},
      {"missing_comma", "[1 2]", ErrorCode::EncodingUnexpectedByte},
      {"missing_comma_object", "{\"a\":1 \"b\":2}", ErrorCode::EncodingUnexpectedByte},
      {"double_comma", "[1,,2]", ErrorCode::EncodingUnexpectedByte},
      {"mismatched_close", "[1}", ErrorCode::EncodingUnexpectedByte},
      {"mismatched_close_object", "{\"a\":1]", ErrorCode::EncodingUnexpectedByte},
  };
  check_rejections(cases);
}

FBM_TEST(json_reader_rejects_trailing_content) {
  const std::vector<RejectionCase> cases = {
      {"two_objects", "{} {}", ErrorCode::EncodingTrailingContent},
      {"two_numbers", "1 2", ErrorCode::EncodingTrailingContent},
      {"array_then_text", "[1]x", ErrorCode::EncodingTrailingContent},
      {"null_then_null", "null null", ErrorCode::EncodingTrailingContent},
      {"true_then_text", "truex", ErrorCode::EncodingTrailingContent},
      {"number_then_text", "0x10", ErrorCode::EncodingTrailingContent},
      {"number_then_bracket", "1]", ErrorCode::EncodingTrailingContent},
      {"string_then_string", "\"a\"\"b\"", ErrorCode::EncodingTrailingContent},
      {"nested_then_object", "{\"a\":1}{\"b\":2}", ErrorCode::EncodingTrailingContent},
  };
  check_rejections(cases);
  // Trailing whitespace is not content.
  CHECK_EQ(canonical_text("{\"a\":1}\n\t "), std::string{"{\"a\":1}"});
}

// ---------------------------------------------------------------------------
// Error paths and limits
// ---------------------------------------------------------------------------

FBM_TEST(json_error_paths_are_json_pointers) {
  {
    const Result<Value> result = parse_document("{\"a\":{\"b\":[1,oops]}}");
    CHECK_ERROR(result, ErrorCode::EncodingUnexpectedByte);
    CHECK_EQ(result.error().path(), std::string{"/a/b/1"});
  }
  {
    const Result<Value> result = parse_limited("{\"a\":{\"b\":[1,oops]}}", Limits{}, "/root");
    CHECK_ERROR(result, ErrorCode::EncodingUnexpectedByte);
    CHECK_EQ(result.error().path(), std::string{"/root/a/b/1"});
  }
  {
    const Result<Value> result = parse_document("[0,[1,bad]]");
    CHECK_ERROR(result, ErrorCode::EncodingUnexpectedByte);
    CHECK_EQ(result.error().path(), std::string{"/1/1"});
  }
  {
    // '/' and '~' inside a key are escaped per RFC 6901.
    const Result<Value> result = parse_document("{\"a/b\":nope}");
    CHECK_ERROR(result, ErrorCode::EncodingUnexpectedByte);
    CHECK_EQ(result.error().path(), std::string{"/a~1b"});
  }
  {
    const Result<Value> result = parse_document("{\"a~b\":nope}");
    CHECK_ERROR(result, ErrorCode::EncodingUnexpectedByte);
    CHECK_EQ(result.error().path(), std::string{"/a~0b"});
  }
  {
    const Result<Value> result = parse_document("{\"a\":{\"b\":1,\"b\":2}}");
    CHECK_ERROR(result, ErrorCode::EncodingDuplicateKey);
    CHECK_EQ(result.error().path(), std::string{"/a/b"});
  }
  {
    const Result<Value> result = parse_document("{\"a\":\"unterminated");
    CHECK_ERROR(result, ErrorCode::EncodingUnexpectedEnd);
    CHECK_EQ(result.error().path(), std::string{"/a"});
  }
  {
    const Result<Value> result = parse_document("{\"a\":[1,\"\\q\"]}");
    CHECK_ERROR(result, ErrorCode::EncodingInvalidEscape);
    CHECK_EQ(result.error().path(), std::string{"/a/1"});
  }
  {
    Limits limits;
    limits.max_depth = 4;
    const Result<Value> result = parse_limited("{\"a\":{\"b\":[[[1]]]}}", limits);
    CHECK_ERROR(result, ErrorCode::EncodingDepthExceeded);
    CHECK_EQ(result.error().path(), std::string{"/a/b/0/0"});
  }
  {
    Limits limits;
    limits.max_array_elements = 2;
    const Result<Value> result = parse_limited("{\"a\":[1,2,3]}", limits);
    CHECK_ERROR(result, ErrorCode::EncodingSizeExceeded);
    CHECK_EQ(result.error().path(), std::string{"/a"});
  }
  {
    Limits limits;
    limits.max_object_members = 1;
    const Result<Value> result = parse_limited("{\"a\":1,\"b\":2}", limits);
    CHECK_ERROR(result, ErrorCode::EncodingSizeExceeded);
    CHECK_EQ(result.error().path(), std::string{});
  }
  {
    Limits limits;
    limits.max_bytes = 4;
    const Result<Value> result = parse_limited("{\"a\":1}", limits, "/doc");
    CHECK_ERROR(result, ErrorCode::EncodingSizeExceeded);
    CHECK_EQ(result.error().path(), std::string{"/doc"});
  }
  {
    Limits limits;
    limits.max_nodes = 3;
    const Result<Value> result = parse_limited("{\"a\":{\"b\":1,\"c\":2}}", limits);
    CHECK_ERROR(result, ErrorCode::EncodingSizeExceeded);
    CHECK_EQ(result.error().path(), std::string{"/a/c"});
  }
}

FBM_TEST(json_limits_are_enforced_before_allocating) {
  {
    Limits limits;
    limits.max_bytes = 4;
    CHECK(parse_limited("1234", limits).has_value());
    CHECK_ERROR(parse_limited("12345", limits), ErrorCode::EncodingSizeExceeded);
    CHECK_ERROR(parse_limited("[1,2]", limits), ErrorCode::EncodingSizeExceeded);
    Limits unbounded;
    unbounded.max_bytes = 4u * 1024u * 1024u;
    CHECK(parse_limited("[1,2]", unbounded).has_value());
  }
  {
    Limits limits;
    limits.max_depth = 3;
    CHECK(parse_limited("[[1]]", limits).has_value());
    CHECK(parse_limited("1", limits).has_value());
    CHECK_ERROR(parse_limited("[[[1]]]", limits), ErrorCode::EncodingDepthExceeded);
    CHECK_ERROR(parse_limited("{\"a\":{\"b\":[1]}}", limits),
                ErrorCode::EncodingDepthExceeded);
    // An empty container is one value deep, so it is still within the limit.
    CHECK(parse_limited("[[]]", limits).has_value());
    Limits scalars_only;
    scalars_only.max_depth = 1;
    CHECK(parse_limited("1", scalars_only).has_value());
    CHECK(parse_limited("[]", scalars_only).has_value());
    CHECK_ERROR(parse_limited("[1]", scalars_only), ErrorCode::EncodingDepthExceeded);
  }
  {
    Limits limits;
    limits.max_nodes = 3;
    CHECK(parse_limited("[1,2]", limits).has_value());
    CHECK(parse_limited("{\"a\":1}", limits).has_value());
    CHECK_ERROR(parse_limited("[1,2,3]", limits), ErrorCode::EncodingSizeExceeded);
    CHECK_ERROR(parse_limited("{\"a\":1,\"b\":2,\"c\":3}", limits),
                ErrorCode::EncodingSizeExceeded);
    // Three values are fine; a nested pair of arrays around two scalars is four.
    CHECK(parse_limited("[[1]]", limits).has_value());
    CHECK_ERROR(parse_limited("[[1,2]]", limits), ErrorCode::EncodingSizeExceeded);
  }
  {
    Limits limits;
    limits.max_string_bytes = 2;
    CHECK(parse_limited("\"ab\"", limits).has_value());
    CHECK(parse_limited("[\"ab\",\"cd\"]", limits).has_value());
    CHECK_ERROR(parse_limited("\"abc\"", limits), ErrorCode::EncodingSizeExceeded);
    // The limit counts decoded bytes, not source bytes.
    CHECK_ERROR(parse_limited("\"\\u0041\\u0042\\u0043\"", limits),
                ErrorCode::EncodingSizeExceeded);
    CHECK_ERROR(parse_limited("\"\\uD83D\\uDE00\"", limits), ErrorCode::EncodingSizeExceeded);
    CHECK_ERROR(parse_limited("{\"abc\":1}", limits), ErrorCode::EncodingSizeExceeded);
  }
  {
    Limits limits;
    limits.max_object_members = 2;
    CHECK(parse_limited("{\"a\":1,\"b\":2}", limits).has_value());
    CHECK_ERROR(parse_limited("{\"a\":1,\"b\":2,\"c\":3}", limits),
                ErrorCode::EncodingSizeExceeded);
  }
  {
    Limits limits;
    limits.max_array_elements = 2;
    CHECK(parse_limited("[1,2]", limits).has_value());
    CHECK_ERROR(parse_limited("[1,2,3]", limits), ErrorCode::EncodingSizeExceeded);
  }
  {
    // The default limits accept a moderate document.
    CHECK(parse_document("{\"a\":[1,2,3],\"b\":\"text\"}").has_value());
  }
}

// ---------------------------------------------------------------------------
// ObjectReader
// ---------------------------------------------------------------------------

FBM_TEST(json_object_reader_reports_fields) {
  const Value object = parse_ok(
      "{\"zeta\":1,\"alpha\":\"x\",\"mid\":true,\"count\":\"not-a-number\",\"yankee\":[],"
      "\"bravo\":{}}");
  Diagnostics diagnostics;
  ObjectReader reader{object, std::string{"/root"}, diagnostics};

  CHECK_EQ(reader.path(), std::string{"/root"});
  CHECK_EQ(reader.child_path("alpha"), std::string{"/root/alpha"});
  CHECK_EQ(reader.child_path("a/b"), std::string{"/root/a~1b"});
  CHECK_EQ(reader.child_path("a~b"), std::string{"/root/a~0b"});
  CHECK(reader.has("alpha"));
  CHECK(!reader.has("absent"));

  const Value* alpha = reader.required("alpha", Type::String);
  REQUIRE(alpha != nullptr);
  CHECK_EQ(alpha->as_string(), std::string{"x"});

  const Value* missing = reader.required("missing", Type::Integer);
  CHECK(missing == nullptr);

  // An absent optional field is silent.
  const Value* absent = reader.optional("absent", Type::String);
  CHECK(absent == nullptr);

  // A present field of the wrong type is reported and yields nothing.
  const Value* count = reader.required("count", Type::Integer);
  CHECK(count == nullptr);
  const Value* mid_wrong = reader.optional("mid", Type::String);
  CHECK(mid_wrong == nullptr);

  const Value* mid = reader.optional("mid", Type::Boolean);
  REQUIRE(mid != nullptr);
  CHECK(mid->as_boolean());

  // Only the missing field and the two wrong types are known before finish().
  REQUIRE(diagnostics.size() == 3);

  reader.finish();
  REQUIRE(diagnostics.size() == 6);
  const std::vector<Error>& errors = diagnostics.errors();
  CHECK_EQ(errors[0].code(), ErrorCode::SchemaMissingField);
  CHECK_EQ(errors[0].path(), std::string{"/root/missing"});
  CHECK(errors[0].message().find("missing") != std::string::npos);

  CHECK_EQ(errors[1].code(), ErrorCode::SchemaWrongType);
  CHECK_EQ(errors[1].path(), std::string{"/root/count"});
  // The message names the actual type through type_name().
  CHECK(errors[1].message().find("string") != std::string::npos);
  CHECK(errors[1].message().find("integer") != std::string::npos);

  CHECK_EQ(errors[2].code(), ErrorCode::SchemaWrongType);
  CHECK_EQ(errors[2].path(), std::string{"/root/mid"});

  // Unknown members are reported in ascending key order, not document order.
  CHECK_EQ(errors[3].code(), ErrorCode::SchemaUnknownField);
  CHECK_EQ(errors[3].path(), std::string{"/root/bravo"});
  CHECK_EQ(errors[4].code(), ErrorCode::SchemaUnknownField);
  CHECK_EQ(errors[4].path(), std::string{"/root/yankee"});
  CHECK_EQ(errors[5].code(), ErrorCode::SchemaUnknownField);
  CHECK_EQ(errors[5].path(), std::string{"/root/zeta"});

  // The report does not depend on the order of the members in the document.
  const Value reordered = parse_ok(
      "{\"bravo\":{},\"yankee\":[],\"count\":\"not-a-number\",\"mid\":true,\"alpha\":\"x\","
      "\"zeta\":1}");
  Diagnostics other;
  ObjectReader other_reader{reordered, std::string{"/root"}, other};
  CHECK(other_reader.required("alpha", Type::String) != nullptr);
  CHECK(other_reader.optional("mid", Type::Boolean) != nullptr);
  CHECK(other_reader.required("count", Type::Integer) == nullptr);
  other_reader.finish();
  REQUIRE(other.size() == 4);
  CHECK_EQ(other.errors()[0].code(), ErrorCode::SchemaWrongType);
  CHECK_EQ(other.errors()[0].path(), std::string{"/root/count"});
  CHECK_EQ(other.errors()[1].path(), std::string{"/root/bravo"});
  CHECK_EQ(other.errors()[2].path(), std::string{"/root/yankee"});
  CHECK_EQ(other.errors()[3].path(), std::string{"/root/zeta"});
}

FBM_TEST(json_object_reader_on_non_object) {
  const Value number = parse_ok("42");
  Diagnostics diagnostics;
  ObjectReader reader{number, std::string{"/n"}, diagnostics};
  CHECK(reader.required("a", Type::Integer) == nullptr);
  CHECK(reader.optional("a", Type::Integer) == nullptr);
  CHECK(!reader.has("a"));
  reader.finish();
  REQUIRE(diagnostics.size() == 1);
  CHECK_EQ(diagnostics.errors()[0].code(), ErrorCode::SchemaWrongType);
  CHECK_EQ(diagnostics.errors()[0].path(), std::string{"/n"});
  CHECK(diagnostics.errors()[0].message().find("integer") != std::string::npos);

  // An object with no members reports nothing.
  const Value empty = parse_ok("{}");
  Diagnostics none;
  ObjectReader empty_reader{empty, std::string{"/e"}, none};
  empty_reader.finish();
  CHECK_EQ(none.size(), std::size_t{0});

  // Requesting a member twice is not an unknown field, and does not duplicate
  // diagnostics.
  const Value once = parse_ok("{\"a\":1}");
  Diagnostics twice;
  ObjectReader twice_reader{once, std::string{}, twice};
  CHECK(twice_reader.required("a", Type::Integer) != nullptr);
  CHECK(twice_reader.required("a", Type::Integer) != nullptr);
  twice_reader.finish();
  CHECK_EQ(twice.size(), std::size_t{0});
}

FBM_TEST(json_pointer_joining) {
  CHECK_EQ(json::join_path("", "a"), std::string{"/a"});
  CHECK_EQ(json::join_path("/root", "a"), std::string{"/root/a"});
  CHECK_EQ(json::join_path("/root", "a/b"), std::string{"/root/a~1b"});
  CHECK_EQ(json::join_path("/root", "a~b"), std::string{"/root/a~0b"});
  CHECK_EQ(json::join_path("/root", "~/"), std::string{"/root/~0~1"});
  CHECK_EQ(json::join_path("/root", ""), std::string{"/root/"});
  CHECK_EQ(json::join_index("", 0), std::string{"/0"});
  CHECK_EQ(json::join_index("/root", 12), std::string{"/root/12"});
  CHECK_EQ(json::join_index("/root", std::size_t{123456789}), std::string{"/root/123456789"});
}

// ---------------------------------------------------------------------------
// Determinism over mutated documents
// ---------------------------------------------------------------------------

FBM_TEST(json_malformed_inputs_are_deterministic) {
  const std::vector<std::string> documents = {
      "{\"a\":[1,2,3],\"b\":{\"c\":true,\"d\":null},\"e\":\"text\"}",
      "[1,-2.5e3,\"x\\ny\",false,null,{}]",
      "-0.75",
      "\"\\u00e9\\uD83D\\uDE00\"",
      "[[[[1]]]]",
      "{\"\":\"\"}",
  };
  std::size_t accepted = 0;
  std::size_t rejected = 0;
  for (const std::string& document : documents) {
    std::vector<std::string> variants;
    for (std::size_t length = 0; length <= document.size(); ++length) {
      variants.push_back(document.substr(0, length));
    }
    for (std::size_t index = 0; index < document.size(); ++index) {
      std::string mutated = document;
      mutated[index] = 'x';
      variants.push_back(mutated);
    }
    for (const std::string& variant : variants) {
      const Result<Value> first = parse_document(variant);
      const Result<Value> second = parse_document(variant);
      CHECK_EQ(first.has_value(), second.has_value());
      if (first.has_value()) {
        ++accepted;
        CHECK(second.has_value());
        CHECK_EQ(json::write_canonical(first.value()), json::write_canonical(second.value()));
        CHECK_EQ(json::write_canonical(parse_ok(json::write_canonical(first.value()))),
                 json::write_canonical(first.value()));
      } else {
        ++rejected;
        CHECK(!second.has_value());
        CHECK_EQ(static_cast<unsigned>(first.error().code()),
                 static_cast<unsigned>(second.error().code()));
        CHECK_EQ(first.error().path(), second.error().path());
        CHECK_EQ(first.error().message(), second.error().message());
        // A malformed document is always rejected with a specific encoding
        // defect, never with an arbitrary code.
        CHECK(is_encoding_code(first.error().code()));
      }
    }
  }
  CHECK(accepted > 0);
  CHECK(rejected > 0);
}
