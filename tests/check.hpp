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

// Minimal, dependency-free test harness. Tests are proof obligations: every
// assertion names the property it checks, and a failure prints enough context
// (seed, iteration, operation index) to reproduce it exactly.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/result.hpp"

namespace fbm_test {

struct TestCase {
  const char* name;
  void (*function)();
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

inline int& failure_count() {
  static int count = 0;
  return count;
}

inline int& check_count() {
  static int count = 0;
  return count;
}

inline const char*& current_test() {
  static const char* name = "";
  return name;
}

// Thrown by REQUIRE to abandon the remainder of the current test without
// abandoning the run.
struct Abort {};

struct Registrar {
  Registrar(const char* name, void (*function)()) { registry().push_back(TestCase{name, function}); }
};

void report_failure(const char* file, int line, const std::string& message);

// --- Value description ------------------------------------------------------

template <class T>
std::string describe(const T& value);

template <class T>
std::string describe(const std::optional<T>& value) {
  return value.has_value() ? describe(*value) : std::string{"<unset>"};
}

template <class T>
std::string describe(const std::vector<T>& value) {
  std::string out = "[";
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (i != 0) {
      out += ", ";
    }
    out += describe(value[i]);
  }
  out += "]";
  return out;
}

template <class T>
std::string describe(const T& value) {
  if constexpr (requires(const T& v) { v.to_string(); }) {
    return value.to_string();
  } else if constexpr (requires(const T& v) { v.value(); v.is_set(); }) {
    if (value.is_set()) {
      std::ostringstream oss;
      oss << value.value();
      return oss.str();
    }
    return "<unset>";
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (requires(std::ostream& os, const T& v) { os << v; }) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
  } else {
    return "<unprintable>";
  }
}

template <>
inline std::string describe<std::string>(const std::string& value) {
  return "\"" + value + "\"";
}

inline std::string describe(bool value) { return value ? "true" : "false"; }
inline std::string describe(std::string_view value) { return "\"" + std::string{value} + "\""; }
inline std::string describe(const char* value) { return std::string{"\""} + value + "\""; }

// --- Scratch directories ----------------------------------------------------

// Returns a clean, existing scratch directory named "name" under
// FBM_TEST_SCRATCH (or ./test-scratch when the variable is unset).
std::filesystem::path scratch_directory(const std::string& name);

// Removes a directory tree, ignoring absence.
void remove_tree(const std::filesystem::path& path);

}  // namespace fbm_test

#define FBM_TEST(name)                                          \
  static void name();                                           \
  static const ::fbm_test::Registrar name##_registrar(#name, &name); \
  static void name()

#define FBM_CHECK_IMPL(cond, detail)                                                      \
  do {                                                                                    \
    ::fbm_test::check_count() += 1;                                                       \
    if (!(cond)) {                                                                        \
      std::ostringstream fbm_oss;                                                         \
      fbm_oss << detail;                                                                  \
      ::fbm_test::report_failure(__FILE__, __LINE__, fbm_oss.str());                      \
    }                                                                                     \
  } while (false)

#define CHECK(cond) FBM_CHECK_IMPL(cond, "expected: " #cond)

#define REQUIRE(cond)                                        \
  do {                                                       \
    ::fbm_test::check_count() += 1;                          \
    if (!(cond)) {                                           \
      ::fbm_test::report_failure(__FILE__, __LINE__,         \
                                 "required: " #cond);        \
      throw ::fbm_test::Abort{};                             \
    }                                                        \
  } while (false)

#define CHECK_MSG(cond, message)          \
  FBM_CHECK_IMPL(cond, message << " | expected: " #cond)

#define CHECK_EQ(a, b)                                                              \
  FBM_CHECK_IMPL((a) == (b), #a " == " #b " | left = " << ::fbm_test::describe(a)    \
                                << " right = " << ::fbm_test::describe(b))

#define CHECK_NE(a, b)                                                              \
  FBM_CHECK_IMPL((a) != (b), #a " != " #b " | left = " << ::fbm_test::describe(a)    \
                                << " right = " << ::fbm_test::describe(b))

#define CHECK_LT(a, b)                                                             \
  FBM_CHECK_IMPL((a) < (b), #a " < " #b " | left = " << ::fbm_test::describe(a)     \
                               << " right = " << ::fbm_test::describe(b))

#define CHECK_LE(a, b)                                                             \
  FBM_CHECK_IMPL((a) <= (b), #a " <= " #b " | left = " << ::fbm_test::describe(a)   \
                                << " right = " << ::fbm_test::describe(b))

#define CHECK_GT(a, b)                                                             \
  FBM_CHECK_IMPL((a) > (b), #a " > " #b " | left = " << ::fbm_test::describe(a)     \
                               << " right = " << ::fbm_test::describe(b))

#define CHECK_GE(a, b)                                                             \
  FBM_CHECK_IMPL((a) >= (b), #a " >= " #b " | left = " << ::fbm_test::describe(a)   \
                                << " right = " << ::fbm_test::describe(b))

// Asserts that a Result carries a value. The expression is evaluated exactly
// once.
#define CHECK_OK(result)                                                            \
  do {                                                                              \
    auto&& fbm_result = (result);                                                   \
    ::fbm_test::check_count() += 1;                                                 \
    if (!fbm_result.has_value()) {                                                  \
      ::fbm_test::report_failure(__FILE__, __LINE__,                                \
                                 std::string{#result " failed: "} +                 \
                                     fbm_result.error().to_string());               \
      throw ::fbm_test::Abort{};                                                    \
    }                                                                               \
  } while (false)

// Asserts that a Result carries the exact expected error code. The expression is
// evaluated exactly once.
#define CHECK_ERROR(result, expected_code)                                          \
  do {                                                                              \
    auto&& fbm_result = (result);                                                   \
    ::fbm_test::check_count() += 1;                                                 \
    if (fbm_result.has_value()) {                                                   \
      ::fbm_test::report_failure(__FILE__, __LINE__,                                \
                                 #result " unexpectedly succeeded");                \
      throw ::fbm_test::Abort{};                                                    \
    } else if (fbm_result.error().code() != (expected_code)) {                      \
      ::fbm_test::report_failure(                                                   \
          __FILE__, __LINE__,                                                       \
          std::string{#result " error was "} + fbm_result.error().to_string() +     \
              " expected token " +                                                  \
              std::string{::summon::fbm::error_code_token(expected_code)});         \
      throw ::fbm_test::Abort{};                                                    \
    }                                                                               \
  } while (false)
