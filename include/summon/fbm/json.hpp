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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "summon/fbm/error.hpp"
#include "summon/fbm/result.hpp"

// A strict, dependency-free JSON reader and canonical writer.
//
// "Strict" is load bearing: the reader rejects a byte order mark, invalid or
// overlong UTF-8, unpaired surrogates, raw control characters in strings,
// duplicate object keys, leading zeroes in numbers, the literals NaN and
// Infinity, trailing content after the top-level value, and documents that
// exceed the configured byte, depth, element, or string limits.
//
// Canonical form is a byte-for-byte reproducible serialization: no insignificant
// whitespace, object members sorted by key byte order, minimal string escapes,
// shortest round-trip real formatting. Two structurally equal documents always
// produce identical canonical bytes, which is what makes content-addressed
// digests meaningful.
namespace summon::fbm::json {

enum class Type : std::uint8_t {
  Null = 0,
  Boolean = 1,
  Integer = 2,
  Real = 3,
  String = 4,
  Array = 5,
  Object = 6,
};

std::string_view type_name(Type type) noexcept;

class Value {
 public:
  using Array = std::vector<Value>;
  using Member = std::pair<std::string, Value>;
  using Object = std::vector<Member>;

  Value() noexcept : storage_(nullptr) {}
  Value(std::nullptr_t) noexcept : storage_(nullptr) {}
  Value(bool value) noexcept : storage_(value) {}

  template <class T>
    requires(std::is_integral_v<T> && !std::is_same_v<T, bool>)
  Value(T value) noexcept : storage_(static_cast<std::int64_t>(value)) {}

  template <class T>
    requires std::is_floating_point_v<T>
  Value(T value) noexcept : storage_(static_cast<double>(value)) {}

  Value(std::string value) : storage_(std::move(value)) {}
  Value(const char* value) : storage_(std::string{value}) {}
  Value(Array value) : storage_(std::move(value)) {}
  Value(Object value) : storage_(std::move(value)) {}

  static Value make_object() { return Value{Object{}}; }
  static Value make_array() { return Value{Array{}}; }

  Type type() const noexcept;
  bool is_null() const noexcept { return type() == Type::Null; }
  bool is_boolean() const noexcept { return type() == Type::Boolean; }
  bool is_integer() const noexcept { return type() == Type::Integer; }
  bool is_real() const noexcept { return type() == Type::Real; }
  bool is_number() const noexcept { return is_integer() || is_real(); }
  bool is_string() const noexcept { return type() == Type::String; }
  bool is_array() const noexcept { return type() == Type::Array; }
  bool is_object() const noexcept { return type() == Type::Object; }

  // Typed accessors. Calling one with the wrong type is a programming error and
  // aborts rather than inventing a value.
  bool as_boolean() const;
  std::int64_t as_integer() const;
  double as_real() const;
  const std::string& as_string() const;
  const Array& as_array() const;
  Array& as_array();
  const Object& as_object() const;
  Object& as_object();

  // Object member lookup. Returns nullptr when the member is absent.
  const Value* find(std::string_view key) const noexcept;
  bool has(std::string_view key) const noexcept { return find(key) != nullptr; }

  // Inserts or replaces an object member. Aborts when this is not an object.
  void set(std::string key, Value value);

  // Removes an object member, returning true when a member was removed.
  bool erase(std::string_view key);

  // Appends to an array. Aborts when this is not an array.
  void push_back(Value value);

  std::size_t size() const noexcept;

  friend bool operator==(const Value& a, const Value& b) noexcept;
  friend bool operator!=(const Value& a, const Value& b) noexcept { return !(a == b); }

 private:
  using Storage =
      std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;
  Storage storage_;
};

// Resource limits applied while reading. Limits exist so that a hostile or
// truncated document fails deterministically instead of exhausting the host.
struct Limits {
  std::size_t max_bytes = 64u * 1024u * 1024u;
  std::size_t max_depth = 64u;
  std::size_t max_string_bytes = 4u * 1024u * 1024u;
  std::size_t max_nodes = 1u << 22;
  std::size_t max_object_members = 1u << 20;
  std::size_t max_array_elements = 1u << 20;
};

// Parses one complete JSON document. Every byte of the input must belong to the
// document. Errors carry the JSON pointer path of the offending value.
Result<Value> parse(std::string_view text, const Limits& limits, std::string_view path_prefix);

inline Result<Value> parse(std::string_view text) { return parse(text, Limits{}, std::string{}); }

// Canonical serialization: no insignificant whitespace, sorted object members.
std::string write_canonical(const Value& value);

// Human-readable serialization. Deterministic for a given value and indent.
std::string write_pretty(const Value& value, unsigned indent_width = 2u);

// Strict, order-independent reader for one JSON object.
//
// Every field access records a diagnostic instead of throwing, so a caller can
// gather all defects and then select the single deterministic primary error.
// Unknown members are reported by finish().
class ObjectReader {
 public:
  ObjectReader(const Value& object, std::string path, Diagnostics& diagnostics);

  const Value* required(std::string_view key, Type expected);
  const Value* optional(std::string_view key, Type expected);

  bool has(std::string_view key) const noexcept;

  // Reports every member that was never requested, sorted by key.
  void finish();

  const std::string& path() const noexcept { return path_; }
  std::string child_path(std::string_view key) const;

 private:
  const Value& object_;
  std::string path_;
  Diagnostics& diagnostics_;
  std::vector<std::string> requested_;
};

// Appends "/key" or "/index" to a JSON pointer path.
std::string join_path(std::string_view base, std::string_view key);
std::string join_index(std::string_view base, std::size_t index);

}  // namespace summon::fbm::json
