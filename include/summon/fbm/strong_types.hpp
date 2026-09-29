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
#include <functional>
#include <string>
#include <string_view>

namespace summon::fbm {

// A string identity distinguished by a tag type. An unset identity compares
// unequal to every set identity, including one that carries an empty string, so
// "missing" can never be mistaken for a real value.
template <class Tag>
class StrongId {
 public:
  using tag_type = Tag;

  StrongId() = default;
  explicit StrongId(std::string value) : value_(std::move(value)), set_(true) {}

  static StrongId unset() { return StrongId{}; }

  bool is_set() const noexcept { return set_; }
  const std::string& value() const noexcept { return value_; }
  std::string_view view() const noexcept { return value_; }

  // The identity text, or "<unset>" when unset. Used for diagnostics only.
  std::string to_string() const { return set_ ? value_ : std::string{"<unset>"}; }

  friend bool operator==(const StrongId&, const StrongId&) = default;
  friend std::strong_ordering operator<=>(const StrongId&, const StrongId&) = default;

 private:
  std::string value_;
  bool set_ = false;
};

template <class Tag>
struct StrongIdHash {
  std::size_t operator()(const StrongId<Tag>& id) const noexcept {
    return std::hash<std::string>{}(id.value()) * 1099511628211ull + (id.is_set() ? 1u : 0u);
  }
};

// A scalar counter or generation distinguished by a tag type. An unset scalar
// is ordered before every set scalar, which is the explicit statement that
// "unknown" precedes "known" rather than equalling zero.
template <class Tag, class UInt = std::uint64_t>
class Scalar {
 public:
  using tag_type = Tag;
  using value_type = UInt;

  constexpr Scalar() noexcept = default;
  constexpr explicit Scalar(UInt value) noexcept : value_(value), set_(true) {}

  static constexpr Scalar unset() noexcept { return Scalar{}; }
  static constexpr Scalar first() noexcept { return Scalar{static_cast<UInt>(1)}; }

  constexpr bool is_set() const noexcept { return set_; }
  constexpr UInt value() const noexcept { return value_; }
  constexpr UInt value_or(UInt fallback) const noexcept { return set_ ? value_ : fallback; }

  // Successor, or nothing when the counter would overflow its representation.
  // Overflow is reported rather than wrapped.
  constexpr bool checked_next(Scalar& out) const noexcept {
    if (!set_) {
      return false;
    }
    if (value_ == static_cast<UInt>(-1)) {
      return false;
    }
    out = Scalar{static_cast<UInt>(value_ + 1)};
    return true;
  }

  friend constexpr bool operator==(const Scalar&, const Scalar&) = default;
  friend constexpr std::strong_ordering operator<=>(const Scalar&, const Scalar&) = default;

 private:
  UInt value_{};
  bool set_ = false;
};

template <class Tag, class UInt = std::uint64_t>
struct ScalarHash {
  std::size_t operator()(const Scalar<Tag, UInt>& value) const noexcept {
    return std::hash<UInt>{}(value.value()) * 1099511628211ull + (value.is_set() ? 1u : 0u);
  }
};

// Monotonic 64-bit counter.
template <class Tag>
using Counter = Scalar<Tag, std::uint64_t>;

// Reports a violated precondition. Preconditions guard states that must never
// be silently accepted; they are never used for input validation.
[[noreturn]] void precondition_failed(const char* expression, const char* file, int line);

}  // namespace summon::fbm

#define FBM_PRECONDITION(expr)                                       \
  do {                                                               \
    if (!(expr)) {                                                   \
      ::summon::fbm::precondition_failed(#expr, __FILE__, __LINE__); \
    }                                                                \
  } while (false)
