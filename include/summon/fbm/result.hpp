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

#include <cstdlib>
#include <iostream>
#include <optional>
#include <type_traits>
#include <utility>

#include "summon/fbm/error.hpp"

namespace summon::fbm {

// Empty success payload.
struct Unit {};

namespace detail {

[[noreturn]] inline void contract_violation(const char* what) noexcept {
  std::cerr << "fbm: contract violation: " << what << '\n';
  std::abort();
}

}  // namespace detail

// A value or an error, never both and never neither. Result is deliberately not
// default constructible: a default-constructed result would be exactly the
// "missing becomes success" conversion this system refuses to make.
template <class T>
class Result {
 public:
  using value_type = T;

  // Deliberate ergonomic conversion so that "return value;" and "return error;"
  // both work in factory functions.
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Error error) : error_(std::move(error)) {}      // NOLINT(google-explicit-constructor)

  Result(const Result&) = default;
  Result(Result&&) noexcept = default;
  Result& operator=(const Result&) = default;
  Result& operator=(Result&&) noexcept = default;
  ~Result() = default;

  bool has_value() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return has_value(); }

  const T& value() const& {
    if (!value_.has_value()) {
      detail::contract_violation("Result::value() on an error result");
    }
    return *value_;
  }
  T& value() & {
    if (!value_.has_value()) {
      detail::contract_violation("Result::value() on an error result");
    }
    return *value_;
  }
  T&& value() && {
    if (!value_.has_value()) {
      detail::contract_violation("Result::value() on an error result");
    }
    return std::move(*value_);
  }

  // Moves the payload out. Only valid on a success result.
  T take() {
    if (!value_.has_value()) {
      detail::contract_violation("Result::take() on an error result");
    }
    T out = std::move(*value_);
    value_.reset();
    return out;
  }

  const Error& error() const& {
    if (value_.has_value()) {
      detail::contract_violation("Result::error() on a success result");
    }
    return *error_;
  }

  // The payload when present, otherwise the supplied fallback. The fallback is
  // always supplied explicitly by the caller, so absence is never silently
  // converted into a default.
  T value_or(T fallback) const {
    return value_.has_value() ? *value_ : std::move(fallback);
  }

 private:
  std::optional<T> value_;
  std::optional<Error> error_;
};

// Result of an operation with no payload.
using Status = Result<Unit>;

inline Status ok_status() { return Status{Unit{}}; }

inline Status fail(ErrorCode code, std::string message, std::string path = {}) {
  return Status{Error{code, std::move(message), std::move(path)}};
}

inline Status fail(Error error) { return Status{std::move(error)}; }

}  // namespace summon::fbm
