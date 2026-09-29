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

#include "summon/fbm/version.hpp"

#include <string>

namespace summon::fbm {
namespace {

// Compiler identity only. No include path, no source path, and no environment
// value enters this string, so two builds of the same source at the same
// version produce byte-identical diagnostics.
std::string compiler_description() {
#if defined(__clang__)
  return "Clang " + std::to_string(__clang_major__) + "." + std::to_string(__clang_minor__);
#elif defined(_MSC_VER)
  return "MSVC " + std::to_string(_MSC_VER / 100) + "." + std::to_string(_MSC_VER % 100);
#elif defined(__GNUC__)
  return "GCC " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__);
#else
  return "unknown compiler";
#endif
}

// Configuration derived only from the standard configuration macros. A build
// that defines neither macro is reported as unspecified rather than being
// guessed to be a release build.
std::string configuration_description() {
#if defined(NDEBUG) && defined(_DEBUG)
  return "Release+Debug";
#elif defined(NDEBUG)
  return "Release";
#elif defined(_DEBUG)
  return "Debug";
#else
  return "Unspecified";
#endif
}

}  // namespace

std::string version_string() { return std::string{FBM_VERSION_STRING}; }

std::string build_info() {
  return compiler_description() + " (" + configuration_description() + ")";
}

}  // namespace summon::fbm
