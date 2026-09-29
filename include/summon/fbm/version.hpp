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

#include <string>

// The version string is injected by the build system as FBM_VERSION_STRING so
// that the header remains usable, with an explicit "unknown" fallback, outside
// of the CMake build.
#ifndef FBM_VERSION_STRING
#define FBM_VERSION_STRING "0.0.0-unknown"
#endif

namespace summon::fbm {

// Product identity, reported by the CLI and embedded in nothing else.
inline constexpr const char* kProductName = "Firmware Baseline Manager";
inline constexpr const char* kProductVendor = "Summon Software Labs";

// Semantic version of this build.
std::string version_string();

// Durable record format version understood by this build. Bumping this value
// makes every previously written store unreadable by design; there is no
// silent migration path.
inline constexpr unsigned kDurableFormatVersion = 1u;

// Version of the canonical policy document schema understood by this build.
inline constexpr unsigned kPolicySchemaVersion = 1u;

// Compiler and build-configuration description of this build, for support
// diagnostics. Contains no machine-specific absolute paths.
std::string build_info();

}  // namespace summon::fbm
