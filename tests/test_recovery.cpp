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

// Crash consistency, proved with real process termination.
//
// Each case builds a store with one committed generation, then runs
// fbm_crash_tool as an independent operating-system process that is terminated
// at one exact commit point with no cleanup, no destructor, and no atexit
// handler. A third process then opens the store and reports exactly which
// generation became authoritative.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "check.hpp"
#include "support.hpp"

using namespace summon::fbm;
using namespace fbm_test;

namespace {

constexpr int kCrashExitCode = 97;
constexpr std::uint64_t kFirstMarker = 1000000000ull;
constexpr std::uint64_t kCrashMarker = 2000000000ull;

struct CrashCase {
  const char* point;
  std::uint64_t expected_sequence;
  bool expected_unpublished;
  std::uint64_t expected_updated_at;
};

const CrashCase kCases[] = {
    {"before_stage_write", 1u, false, kFirstMarker},
    {"after_stage_flush", 1u, false, kFirstMarker},
    {"after_stage_verify", 1u, false, kFirstMarker},
    {"after_publish", 1u, true, kFirstMarker},
    {"before_fence_write", 1u, true, kFirstMarker},
    {"after_fence_write", 2u, false, kCrashMarker},
};

std::string directory_for(const char* name) {
  return scratch_directory(name).string();
}

}  // namespace

FBM_TEST(recovery_every_commit_point_recovers_exactly_one_generation) {
  for (const CrashCase& item : kCases) {
    const std::string tag = std::string{"crash-"} + item.point;
    const std::filesystem::path scratch = scratch_directory(tag);
    const std::string directory = scratch.string();

    ToolRun first = run_tool(FBM_PROC_TOOL_PATH,
                             {"commit", "--dir", directory, "--marker-nanos",
                              std::to_string(kFirstMarker)},
                             scratch, "first");
    REQUIRE(first.started);
    CHECK_EQ(first.exit_code, 0);
    CHECK_EQ(field_of(first.standard_output, "commit_sequence"), std::string{"1"});

    ToolRun crashed = run_tool(FBM_CRASH_TOOL_PATH,
                               {"--dir", directory, "--crash-at", item.point, "--marker-nanos",
                                std::to_string(kCrashMarker)},
                               scratch, "crash");
    REQUIRE(crashed.started);
    CHECK_MSG(crashed.exit_code == kCrashExitCode,
              "point " << item.point << " exited with " << crashed.exit_code << " stderr="
                       << crashed.standard_error);

    ToolRun status = run_tool(FBM_PROC_TOOL_PATH, {"status", "--dir", directory}, scratch, "status");
    REQUIRE(status.started);
    CHECK_EQ(status.exit_code, 0);
    CHECK_EQ(field_of(status.standard_output, "commit_sequence"),
             std::to_string(item.expected_sequence));
    CHECK_EQ(field_of(status.standard_output, "unpublished_slot_present"),
             item.expected_unpublished ? std::string{"true"} : std::string{"false"});

    ToolRun read = run_tool(FBM_PROC_TOOL_PATH, {"read", "--dir", directory}, scratch, "read");
    REQUIRE(read.started);
    CHECK_EQ(read.exit_code, 0);
    CHECK_EQ(field_of(read.standard_output, "commit_sequence"),
             std::to_string(item.expected_sequence));
    CHECK_MSG(field_of(read.standard_output, "updated_at") ==
                  std::to_string(item.expected_updated_at),
              "point " << item.point << " recovered updated_at="
                       << field_of(read.standard_output, "updated_at") << " expected "
                       << item.expected_updated_at);

    // The store must still be usable after the crash, and the next commit must
    // continue from the recovered sequence rather than from the lost one.
    ToolRun resumed = run_tool(FBM_PROC_TOOL_PATH,
                               {"commit", "--dir", directory, "--marker-nanos",
                                std::to_string(kCrashMarker + 1000ull)},
                               scratch, "resume");
    REQUIRE(resumed.started);
    CHECK_EQ(resumed.exit_code, 0);
    CHECK_EQ(field_of(resumed.standard_output, "commit_sequence"),
             std::to_string(item.expected_sequence + 1u));
  }
}

FBM_TEST(recovery_repeated_crashes_never_merge_partial_state) {
  const std::filesystem::path scratch = scratch_directory("crash-repeat");
  const std::string directory = scratch.string();

  ToolRun first = run_tool(FBM_PROC_TOOL_PATH,
                           {"commit", "--dir", directory, "--marker-nanos", "5000000000"},
                           scratch, "first");
  REQUIRE(first.started);
  CHECK_EQ(first.exit_code, 0);

  std::uint64_t expected = 1u;
  for (int round = 0; round < 3; ++round) {
    for (const CrashCase& item : kCases) {
      const std::uint64_t marker = 6000000000ull + static_cast<std::uint64_t>(round) * 100u;
      ToolRun crashed =
          run_tool(FBM_CRASH_TOOL_PATH,
                   {"--dir", directory, "--crash-at", item.point, "--marker-nanos",
                    std::to_string(marker)},
                   scratch, std::string{"crash-"} + item.point + "-" + std::to_string(round));
      REQUIRE(crashed.started);
      CHECK_EQ(crashed.exit_code, kCrashExitCode);

      ToolRun status =
          run_tool(FBM_PROC_TOOL_PATH, {"status", "--dir", directory}, scratch,
                   std::string{"status-"} + item.point + "-" + std::to_string(round));
      REQUIRE(status.started);
      const std::uint64_t observed =
          std::stoull(field_of(status.standard_output, "commit_sequence"));
      CHECK_MSG(observed == expected || observed == expected + 1u,
                "round " << round << " point " << item.point << " recovered sequence " << observed
                         << " expected " << expected << " or " << (expected + 1u));
      expected = observed;
    }
  }

  ToolRun final_read = run_tool(FBM_PROC_TOOL_PATH, {"read", "--dir", directory}, scratch, "final");
  REQUIRE(final_read.started);
  CHECK_EQ(final_read.exit_code, 0);
  CHECK_EQ(field_of(final_read.standard_output, "commit_sequence"), std::to_string(expected));
}

FBM_TEST(recovery_lock_is_released_when_the_holder_is_terminated) {
  const std::filesystem::path scratch = scratch_directory("crash-lock");
  const std::string directory = scratch.string();

  ToolRun first = run_tool(FBM_PROC_TOOL_PATH,
                           {"commit", "--dir", directory, "--marker-nanos", "7000000000"},
                           scratch, "first");
  REQUIRE(first.started);
  CHECK_EQ(first.exit_code, 0);

  ToolRun crashed = run_tool(FBM_CRASH_TOOL_PATH,
                             {"--dir", directory, "--crash-at", "after_publish", "--marker-nanos",
                              "8000000000"},
                             scratch, "crash");
  REQUIRE(crashed.started);
  CHECK_EQ(crashed.exit_code, kCrashExitCode);

  // The terminated process was holding the store writer lock at the instant it
  // died. The kernel, not the process, must have released it.
  ToolRun probe = run_tool(FBM_PROC_TOOL_PATH, {"lock-try", "--dir", directory}, scratch, "probe");
  REQUIRE(probe.started);
  CHECK_EQ(probe.exit_code, 0);
  CHECK_EQ(field_of(probe.standard_output, "acquired"), std::string{"true"});
}
