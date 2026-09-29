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

// Real independent-process tests for the single-writer claim.
//
// Every observation about exclusion, cross-process visibility, and lock release
// on process death is made by a genuinely separate operating-system process,
// not by a thread inside the test process.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "check.hpp"
#include "support.hpp"

using namespace summon::fbm;
using namespace fbm_test;

namespace {

// Starts a peer that holds the store lock, then rendezvouses with it through a
// second peer that reports only once it has observed the lock as busy. The
// rendezvous makes the test deterministic without guessing at a sleep.
struct LockHolder {
  platform::ChildProcess process;
  bool started = false;
};

LockHolder start_holder(const std::filesystem::path& scratch, const std::string& directory) {
  LockHolder holder;
  const std::filesystem::path out = scratch / "holder.stdout";
  const std::filesystem::path err = scratch / "holder.stderr";
  auto spawned = platform::spawn_process(FBM_PROC_TOOL_PATH,
                                         {"lock-hold", "--dir", directory, "--millis", "600000"},
                                         scratch, out, err);
  if (!spawned.has_value()) {
    return holder;
  }
  holder.process = spawned.take();
  holder.started = true;
  return holder;
}

std::string directory_of(const char* name) { return scratch_directory(name).string(); }

}  // namespace

FBM_TEST(lock_a_peer_process_is_locked_out_while_another_holds_the_writer_lock) {
  const std::filesystem::path scratch = scratch_directory("mp-exclusion");
  const std::string directory = scratch.string();

  LockHolder holder = start_holder(scratch, directory);
  REQUIRE(holder.started);

  ToolRun observed = run_tool(FBM_PROC_TOOL_PATH,
                              {"lock-observe", "--dir", directory, "--millis", "15000"}, scratch,
                              "observe");
  REQUIRE(observed.started);
  CHECK_MSG(observed.exit_code == 0,
            "the peer never observed the lock as held: exit " << observed.exit_code << " out="
                                                              << observed.standard_output
                                                              << " err=" << observed.standard_error);
  CHECK_EQ(field_of(observed.standard_output, "busy"), std::string{"true"});

  ToolRun refused = run_tool(FBM_PROC_TOOL_PATH, {"lock-try", "--dir", directory}, scratch, "try");
  REQUIRE(refused.started);
  CHECK_EQ(refused.exit_code, 4);
  CHECK_EQ(field_of(refused.standard_output, "acquired"), std::string{"false"});

  platform::terminate_immediately(holder.process);
  auto exit_code = platform::wait_for_exit(holder.process);
  CHECK(exit_code.has_value());
  platform::abandon_process(holder.process);
}

FBM_TEST(lock_the_kernel_releases_the_lock_when_the_holder_is_killed) {
  const std::filesystem::path scratch = scratch_directory("mp-kill");
  const std::string directory = scratch.string();

  LockHolder holder = start_holder(scratch, directory);
  REQUIRE(holder.started);

  ToolRun observed = run_tool(FBM_PROC_TOOL_PATH,
                              {"lock-observe", "--dir", directory, "--millis", "15000"}, scratch,
                              "observe");
  REQUIRE(observed.started);
  CHECK_EQ(field_of(observed.standard_output, "busy"), std::string{"true"});

  CHECK(platform::terminate_immediately(holder.process).has_value());
  auto exit_code = platform::wait_for_exit(holder.process);
  CHECK(exit_code.has_value());
  platform::abandon_process(holder.process);

  ToolRun after = run_tool(FBM_PROC_TOOL_PATH, {"lock-try", "--dir", directory}, scratch, "after");
  REQUIRE(after.started);
  CHECK_MSG(after.exit_code == 0,
            "the lock survived the death of its holder: exit " << after.exit_code << " err="
                                                               << after.standard_error);
  CHECK_EQ(field_of(after.standard_output, "acquired"), std::string{"true"});
}

FBM_TEST(lock_separate_processes_see_each_others_committed_generations) {
  const std::filesystem::path scratch = scratch_directory("mp-visibility");
  const std::string directory = scratch.string();

  ToolRun first = run_tool(FBM_PROC_TOOL_PATH,
                           {"commit", "--dir", directory, "--marker-nanos", "1000"}, scratch, "c1");
  REQUIRE(first.started);
  CHECK_EQ(first.exit_code, 0);
  CHECK_EQ(field_of(first.standard_output, "commit_sequence"), std::string{"1"});

  ToolRun second = run_tool(FBM_PROC_TOOL_PATH,
                            {"commit", "--dir", directory, "--marker-nanos", "2000"}, scratch,
                            "c2");
  REQUIRE(second.started);
  CHECK_EQ(second.exit_code, 0);
  CHECK_EQ(field_of(second.standard_output, "commit_sequence"), std::string{"2"});

  ToolRun read = run_tool(FBM_PROC_TOOL_PATH, {"read", "--dir", directory}, scratch, "read");
  REQUIRE(read.started);
  CHECK_EQ(read.exit_code, 0);
  CHECK_EQ(field_of(read.standard_output, "commit_sequence"), std::string{"2"});
  CHECK_EQ(field_of(read.standard_output, "updated_at"), std::string{"2000"});

  ToolRun status = run_tool(FBM_PROC_TOOL_PATH, {"status", "--dir", directory}, scratch, "status");
  REQUIRE(status.started);
  CHECK_EQ(status.exit_code, 0);
  CHECK_EQ(field_of(status.standard_output, "commit_sequence"), std::string{"2"});
  CHECK_EQ(field_of(status.standard_output, "unpublished_slot_present"), std::string{"false"});
}

FBM_TEST(lock_incarnation_advances_once_per_opened_writer) {
  const std::filesystem::path scratch = scratch_directory("mp-incarnation");
  const std::string directory = scratch.string();

  // A plain durable-store open recovers a generation; it does not mint an
  // authority incarnation. Only an authority opening the store does that, and
  // that path is covered by the manager and state machine tests.
  ToolRun first = run_tool(FBM_PROC_TOOL_PATH, {"read", "--dir", directory}, scratch, "r1");
  REQUIRE(first.started);
  CHECK_EQ(first.exit_code, 0);
  CHECK_EQ(field_of(first.standard_output, "incarnation"), std::string{"unset"});
  CHECK_EQ(field_of(first.standard_output, "commit_sequence"), std::string{"unset"});
  CHECK_EQ(field_of(first.standard_output, "outcome"), std::string{"empty"});

  ToolRun second = run_tool(FBM_PROC_TOOL_PATH, {"read", "--dir", directory}, scratch, "r2");
  REQUIRE(second.started);
  CHECK_EQ(field_of(second.standard_output, "incarnation"), std::string{"unset"});

  ToolRun first_commit = run_tool(FBM_PROC_TOOL_PATH,
                                  {"commit", "--dir", directory, "--marker-nanos", "1000"}, scratch,
                                  "c1");
  REQUIRE(first_commit.started);
  CHECK_EQ(first_commit.exit_code, 0);
  CHECK_EQ(field_of(first_commit.standard_output, "commit_sequence"), std::string{"1"});

  // Still no incarnation: a commit records state, it does not claim an
  // authority identity.
  ToolRun third = run_tool(FBM_PROC_TOOL_PATH, {"read", "--dir", directory}, scratch, "r3");
  REQUIRE(third.started);
  CHECK_EQ(field_of(third.standard_output, "incarnation"), std::string{"unset"});
  CHECK_EQ(field_of(third.standard_output, "commit_sequence"), std::string{"1"});
}

FBM_TEST(lock_many_sequential_processes_all_serialize) {
  const std::filesystem::path scratch = scratch_directory("mp-serial");
  const std::string directory = scratch.string();

  for (std::uint64_t round = 1; round <= 6; ++round) {
    ToolRun run = run_tool(FBM_PROC_TOOL_PATH,
                           {"commit", "--dir", directory, "--marker-nanos",
                            std::to_string(round * 1000ull)},
                           scratch, "c" + std::to_string(round));
    REQUIRE(run.started);
    CHECK_EQ(run.exit_code, 0);
    CHECK_EQ(field_of(run.standard_output, "commit_sequence"), std::to_string(round));
  }

  ToolRun read = run_tool(FBM_PROC_TOOL_PATH, {"read", "--dir", directory}, scratch, "final");
  REQUIRE(read.started);
  CHECK_EQ(field_of(read.standard_output, "commit_sequence"), std::string{"6"});
  CHECK_EQ(field_of(read.standard_output, "revision"), std::string{"6"});
}
