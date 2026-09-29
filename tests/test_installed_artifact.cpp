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

// Installed-artifact tests.
//
// These exercise the command-line artifact exactly as a user would: as a real
// operating-system process, with real arguments, real files, and a real exit
// code. The CMake packaging test in cmake/RunConsumerTest.cmake.in separately
// proves that an independent out-of-tree project can consume the installed
// package through find_package.

#include <filesystem>
#include <string>
#include <vector>

#include "check.hpp"
#include "support.hpp"

using namespace summon::fbm;
using namespace fbm_test;

namespace {

ToolRun cli(const std::vector<std::string>& arguments, const std::filesystem::path& scratch,
            const std::string& tag) {
  return run_tool(FBM_CLI_PATH, arguments, scratch, tag);
}

}  // namespace

FBM_TEST(installed_cli_reports_its_version) {
  const std::filesystem::path scratch = scratch_directory("cli-version");
  ToolRun run = cli({"version"}, scratch, "version");
  REQUIRE(run.started);
  CHECK_EQ(run.exit_code, 0);
  CHECK(run.standard_output.find("Firmware Baseline Manager") != std::string::npos);
  CHECK(run.standard_output.find(version_string()) != std::string::npos);
}

FBM_TEST(installed_cli_prints_usage_for_an_unknown_command) {
  const std::filesystem::path scratch = scratch_directory("cli-usage");
  ToolRun run = cli({"not-a-command"}, scratch, "unknown");
  REQUIRE(run.started);
  CHECK_EQ(run.exit_code, 2);
}

FBM_TEST(installed_cli_init_then_status_round_trips_through_a_real_process) {
  const std::filesystem::path scratch = scratch_directory("cli-init");
  const std::filesystem::path store = scratch / "store";

  ToolRun init = cli({"--store", store.string(), "init"}, scratch, "init");
  REQUIRE(init.started);
  CHECK_MSG(init.exit_code == 0, "init failed: " << init.standard_error);
  CHECK(std::filesystem::exists(store / "store.lock"));

  ToolRun status = cli({"--store", store.string(), "status"}, scratch, "status");
  REQUIRE(status.started);
  CHECK_EQ(status.exit_code, 0);

  ToolRun verify = cli({"--store", store.string(), "verify"}, scratch, "verify");
  REQUIRE(verify.started);
  CHECK_EQ(verify.exit_code, 0);

  // The store must still be exactly one authoritative generation afterwards.
  auto report = DurableStore::inspect(store);
  CHECK_OK(report);
  CHECK(report.value().outcome == RecoveryOutcome::Recovered);
}

FBM_TEST(installed_cli_rejects_a_missing_store_instead_of_creating_one) {
  const std::filesystem::path scratch = scratch_directory("cli-missing");
  const std::filesystem::path store = scratch / "absent";
  ToolRun run = cli({"--store", store.string(), "status"}, scratch, "missing");
  REQUIRE(run.started);
  CHECK_EQ(run.exit_code, 1);
  CHECK(!std::filesystem::exists(store));
}

FBM_TEST(installed_cli_json_output_parses_back) {
  const std::filesystem::path scratch = scratch_directory("cli-json");
  const std::filesystem::path store = scratch / "store";

  ToolRun init = cli({"--store", store.string(), "init"}, scratch, "init");
  REQUIRE(init.started);
  CHECK_EQ(init.exit_code, 0);

  ToolRun status = cli({"--store", store.string(), "--json", "status"}, scratch, "status");
  REQUIRE(status.started);
  CHECK_EQ(status.exit_code, 0);
  auto parsed = json::parse(status.standard_output);
  CHECK_MSG(parsed.has_value(), "status --json did not emit parseable JSON: "
                                    << status.standard_output << " error="
                                    << (parsed.has_value() ? std::string{} : parsed.error().to_string()));
}

FBM_TEST(installed_cli_output_is_deterministic_for_the_same_store) {
  const std::filesystem::path scratch = scratch_directory("cli-deterministic");
  const std::filesystem::path store = scratch / "store";

  ToolRun init = cli({"--store", store.string(), "init"}, scratch, "init");
  REQUIRE(init.started);
  CHECK_EQ(init.exit_code, 0);

  ToolRun first = cli({"--store", store.string(), "--at", "2026-02-01T00:00:00.000000000Z", "status"},
                      scratch, "first");
  REQUIRE(first.started);
  ToolRun second = cli({"--store", store.string(), "--at", "2026-02-01T00:00:00.000000000Z", "status"},
                       scratch, "second");
  REQUIRE(second.started);
  CHECK_EQ(first.exit_code, second.exit_code);
  CHECK_EQ(first.standard_output, second.standard_output);
}
