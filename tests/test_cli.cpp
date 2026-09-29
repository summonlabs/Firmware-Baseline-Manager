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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include "check.hpp"
#include "support.hpp"
#include "summon/fbm/cli.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/platform.hpp"
#include "summon/fbm/policy_document.hpp"
#include "summon/fbm/version.hpp"

namespace {

using namespace summon::fbm;

// A fixed instant. Every CLI run in this file passes it with --at, so no test
// reads the system clock and every command sequence is reproducible.
const char* const kInstant = "2026-02-01T00:00:00.000000000Z";
const char* const kExpiresAt = "2026-03-01T00:00:00.000000000Z";

struct CliRun {
  int exit_code = -1;
  std::string out;
  std::string err;
};

CliRun run_raw(const std::vector<std::string>& arguments) {
  CliRun result;
  std::ostringstream out;
  std::ostringstream err;
  result.exit_code = run_cli(arguments, out, err);
  result.out = out.str();
  result.err = err.str();
  return result;
}

std::vector<std::string> with_globals(const std::filesystem::path& store, bool json,
                                      const std::vector<std::string>& arguments) {
  std::vector<std::string> full;
  full.emplace_back("--store");
  full.emplace_back(store.string());
  full.emplace_back("--at");
  full.emplace_back(kInstant);
  if (json) {
    full.emplace_back("--json");
  }
  full.insert(full.end(), arguments.begin(), arguments.end());
  return full;
}

CliRun run_in(const std::filesystem::path& store, const std::vector<std::string>& arguments) {
  return run_raw(with_globals(store, false, arguments));
}

CliRun run_json_in(const std::filesystem::path& store, const std::vector<std::string>& arguments) {
  return run_raw(with_globals(store, true, arguments));
}

// --- error shape ------------------------------------------------------------

bool valid_error_token(const std::string& token) {
  if (token.empty() || token == "unknown_error") {
    return false;
  }
  for (const char character : token) {
    const bool allowed = (character >= 'a' && character <= 'z') ||
                         (character >= '0' && character <= '9') || character == '_';
    if (!allowed) {
      return false;
    }
  }
  return true;
}

// A rejected request or a usage error prints exactly one line of the form
// "error: <token>: <message>".
void check_error_line(const CliRun& run) {
  CHECK_MSG(run.err.find('\n') != std::string::npos, "no error line was printed");
  CHECK_EQ(run.err.find('\n') + 1u, run.err.size());
  CHECK_EQ(run.err.rfind("error: ", 0u), 0u);
  const std::size_t separator = run.err.find(": ", 7u);
  CHECK(separator != std::string::npos);
  if (separator == std::string::npos) {
    return;
  }
  const std::string token = run.err.substr(7u, separator - 7u);
  CHECK_MSG(valid_error_token(token), "invalid error token " << token << " in " << run.err);
}

void check_rejected(const CliRun& run, const std::string& expected_token = std::string{}) {
  CHECK_EQ(run.exit_code, 1);
  check_error_line(run);
  if (!expected_token.empty()) {
    CHECK_MSG(run.err.rfind("error: " + expected_token + ": ", 0u) == 0u,
              "expected token " << expected_token << " but stderr was " << run.err);
  }
}

void check_usage(const CliRun& run) {
  CHECK_EQ(run.exit_code, 2);
  check_error_line(run);
}

void check_json_error(const CliRun& run, int expected_exit_code) {
  CHECK_EQ(run.exit_code, expected_exit_code);
  auto parsed = json::parse(run.err);
  CHECK_OK(parsed);
  const json::Value& value = parsed.value();
  CHECK(value.is_object());
  const json::Value* token = value.find("token");
  const json::Value* message = value.find("message");
  const json::Value* path = value.find("path");
  CHECK(token != nullptr);
  CHECK(message != nullptr);
  CHECK(path != nullptr);
  if (token != nullptr && token->is_string()) {
    CHECK_MSG(valid_error_token(token->as_string()), "invalid token " << token->as_string());
  }
  if (message != nullptr) {
    CHECK(message->is_string());
  }
  if (path != nullptr) {
    CHECK(path->is_string());
  }
}

CliRun require_ok(CliRun run) {
  ::fbm_test::check_count() += 1;
  if (run.exit_code != 0) {
    ::fbm_test::report_failure(__FILE__, __LINE__,
                               "command failed with exit " + std::to_string(run.exit_code) +
                                   " and stderr " + run.err);
    throw ::fbm_test::Abort{};
  }
  return run;
}

// --- files and documents ----------------------------------------------------

void write_file(const std::filesystem::path& path, const std::string& text) {
  auto written = platform::write_file_flushed(path, text);
  CHECK_MSG(written.has_value(), "could not write " << path.string() << ": "
                                                    << (written.has_value()
                                                            ? std::string{}
                                                            : written.error().to_string()));
}

std::string read_file(const std::filesystem::path& path) {
  auto content = platform::read_file(path, 4ull * 1024ull * 1024ull);
  CHECK_OK(content);
  return content.value();
}

// A draft baseline with two components, one compatibility rule, and three
// promotion stages so that one promotion leaves the cohort active. Components
// are ascending by component identity and the composed document is the same
// shape a policy author writes.
Baseline draft_baseline() {
  Baseline baseline;
  baseline.id = BaselineId{"gpu-h100-train"};
  baseline.title = "H100 training baseline";

  HardwareSelector selector;
  selector.hardware_class = HardwareClassId{"gpu"};
  selector.model = HardwareModelId{"h100"};
  selector.minimum_revision = HardwareRevision{1};
  selector.maximum_revision = HardwareRevision{4};
  baseline.selectors.push_back(selector);

  ComponentRequirement bios{.component = FirmwareComponentId{"bios"},
                            .approved_version = fbm_test::version("3.1.0")};
  bios.conformant_versions = {fbm_test::version("3.1.0")};
  bios.rollback_targets = {fbm_test::version("3.0.4")};
  bios.freshness = FreshnessBound::within(86400000000000ull);
  baseline.components.push_back(bios);

  ComponentRequirement bmc{.component = FirmwareComponentId{"bmc"},
                           .approved_version = fbm_test::version("2.4.1")};
  bmc.conformant_versions = {fbm_test::version("2.4.0"), fbm_test::version("2.4.1")};
  bmc.rollback_targets = {fbm_test::version("2.3.9")};
  bmc.freshness = FreshnessBound::within(86400000000000ull);
  baseline.components.push_back(bmc);

  CompatibilityRule rule;
  rule.id = RuleId{"r-bmc-bios"};
  rule.when_component = FirmwareComponentId{"bmc"};
  rule.when_versions = fbm_test::range("2.4.0", "2.4.99");
  rule.requirement.kind = RequirementKind::ComponentVersionInRange;
  rule.requirement.component = FirmwareComponentId{"bios"};
  rule.requirement.versions = fbm_test::range("3.0.0", "3.9.99");
  rule.reason = "BMC 2.4 requires BIOS 3.x";
  baseline.rules.add(rule);

  // Every threshold is stated explicitly. The gate demands one fully
  // conformant member, so promoting the cohort proves that a conformant asset
  // is still counted as conformant while it belongs to the running cohort.
  baseline.gate.minimum_conformant_basis_points = 10000u;
  baseline.gate.minimum_decided_assets = 1u;
  baseline.gate.minimum_conformant_assets = 1u;
  baseline.gate.required_stages = StageIndex{3};
  baseline.generation = BaselineGeneration{1};
  baseline.revision = Revision{1};
  baseline.state = BaselineState::Draft;
  baseline.created_at = fbm_test::base_time();
  return baseline;
}

void write_policy_document(const std::filesystem::path& path) {
  const PolicyDocument document({draft_baseline()});
  write_file(path, json::write_canonical(document.to_json()));
}

std::vector<std::string> observe_profile_arguments(const std::string& asset,
                                                   const std::string& sequence) {
  return {"observe", "--asset", asset, "--evidence", asset + ".profile", "--sequence", sequence,
          "--generation", "1", "--hardware-class", "gpu", "--model", "h100", "--revision", "2"};
}

std::vector<std::string> observe_component_arguments(const std::string& asset,
                                                     const std::string& component,
                                                     const std::string& version,
                                                     const std::string& sequence) {
  return {"observe",          "--asset",     asset,   "--evidence", asset + "." + component,
          "--sequence",       sequence,      "--generation", "1", "--component", component,
          "--version",        version};
}

// Drives init, define, publish, and the three observations that make node-01
// fully conformant.
void prepare_conformant_store(const std::filesystem::path& store,
                              const std::filesystem::path& policy) {
  write_policy_document(policy);
  require_ok(run_in(store, {"init"}));
  require_ok(run_in(store, {"baseline", "define", "--file", policy.string()}));
  require_ok(run_in(store, {"baseline", "publish", "gpu-h100-train", "--generation", "1"}));
  require_ok(run_in(store, observe_profile_arguments("node-01", "1")));
  require_ok(run_in(store, observe_component_arguments("node-01", "bmc", "2.4.1", "2")));
  require_ok(run_in(store, observe_component_arguments("node-01", "bios", "3.1.0", "3")));
}

// Reads one cohort's revision out of "cohort list --json".
std::uint64_t cohort_revision(const CliRun& listed, const std::string& id) {
  auto parsed = json::parse(listed.out);
  CHECK_OK(parsed);
  const json::Value* cohorts = parsed.value().find("cohorts");
  CHECK(cohorts != nullptr);
  if (cohorts == nullptr || !cohorts->is_array()) {
    return 0;
  }
  for (const json::Value& item : cohorts->as_array()) {
    const json::Value* identity = item.find("id");
    const json::Value* revision = item.find("revision");
    if (identity != nullptr && identity->is_string() && identity->as_string() == id) {
      if (revision != nullptr && revision->is_integer()) {
        return static_cast<std::uint64_t>(revision->as_integer());
      }
    }
  }
  return 0;
}

const std::vector<std::string> kOpenGateArguments = {
    "--capacity",    "open", "--capacity-generation",    "7", "--dependency", "open",
    "--dependency-generation", "8",    "--maintenance",  "open", "--maintenance-generation", "9",
    "--topology",    "open", "--topology-generation",    "10"};

// --- tests ------------------------------------------------------------------

FBM_TEST(cli_version_and_help_are_stable) {
  const CliRun version = run_raw({"version"});
  CHECK_EQ(version.exit_code, 0);
  CHECK(version.err.empty());
  CHECK(version.out.find(kProductName) != std::string::npos);
  CHECK(version.out.find(version_string()) != std::string::npos);
  CHECK(version.out.find(std::to_string(kDurableFormatVersion)) != std::string::npos);
  CHECK(version.out.find(build_info()) != std::string::npos);

  const CliRun json = run_raw({"version", "--json"});
  CHECK_EQ(json.exit_code, 0);
  CHECK(json.err.empty());
  auto parsed = json::parse(json.out);
  CHECK_OK(parsed);
  const json::Value& value = parsed.value();
  CHECK(value.is_object());
  CHECK_EQ(value.find("product")->as_string(), std::string{kProductName});
  CHECK_EQ(value.find("version")->as_string(), version_string());
  CHECK_EQ(value.find("durable_format_version")->as_integer(),
           static_cast<std::int64_t>(kDurableFormatVersion));
  CHECK_EQ(value.find("build")->as_string(), build_info());

  const CliRun help = run_raw({"help"});
  CHECK_EQ(help.exit_code, 0);
  CHECK(help.err.empty());
  CHECK(help.out.find("usage: fbm") != std::string::npos);
  CHECK(help.out.find("baseline publish") != std::string::npos);
  CHECK(help.out.find("token verify") != std::string::npos);

  const CliRun topic = run_raw({"help", "baseline"});
  CHECK_EQ(topic.exit_code, 0);
  CHECK(topic.out.find("baseline define") != std::string::npos);

  const CliRun nested = run_raw({"help", "cohort", "promote"});
  CHECK_EQ(nested.exit_code, 0);
  CHECK(nested.out.find("cohort promote") != std::string::npos);
}

FBM_TEST(cli_unknown_command_and_unknown_topics_exit_two) {
  const CliRun unknown = run_raw({"nonsense"});
  check_usage(unknown);
  CHECK(unknown.err.find("unknown command") != std::string::npos);

  check_usage(run_raw({"policy"}));
  check_usage(run_raw({"policy", "nonsense"}));
  check_usage(run_raw({"baseline", "nonsense"}));
  check_usage(run_raw({"exception", "nonsense"}));
  check_usage(run_raw({"cohort", "nonsense"}));
  check_usage(run_raw({"authorize", "nonsense"}));
  check_usage(run_raw({"token", "nonsense"}));
  check_usage(run_raw({"help", "nonsense"}));
  check_usage(run_raw({}));

  const CliRun unknown_option = run_raw({"version", "--bogus"});
  check_usage(unknown_option);
  CHECK(unknown_option.err.find("unknown option") != std::string::npos);
}

FBM_TEST(cli_usage_errors_exit_two_without_touching_the_store) {
  const std::filesystem::path scratch = fbm_test::scratch_directory("cli-usage");
  const std::filesystem::path store = scratch / "store";

  check_usage(run_in(store, {"status", "--bogus"}));
  check_usage(run_in(store, {"baseline", "publish", "gpu-h100-train"}));
  check_usage(run_in(store, {"baseline", "publish", "gpu-h100-train", "--generation", "x"}));
  check_usage(run_in(store, {"baseline", "publish", "bad id", "--generation", "1"}));
  check_usage(run_in(store, {"baseline", "publish", "a", "b", "--generation", "1"}));
  check_usage(run_in(store, {"observe", "--asset", "node-01"}));
  check_usage(run_in(store, {"observe", "--asset", "node-01", "--evidence", "e"}));
  check_usage(run_in(store,
                     {"observe", "--asset", "node-01", "--evidence", "e", "--sequence", "1"}));
  check_usage(run_in(store, {"observe", "--asset", "node-01", "--evidence", "e", "--sequence", "1",
                             "--component", "bmc", "--hardware-class", "gpu"}));
  check_usage(run_in(store, {"observe", "--asset", "node-01", "--evidence", "e", "--sequence", "1",
                             "--component", "bmc", "--capability", "sriov"}));
  check_usage(run_in(store, {"observe", "--asset", "node-01", "--evidence", "e", "--sequence", "1",
                             "--hardware-class", "gpu"}));
  check_usage(run_in(store, {"observe", "--asset", "node-01", "--evidence", "e", "--sequence", "1",
                             "--hardware-class", "gpu", "--model", "h100", "--version", "1.0.0"}));
  check_usage(run_in(store, {"observe", "--asset", "node-01", "--evidence", "e", "--sequence", "1",
                             "--hardware-class", "gpu", "--model", "h100", "--revision", "x"}));
  check_usage(run_in(store, {"exception", "add", "--id", "e1", "--hardware-class", "gpu",
                             "--reason", "r", "--approval", "a"}));
  check_usage(run_in(store, {"exception", "add", "--id", "e1", "--hardware-class", "gpu",
                             "--reason", "r", "--approval", "a", "--expires-at", kExpiresAt,
                             "--expires", "never"}));
  check_usage(run_in(store, {"exception", "add", "--id", "e1", "--hardware-class", "gpu",
                             "--reason", "r", "--approval", "a", "--expires", "sometimes"}));
  check_usage(run_in(store, {"exception", "add", "--id", "e1", "--hardware-class", "gpu",
                             "--reason", "", "--approval", "a", "--expires", "never"}));
  check_usage(run_in(store, {"cohort", "create", "--id", "wave-1", "--baseline", "gpu-h100-train",
                             "--generation", "1"}));
  check_usage(run_in(store, {"cohort", "create", "--id", "wave-1", "--baseline", "gpu-h100-train",
                             "--generation", "1", "--asset", "node-01", "--asset", "node-01"}));
  check_usage(run_in(store, {"cohort", "promote", "--id", "wave-1", "--revision", "1", "--capacity",
                             "maybe"}));
  check_usage(run_in(store, {"rollout-eligibility", "--asset", "node-01", "--capacity", "maybe"}));
  check_usage(run_in(store, {"rollback-eligibility", "--asset", "node-01"}));
  check_usage(run_in(store, {"rollback-eligibility", "--asset", "node-01", "--target", "not a version"}));
  check_usage(run_in(store, {"token", "verify", "--scope", "s", "--plan", "p"}));
  check_usage(run_in(store, {"policy", "apply", "--file"}));

  check_usage(run_raw({"--store"}));
  check_usage(run_raw({"--store", "--json", "version"}));
  check_usage(run_raw({"--at"}));
  check_usage(run_raw({"--at", "yesterday", "version"}));
  check_usage(run_raw({"--key-file"}));
  check_usage(run_raw({"--store", "anywhere", "version", "extra"}));

  // None of the runs above opened the store, so the directory was never
  // created: a usage error must not have a side effect.
  CHECK_EQ(std::filesystem::exists(store), false);
}
// --- JSON helpers -----------------------------------------------------------

const json::Value* member(const json::Value& object, const char* key) {
  const json::Value* found = object.find(key);
  REQUIRE(found != nullptr);
  return found;
}

std::string string_member(const json::Value& object, const char* key) {
  const json::Value* found = member(object, key);
  REQUIRE(found->is_string());
  return found->as_string();
}

json::Value parsed_or_abort(const CliRun& run) {
  auto parsed = json::parse(run.out);
  CHECK_OK(parsed);
  return parsed.take();
}

// --- lifecycle --------------------------------------------------------------

FBM_TEST(cli_lifecycle_end_to_end) {
  const std::filesystem::path scratch = fbm_test::scratch_directory("cli-lifecycle");
  const std::filesystem::path store = scratch / "store";
  const std::filesystem::path policy = scratch / "policy.json";
  write_policy_document(policy);

  const CliRun init = require_ok(run_in(store, {"init"}));
  CHECK(init.out.find("outcome") != std::string::npos);
  CHECK(init.out.find("incarnation") != std::string::npos);

  const CliRun status = require_ok(run_in(store, {"status"}));
  CHECK(status.out.find("commit_sequence") != std::string::npos);
  CHECK(status.out.find("control_epoch") != std::string::npos);
  CHECK(status.out.find("policy_generation") != std::string::npos);

  const CliRun verify = require_ok(run_in(store, {"verify"}));
  CHECK(verify.out.find("active_slot") != std::string::npos);
  CHECK(verify.out.find("notes") != std::string::npos);

  const CliRun define = require_ok(run_in(store, {"baseline", "define", "--file", policy.string()}));
  CHECK(define.out.find("gpu-h100-train") != std::string::npos);
  CHECK(define.out.find("draft") != std::string::npos);

  const CliRun list = require_ok(run_in(store, {"baseline", "list"}));
  CHECK(list.out.find("gpu-h100-train") != std::string::npos);
  CHECK(list.out.find("draft") != std::string::npos);

  const CliRun publish =
      require_ok(run_in(store, {"baseline", "publish", "gpu-h100-train", "--generation", "1"}));
  CHECK(publish.out.find("published") != std::string::npos);

  const CliRun profile = require_ok(run_in(store, observe_profile_arguments("node-01", "1")));
  CHECK(profile.out.find("recorded") != std::string::npos);
  CHECK(profile.out.find("hardware_class") != std::string::npos);

  const CliRun bmc = require_ok(run_in(store, observe_component_arguments("node-01", "bmc", "2.4.1", "2")));
  CHECK(bmc.out.find("bmc") != std::string::npos);
  CHECK(bmc.out.find("2.4.1") != std::string::npos);

  require_ok(run_in(store, observe_component_arguments("node-01", "bios", "3.1.0", "3")));

  const CliRun evaluate = require_ok(run_in(store, {"evaluate", "--asset", "node-01"}));
  CHECK_MSG(evaluate.out.find("conformant") != std::string::npos, evaluate.out);

  const CliRun drift = require_ok(run_in(store, {"drift", "--asset", "node-01"}));
  CHECK(drift.out.find("kind") != std::string::npos);

  const CliRun explain = require_ok(run_in(store, {"explain", "--asset", "node-01"}));
  CHECK(explain.out.find("node-01") != std::string::npos);

  const CliRun granted =
      require_ok(run_in(store, {"exception", "add", "--id", "exc-1", "--hardware-class", "gpu",
                                "--model", "h100", "--component", "bios", "--reason",
                                "planned bios maintenance", "--approval", "ap-1", "--expires-at",
                                kExpiresAt}));
  CHECK(granted.out.find("exc-1") != std::string::npos);
  CHECK(granted.out.find("active") != std::string::npos);

  const CliRun exceptions = require_ok(run_in(store, {"exception", "list"}));
  CHECK(exceptions.out.find("exc-1") != std::string::npos);

  const CliRun revoked =
      require_ok(run_in(store, {"exception", "revoke", "--id", "exc-1", "--revision", "1"}));
  CHECK(revoked.out.find("revoked") != std::string::npos);

  const CliRun cohort =
      require_ok(run_in(store, {"cohort", "create", "--id", "wave-1", "--baseline",
                                "gpu-h100-train", "--generation", "1", "--asset", "node-01"}));
  CHECK(cohort.out.find("wave-1") != std::string::npos);
  CHECK(cohort.out.find("draft") != std::string::npos);

  const CliRun cohorts = require_ok(run_in(store, {"cohort", "list"}));
  CHECK(cohorts.out.find("wave-1") != std::string::npos);

  const CliRun authorized =
      require_ok(run_in(store, {"cohort", "authorize", "--id", "wave-1", "--revision", "1"}));
  CHECK(authorized.out.find("authorized") != std::string::npos);

  std::vector<std::string> promote_arguments{"cohort", "promote", "--id", "wave-1", "--revision",
                                             "2"};
  promote_arguments.insert(promote_arguments.end(), kOpenGateArguments.begin(),
                           kOpenGateArguments.end());
  const CliRun promoted = require_ok(run_in(store, promote_arguments));
  CHECK(promoted.out.find("satisfied") != std::string::npos);
  CHECK(promoted.out.find("true") != std::string::npos);
  CHECK(promoted.out.find("active") != std::string::npos);

  const std::uint64_t revision = cohort_revision(run_json_in(store, {"cohort", "list"}), "wave-1");
  CHECK_GE(revision, 3u);

  const CliRun rollout =
      require_ok(run_in(store, {"authorize", "rollout", "--id", "wave-1", "--revision",
                                std::to_string(revision), "--request", "req-rollout"}));
  CHECK(rollout.out.find("cohort/wave-1/rollout") != std::string::npos);
  CHECK(rollout.out.find("wave-1.plan") != std::string::npos);
  CHECK(rollout.out.find("none") != std::string::npos);

  const std::string token_text = fbm_test::field_of(rollout.out, "token");
  CHECK(!token_text.empty());
  auto token_value = json::parse(token_text);
  CHECK_OK(token_value);
  CHECK(member(token_value.value(), "binding")->is_object());
  CHECK(member(token_value.value(), "mac")->is_string());
  const std::filesystem::path token_file = scratch / "token.json";
  write_file(token_file, token_text);

  const CliRun verified =
      require_ok(run_in(store, {"token", "verify", "--scope", "cohort/wave-1/rollout", "--plan",
                                "wave-1.plan", "--token", token_file.string()}));
  CHECK(verified.out.find("valid") != std::string::npos);
  CHECK(verified.out.find("true") != std::string::npos);

  check_rejected(run_in(store, {"token", "verify", "--scope", "cohort/wave-1/rollback", "--plan",
                                "wave-1.plan", "--token", token_file.string()}),
                 "authority_foreign_scope");

  // A promotion whose gate is not satisfied is reported as a rejected request,
  // and the gate report is printed so the unmet conditions stay visible.
  require_ok(run_in(store, {"cohort", "create", "--id", "wave-2", "--baseline", "gpu-h100-train",
                            "--generation", "1", "--asset", "node-99"}));
  require_ok(run_in(store, {"cohort", "authorize", "--id", "wave-2", "--revision", "1"}));
  const CliRun unmet =
      run_in(store, {"cohort", "promote", "--id", "wave-2", "--revision", "2"});
  check_rejected(unmet, "policy_gate_not_satisfied");
  CHECK(unmet.out.find("unmet_conditions") != std::string::npos);
}

FBM_TEST(cli_rejected_requests_exit_one) {
  const std::filesystem::path scratch = fbm_test::scratch_directory("cli-rejected");
  const std::filesystem::path store = scratch / "store";
  const std::filesystem::path policy = scratch / "policy.json";
  write_policy_document(policy);

  // A missing store is never created implicitly.
  const CliRun missing = run_in(store, {"status"});
  check_rejected(missing);
  CHECK_EQ(std::filesystem::exists(store), false);

  const CliRun missing_verify = run_in(store, {"verify"});
  check_rejected(missing_verify);
  CHECK_EQ(std::filesystem::exists(store), false);

  require_ok(run_in(store, {"init"}));
  require_ok(run_in(store, {"baseline", "define", "--file", policy.string()}));
  require_ok(run_in(store, {"baseline", "publish", "gpu-h100-train", "--generation", "1"}));

  check_rejected(run_in(store, {"baseline", "publish", "no-such-baseline", "--generation", "1"}),
                 "identity_unknown_baseline");
  check_rejected(run_in(store, {"baseline", "publish", "gpu-h100-train", "--generation", "99"}),
                 "authority_stale_generation");
  check_rejected(run_in(store, {"baseline", "retire", "gpu-h100-train", "--generation", "99"}),
                 "authority_stale_generation");
  check_rejected(run_in(store, {"cohort", "create", "--id", "wave-1", "--baseline",
                                "gpu-h100-train", "--generation", "99", "--asset", "node-01"}),
                 "authority_stale_generation");
  check_rejected(run_in(store, {"cohort", "authorize", "--id", "no-such-cohort", "--revision", "1"}),
                 "identity_unknown_cohort");
  check_rejected(run_in(store, {"exception", "revoke", "--id", "no-such-exception", "--revision", "1"}),
                 "identity_unknown_exception");
  check_rejected(run_in(store, {"baseline", "define", "--file", (scratch / "no.json").string()}));
  check_rejected(run_in(store, {"policy", "apply", "--file", (scratch / "no.json").string()}));
  check_rejected(run_in(store, {"policy", "export", "--out",
                                (scratch / "no-such-directory" / "out.json").string()}));
  check_rejected(run_in(store, {"token", "verify", "--scope", "s", "--plan", "p",
                                "--token", (scratch / "no-token.json").string()}));

  const std::filesystem::path not_a_document = scratch / "not-a-document.json";
  write_file(not_a_document, "{\"schema\":\"summon.fbm.policy\"}");
  check_rejected(run_in(store, {"policy", "apply", "--file", not_a_document.string()}));

  // A document whose baseline is already published cannot be defined as a draft.
  const std::filesystem::path exported = scratch / "exported.json";
  require_ok(run_in(store, {"policy", "export", "--out", exported.string()}));
  check_rejected(run_in(store, {"baseline", "define", "--file", exported.string()}),
                 "schema_inconsistent_document");
}

FBM_TEST(cli_json_output_parses_back) {
  const std::filesystem::path scratch = fbm_test::scratch_directory("cli-json");
  const std::filesystem::path store = scratch / "store";
  const std::filesystem::path policy = scratch / "policy.json";
  prepare_conformant_store(store, policy);

  const json::Value status = parsed_or_abort(require_ok(run_json_in(store, {"status"})));
  CHECK(member(status, "recovery")->is_object());
  CHECK(member(status, "incarnation")->is_integer());
  CHECK(member(status, "policy_generation")->is_integer());

  const json::Value verify = parsed_or_abort(require_ok(run_json_in(store, {"verify"})));
  CHECK(member(verify, "outcome")->is_string());
  CHECK(member(verify, "active_slot")->is_integer());

  const json::Value baselines = parsed_or_abort(require_ok(run_json_in(store, {"baseline", "list"})));
  const json::Value* list = member(baselines, "baselines");
  REQUIRE(list->is_array());
  CHECK_EQ(list->as_array().size(), 1u);
  CHECK_EQ(string_member(list->as_array().front(), "id"), std::string{"gpu-h100-train"});
  CHECK_EQ(string_member(list->as_array().front(), "state"), std::string{"published"});

  const json::Value evaluate =
      parsed_or_abort(require_ok(run_json_in(store, {"evaluate", "--asset", "node-01"})));
  CHECK_EQ(string_member(evaluate, "state"), std::string{"conformant"});

  const json::Value drift =
      parsed_or_abort(require_ok(run_json_in(store, {"drift", "--asset", "node-01"})));
  CHECK(member(drift, "residuals")->is_array());

  const json::Value explain =
      parsed_or_abort(require_ok(run_json_in(store, {"explain", "--asset", "node-01"})));
  CHECK(member(explain, "explanation")->is_string());

  const json::Value eligibility =
      parsed_or_abort(require_ok(run_json_in(store, {"rollout-eligibility", "--asset", "node-01"})));
  CHECK(member(eligibility, "eligibility")->is_string());
  CHECK(member(eligibility, "blockers")->is_array());

  const json::Value exceptions =
      parsed_or_abort(require_ok(run_json_in(store, {"exception", "list"})));
  CHECK(member(exceptions, "exceptions")->is_array());

  const json::Value cohorts = parsed_or_abort(require_ok(run_json_in(store, {"cohort", "list"})));
  CHECK(member(cohorts, "cohorts")->is_array());

  const json::Value observe =
      parsed_or_abort(require_ok(run_json_in(store, observe_profile_arguments("node-01", "9"))));
  CHECK_EQ(string_member(observe, "kind"), std::string{"hardware"});
  CHECK(member(observe, "hardware")->is_object());

  check_json_error(run_json_in(store, {"baseline", "publish", "no-such-baseline", "--generation", "1"}),
                   1);
  check_json_error(run_json_in(store, {"status", "--bogus"}), 2);
  check_json_error(run_json_in(store, {"baseline", "publish", "gpu-h100-train", "--generation", "x"}),
                   2);
}

// --- determinism ------------------------------------------------------------

std::string command_transcript(const CliRun& run) {
  std::string text;
  text += "exit=" + std::to_string(run.exit_code) + "\n";
  text += "stdout:\n";
  text += run.out;
  text += "stderr:\n";
  text += run.err;
  return text;
}

// One command of the reproduction series: its label and the exact bytes it
// produced on both streams.
struct SeriesStep {
  std::string label;
  std::string output;
};

std::vector<SeriesStep> run_series(const std::filesystem::path& store,
                                   const std::filesystem::path& shared) {
  const std::string policy = (shared / "policy.json").string();
  const std::string token = (shared / "token.json").string();
  const std::string exported = (shared / "exported.json").string();
  std::vector<SeriesStep> steps;
  const auto step = [&steps](const char* label, const CliRun& run) {
    steps.push_back(SeriesStep{std::string{label}, command_transcript(run)});
  };

  step("init", run_in(store, {"init"}));
  step("status", run_in(store, {"status"}));
  step("verify", run_in(store, {"verify"}));
  step("define", run_in(store, {"baseline", "define", "--file", policy}));
  step("list", run_json_in(store, {"baseline", "list"}));
  step("publish",
       run_in(store, {"baseline", "publish", "gpu-h100-train", "--generation", "1"}));
  step("observe-profile", run_in(store, observe_profile_arguments("node-01", "1")));
  step("observe-bmc", run_in(store, observe_component_arguments("node-01", "bmc", "2.4.1", "2")));
  step("observe-bios", run_in(store, observe_component_arguments("node-01", "bios", "3.1.0", "3")));
  step("evaluate", run_json_in(store, {"evaluate", "--asset", "node-01"}));
  step("eligibility-unknown", run_in(store, {"rollout-eligibility", "--asset", "node-01"}));
  std::vector<std::string> open_eligibility{"rollout-eligibility", "--asset", "node-01"};
  open_eligibility.insert(open_eligibility.end(), kOpenGateArguments.begin(),
                          kOpenGateArguments.end());
  step("eligibility-open", run_in(store, open_eligibility));
  step("drift", run_in(store, {"drift", "--asset", "node-01"}));
  step("explain", run_in(store, {"explain", "--asset", "node-01"}));
  step("exception-add",
       run_in(store, {"exception", "add", "--id", "exc-1", "--hardware-class", "gpu", "--model",
                      "h100", "--component", "bios", "--reason", "planned bios maintenance",
                      "--approval", "ap-1", "--expires-at", kExpiresAt}));
  step("exception-list", run_in(store, {"exception", "list"}));
  step("exception-revoke",
       run_in(store, {"exception", "revoke", "--id", "exc-1", "--revision", "1"}));
  step("cohort-create", run_in(store, {"cohort", "create", "--id", "wave-1", "--baseline",
                                       "gpu-h100-train", "--generation", "1", "--asset", "node-01"}));
  step("cohort-list", run_in(store, {"cohort", "list"}));
  step("cohort-authorize",
       run_in(store, {"cohort", "authorize", "--id", "wave-1", "--revision", "1"}));
  std::vector<std::string> promote{"cohort", "promote", "--id", "wave-1", "--revision", "2"};
  promote.insert(promote.end(), kOpenGateArguments.begin(), kOpenGateArguments.end());
  step("cohort-promote", run_in(store, promote));

  const CliRun rollout = run_in(store, {"authorize", "rollout", "--id", "wave-1", "--revision", "3",
                                        "--request", "req-rollout"});
  step("authorize-rollout", rollout);
  const std::string token_text = fbm_test::field_of(rollout.out, "token");
  if (!token_text.empty()) {
    write_file(token, token_text);
  }
  step("token-verify", run_in(store, {"token", "verify", "--scope", "cohort/wave-1/rollout",
                                      "--plan", "wave-1.plan", "--token", token}));
  step("policy-export", run_in(store, {"policy", "export", "--out", exported}));
  step("verify-final", run_in(store, {"verify"}));
  return steps;
}

FBM_TEST(cli_determinism_across_independent_stores) {
  const std::filesystem::path scratch = fbm_test::scratch_directory("cli-determinism");
  const std::filesystem::path shared = scratch / "shared";
  std::error_code error;
  std::filesystem::create_directories(shared, error);
  write_policy_document(shared / "policy.json");

  // The two stores live at different absolute paths and are created
  // independently. The same commands with the same --at and the same policy
  // document must produce byte-identical output, so no machine-specific path
  // may leak into any output.
  const std::vector<SeriesStep> first = run_series(scratch / "store-a", shared);
  const std::vector<SeriesStep> second = run_series(scratch / "store-b", shared);

  CHECK_EQ(first.size(), second.size());
  const std::size_t count = std::min(first.size(), second.size());
  std::string transcript;
  for (std::size_t index = 0; index < count; ++index) {
    CHECK_EQ(first[index].label, second[index].label);
    if (first[index].output == second[index].output) {
      transcript += first[index].output;
      continue;
    }
    // Keep both renderings so the difference can be inspected directly.
    write_file(scratch / ("store-a." + first[index].label + ".txt"), first[index].output);
    write_file(scratch / ("store-b." + second[index].label + ".txt"), second[index].output);
    CHECK_MSG(false, "step " << first[index].label
                             << " differs between two independently created stores");
  }
  CHECK_MSG(transcript.find("exit=1") == std::string::npos,
            "a step was rejected: " << transcript.find("exit=1"));
  CHECK_MSG(transcript.find("exit=2") == std::string::npos,
            "a step was a usage error: " << transcript.find("exit=2"));
  CHECK(transcript.find("valid") != std::string::npos);
}

// --- signing key handling ---------------------------------------------------

FBM_TEST(cli_signing_key_is_used_and_never_printed) {
  const std::filesystem::path scratch = fbm_test::scratch_directory("cli-signing");
  const std::filesystem::path store = scratch / "store";
  const std::filesystem::path policy = scratch / "policy.json";
  const std::filesystem::path key_file = scratch / "key.txt";
  const std::string key = "unit-test-signing-key";
  write_file(key_file, key + "\n");
  prepare_conformant_store(store, policy);

  require_ok(run_in(store, {"cohort", "create", "--id", "wave-1", "--baseline", "gpu-h100-train",
                            "--generation", "1", "--asset", "node-01"}));
  require_ok(run_in(store, {"cohort", "authorize", "--id", "wave-1", "--revision", "1"}));

  // require-signature without a configured key cannot mint anything.
  check_rejected(run_raw({"--store", store.string(), "--at", kInstant, "--require-signature",
                          "authorize", "rollout", "--id", "wave-1", "--revision", "2", "--request",
                          "req-unsigned"}),
                 "authority_not_authorized");

  const CliRun signed_token =
      require_ok(run_raw({"--store", store.string(), "--at", kInstant, "--key-file",
                          key_file.string(), "authorize", "rollout", "--id", "wave-1", "--revision",
                          "2", "--request", "req-signed"}));
  CHECK(signed_token.out.find("hmac_sha256") != std::string::npos);
  CHECK_EQ(signed_token.out.find(key), std::string::npos);
  CHECK_EQ(signed_token.err.find(key), std::string::npos);
  const std::string token_text = fbm_test::field_of(signed_token.out, "token");
  CHECK(!token_text.empty());
  const std::filesystem::path token_file = scratch / "token.json";
  write_file(token_file, token_text);

  const CliRun verified =
      require_ok(run_raw({"--store", store.string(), "--at", kInstant, "--key-file", key_file.string(),
                          "token", "verify", "--scope", "cohort/wave-1/rollout", "--plan",
                          "wave-1.plan", "--token", token_file.string()}));
  CHECK(verified.out.find("hmac_sha256") != std::string::npos);
  CHECK_EQ(verified.out.find(key), std::string::npos);
  CHECK_EQ(verified.err.find(key), std::string::npos);

  // A signed token cannot be verified by an authority that holds no key.
  check_rejected(run_in(store, {"token", "verify", "--scope", "cohort/wave-1/rollout", "--plan",
                                "wave-1.plan", "--token", token_file.string()}),
                 "authority_not_authorized");

  // A detached policy signature is verified against the canonical document.
  const std::filesystem::path exported = scratch / "exported.json";
  require_ok(run_in(store, {"policy", "export", "--out", exported.string()}));
  const std::string canonical = read_file(exported);
  const DetachedSignature signature = sign_policy_document(canonical, key);
  const std::filesystem::path signature_file = scratch / "signature.json";
  write_file(signature_file, json::write_canonical(signature.to_json()));

  const std::filesystem::path target = scratch / "target";
  require_ok(run_in(target, {"init"}));
  const CliRun applied =
      require_ok(run_raw({"--store", target.string(), "--at", kInstant, "--key-file",
                          key_file.string(), "policy", "apply", "--file", exported.string(),
                          "--signature", signature_file.string()}));
  CHECK_EQ(applied.out.find(key), std::string::npos);
  CHECK(applied.out.find("gpu-h100-train") != std::string::npos);

  // A supplied signature with no configured key is never reported as valid.
  check_rejected(run_raw({"--store", target.string(), "--at", kInstant, "policy", "apply",
                          "--file", exported.string(), "--signature", signature_file.string()}),
                 "authority_not_authorized");

  // A signature over a different document does not verify.
  check_rejected(run_raw({"--store", target.string(), "--at", kInstant, "--key-file",
                          key_file.string(), "policy", "apply", "--file", policy.string(),
                          "--signature", signature_file.string()}),
                 "authority_not_authorized");

  // An empty key file configures nothing and is rejected rather than silently
  // producing unsigned tokens.
  const std::filesystem::path empty_key = scratch / "empty-key.txt";
  write_file(empty_key, "");
  check_rejected(run_raw({"--store", store.string(), "--at", kInstant, "--key-file",
                          empty_key.string(), "authorize", "rollout", "--id", "wave-1",
                          "--revision", "2", "--request", "req-empty-key"}),
                 "invalid_argument");
}

}  // namespace
