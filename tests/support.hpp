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

// Shared fixtures for the Firmware Baseline Manager test suite. Everything here
// is deterministic: fixed instants, fixed identities, fixed policies. Nothing
// reads the clock except where a test explicitly asks the library to.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "check.hpp"
#include "summon/fbm/manager.hpp"
#include "summon/fbm/platform.hpp"
#include "summon/fbm/store.hpp"
#include "summon/fbm/text_format.hpp"

#ifndef FBM_PROC_TOOL_PATH
#define FBM_PROC_TOOL_PATH "fbm_proc_tool"
#endif
#ifndef FBM_CRASH_TOOL_PATH
#define FBM_CRASH_TOOL_PATH "fbm_crash_tool"
#endif
#ifndef FBM_CLI_PATH
#define FBM_CLI_PATH "fbm"
#endif

namespace fbm_test {

using namespace summon::fbm;

// A fixed instant: 2026-02-01T00:00:00Z.
inline Timestamp at(std::uint64_t seconds, std::uint64_t nanos = 0) {
  return Timestamp::from_unix_nanos(seconds * 1000000000ull + nanos);
}

inline Timestamp base_time() { return at(1769904000ull); }

inline FirmwareVersion version(const char* text) {
  auto parsed = FirmwareVersion::parse(text, "/version");
  if (!parsed.has_value()) {
    ::fbm_test::report_failure(__FILE__, __LINE__,
                               std::string{"test fixture version did not parse: "} + text);
    throw ::fbm_test::Abort{};
  }
  return parsed.value();
}

inline VersionRange range(const char* low, const char* high) {
  auto made = VersionRange::make(version(low), true, version(high), true, "/range");
  if (!made.has_value()) {
    ::fbm_test::report_failure(__FILE__, __LINE__, "test fixture range did not build");
    throw ::fbm_test::Abort{};
  }
  return made.value();
}

inline FacilityGates open_gates() {
  FacilityGates gates;
  gates.capacity = GateState::Open;
  gates.capacity_generation = CapacityGeneration{7};
  gates.dependency = GateState::Open;
  gates.dependency_generation = DependencyGeneration{8};
  gates.maintenance = GateState::Open;
  gates.maintenance_generation = MaintenanceGeneration{9};
  gates.topology = GateState::Open;
  gates.topology_generation = TopologyGeneration{10};
  return gates;
}

// A two-component baseline used by most tests: bmc and bios, with one rule that
// ties BMC 2.4.x to BIOS 3.x.
inline BaselineDraft standard_draft(const char* id = "gpu-h100-train") {
  BaselineDraft draft;
  draft.id = BaselineId{id};
  draft.title = "H100 training baseline";

  HardwareSelector selector;
  selector.hardware_class = HardwareClassId{"gpu"};
  selector.model = HardwareModelId{"h100"};
  selector.minimum_revision = HardwareRevision{1};
  selector.maximum_revision = HardwareRevision{4};
  draft.selectors.push_back(selector);

  // Components must be ascending by component identity, and "bios" orders
  // before "bmc".
  ComponentRequirement bios{.component = FirmwareComponentId{"bios"},
                            .approved_version = version("3.1.0")};
  bios.conformant_versions = {version("3.1.0")};
  bios.rollback_targets = {version("3.0.4")};
  bios.freshness = FreshnessBound::within(24ull * 3600ull * 1000000000ull);
  draft.components.push_back(bios);

  ComponentRequirement bmc{.component = FirmwareComponentId{"bmc"},
                           .approved_version = version("2.4.1")};
  bmc.conformant_versions = {version("2.4.0"), version("2.4.1")};
  bmc.rollback_targets = {version("2.3.9"), version("2.3.8")};
  bmc.freshness = FreshnessBound::within(24ull * 3600ull * 1000000000ull);
  draft.components.push_back(bmc);

  CompatibilityRule rule;
  rule.id = RuleId{"r-bmc-bios"};
  rule.when_component = FirmwareComponentId{"bmc"};
  rule.when_versions = range("2.4.0", "2.4.99");
  rule.requirement.kind = RequirementKind::ComponentVersionInRange;
  rule.requirement.component = FirmwareComponentId{"bios"};
  rule.requirement.versions = range("3.0.0", "3.9.99");
  rule.reason = "BMC 2.4 requires BIOS 3.x";
  draft.rules.add(rule);

  draft.gate.minimum_conformant_basis_points = 10000u;
  draft.gate.minimum_decided_assets = 1u;
  draft.gate.minimum_conformant_assets = 1u;
  draft.gate.required_stages = StageIndex{2};
  return draft;
}

inline MutationContext context_at(const Timestamp& now, const char* request = "req-1",
                                  const char* approval = "approval-1") {
  MutationContext context;
  context.now = now;
  context.request = RequestId{request};
  context.approval = ApprovalId{approval};
  context.actor = "test";
  return context;
}

inline ManagerOptions manager_options(const std::filesystem::path& directory, bool create,
                                      const Timestamp& opened_at = base_time()) {
  ManagerOptions options;
  options.directory = directory;
  options.create_if_missing = create;
  options.opened_at = opened_at;
  return options;
}

struct ToolRun {
  int exit_code = -1;
  std::string standard_output;
  std::string standard_error;
  bool started = false;
};

// Runs one of the harness executables as a real, independent operating-system
// process. Output is captured through files rather than pipes, so a child that
// writes a large amount of output can never block.
inline ToolRun run_tool(const std::string& executable, const std::vector<std::string>& arguments,
                        const std::filesystem::path& scratch, const std::string& tag) {
  ToolRun result;
  std::error_code ec;
  std::filesystem::create_directories(scratch, ec);
  const std::filesystem::path out_path = scratch / (tag + ".stdout");
  const std::filesystem::path err_path = scratch / (tag + ".stderr");
  std::filesystem::remove(out_path, ec);
  std::filesystem::remove(err_path, ec);

  auto spawned = platform::spawn_process(executable, arguments, scratch, out_path, err_path);
  if (!spawned.has_value()) {
    result.standard_error = spawned.error().to_string();
    return result;
  }
  result.started = true;
  auto exit_code = platform::wait_for_exit(spawned.value());
  result.exit_code = exit_code.has_value() ? exit_code.value() : -1;

  {
    std::ifstream input(out_path, std::ios::binary);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    result.standard_output = buffer.str();
  }
  {
    std::ifstream input(err_path, std::ios::binary);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    result.standard_error = buffer.str();
  }
  platform::abandon_process(spawned.value());
  return result;
}

// Extracts "key=value" from a harness tool's output.
inline std::string field_of(const std::string& output, const std::string& key) {
  const std::string prefix = key + "=";
  std::size_t position = 0;
  while (position < output.size()) {
    const std::size_t end = output.find('\n', position);
    const std::string line =
        output.substr(position, end == std::string::npos ? std::string::npos : end - position);
    if (line.rfind(prefix, 0) == 0) {
      std::string value = line.substr(prefix.size());
      // Harness output is written on Windows, so a line ends with CR LF; the
      // value must not carry the carriage return into a comparison.
      while (!value.empty() &&
             (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
        value.pop_back();
      }
      return value;
    }
    if (end == std::string::npos) {
      break;
    }
    position = end + 1;
  }
  return {};
}

inline HardwareProfile profile_of(const char* hardware_class = "gpu", const char* model = "h100",
                                  std::uint32_t revision = 2) {
  HardwareProfile profile;
  profile.hardware_class = HardwareClassId{hardware_class};
  profile.model = HardwareModelId{model};
  profile.revision = HardwareRevision{revision};
  profile.capabilities_observed = true;
  return profile;
}

inline Result<ObservationOutcome> observe_profile(BaselineManager& manager, const AssetId& asset,
                                                  const HardwareProfile& profile,
                                                  ObservationSequence sequence,
                                                  const Timestamp& now,
                                                  const char* evidence = "ev-profile") {
  ObserveRequest request;
  request.now = now;
  request.evidence = EvidenceId{evidence};
  request.asset = asset;
  request.sequence = sequence;
  request.has_hardware = true;
  request.hardware = profile;
  request.hardware_generation = HardwareGeneration{1};
  request.reporter = IncarnationId{1};
  return manager.observe(request);
}

// An empty version records the component as observed with an undetermined
// version, which is a different fact from never having observed it.
inline Result<ObservationOutcome> observe_component(BaselineManager& manager, const AssetId& asset,
                                                    const char* component,
                                                    const std::optional<FirmwareVersion>& observed,
                                                    ObservationSequence sequence,
                                                    const Timestamp& now,
                                                    const char* evidence = "ev-component") {
  ObserveRequest request;
  request.now = now;
  request.evidence = EvidenceId{evidence};
  request.asset = asset;
  request.sequence = sequence;
  request.has_component = true;
  request.component = FirmwareComponentId{component};
  request.version = observed;
  request.firmware_generation = FirmwareGeneration{1};
  request.reporter = IncarnationId{1};
  return manager.observe(request);
}

struct Fixture {
  std::unique_ptr<BaselineManager> manager;
  BaselineId baseline;
  BaselineGeneration generation;
  Revision baseline_revision;
  AssetId asset;
  Timestamp now;
};

// Opens a manager, defines and publishes the standard baseline, and returns the
// handles a test needs.
inline Fixture publish_fixture(const std::filesystem::path& directory,
                               const Timestamp& start = base_time(),
                               const char* baseline_id = "gpu-h100-train") {
  Fixture fixture;
  fixture.now = start;
  fixture.asset = AssetId{"node-01"};

  auto manager = BaselineManager::open(manager_options(directory, true, start));
  if (!manager.has_value()) {
    ::fbm_test::report_failure(__FILE__, __LINE__,
                               "fixture could not open the manager: " +
                                   manager.error().to_string());
    throw ::fbm_test::Abort{};
  }
  fixture.manager = manager.take();

  auto defined = fixture.manager->define_baseline(standard_draft(baseline_id),
                                                 context_at(start, "req-define"));
  if (!defined.has_value()) {
    ::fbm_test::report_failure(__FILE__, __LINE__, "fixture could not define the baseline: " +
                                                      defined.error().to_string());
    throw ::fbm_test::Abort{};
  }
  auto published = fixture.manager->publish_baseline(defined.value().id, defined.value().generation,
                                                    context_at(start, "req-publish"));
  if (!published.has_value()) {
    ::fbm_test::report_failure(__FILE__, __LINE__, "fixture could not publish the baseline: " +
                                                      published.error().to_string());
    throw ::fbm_test::Abort{};
  }
  fixture.baseline = published.value().id;
  fixture.generation = published.value().generation;
  fixture.baseline_revision = published.value().revision;
  return fixture;
}

// Makes the standard asset fully conformant.
inline void make_conformant(BaselineManager& manager, const AssetId& asset, const Timestamp& now,
                            ObservationSequence first_sequence = ObservationSequence{1}) {
  observe_profile(manager, asset, profile_of(), first_sequence, now, "ev-profile");
  std::uint64_t sequence = first_sequence.value_or(0u);
  observe_component(manager, asset, "bmc", version("2.4.1"), ObservationSequence{sequence + 1}, now,
                    "ev-bmc");
  observe_component(manager, asset, "bios", version("3.1.0"), ObservationSequence{sequence + 2},
                    now, "ev-bios");
}

}  // namespace fbm_test
