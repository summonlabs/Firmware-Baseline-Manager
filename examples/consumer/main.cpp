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

// Out-of-tree consumer proof.
//
// Builds only against the installed package through
// find_package(FirmwareBaselineManager) and Summon::FirmwareBaselineManager, and
// exercises the installed artifact end to end: store creation, policy
// publication, evidence recording, conformance evaluation, drift detection, and
// recovery in a fresh process object.
//
// Returns 0 only when every check holds.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <summon/fbm/manager.hpp>

namespace {

int failures = 0;

void check(bool condition, const std::string& what) {
  std::cout << (condition ? "ok   " : "FAIL ") << what << "\n";
  if (!condition) {
    ++failures;
  }
}

summon::fbm::BaselineDraft make_draft() {
  using namespace summon::fbm;

  BaselineDraft draft;
  draft.id = BaselineId{"gpu-h100-train"};
  draft.title = "H100 training baseline";

  HardwareSelector selector;
  selector.hardware_class = HardwareClassId{"gpu"};
  selector.model = HardwareModelId{"h100"};
  selector.minimum_revision = HardwareRevision{1};
  selector.maximum_revision = HardwareRevision{4};
  draft.selectors.push_back(selector);

  // Components are kept ascending by component identity; "bios" orders before
  // "bmc".
  ComponentRequirement bios{.component = FirmwareComponentId{"bios"},
                            .approved_version = FirmwareVersion::parse("3.1.0", "/approved").value()};
  bios.conformant_versions = {FirmwareVersion::parse("3.1.0", "/c").value()};
  bios.rollback_targets = {FirmwareVersion::parse("3.0.4", "/r").value()};
  bios.freshness = FreshnessBound::within(24ull * 3600ull * 1000000000ull);
  draft.components.push_back(bios);

  ComponentRequirement bmc{.component = FirmwareComponentId{"bmc"},
                           .approved_version = FirmwareVersion::parse("2.4.1", "/approved").value()};
  bmc.conformant_versions = {FirmwareVersion::parse("2.4.0", "/c").value(),
                             FirmwareVersion::parse("2.4.1", "/c").value()};
  bmc.rollback_targets = {FirmwareVersion::parse("2.3.9", "/r").value()};
  bmc.freshness = FreshnessBound::within(24ull * 3600ull * 1000000000ull);
  draft.components.push_back(bmc);

  CompatibilityRule rule;
  rule.id = RuleId{"r-bmc-bios"};
  rule.when_component = FirmwareComponentId{"bmc"};
  rule.when_versions =
      VersionRange::make(FirmwareVersion::parse("2.4.0", "/r").value(), true,
                         FirmwareVersion::parse("2.4.99", "/r").value(), true, "/range")
          .value();
  rule.requirement.kind = RequirementKind::ComponentVersionInRange;
  rule.requirement.component = FirmwareComponentId{"bios"};
  rule.requirement.versions =
      VersionRange::make(FirmwareVersion::parse("3.0.0", "/r").value(), true,
                         FirmwareVersion::parse("3.9.99", "/r").value(), true, "/range")
          .value();
  rule.reason = "BMC 2.4 requires BIOS 3.x";
  draft.rules.add(rule);

  draft.gate.minimum_conformant_basis_points = 10000u;
  draft.gate.minimum_decided_assets = 1u;
  draft.gate.minimum_conformant_assets = 1u;
  draft.gate.required_stages = summon::fbm::StageIndex{1};
  return draft;
}

summon::fbm::MutationContext context_at(std::uint64_t nanos, const char* request) {
  summon::fbm::MutationContext context;
  context.now = summon::fbm::Timestamp::from_unix_nanos(nanos);
  context.request = summon::fbm::RequestId{request};
  context.approval = summon::fbm::ApprovalId{"approval-1"};
  context.actor = "consumer";
  return context;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace summon::fbm;

  const std::filesystem::path scratch =
      argc > 1 ? std::filesystem::path{argv[1]} : std::filesystem::path{"consumer-scratch"};
  const std::filesystem::path store_directory = scratch / "store";
  std::error_code ec;
  std::filesystem::remove_all(store_directory, ec);

  const std::uint64_t base_nanos = 1770000000ull * 1000000000ull;

  ManagerOptions options;
  options.directory = store_directory;
  options.create_if_missing = true;
  options.opened_at = Timestamp::from_unix_nanos(base_nanos);

  auto manager = BaselineManager::open(options);
  if (!manager.has_value()) {
    std::cerr << "open failed: " << manager.error().to_string() << "\n";
    return 1;
  }
  check(true, "opened the installed library and created the store");

  auto defined = manager.value()->define_baseline(make_draft(), context_at(base_nanos, "req-define"));
  if (!defined.has_value()) {
    std::cerr << "define failed: " << defined.error().to_string() << "\n";
    return 1;
  }
  check(defined.value().state == BaselineState::Draft, "a newly defined baseline is a draft");

  auto published = manager.value()->publish_baseline(
      defined.value().id, defined.value().generation, context_at(base_nanos + 1000, "req-publish"));
  if (!published.has_value()) {
    std::cerr << "publish failed: " << published.error().to_string() << "\n";
    return 1;
  }
  check(published.value().state == BaselineState::Published, "the baseline is published");

  {
    ObserveRequest observe;
    observe.now = Timestamp::from_unix_nanos(base_nanos + 2000);
    observe.evidence = EvidenceId{"ev-profile-1"};
    observe.asset = AssetId{"node-01"};
    observe.sequence = ObservationSequence{1};
    observe.has_hardware = true;
    observe.hardware.hardware_class = HardwareClassId{"gpu"};
    observe.hardware.model = HardwareModelId{"h100"};
    observe.hardware.revision = HardwareRevision{2};
    observe.hardware.capabilities_observed = true;
    observe.hardware_generation = HardwareGeneration{1};
    observe.reporter = IncarnationId{1};
    auto recorded = manager.value()->observe(observe);
    check(recorded.has_value(), "hardware evidence was recorded");
  }

  for (const char* component : {"bmc", "bios"}) {
    ObserveRequest observe;
    observe.now = Timestamp::from_unix_nanos(base_nanos + 3000);
    observe.evidence = EvidenceId{std::string{"ev-"} + component};
    observe.asset = AssetId{"node-01"};
    observe.sequence = ObservationSequence{2};
    observe.has_component = true;
    observe.component = FirmwareComponentId{component};
    observe.version = FirmwareVersion::parse(std::string{component} == "bmc" ? "2.4.1" : "3.1.0",
                                             "/version")
                          .value();
    observe.firmware_generation = FirmwareGeneration{1};
    observe.reporter = IncarnationId{1};
    auto recorded = manager.value()->observe(observe);
    check(recorded.has_value(), std::string{"firmware evidence for "} + component +
                                    " was recorded");
  }

  EvaluationRequest evaluation;
  evaluation.asset = AssetId{"node-01"};
  evaluation.now = Timestamp::from_unix_nanos(base_nanos + 4000);

  auto verdict = manager.value()->evaluate(evaluation);
  if (!verdict.has_value()) {
    std::cerr << "evaluate failed: " << verdict.error().to_string() << "\n";
    return 1;
  }
  check(verdict.value().state == ConformanceState::Conformant,
        "the asset is conformant against the published baseline");
  check(verdict.value().residuals.empty(), "no residual remains");

  {
    ObserveRequest observe;
    observe.now = Timestamp::from_unix_nanos(base_nanos + 5000);
    observe.evidence = EvidenceId{"ev-bmc-drift"};
    observe.asset = AssetId{"node-01"};
    observe.sequence = ObservationSequence{3};
    observe.has_component = true;
    observe.component = FirmwareComponentId{"bmc"};
    observe.version = FirmwareVersion::parse("2.3.0", "/version").value();
    observe.firmware_generation = FirmwareGeneration{1};
    observe.reporter = IncarnationId{1};
    auto recorded = manager.value()->observe(observe);
    check(recorded.has_value(), "drifted firmware evidence was recorded");
  }

  evaluation.now = Timestamp::from_unix_nanos(base_nanos + 6000);
  auto drifted = manager.value()->evaluate(evaluation);
  if (!drifted.has_value()) {
    std::cerr << "evaluate failed: " << drifted.error().to_string() << "\n";
    return 1;
  }
  check(drifted.value().state == ConformanceState::Drifted, "the asset is now drifted");
  check(drifted.value().residuals.size() == 1u, "exactly one residual remains");
  if (drifted.value().residuals.size() == 1u) {
    const DriftResidual& residual = drifted.value().residuals.front();
    check(residual.kind == DriftKind::VersionMismatch, "the residual is a version mismatch");
    check(residual.observed.has_value() && residual.observed->to_string() == "2.3.0",
          "the residual keeps the exact observed version");
    check(residual.required.has_value() && residual.required->to_string() == "2.4.1",
          "the residual keeps the exact required version");
    check(residual.has_version_delta, "the residual keeps the signed distance");
  }

  auto drift_list = manager.value()->list_drift(evaluation);
  check(drift_list.has_value() && drift_list.value().size() == 1u,
        "the drift list reports the same residual");

  auto eligibility = manager.value()->rollout_eligibility(evaluation);
  check(eligibility.has_value(), "rollout eligibility was evaluated");
  check(eligibility.has_value() && eligibility.value().eligibility == Eligibility::Unknown,
        "eligibility is unknown while the facility gates are not established");

  manager.value().reset();

  ManagerOptions reopened;
  reopened.directory = store_directory;
  reopened.create_if_missing = false;
  reopened.opened_at = Timestamp::from_unix_nanos(base_nanos + 7000);
  auto second = BaselineManager::open(reopened);
  if (!second.has_value()) {
    std::cerr << "reopen failed: " << second.error().to_string() << "\n";
    return 1;
  }
  check(second.value()->baselines().size() == 1u, "the baseline survived a close and reopen");
  check(second.value()->assets().size() == 1u, "the observation log survived a close and reopen");

  auto second_verdict = second.value()->evaluate(evaluation);
  check(second_verdict.has_value() &&
            second_verdict.value().state == ConformanceState::Drifted,
        "the recovered state reproduces the same verdict");

  std::cout << "\nconsumer checks failed: " << failures << "\n";
  return failures == 0 ? 0 : 1;
}
