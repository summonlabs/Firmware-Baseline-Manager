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

// Benchmarks.
//
// Methodology, stated so that the numbers can be read correctly:
//   * Every throughput figure counts COMPLETED operations. Nothing here measures
//     submission or enqueue latency.
//   * Durable operations include their durable cost: the commit benchmark
//     reports the cost of the full stage, flush, verify, publish, fence cycle,
//     which is what a caller actually waits for.
//   * Latency figures are the median of the individual completed operations,
//     computed from the full sample, not a mean of a mean.
//   * Inputs are SYNTHETIC: generated in process. The storage medium and the
//     operating system are REAL, so the durable numbers reflect this host.
//   * The reported environment line names the compiler and the build
//     configuration so that a number is never quoted without its context.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "summon/fbm/manager.hpp"
#include "summon/fbm/platform.hpp"
#include "summon/fbm/policy_document.hpp"
#include "summon/fbm/store.hpp"

namespace {

using namespace summon::fbm;
using Clock = std::chrono::steady_clock;

std::uint64_t millis_between(Clock::time_point start, Clock::time_point end) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

struct Sample {
  std::uint64_t total_nanos = 0;
  std::uint64_t median_nanos = 0;
  std::uint64_t minimum_nanos = 0;
  std::uint64_t maximum_nanos = 0;
};

Sample summarise(std::vector<std::uint64_t> samples) {
  Sample out;
  if (samples.empty()) {
    return out;
  }
  std::sort(samples.begin(), samples.end());
  for (const std::uint64_t value : samples) {
    out.total_nanos += value;
  }
  out.median_nanos = samples[samples.size() / 2u];
  out.minimum_nanos = samples.front();
  out.maximum_nanos = samples.back();
  return out;
}

void report(const char* name, const Sample& sample, std::size_t operations) {
  const double seconds =
      static_cast<double>(sample.total_nanos) / 1000000000.0;
  const double per_second = seconds > 0.0 ? static_cast<double>(operations) / seconds : 0.0;
  std::cout << "benchmark=" << name << "\n";
  std::cout << "  operations_completed=" << operations << "\n";
  std::cout << "  total_nanos=" << sample.total_nanos << "\n";
  std::cout << "  completed_per_second=" << static_cast<std::uint64_t>(per_second) << "\n";
  std::cout << "  median_nanos=" << sample.median_nanos << "\n";
  std::cout << "  minimum_nanos=" << sample.minimum_nanos << "\n";
  std::cout << "  maximum_nanos=" << sample.maximum_nanos << "\n";
}

// Deterministic synthetic generator; never the clock, never random_device.
struct Generator {
  std::uint64_t state = 0x2545F4914F6CDD1Dull;
  std::uint64_t next() {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
  }
  std::uint32_t bounded(std::uint32_t limit) {
    return static_cast<std::uint32_t>(next() % limit);
  }
};

BaselineDraft synthetic_draft(std::uint32_t component_count, std::uint32_t rule_count) {
  BaselineDraft draft;
  draft.id = BaselineId{"bench-baseline"};
  draft.title = "synthetic benchmark baseline";

  HardwareSelector selector;
  selector.hardware_class = HardwareClassId{"gpu"};
  selector.model = HardwareModelId{"bench-model"};
  selector.minimum_revision = HardwareRevision{1};
  selector.maximum_revision = HardwareRevision{9};
  draft.selectors.push_back(selector);

  // Component requirements have no default constructor: approved_version is a
  // required field, so the value is supplied at construction.
  std::vector<ComponentRequirement> components;
  for (std::uint32_t index = 0; index < component_count; ++index) {
    auto approved = FirmwareVersion::parse("2.4.1", "/v");
    auto previous = FirmwareVersion::parse("2.4.0", "/v");
    auto rollback = FirmwareVersion::parse("2.3.9", "/v");
    if (!approved.has_value() || !previous.has_value() || !rollback.has_value()) {
      std::cerr << "benchmark version literal did not parse\n";
      std::exit(1);
    }
    ComponentRequirement requirement{.component = FirmwareComponentId{"component-" +
                                                                      std::to_string(index)},
                                     .approved_version = approved.value()};
    requirement.conformant_versions = {previous.value(), approved.value()};
    requirement.rollback_targets = {rollback.value()};
    requirement.freshness = FreshnessBound::within(24ull * 3600ull * 1000000000ull);
    components.push_back(std::move(requirement));
  }
  // The registry requires components ascending by identity, which the generated
  // names already are for a count below ten.
  draft.components = std::move(components);

  for (std::uint32_t index = 0; index + 1u < component_count && index < rule_count; ++index) {
    CompatibilityRule rule;
    rule.id = RuleId{"rule-" + std::to_string(index)};
    rule.when_component = FirmwareComponentId{"component-" + std::to_string(index)};
    rule.when_versions =
        VersionRange::make(FirmwareVersion::parse("2.4.0", "/v").value(), true,
                           FirmwareVersion::parse("2.4.99", "/v").value(), true, "/r")
            .value();
    rule.requirement.kind = RequirementKind::ComponentVersionInRange;
    rule.requirement.component = FirmwareComponentId{"component-" + std::to_string(index + 1u)};
    rule.requirement.versions =
        VersionRange::make(FirmwareVersion::parse("2.0.0", "/v").value(), true,
                           FirmwareVersion::parse("3.9.99", "/v").value(), true, "/r")
            .value();
    rule.reason = "synthetic chained compatibility rule";
    draft.rules.add(rule);
  }

  draft.gate.minimum_conformant_basis_points = 10000u;
  return draft;
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t commit_operations = 200;
  std::uint64_t evaluation_operations = 2000;
  std::uint32_t asset_count = 32;

  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--quick") {
      commit_operations = 50;
      evaluation_operations = 500;
      asset_count = 8;
    } else {
      std::cerr << "unknown argument: " << argument << "\n";
      return 2;
    }
  }

  const std::filesystem::path root = std::filesystem::temp_directory_path() / "fbm-benchmark";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  std::filesystem::create_directories(root, ec);

  std::cout << "environment=" << build_info() << "\n";
  std::cout << "version=" << version_string() << "\n";
  std::cout << "inputs=SYNTHETIC\n";
  std::cout << "storage=REAL\n\n";

  // --- Durable commit throughput -------------------------------------------
  {
    StoreOptions options;
    options.directory = root / "commit-store";
    options.create_if_missing = true;
    auto store = DurableStore::open(options);
    if (!store.has_value()) {
      std::cerr << "benchmark store open failed: " << store.error().to_string() << "\n";
      return 1;
    }

    std::vector<std::uint64_t> samples;
    samples.reserve(static_cast<std::size_t>(commit_operations));
    std::uint64_t bytes = 0;
    for (std::uint64_t index = 0; index < commit_operations; ++index) {
      Snapshot next = store.value()->snapshot();
      next.revision = Revision{index + 1u};
      next.policy_generation = PolicyGeneration{index + 1u};
      const auto start = Clock::now();
      auto outcome = store.value()->commit(std::move(next));
      const auto end = Clock::now();
      if (!outcome.has_value()) {
        std::cerr << "benchmark commit failed: " << outcome.error().to_string() << "\n";
        return 1;
      }
      bytes += outcome.value().payload_bytes;
      samples.push_back(millis_between(start, end));
    }
    const Sample sample = summarise(std::move(samples));
    std::cout << "durable=full stage, flush, read-back verify, atomic publish, fence\n";
    report("durable_commit", sample, static_cast<std::size_t>(commit_operations));
    std::cout << "  payload_bytes_total=" << bytes << "\n\n";
  }

  // --- Conformance evaluation throughput ------------------------------------
  {
    const std::filesystem::path directory = root / "eval-store";
    ManagerOptions options;
    options.directory = directory;
    options.create_if_missing = true;
    options.opened_at = Timestamp::from_unix_nanos(1769904000ull * 1000000000ull);
    auto manager = BaselineManager::open(options);
    if (!manager.has_value()) {
      std::cerr << "benchmark manager open failed: " << manager.error().to_string() << "\n";
      return 1;
    }

    MutationContext context;
    context.now = Timestamp::from_unix_nanos(1769904000ull * 1000000000ull);
    context.request = RequestId{"bench-define"};

    auto defined = manager.value()->define_baseline(synthetic_draft(8, 7), context);
    if (!defined.has_value()) {
      std::cerr << "benchmark define failed: " << defined.error().to_string() << "\n";
      return 1;
    }
    auto published = manager.value()->publish_baseline(defined.value().id,
                                                      defined.value().generation, context);
    if (!published.has_value()) {
      std::cerr << "benchmark publish failed: " << published.error().to_string() << "\n";
      return 1;
    }

    std::vector<AssetId> assets;
    for (std::uint32_t index = 0; index < asset_count; ++index) {
      const AssetId asset{"bench-node-" + std::to_string(index)};
      assets.push_back(asset);

      ObserveRequest profile;
      profile.now = context.now;
      profile.evidence = EvidenceId{"bench-profile-" + std::to_string(index)};
      profile.asset = asset;
      profile.sequence = ObservationSequence{1};
      profile.has_hardware = true;
      profile.hardware.hardware_class = HardwareClassId{"gpu"};
      profile.hardware.model = HardwareModelId{"bench-model"};
      profile.hardware.revision = HardwareRevision{2};
      profile.hardware.capabilities_observed = true;
      profile.hardware_generation = HardwareGeneration{1};
      profile.reporter = IncarnationId{1};
      if (!manager.value()->observe(profile).has_value()) {
        std::cerr << "benchmark profile observation failed\n";
        return 1;
      }
      for (std::uint32_t component = 0; component < 8; ++component) {
        ObserveRequest observation;
        observation.now = context.now;
        observation.evidence =
            EvidenceId{"bench-ev-" + std::to_string(index) + "-" + std::to_string(component)};
        observation.asset = asset;
        observation.sequence = ObservationSequence{2};
        observation.has_component = true;
        observation.component =
            FirmwareComponentId{"component-" + std::to_string(component)};
        // Half the fleet is deliberately drifted so that the residual path is
        // exercised rather than only the fast conformant path.
        auto parsed_version =
            FirmwareVersion::parse((index % 2u == 0u) ? "2.4.1" : "2.3.0", "/v");
        if (!parsed_version.has_value()) {
          std::cerr << "benchmark version literal did not parse: "
                    << parsed_version.error().to_string() << "\n";
          return 1;
        }
        observation.version = parsed_version.value();
        observation.firmware_generation = FirmwareGeneration{1};
        observation.reporter = IncarnationId{1};
        if (!manager.value()->observe(observation).has_value()) {
          std::cerr << "benchmark component observation failed\n";
          return 1;
        }
      }
    }

    Generator generator;
    std::vector<std::uint64_t> samples;
    samples.reserve(static_cast<std::size_t>(evaluation_operations));
    std::size_t conformant = 0;
    std::size_t drifted = 0;
    for (std::uint64_t index = 0; index < evaluation_operations; ++index) {
      EvaluationRequest request;
      request.asset = assets[generator.bounded(static_cast<std::uint32_t>(assets.size()))];
      request.now = context.now;
      const auto start = Clock::now();
      auto verdict = manager.value()->evaluate(request);
      const auto end = Clock::now();
      if (!verdict.has_value()) {
        std::cerr << "benchmark evaluation failed: " << verdict.error().to_string() << "\n";
        return 1;
      }
      if (verdict.value().state == ConformanceState::Conformant) {
        ++conformant;
      } else if (verdict.value().state == ConformanceState::Drifted) {
        ++drifted;
      }
      samples.push_back(millis_between(start, end));
    }
    const Sample sample = summarise(std::move(samples));
    std::cout << "durable=none, read-only evaluation of an in-memory snapshot\n";
    report("conformance_evaluation", sample, static_cast<std::size_t>(evaluation_operations));
    std::cout << "  assets=" << asset_count << "\n";
    std::cout << "  conformant_results=" << conformant << "\n";
    std::cout << "  drifted_results=" << drifted << "\n\n";
  }

  // --- Policy document parse and canonicalize --------------------------------
  {
    const std::filesystem::path directory = root / "eval-store";
    ManagerOptions options;
    options.directory = directory;
    options.create_if_missing = false;
    options.opened_at = Timestamp::from_unix_nanos(1769904000ull * 1000000000ull);
    auto manager = BaselineManager::open(options);
    if (!manager.has_value()) {
      std::cerr << "benchmark reopen failed: " << manager.error().to_string() << "\n";
      return 1;
    }
    const PolicyDocument document = manager.value()->export_policy_document();
    const std::string text = json::write_pretty(document.to_json(), 2u);

    constexpr std::size_t kIterations = 500;
    std::vector<std::uint64_t> samples;
    samples.reserve(kIterations);
    for (std::size_t index = 0; index < kIterations; ++index) {
      const auto start = Clock::now();
      auto parsed = PolicyDocument::parse(text, "/policy");
      if (!parsed.has_value()) {
        std::cerr << "benchmark policy parse failed: " << parsed.error().to_string() << "\n";
        return 1;
      }
      const std::string canonical = parsed.value().canonical_bytes();
      const auto end = Clock::now();
      if (canonical.empty()) {
        std::cerr << "benchmark produced empty canonical bytes\n";
        return 1;
      }
      samples.push_back(millis_between(start, end));
    }
    const Sample sample = summarise(std::move(samples));
    std::cout << "durable=none, strict parse plus canonical serialization\n";
    report("policy_document_parse_and_canonicalize", sample, kIterations);
    std::cout << "  document_bytes=" << text.size() << "\n";
  }

  std::filesystem::remove_all(root, ec);
  return 0;
}
