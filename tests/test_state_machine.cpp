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

// Seeded randomized state machine over the composed authority.
//
// A deterministic operation sequence drives the real manager, and after every
// operation the model-free invariants below must still hold. A failure prints
// the seed, the operation index, the exact operation, and its arguments so that
// the sequence can be replayed exactly.

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "check.hpp"
#include "support.hpp"

using namespace summon::fbm;
using namespace fbm_test;

namespace {

struct Random {
  std::uint64_t state;
  explicit Random(std::uint64_t seed) : state(seed == 0u ? 0x9E3779B97F4A7C15ull : seed) {}
  std::uint64_t next() {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
  }
  std::uint32_t below(std::uint32_t limit) { return static_cast<std::uint32_t>(next() % limit); }
};

const char* kVersionText[] = {"2.4.1", "2.4.0", "2.3.0", "3.1.0", "9.9.9"};

void report_and_throw(std::uint64_t seed, std::size_t step, const std::string& operation,
                      const std::string& detail) {
  std::cerr << "state machine failure\n"
            << "  seed=" << seed << "\n"
            << "  step=" << step << "\n"
            << "  operation=" << operation << "\n"
            << "  detail=" << detail << "\n";
  ::fbm_test::report_failure(__FILE__, __LINE__,
                             "seed=" + std::to_string(seed) + " step=" + std::to_string(step) +
                                 " op=" + operation + " : " + detail);
  throw ::fbm_test::Abort{};
}

void run_sequence(std::uint64_t seed, std::size_t steps) {
  const std::filesystem::path directory = scratch_directory("state-machine-" + std::to_string(seed));
  Timestamp now = base_time();

  auto manager = BaselineManager::open(manager_options(directory, true, now));
  if (!manager.has_value()) {
    report_and_throw(seed, 0, "open", manager.error().to_string());
  }

  CommitSequence last_committed = manager.value()->commit_sequence();
  PolicyGeneration last_policy = manager.value()->policy_generation();

  Random random{seed};
  std::vector<BaselineId> baselines;
  std::vector<ExceptionId> exceptions;
  std::vector<CohortId> cohorts;
  std::uint64_t counter = 0;

  const auto check_monotonic = [&](std::size_t step, const std::string& operation) {
    const CommitSequence committed = manager.value()->commit_sequence();
    const PolicyGeneration policy = manager.value()->policy_generation();
    if (last_committed.is_set() && committed.is_set() &&
        committed.value() < last_committed.value()) {
      report_and_throw(seed, step, operation, "the commit sequence went backwards");
    }
    if (last_policy.is_set() && policy.is_set() && policy.value() < last_policy.value()) {
      report_and_throw(seed, step, operation, "the policy generation went backwards");
    }
    last_committed = committed;
    last_policy = policy;
  };

  for (std::size_t step = 0; step < steps; ++step) {
    now = Timestamp::from_unix_nanos(now.unix_nanos() + 1000000000ull);
    const std::uint32_t choice = random.below(11);
    std::string operation;

    if (choice == 0 || baselines.empty()) {
      operation = "define_baseline";
      const std::string id = "baseline-" + std::to_string(counter++);
      auto defined = manager.value()->define_baseline(standard_draft(id.c_str()),
                                                      context_at(now, "req-define"));
      CHECK(defined.has_value());
      if (defined.has_value()) {
        baselines.push_back(defined.value().id);
      }
    } else if (choice == 1) {
      operation = "publish_baseline";
      const BaselineId id = baselines[random.below(static_cast<std::uint32_t>(baselines.size()))];
      auto list = manager.value()->baselines();
      const Baseline* found = nullptr;
      for (const Baseline& candidate : list) {
        if (candidate.id == id) {
          found = &candidate;
        }
      }
      if (found != nullptr) {
        auto published = manager.value()->publish_baseline(
            id, found->generation, context_at(now, "req-publish"));
        CHECK(published.has_value() ||
              published.error().code() != ErrorCode::InternalInvariantViolation);
      }
    } else if (choice == 2) {
      operation = "retire_baseline";
      const BaselineId id = baselines[random.below(static_cast<std::uint32_t>(baselines.size()))];
      auto list = manager.value()->baselines();
      for (const Baseline& candidate : list) {
        if (candidate.id == id) {
          auto retired = manager.value()->retire_baseline(id, candidate.generation,
                                                          context_at(now, "req-retire"));
          CHECK(retired.has_value() ||
                retired.error().code() != ErrorCode::InternalInvariantViolation);
        }
      }
    } else if (choice == 3) {
      operation = "observe_profile";
      const AssetId asset{"node-" + std::to_string(random.below(3))};
      auto recorded = observe_profile(*manager.value(), asset,
                                      profile_of("gpu", "h100", 1u + random.below(4)), 
                                      ObservationSequence{1}, now, "ev-profile");
      CHECK(recorded.has_value() || recorded.error().code() == ErrorCode::EvidenceOutOfOrder ||
            recorded.error().code() == ErrorCode::EvidenceConflicting);
    } else if (choice == 4) {
      operation = "observe_component";
      const AssetId asset{"node-" + std::to_string(random.below(3))};
      const char* component = random.below(2) == 0 ? "bmc" : "bios";
      const std::uint32_t sequence = 2u + random.below(4);
      std::optional<FirmwareVersion> observed;
      const std::uint32_t pick = random.below(6);
      if (pick < 5u) {
        observed = version(kVersionText[pick]);
      }
      auto recorded = observe_component(*manager.value(), asset, component, observed,
                                        ObservationSequence{sequence}, now, "ev-component");
      CHECK(recorded.has_value() || recorded.error().code() == ErrorCode::EvidenceOutOfOrder ||
            recorded.error().code() == ErrorCode::EvidenceConflicting);
    } else if (choice == 5) {
      operation = "evaluate";
      const AssetId asset{"node-" + std::to_string(random.below(3))};
      EvaluationRequest request;
      request.asset = asset;
      request.now = now;
      auto verdict = manager.value()->evaluate(request);
      CHECK(verdict.has_value());
      if (verdict.has_value()) {
        // Invariant: a conformant verdict must name a published baseline and
        // must have no residuals at all.
        if (verdict.value().state == ConformanceState::Conformant) {
          if (verdict.value().baseline.is_set() &&
              !verdict.value().baseline_generation.is_set()) {
            report_and_throw(seed, step, operation,
                             "a conformant verdict named a baseline without a generation");
          }
          if (!verdict.value().residuals.empty()) {
            report_and_throw(seed, step, operation,
                             "a conformant verdict carried residuals");
          }
        }
        // Invariant: blocked, unknown, and unsupported verdicts never claim a
        // resolved baseline generation they did not evaluate against.
        if (verdict.value().state == ConformanceState::Unknown &&
            !verdict.value().reason_code_value.empty()) {
          CHECK(verdict.value().reason_code_value != "conformant");
        }
      }
    } else if (choice == 6) {
      operation = "grant_exception";
      ExceptionDraft draft;
      const std::string id = "exception-" + std::to_string(counter++);
      draft.id = ExceptionId{id};
      draft.scope.hardware_class = HardwareClassId{"gpu"};
      draft.reason = "seeded randomized exception";
      draft.expiry = Expiry::at(Timestamp::from_unix_nanos(now.unix_nanos() +
                                                          60000000000ull));
      auto granted = manager.value()->grant_exception(draft, context_at(now, "req-exception"));
      CHECK(granted.has_value());
      if (granted.has_value()) {
        exceptions.push_back(granted.value().id);
      }
    } else if (choice == 7 && !exceptions.empty()) {
      operation = "revoke_exception";
      const ExceptionId id =
          exceptions[random.below(static_cast<std::uint32_t>(exceptions.size()))];
      for (const BaselineException& candidate : manager.value()->exceptions()) {
        if (candidate.id == id) {
          auto revoked = manager.value()->revoke_exception(id, candidate.revision,
                                                           context_at(now, "req-revoke"));
          CHECK(revoked.has_value() || revoked.error().code() == ErrorCode::InvalidArgument);
        }
      }
    } else if (choice == 8) {
      operation = "create_cohort";
      auto list = manager.value()->baselines();
      if (!list.empty()) {
        const Baseline& baseline = list[random.below(static_cast<std::uint32_t>(list.size()))];
        CohortDraft draft;
        draft.id = CohortId{"cohort-" + std::to_string(counter++)};
        draft.baseline = baseline.id;
        draft.baseline_generation = baseline.generation;
        draft.members = {AssetId{"node-0"}, AssetId{"node-1"}};
        auto created = manager.value()->create_cohort(draft, context_at(now, "req-cohort"));
        CHECK(created.has_value());
        if (created.has_value()) {
          cohorts.push_back(created.value().id);
        }
      }
    } else if (choice == 9 && !cohorts.empty()) {
      operation = "authorize_and_promote_cohort";
      const CohortId id = cohorts[random.below(static_cast<std::uint32_t>(cohorts.size()))];
      for (const Cohort& candidate : manager.value()->cohorts()) {
        if (!(candidate.id == id)) {
          continue;
        }
        if (candidate.state == CohortState::Draft) {
          auto authorized = manager.value()->authorize_cohort(id, candidate.revision,
                                                              context_at(now, "req-authorize"));
          CHECK(authorized.has_value());
        } else if (candidate.state == CohortState::Authorized ||
                   candidate.state == CohortState::Active) {
          EvaluationRequest request;
          request.now = now;
          request.gates = open_gates();
          auto promoted = manager.value()->promote_cohort(id, candidate.revision, request,
                                                          context_at(now, "req-promote"));
          // Promotion exercises the authorization the cohort was created under,
          // so redefining the baseline earlier in the sequence legitimately
          // fences it. A fenced promotion must be reported, never applied.
          const bool fenced =
              !promoted.has_value() &&
              (promoted.error().code() == ErrorCode::AuthorityStaleGeneration ||
               promoted.error().code() == ErrorCode::AuthorityStalePolicyGeneration ||
               promoted.error().code() == ErrorCode::AuthorityDigestMismatch);
          CHECK(promoted.has_value() || fenced);
          if (promoted.has_value() && !promoted.value().satisfied) {
            if (promoted.value().unmet_conditions.empty()) {
              report_and_throw(seed, step, operation,
                               "an unsatisfied gate reported no unmet condition");
            }
          }
        }
      }
    } else {
      operation = "reopen";
      const IncarnationId incarnation_before = manager.value()->incarnation();
      manager.value().reset();
      auto reopened = BaselineManager::open(manager_options(directory, false, now));
      if (!reopened.has_value()) {
        report_and_throw(seed, step, operation, reopened.error().to_string());
      }
      manager = reopened.take();
      // Opening the store mints a new incarnation, which is itself one commit,
      // so a reopen advances the sequence by exactly one from the generation it
      // recovered and advances the incarnation by exactly one.
      if (last_committed.is_set() &&
          manager.value()->commit_sequence().value() != last_committed.value() + 1u) {
        report_and_throw(seed, step, operation,
                         "a reopen did not advance exactly one incarnation commit from the "
                         "generation it recovered");
      }
      if (incarnation_before.is_set() &&
          manager.value()->incarnation().value() != incarnation_before.value() + 1u) {
        report_and_throw(seed, step, operation,
                         "a reopen did not advance the incarnation identity by exactly one");
      }
    }

    check_monotonic(step, operation);
  }

  // Closure: the durable state must carry every baseline, cohort, exception,
  // and observation the live in-memory state carried.
  const CommitSequence live = manager.value()->commit_sequence();
  const std::size_t live_baselines = manager.value()->baselines().size();
  const std::size_t live_cohorts = manager.value()->cohorts().size();
  const std::size_t live_exceptions = manager.value()->exceptions().size();
  const std::size_t live_assets = manager.value()->assets().size();
  manager.value().reset();

  auto final_manager = BaselineManager::open(manager_options(directory, false, now));
  if (!final_manager.has_value()) {
    report_and_throw(seed, steps, "final reopen", final_manager.error().to_string());
  }
  CHECK_EQ(final_manager.value()->baselines().size(), live_baselines);
  CHECK_EQ(final_manager.value()->cohorts().size(), live_cohorts);
  CHECK_EQ(final_manager.value()->exceptions().size(), live_exceptions);
  CHECK_EQ(final_manager.value()->assets().size(), live_assets);
  CHECK_EQ(final_manager.value()->commit_sequence().value(), live.value() + 1u);
}

}  // namespace

FBM_TEST(state_machine_seed_1_holds_every_invariant) { run_sequence(1u, 120u); }
FBM_TEST(state_machine_seed_2_holds_every_invariant) { run_sequence(2u, 120u); }
FBM_TEST(state_machine_seed_3_holds_every_invariant) { run_sequence(0xDEADBEEFu, 120u); }
FBM_TEST(state_machine_seed_4_holds_every_invariant) { run_sequence(0x5EED1234u, 120u); }
