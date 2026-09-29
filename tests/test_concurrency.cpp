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

// Proofs for the documented concurrency model of BaselineManager:
//
//   * readers load the published snapshot in one atomic load and work on their
//     own immutable copy, so a reader never observes a partially applied
//     mutation and never blocks a writer;
//   * writers serialize on one mutex, build a complete snapshot, commit it, and
//     only then publish it;
//   * no callback, event, or user code runs while the writer mutex is held;
//   * a failed mutation leaves the previously published snapshot untouched;
//   * repeated open and close of the same store is safe and advances the
//     incarnation by exactly one per open.
//
// Nothing here relies on timing for correctness: every wait is a fixed
// handshake between threads, every observation is checked against the exact
// generation it names, and no thread performs a check on the test harness
// (reporting is done by the main thread after every join, because the harness
// counters are not atomic).

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "support.hpp"

namespace {

using namespace fbm_test;

// The tree's shared draft lists components in schema order; sorting is a no-op
// today and keeps these tests correct if a fixture is authored out of order.
BaselineDraft schema_ordered(BaselineDraft draft) {
  std::sort(draft.components.begin(), draft.components.end(),
            [](const ComponentRequirement& left, const ComponentRequirement& right) {
              return left.component < right.component;
            });
  return draft;
}

struct Authority {
  std::unique_ptr<BaselineManager> manager;
  BaselineId baseline;
  BaselineGeneration generation;
  Revision baseline_revision;
  AssetId asset;
  Timestamp now;
};

Authority publish_authority(const std::filesystem::path& directory,
                            const Timestamp& start = base_time()) {
  Fixture fixture = publish_fixture(directory, start);
  Authority authority;
  authority.manager = std::move(fixture.manager);
  authority.baseline = fixture.baseline;
  authority.generation = fixture.generation;
  authority.baseline_revision = fixture.baseline_revision;
  authority.asset = fixture.asset;
  authority.now = fixture.now;
  return authority;
}

EvaluationRequest request_for(const AssetId& asset, const Timestamp& now) {
  EvaluationRequest request;
  request.asset = asset;
  request.now = now;
  request.gates = open_gates();
  return request;
}

const ComponentEvaluation* component_for(const ConformanceVerdict& verdict,
                                         const FirmwareComponentId& component) {
  for (const ComponentEvaluation& evaluation : verdict.components) {
    if (evaluation.component == component) {
      return &evaluation;
    }
  }
  return nullptr;
}

void spin_until(const std::atomic<bool>& flag) {
  while (!flag.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
}

// Records only what the main thread needs to check afterwards. No thread other
// than the main thread ever reports a failure.
struct ReaderOutcome {
  std::vector<ConformanceVerdict> verdicts;
  std::vector<std::string> errors;
  bool reached_mid_loop = false;
};

struct WriterOutcome {
  bool finished = false;
  std::string error;
  std::vector<std::uint64_t> sequences;
};

}  // namespace

// ---------------------------------------------------------------------------
// Readers never observe a partially applied mutation.
// ---------------------------------------------------------------------------

FBM_TEST(readers_never_observe_a_partially_applied_mutation) {
  const std::filesystem::path directory = scratch_directory("concurrency-readers");
  Authority authority = publish_authority(directory);
  const AssetId asset = authority.asset;
  make_conformant(*authority.manager, asset, authority.now);

  constexpr int kReaders = 4;
  constexpr int kReadsPerReader = 48;
  constexpr int kMutations = 96;
  const FirmwareVersion conformant = version("2.4.1");
  const FirmwareVersion drifted = version("2.5.0");

  // Every published generation, with the exact bmc version it contains. Only
  // the single writer touches it, and only the main thread reads it after the
  // join, so it needs no lock of its own.
  std::map<std::uint64_t, std::string> bmc_by_sequence;
  bmc_by_sequence[authority.manager->commit_sequence().value()] = conformant.to_string();

  const PolicyGeneration policy_generation = authority.manager->policy_generation();
  const CommitSequence first_sequence = authority.manager->commit_sequence();

  // Readers evaluate at a fixed instant after every observation time, so all
  // evidence is fresh and the expected verdict is a pure function of the
  // generation the reader names.
  const Timestamp evaluation_time = at(1769904000ull + 1000ull);
  EvaluationRequest request = request_for(asset, evaluation_time);

  std::atomic<bool> go{false};
  std::atomic<int> readers_ready{0};
  std::atomic<int> readers_mid_loop{0};

  std::vector<ReaderOutcome> outcomes(kReaders);
  std::vector<std::thread> readers;
  readers.reserve(kReaders);
  for (int index = 0; index < kReaders; ++index) {
    readers.emplace_back([&, index]() {
      ReaderOutcome& outcome = outcomes[static_cast<std::size_t>(index)];
      outcome.verdicts.reserve(kReadsPerReader);
      // A read before the writer is released, so that "started" means a reader
      // that is already evaluating.
      auto warm_up = authority.manager->evaluate(request);
      if (warm_up.has_value()) {
        outcome.verdicts.push_back(warm_up.value());
      } else {
        outcome.errors.push_back(warm_up.error().to_string());
      }
      readers_ready.fetch_add(1);
      spin_until(go);
      // The writer is released only after every reader has announced readiness,
      // and the writer is released before this loop runs. Every reader still has
      // kReadsPerReader - 1 evaluations to perform from here, so the remaining
      // reads are concurrent with the writer's mutation loop by construction.
      outcome.reached_mid_loop = true;
      readers_mid_loop.fetch_add(1);
      for (int read = 1; read < kReadsPerReader; ++read) {
        auto verdict = authority.manager->evaluate(request);
        if (verdict.has_value()) {
          outcome.verdicts.push_back(verdict.value());
        } else {
          outcome.errors.push_back(verdict.error().to_string());
        }
      }
    });
  }

  WriterOutcome writer;
  std::thread writer_thread([&]() {
    writer.sequences.reserve(kMutations);
    spin_until(go);
    // Wait until every reader is inside its read loop, so the writer's commits
    // provably overlap live readers.
    while (readers_mid_loop.load() < kReaders) {
      std::this_thread::yield();
    }
    const FirmwareVersion values[2] = {drifted, conformant};
    for (int mutation = 0; mutation < kMutations; ++mutation) {
      const FirmwareVersion& value = values[mutation % 2];
      const Timestamp when = at(1769904000ull + 1ull + static_cast<std::uint64_t>(mutation));
      auto outcome = observe_component(*authority.manager, asset, "bmc",
                                       std::optional<FirmwareVersion>{value},
                                       ObservationSequence{10ull + static_cast<std::uint64_t>(mutation)},
                                       when, "ev-writer");
      if (!outcome.has_value()) {
        writer.error = outcome.error().to_string();
        break;
      }
      // This is the only writer, so the published sequence is this mutation's.
      const std::uint64_t sequence = authority.manager->commit_sequence().value();
      writer.sequences.push_back(sequence);
      bmc_by_sequence[sequence] = value.to_string();
    }
    writer.finished = true;
  });

  // Release the writer once every reader has started.
  while (readers_ready.load() < kReaders) {
    std::this_thread::yield();
  }
  go.store(true, std::memory_order_release);

  for (std::thread& reader : readers) {
    reader.join();
  }
  writer_thread.join();

  // The writer serialized: one contiguous sequence per mutation, no gaps.
  CHECK(writer.error.empty());
  CHECK(writer.finished);
  CHECK_EQ(writer.sequences.size(), static_cast<std::size_t>(kMutations));
  for (std::size_t index = 1; index < writer.sequences.size(); ++index) {
    CHECK_EQ(writer.sequences[index], writer.sequences[index - 1] + 1u);
  }
  CHECK_EQ(writer.sequences.front(), first_sequence.value() + 1u);
  CHECK_EQ(authority.manager->commit_sequence().value(), first_sequence.value() + kMutations);

  std::vector<std::uint64_t> observed_sequences;
  for (int index = 0; index < kReaders; ++index) {
    const ReaderOutcome& outcome = outcomes[static_cast<std::size_t>(index)];
    CHECK(outcome.reached_mid_loop);
    // Readers never block on a writer: each one completed every evaluation it
    // was asked for, and the join above returned.
    CHECK(outcome.errors.empty());
    CHECK_EQ(outcome.verdicts.size(), static_cast<std::size_t>(kReadsPerReader));
    for (const ConformanceVerdict& verdict : outcome.verdicts) {
      // The verdict must name a generation the writer actually published, and
      // the content it reports must be exactly that generation's content.
      const auto found = bmc_by_sequence.find(verdict.commit_sequence.value());
      CHECK(found != bmc_by_sequence.end());
      if (found == bmc_by_sequence.end()) {
        continue;
      }
      observed_sequences.push_back(verdict.commit_sequence.value());
      CHECK_EQ(verdict.policy_generation, policy_generation);
      CHECK_EQ(verdict.baseline, authority.baseline);
      CHECK_EQ(verdict.baseline_generation, authority.generation);
      const ComponentEvaluation* bmc = component_for(verdict, FirmwareComponentId{"bmc"});
      CHECK(bmc != nullptr);
      if (bmc == nullptr) {
        continue;
      }
      CHECK(bmc->observed.has_value());
      CHECK_EQ(bmc->observed->to_string(), found->second);
      CHECK(bmc->conformant == (found->second == conformant.to_string()));
      // A complete generation can only produce one of two verdicts here.
      if (found->second == conformant.to_string()) {
        CHECK_EQ(verdict.state, ConformanceState::Conformant);
        CHECK_EQ(verdict.reason_code_value, std::string{reason_code::kConformant});
        CHECK(verdict.residuals.empty());
      } else {
        CHECK_EQ(verdict.state, ConformanceState::Drifted);
        CHECK_EQ(verdict.reason_code_value, std::string{reason_code::kDrift});
        CHECK_EQ(verdict.residuals.size(), std::size_t{1});
      }
    }
  }
  CHECK(!observed_sequences.empty());
  for (std::uint64_t sequence : observed_sequences) {
    CHECK(sequence >= first_sequence.value());
    CHECK(sequence <= authority.manager->commit_sequence().value());
  }
  // Every recorded generation is a complete one, and the writer's last
  // mutation is the one the store now holds.
  const FirmwareObservation* stored =
      authority.manager->snapshot().observations.component(asset, FirmwareComponentId{"bmc"});
  REQUIRE(stored != nullptr);
  CHECK_EQ(stored->version.value().to_string(), bmc_by_sequence.rbegin()->second);
}

// ---------------------------------------------------------------------------
// Writers serialize: request identity per mutation, one commit each.
// ---------------------------------------------------------------------------

FBM_TEST(writer_serializes_every_mutation_exactly_once) {
  const std::filesystem::path directory = scratch_directory("concurrency-writer-serialization");
  Authority authority = publish_authority(directory);

  CohortDraft cohort_draft;
  cohort_draft.id = CohortId{"wave-serial"};
  cohort_draft.baseline = authority.baseline;
  cohort_draft.baseline_generation = authority.generation;
  cohort_draft.members = {authority.asset};
  auto cohort = authority.manager->create_cohort(cohort_draft, context_at(authority.now, "req-c"));
  CHECK_OK(cohort);
  auto authorized = authority.manager->authorize_cohort(cohort.value().id, cohort.value().revision,
                                                        context_at(authority.now, "req-a"));
  CHECK_OK(authorized);

  constexpr int kWriters = 4;
  constexpr int kMutationsPerWriter = 8;
  constexpr int kTotalMutations = kWriters * kMutationsPerWriter;
  const CommitSequence first_sequence = authority.manager->commit_sequence();

  std::atomic<int> successes{0};
  std::vector<std::string> errors(kWriters);
  std::vector<std::thread> writers;
  writers.reserve(kWriters);
  for (int writer = 0; writer < kWriters; ++writer) {
    writers.emplace_back([&, writer]() {
      for (int mutation = 0; mutation < kMutationsPerWriter; ++mutation) {
        const std::string request_id =
            "req-" + std::to_string(writer) + "-" + std::to_string(mutation);
        MutationContext context = context_at(authority.now, request_id.c_str());
        auto token = authority.manager->authorize_rollout(authorized.value().id,
                                                         authorized.value().revision, context);
        if (!token.has_value()) {
          errors[static_cast<std::size_t>(writer)] = token.error().to_string();
          return;
        }
        successes.fetch_add(1);
      }
    });
  }
  for (std::thread& writer : writers) {
    writer.join();
  }

  for (const std::string& error : errors) {
    CHECK(error.empty());
  }
  CHECK_EQ(successes.load(), kTotalMutations);
  CHECK_EQ(authority.manager->commit_sequence().value(),
           first_sequence.value() + static_cast<std::uint64_t>(kTotalMutations));

  // Each recorded authorization names the generation the writer saw while
  // holding the writer mutex, so the commit it performed is that sequence plus
  // one. Commits are serialized one at a time, so those sequences must be
  // exactly the contiguous range the successful mutations produced: no gap and
  // no duplicate.
  std::vector<std::uint64_t> committed_by_mutation;
  committed_by_mutation.reserve(kTotalMutations);
  for (const auto& entry : authority.manager->snapshot().authorizations.items()) {
    CHECK(entry.first.view().rfind("req-", 0) == 0);
    const AuthorityBinding& binding = entry.second.binding;
    CHECK(binding.commit_sequence.is_set());
    committed_by_mutation.push_back(binding.commit_sequence.value() + 1u);
  }
  CHECK_EQ(committed_by_mutation.size(), static_cast<std::size_t>(kTotalMutations));
  std::sort(committed_by_mutation.begin(), committed_by_mutation.end());
  CHECK_EQ(committed_by_mutation.front(), first_sequence.value() + 1u);
  CHECK_EQ(committed_by_mutation.back(),
           first_sequence.value() + static_cast<std::uint64_t>(kTotalMutations));
  for (std::size_t index = 1; index < committed_by_mutation.size(); ++index) {
    CHECK_EQ(committed_by_mutation[index], committed_by_mutation[index - 1] + 1u);
  }
  CHECK_EQ(authority.manager->snapshot().authorizations.size(),
           static_cast<std::size_t>(kTotalMutations));
}

// ---------------------------------------------------------------------------
// A rejected mutation leaves the published snapshot exactly as it was.
// ---------------------------------------------------------------------------

FBM_TEST(a_rejected_mutation_leaves_the_snapshot_unchanged) {
  const std::filesystem::path directory = scratch_directory("concurrency-rejected");
  Authority authority = publish_authority(directory);
  BaselineManager& manager = *authority.manager;

  // One successful exception so that a duplicate can be attempted, and one
  // observation so that an out-of-order and a conflicting one can be attempted.
  ExceptionDraft exception_draft;
  exception_draft.id = ExceptionId{"exc-1"};
  exception_draft.scope.hardware_class = HardwareClassId{"gpu"};
  exception_draft.expiry = Expiry::never();
  exception_draft.reason = "unchanged";
  CHECK_OK(manager.grant_exception(exception_draft, context_at(authority.now, "req-exc")));
  CHECK_OK(observe_profile(manager, authority.asset, profile_of(), ObservationSequence{1},
                           authority.now, "ev-profile"));

  const CommitSequence sequence_before = manager.commit_sequence();
  const Digest payload_before = manager.published_digest();
  const Digest content_before = manager.snapshot().content_digest();
  const Revision revision_before = manager.snapshot().revision;

  auto check_unchanged = [&](const char* what) {
    CHECK_MSG(manager.commit_sequence() == sequence_before,
              what << ": the commit sequence moved");
    CHECK_MSG(manager.published_digest() == payload_before, what << ": the payload digest moved");
    CHECK_MSG(manager.snapshot().content_digest() == content_before,
              what << ": the snapshot content digest moved");
    CHECK_EQ(manager.snapshot().revision, revision_before);
  };

  auto published_wrong_generation = manager.publish_baseline(
      authority.baseline, BaselineGeneration{authority.generation.value() + 1},
      context_at(authority.now, "req-fail-1"));
  CHECK_ERROR(published_wrong_generation, ErrorCode::AuthorityStaleGeneration);
  check_unchanged("publish with a stale generation");

  auto published_unknown = manager.publish_baseline(BaselineId{"no-such-baseline"},
                                                    BaselineGeneration{1},
                                                    context_at(authority.now, "req-fail-2"));
  CHECK_ERROR(published_unknown, ErrorCode::IdentityUnknownBaseline);
  check_unchanged("publish an unknown baseline");

  auto revoked_unknown = manager.revoke_exception(ExceptionId{"no-such-exception"}, Revision{1},
                                                  context_at(authority.now, "req-fail-3"));
  CHECK_ERROR(revoked_unknown, ErrorCode::IdentityUnknownException);
  check_unchanged("revoke an unknown exception");

  auto duplicated_exception = manager.grant_exception(exception_draft,
                                                      context_at(authority.now, "req-fail-4"));
  CHECK_ERROR(duplicated_exception, ErrorCode::SchemaDuplicateIdentifier);
  check_unchanged("grant a duplicate exception");

  CohortDraft unknown_baseline_cohort;
  unknown_baseline_cohort.id = CohortId{"wave-unknown"};
  unknown_baseline_cohort.baseline = BaselineId{"no-such-baseline"};
  unknown_baseline_cohort.baseline_generation = BaselineGeneration{1};
  unknown_baseline_cohort.members = {authority.asset};
  auto cohort_unknown_baseline = manager.create_cohort(unknown_baseline_cohort,
                                                       context_at(authority.now, "req-fail-5"));
  CHECK_ERROR(cohort_unknown_baseline, ErrorCode::IdentityUnknownBaseline);
  check_unchanged("create a cohort for an unknown baseline");

  CohortDraft stale_cohort = unknown_baseline_cohort;
  stale_cohort.id = CohortId{"wave-stale"};
  stale_cohort.baseline = authority.baseline;
  stale_cohort.baseline_generation = BaselineGeneration{authority.generation.value() + 1};
  auto cohort_stale_generation = manager.create_cohort(stale_cohort,
                                                       context_at(authority.now, "req-fail-6"));
  CHECK_ERROR(cohort_stale_generation, ErrorCode::AuthorityStaleGeneration);
  check_unchanged("create a cohort at a stale generation");

  auto authorized_unknown = manager.authorize_cohort(CohortId{"no-such-cohort"}, Revision{1},
                                                     context_at(authority.now, "req-fail-7"));
  CHECK_ERROR(authorized_unknown, ErrorCode::IdentityUnknownCohort);
  check_unchanged("authorize an unknown cohort");

  // Out of order: the stored profile evidence is already at sequence 1.
  auto out_of_order = observe_profile(manager, authority.asset, profile_of(), ObservationSequence{0},
                                      authority.now, "ev-profile");
  CHECK_ERROR(out_of_order, ErrorCode::EvidenceOutOfOrder);
  check_unchanged("an out-of-order observation");

  // Same sequence, different content.
  HardwareProfile changed = profile_of();
  changed.revision = HardwareRevision{3};
  auto conflicting = observe_profile(manager, authority.asset, changed, ObservationSequence{1},
                                     authority.now, "ev-profile");
  CHECK_ERROR(conflicting, ErrorCode::EvidenceConflicting);
  check_unchanged("a conflicting observation");

  // A draft the schema rejects outright.
  BaselineDraft invalid = standard_draft("invalid-baseline");
  invalid.selectors.clear();
  auto defined_invalid = manager.define_baseline(schema_ordered(std::move(invalid)),
                                                 context_at(authority.now, "req-fail-8"));
  CHECK(!defined_invalid.has_value());
  check_unchanged("an invalid draft");

  // The same request identity replayed with different content is not a second
  // grant either.
  auto replayed = manager.define_baseline(schema_ordered(standard_draft("replayed-baseline")),
                                          context_at(authority.now, "req-fail-4"));
  CHECK_OK(replayed);
}

// ---------------------------------------------------------------------------
// User code never runs inside the manager's critical section.
// ---------------------------------------------------------------------------

namespace {

// A commit observer is user code: it is invoked by the store while a commit is
// in progress. Recording the points it sees is what makes the observation of a
// generation possible from another thread.
class CommitWatcher : public ICommitObserver {
 public:
  void on_commit_point(CommitPoint point) override {
    const std::string token{commit_point_token(point)};
    points.push_back(token);
    if (point == CommitPoint::AfterStageVerify && handshake_enabled) {
      const int index = inspections_started.fetch_add(1);
      permit.store(index + 1, std::memory_order_release);
      // Stay inside the commit until the reader has completed one inspection of
      // the durable directory. This is a handshake, not a delay: if the reader
      // blocked on the writer, the test would not terminate.
      while (!stop.load(std::memory_order_acquire) &&
             inspections_completed.load(std::memory_order_acquire) < index + 1) {
        std::this_thread::yield();
      }
    }
  }

  // The reader handshake is installed only for the test that has a reader.
  bool handshake_enabled = false;
  std::vector<std::string> points;
  std::atomic<int> inspections_started{0};
  std::atomic<int> inspections_completed{0};
  std::atomic<int> permit{0};
  std::atomic<bool> stop{false};
};

}  // namespace

FBM_TEST(no_user_code_runs_inside_the_writers_critical_section) {
  // Part one: the observer mechanism itself. A store that installs an observer
  // reports every commit point, in order.
  const std::filesystem::path observed_directory = scratch_directory("concurrency-observer");
  CommitWatcher watcher;
  {
    StoreOptions options;
    options.directory = observed_directory;
    options.create_if_missing = true;
    options.take_writer_lock = true;
    auto store = DurableStore::open(options, &watcher);
    CHECK_OK(store);
    Snapshot snapshot = Snapshot::empty();
    snapshot.created_at = base_time();
    snapshot.updated_at = base_time();
    auto committed = store.value()->commit(std::move(snapshot));
    CHECK_OK(committed);
  }
  const std::vector<std::string> expected_points = {
      "before_stage_write", "after_stage_flush", "after_stage_verify",
      "after_publish",      "before_fence_write", "after_fence_write",
  };
  CHECK_EQ(watcher.points, expected_points);
  const std::size_t observer_calls_after_store = watcher.points.size();
  CHECK_EQ(observer_calls_after_store, std::size_t{6});

  // Part two: the manager, opened on the same directory with the same observer
  // object still alive, performs policy and evidence mutations. The manager
  // never invokes user code while it holds the writer mutex: the observer is
  // not called once.
  auto opened = BaselineManager::open(manager_options(observed_directory, false, base_time()));
  CHECK_OK(opened);
  std::unique_ptr<BaselineManager> manager = opened.take();
  const IncarnationId first_incarnation = manager->incarnation();
  for (int index = 0; index < 32; ++index) {
    const Timestamp when = at(1769904000ull + static_cast<std::uint64_t>(index));
    CHECK_OK(observe_component(*manager, AssetId{"node-01"}, "bmc", version("2.4.1"),
                               ObservationSequence{static_cast<std::uint64_t>(index) + 1}, when,
                               "ev-manager"));
  }
  CHECK_OK(manager->define_baseline(schema_ordered(standard_draft("gpu-h100-train")),
                                    context_at(base_time(), "req-d")));
  CHECK_OK(manager->publish_baseline(BaselineId{"gpu-h100-train"}, BaselineGeneration{1},
                                     context_at(base_time(), "req-p")));
  CHECK_EQ(watcher.points.size(), observer_calls_after_store);
  CHECK_EQ(manager->incarnation().value(), first_incarnation.value());
  manager.reset();

  // Part three: a reader completes while a writer is inside its commit. The
  // observer holds the writer inside the commit until an independent reader has
  // finished inspecting the durable directory, and every inspection must name a
  // complete generation: no fence before the first commit, then exactly the
  // previously fenced generation, never the in-flight one.
  const std::filesystem::path handshake_directory = scratch_directory("concurrency-handshake");
  CommitWatcher handshake;
  handshake.handshake_enabled = true;
  std::vector<RecoveryReport> inspections;
  std::string inspect_error;
  constexpr int kCommits = 3;
  std::thread reader([&]() {
    int completed = 0;
    while (!handshake.stop.load(std::memory_order_acquire)) {
      const int target = handshake.permit.load(std::memory_order_acquire);
      if (completed >= target) {
        std::this_thread::yield();
        continue;
      }
      auto report = DurableStore::inspect(handshake_directory);
      if (report.has_value()) {
        inspections.push_back(report.value());
      } else if (inspect_error.empty()) {
        inspect_error = report.error().to_string();
      }
      ++completed;
      handshake.inspections_completed.store(completed, std::memory_order_release);
    }
  });

  Status writer_status = ok_status();
  {
    StoreOptions options;
    options.directory = handshake_directory;
    options.create_if_missing = true;
    options.take_writer_lock = true;
    auto store = DurableStore::open(options, &handshake);
    if (!store.has_value()) {
      writer_status = store.error();
    } else {
      for (int commit = 0; commit < kCommits; ++commit) {
        Snapshot snapshot = Snapshot::empty();
        snapshot.created_at = base_time();
        snapshot.updated_at = base_time();
        snapshot.policy_generation = PolicyGeneration{static_cast<std::uint64_t>(commit) + 1};
        auto committed = store.value()->commit(std::move(snapshot));
        if (!committed.has_value()) {
          writer_status = committed.error();
          break;
        }
      }
    }
  }
  handshake.stop.store(true, std::memory_order_release);
  reader.join();

  CHECK_OK(writer_status);
  CHECK(inspect_error.empty());
  CHECK_EQ(inspections.size(), std::size_t{kCommits});
  // Every inspection ran between the writer's stage verification and its
  // fence write, so it can only see the generation the fence still names.
  for (std::size_t index = 0; index < inspections.size(); ++index) {
    const RecoveryReport& report = inspections[index];
    if (index == 0) {
      CHECK_EQ(report.outcome, RecoveryOutcome::Empty);
      CHECK(!report.fence_present);
    } else {
      CHECK_EQ(report.outcome, RecoveryOutcome::Recovered);
      CHECK(report.fence_present);
      CHECK(report.fence_valid);
      CHECK_EQ(report.commit_sequence.value(), index);
    }
  }
  // The writer completed every commit after the reader finished inside it, so
  // the reader never observed a partially applied mutation.
  auto final_report = DurableStore::inspect(handshake_directory);
  CHECK_OK(final_report);
  CHECK_EQ(final_report.value().outcome, RecoveryOutcome::Recovered);
  CHECK_EQ(final_report.value().commit_sequence.value(), static_cast<std::uint64_t>(kCommits));
}

// ---------------------------------------------------------------------------
// Repeated open and close.
// ---------------------------------------------------------------------------

FBM_TEST(repeated_open_and_close_advances_the_incarnation_by_one) {
  const std::filesystem::path directory = scratch_directory("concurrency-reopen");
  Authority authority = publish_authority(directory);
  const BaselineId baseline = authority.baseline;
  const CommitSequence sequence_after_first_open = authority.manager->commit_sequence();
  const IncarnationId first_incarnation = authority.manager->incarnation();
  CHECK_EQ(first_incarnation, IncarnationId{1});

  // A second manager on the same directory cannot take the writer lock while
  // the first is open, so the single-writer property is enforced across opens
  // in one process too.
  auto busy = BaselineManager::open(manager_options(directory, false));
  CHECK_ERROR(busy, ErrorCode::IoLockBusy);

  // Close the first incarnation and reopen the same store from the same process
  // four times. Every open performs exactly one commit, so the incarnation and
  // the commit sequence each advance by exactly one per open.
  authority.manager.reset();
  std::uint64_t rounds = 0;
  for (std::uint64_t round = 1; round <= 4; ++round) {
    const Timestamp opened_at = at(1769904000ull + round * 60ull);
    auto reopened = BaselineManager::open(manager_options(directory, false, opened_at));
    CHECK_OK(reopened);
    std::unique_ptr<BaselineManager> manager = reopened.take();
    CHECK_EQ(manager->incarnation(), IncarnationId{round + 1});
    CHECK_EQ(manager->commit_sequence(), CommitSequence{sequence_after_first_open.value() + round});
    CHECK_EQ(manager->recovery().outcome, RecoveryOutcome::Recovered);
    CHECK(manager->recovery().fence_present);
    CHECK_EQ(manager->baselines().size(), std::size_t{1});
    const Baseline* recovered = manager->snapshot().baselines.find(baseline);
    REQUIRE(recovered != nullptr);
    CHECK_EQ(recovered->state, BaselineState::Published);
    CHECK_EQ(recovered->revision, authority.baseline_revision);
    // While this incarnation is open, no second writer can open the store.
    auto second = BaselineManager::open(manager_options(directory, false));
    CHECK_ERROR(second, ErrorCode::IoLockBusy);
    CHECK_EQ(first_incarnation, IncarnationId{1});
    ++rounds;
    manager.reset();
  }
  CHECK_EQ(rounds, std::uint64_t{4});
}
