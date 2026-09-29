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

#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/baseline.hpp"
#include "summon/fbm/cohort.hpp"
#include "summon/fbm/conformance.hpp"
#include "summon/fbm/engine.hpp"
#include "summon/fbm/exception.hpp"
#include "summon/fbm/observation.hpp"
#include "summon/fbm/policy_document.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/store.hpp"

namespace summon::fbm {

struct ManagerOptions {
  std::filesystem::path directory;
  bool create_if_missing = false;
  // Operator-supplied signing key. When set, minted authorization tokens are
  // HMAC-SHA256 signed. The library never stores or logs the key.
  std::optional<std::string> signing_key;
  // When true, a token whose signature mode is None is rejected outright.
  bool require_signature = false;
  // Time recorded for the incarnation-advancing commit performed at open. Left
  // unset, the system clock is read exactly once, here.
  std::optional<Timestamp> opened_at;
};

// Context every externally meaningful mutation must carry. Binding a mutation
// to a request identity is what makes a lost-response retry idempotent instead
// of a double apply.
struct MutationContext {
  Timestamp now;
  RequestId request;
  ApprovalId approval;
  std::string actor;
};

struct BaselineDraft {
  BaselineId id;
  std::string title;
  std::vector<HardwareSelector> selectors;
  std::vector<ComponentRequirement> components;
  CompatibilityRuleSet rules;
  PromotionGate gate;
};

struct ExceptionDraft {
  ExceptionId id;
  ExceptionScope scope;
  Expiry expiry;
  std::string reason;
};

struct CohortDraft {
  CohortId id;
  BaselineId baseline;
  BaselineGeneration baseline_generation;
  std::vector<AssetId> members;
  std::string note;
};

// One observation submission. Exactly one of the hardware or component payloads
// must be present; a request that carries neither is rejected rather than
// recorded as an empty observation.
struct ObserveRequest {
  Timestamp now;
  EvidenceId evidence;
  AssetId asset;
  HardwareGeneration hardware_generation;
  FirmwareGeneration firmware_generation;
  ObservationSequence sequence;
  bool has_hardware = false;
  HardwareProfile hardware;
  bool has_component = false;
  FirmwareComponentId component;
  std::optional<FirmwareVersion> version;
  IncarnationId reporter;
};

// The composed authority. Owns the durable store, an immutable snapshot, and
// the evaluation engine.
//
// Concurrency model:
//   * Readers acquire the current snapshot through a single atomic load and
//     then work on their own immutable copy. They never block a writer and
//     never observe a partially applied mutation.
//   * Writers serialize on one mutex, build a complete new snapshot, commit it
//     to the durable store, and only then publish it. A commit that fails
//     leaves the previous snapshot published and unchanged.
//   * No callback, event, or user code ever runs while the mutex is held.
//   * The cross-process writer lock is taken once at open and held for the
//     lifetime of the object, so there is exactly one lock acquisition in the
//     whole lock order and no lock nesting is possible.
class BaselineManager {
 public:
  BaselineManager(const BaselineManager&) = delete;
  BaselineManager& operator=(const BaselineManager&) = delete;
  ~BaselineManager();

  static Result<std::unique_ptr<BaselineManager>> open(const ManagerOptions& options);

  // --- Identity of the running authority -----------------------------------
  const RecoveryReport& recovery() const noexcept { return recovery_; }
  const std::filesystem::path& directory() const noexcept { return directory_; }
  IncarnationId incarnation() const;
  PolicyGeneration policy_generation() const;
  ControlEpoch control_epoch() const;
  CommitSequence commit_sequence() const;
  Digest published_digest() const;

  // Re-reads the store without releasing the writer lock. Used to observe state
  // written by a previous incarnation of this process.
  Status reload();

  // --- Policy --------------------------------------------------------------
  // Every one of these advances the policy generation, which fences every
  // authorization and every exception granted under the previous generation.
  Result<Baseline> define_baseline(const BaselineDraft& draft, const MutationContext& context);
  Result<Baseline> publish_baseline(const BaselineId& id, BaselineGeneration generation,
                                    const MutationContext& context);
  Result<Baseline> retire_baseline(const BaselineId& id, BaselineGeneration generation,
                                   const MutationContext& context);
  Result<std::vector<BaselineId>> apply_policy_document(const PolicyDocument& document,
                                                        const MutationContext& context);
  PolicyDocument export_policy_document() const;

  // --- Evidence ------------------------------------------------------------
  Result<ObservationOutcome> observe(const ObserveRequest& request);

  // --- Exceptions ----------------------------------------------------------
  Result<BaselineException> grant_exception(const ExceptionDraft& draft,
                                            const MutationContext& context);
  Result<BaselineException> revoke_exception(const ExceptionId& id, Revision revision,
                                             const MutationContext& context);

  // --- Cohorts -------------------------------------------------------------
  Result<Cohort> create_cohort(const CohortDraft& draft, const MutationContext& context);
  Result<Cohort> authorize_cohort(const CohortId& id, Revision revision,
                                  const MutationContext& context);
  Result<Cohort> pause_cohort(const CohortId& id, Revision revision, const MutationContext& context);
  Result<Cohort> resume_cohort(const CohortId& id, Revision revision, const MutationContext& context);
  Result<Cohort> cancel_cohort(const CohortId& id, Revision revision, const MutationContext& context);
  Result<GateReport> promote_cohort(const CohortId& id, Revision revision,
                                    const EvaluationRequest& request,
                                    const MutationContext& context);

  // Mints a token authorizing an external executor to act for one cohort. The
  // token binds to the cohort's current revision, the baseline generation and
  // digest, the policy generation, the control epoch, and the request identity.
  Result<AuthorizationToken> authorize_rollout(const CohortId& id, Revision revision,
                                               const MutationContext& context);
  Result<AuthorizationToken> authorize_rollback(const CohortId& id, Revision revision,
                                                const MutationContext& context);

  // Verifies a token against the state the manager currently holds.
  Status verify_token(const AuthorizationToken& token, const std::string& scope,
                      const PlanId& plan, Timestamp now) const;

  // --- Queries (never mutate, never block a writer) --------------------------
  Result<ConformanceVerdict> evaluate(const EvaluationRequest& request) const;
  Result<EligibilityVerdict> rollout_eligibility(const EvaluationRequest& request) const;
  Result<EligibilityVerdict> rollback_eligibility(const EvaluationRequest& request) const;
  Result<std::vector<DriftResidual>> list_drift(const EvaluationRequest& request) const;
  Result<std::string> explain(const EvaluationRequest& request) const;

  std::vector<Baseline> baselines() const;
  std::vector<Cohort> cohorts() const;
  std::vector<BaselineException> exceptions() const;
  std::vector<AssetId> assets() const;
  // The snapshot currently published. The reference stays valid until this
  // manager publishes the next generation on this thread, because the manager
  // holds the generation alive even after the temporary shared_ptr that hands
  // it out has been released. A caller that keeps the reference across a
  // mutation on the same thread must take a copy instead.
  const Snapshot& snapshot() const noexcept { return *snapshot_.load(); }

 private:
  BaselineManager() = default;

  // Validates and durably publishes a new snapshot, then makes it visible to
  // readers in one atomic store. A failure at any point leaves the previously
  // published snapshot in place and unchanged.
  Status publish_snapshot(Snapshot next);

  // Shared implementation of the pause, resume, and cancel transitions.
  Result<Cohort> transition_cohort(const CohortId& id, Revision revision,
                                   const MutationContext& context, CohortState from_a,
                                   CohortState from_b, CohortState to, bool restage);

  // Shared implementation of authorize_rollout and authorize_rollback. Mints
  // the token and records it; the caller publishes.
  Result<AuthorizationToken> mint_cohort_token(const Snapshot& next, const CohortId& id,
                                               Revision revision, const char* action,
                                               const MutationContext& context);

  // Builds an engine over the snapshot that is currently published.
  Engine make_engine() const;
  // Builds an engine over a specific snapshot, used inside a commit.
  static Engine engine_for(std::shared_ptr<const Snapshot> snapshot);

  std::shared_ptr<const Snapshot> snapshot_now() const noexcept { return snapshot_.load(); }

  std::filesystem::path directory_;
  std::unique_ptr<DurableStore> store_;
  RecoveryReport recovery_;
  // The publication point. Readers load this without taking any lock.
  mutable std::atomic<std::shared_ptr<const Snapshot>> snapshot_;
  // Serializes writers only.
  mutable std::mutex writer_mutex_;
  AuthorizationAuthority authority_;
  bool require_signature_ = false;
};

}  // namespace summon::fbm
