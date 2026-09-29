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

#include "summon/fbm/manager.hpp"

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "summon/fbm/json.hpp"

namespace summon::fbm {
namespace {

Error make_error(ErrorCode code, std::string message, std::string path) {
  return Error{code, std::move(message), std::move(path)};
}

// Advances a counter, or starts it at one when it has never been set. Exhaustion
// is reported rather than wrapped.
template <class CounterT>
Result<CounterT> advance_counter(CounterT current, const char* what) {
  if (!current.is_set()) {
    return CounterT::first();
  }
  CounterT next;
  if (!current.checked_next(next)) {
    return make_error(ErrorCode::InternalInvariantViolation,
                      std::string{what} + " has reached its maximum value", "");
  }
  return next;
}

Status require_time(const MutationContext& context) {
  if (!context.now.is_set()) {
    return make_error(ErrorCode::InvalidArgument,
                      "a mutation must state the time it was requested", "/now");
  }
  return ok_status();
}

std::string cohort_scope(const CohortId& id, const char* action) {
  return "cohort/" + id.to_string() + "/" + action;
}

Digest subject_digest_for(const Cohort& cohort, const std::string& scope) {
  json::Value::Object members;
  members.emplace_back("scope", json::Value{scope});
  members.emplace_back("cohort", json::Value{cohort.id.to_string()});
  members.emplace_back("revision", json::Value{cohort.revision.value_or(0u)});
  members.emplace_back("baseline", json::Value{cohort.baseline.to_string()});
  members.emplace_back("baseline_generation",
                       json::Value{cohort.baseline_generation.value_or(0u)});
  members.emplace_back("baseline_digest", json::Value{digest_to_hex(cohort.baseline_digest)});
  json::Value::Array assets;
  assets.reserve(cohort.members.size());
  for (const AssetId& asset : cohort.members) {
    assets.emplace_back(asset.to_string());
  }
  members.emplace_back("members", json::Value{std::move(assets)});
  const std::string canonical = json::write_canonical(json::Value{std::move(members)});
  return Sha256::of(canonical.data(), canonical.size());
}

// Replaces an existing registry entry. Registries reject a duplicate identity on
// insert, so an update erases first and then inserts the new value.
template <class RegistryT, class IdT, class ValueT>
Status replace_entry(RegistryT& registry, const IdT& id, ValueT value) {
  registry.erase(id);
  return registry.put(std::move(value));
}

}  // namespace

Status BaselineManager::publish_snapshot(Snapshot next) {
  Diagnostics diagnostics;
  Status valid = next.validate("/", diagnostics);
  if (!valid.has_value()) {
    return diagnostics.empty() ? valid.error() : Status{diagnostics.primary()};
  }

  auto committed = store_->commit(std::move(next));
  if (!committed.has_value()) {
    return committed.error();
  }

  auto published = std::make_shared<const Snapshot>(store_->snapshot());
  snapshot_.store(std::move(published));
  return ok_status();
}

Result<std::unique_ptr<BaselineManager>> BaselineManager::open(const ManagerOptions& options) {
  if (options.directory.empty()) {
    return make_error(ErrorCode::InvalidArgument, "the store directory must not be empty", "");
  }

  StoreOptions store_options;
  store_options.directory = options.directory;
  store_options.create_if_missing = options.create_if_missing;
  store_options.take_writer_lock = true;

  auto opened = DurableStore::open(store_options);
  if (!opened.has_value()) {
    return opened.error();
  }

  std::unique_ptr<BaselineManager> manager(new BaselineManager());
  manager->directory_ = options.directory;
  manager->store_ = opened.take();
  manager->recovery_ = manager->store_->recovery();
  manager->require_signature_ = options.require_signature;
  if (options.signing_key.has_value() && !options.signing_key->empty()) {
    manager->authority_ = AuthorizationAuthority::hmac_authority(options.signing_key.value());
  }

  // Opening the store mints a new incarnation. Every authorization minted by a
  // previous incarnation is fenced from this point on.
  Snapshot next = manager->store_->snapshot();
  auto incarnation = advance_counter(next.incarnation, "the incarnation identity");
  if (!incarnation.has_value()) {
    return incarnation.error();
  }
  next.incarnation = incarnation.value();

  // A new process incarnation begins a new control epoch. The epoch is the
  // fence that survives a restart, so it moves here rather than on every
  // commit; an epoch that advanced per commit would invalidate every
  // outstanding authorization as soon as any unrelated evidence was recorded.
  auto epoch = advance_counter(next.control_epoch, "the control epoch");
  if (!epoch.has_value()) {
    return epoch.error();
  }
  next.control_epoch = epoch.value();

  next.updated_at =
      options.opened_at.has_value() ? options.opened_at.value() : Timestamp::system_now();
  if (!next.created_at.is_set()) {
    next.created_at = next.updated_at;
  }

  Status published = manager->publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }

  return std::move(manager);
}

BaselineManager::~BaselineManager() = default;

IncarnationId BaselineManager::incarnation() const { return snapshot_now()->incarnation; }
PolicyGeneration BaselineManager::policy_generation() const {
  return snapshot_now()->policy_generation;
}
ControlEpoch BaselineManager::control_epoch() const { return snapshot_now()->control_epoch; }
CommitSequence BaselineManager::commit_sequence() const {
  return snapshot_now()->commit_sequence;
}
Digest BaselineManager::published_digest() const { return store_->published_digest(); }

Engine BaselineManager::engine_for(std::shared_ptr<const Snapshot> snapshot) {
  return Engine{std::move(snapshot)};
}

Engine BaselineManager::make_engine() const { return Engine{snapshot_now()}; }

Status BaselineManager::reload() {
  std::lock_guard<std::mutex> guard(writer_mutex_);
  Status reloaded = store_->reload();
  if (!reloaded.has_value()) {
    return reloaded;
  }
  recovery_ = store_->recovery();
  snapshot_.store(std::make_shared<const Snapshot>(store_->snapshot()));
  return ok_status();
}

// --- Policy ------------------------------------------------------------------

Result<Baseline> BaselineManager::define_baseline(const BaselineDraft& draft,
                                                  const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }
  if (!draft.id.is_set()) {
    return make_error(ErrorCode::InvalidArgument, "a baseline identity is required", "/id");
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  const Baseline* existing = next.baselines.find(draft.id);

  Baseline baseline;
  baseline.id = draft.id;
  baseline.title = draft.title;
  baseline.selectors = draft.selectors;
  baseline.components = draft.components;
  baseline.rules = draft.rules;
  baseline.gate = draft.gate;
  baseline.state = BaselineState::Draft;
  baseline.created_at = context.now;

  auto generation = advance_counter(
      existing != nullptr ? existing->generation : BaselineGeneration{}, "the baseline generation");
  if (!generation.has_value()) {
    return generation.error();
  }
  baseline.generation = generation.value();

  auto revision = advance_counter(existing != nullptr ? existing->revision : Revision{},
                                  "the baseline revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  baseline.revision = revision.value();

  Status put = replace_entry(next.baselines, draft.id, std::move(baseline));
  if (!put.has_value()) {
    return put.error();
  }

  auto policy = advance_counter(next.policy_generation, "the policy generation");
  if (!policy.has_value()) {
    return policy.error();
  }
  next.policy_generation = policy.value();

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const Baseline* defined = next.baselines.find(draft.id);
  if (defined == nullptr) {
    return make_error(ErrorCode::InternalInvariantViolation,
                      "the baseline disappeared between insertion and publication", "/id");
  }
  const Baseline result = *defined;

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

Result<Baseline> BaselineManager::publish_baseline(const BaselineId& id,
                                                   BaselineGeneration generation,
                                                   const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  const Baseline* existing = next.baselines.find(id);
  if (existing == nullptr) {
    return make_error(ErrorCode::IdentityUnknownBaseline,
                      "no baseline with identity " + id.to_string() + " is defined", "/id");
  }
  if (!(existing->generation == generation)) {
    return make_error(ErrorCode::AuthorityStaleGeneration,
                      "baseline " + id.to_string() + " is at generation " +
                          std::to_string(existing->generation.value_or(0u)) +
                          ", not the requested generation " +
                          std::to_string(generation.value_or(0u)),
                      "/generation");
  }
  if (existing->state == BaselineState::Retired) {
    return make_error(ErrorCode::InvalidArgument,
                      "baseline " + id.to_string() + " is retired and cannot be published", "/state");
  }

  Baseline updated = *existing;
  auto revision = advance_counter(updated.revision, "the baseline revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  updated.revision = revision.value();
  updated.state = BaselineState::Published;
  updated.published_at = context.now;

  Status put = replace_entry(next.baselines, id, std::move(updated));
  if (!put.has_value()) {
    return put.error();
  }

  auto policy = advance_counter(next.policy_generation, "the policy generation");
  if (!policy.has_value()) {
    return policy.error();
  }
  next.policy_generation = policy.value();
  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const Baseline result = *next.baselines.find(id);

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

Result<Baseline> BaselineManager::retire_baseline(const BaselineId& id,
                                                  BaselineGeneration generation,
                                                  const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  const Baseline* existing = next.baselines.find(id);
  if (existing == nullptr) {
    return make_error(ErrorCode::IdentityUnknownBaseline,
                      "no baseline with identity " + id.to_string() + " is defined", "/id");
  }
  if (!(existing->generation == generation)) {
    return make_error(ErrorCode::AuthorityStaleGeneration,
                      "baseline " + id.to_string() + " is at generation " +
                          std::to_string(existing->generation.value_or(0u)) +
                          ", not the requested generation " +
                          std::to_string(generation.value_or(0u)),
                      "/generation");
  }
  if (existing->state == BaselineState::Retired) {
    return make_error(ErrorCode::InvalidArgument,
                      "baseline " + id.to_string() + " is already retired", "/state");
  }

  Baseline updated = *existing;
  auto revision = advance_counter(updated.revision, "the baseline revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  updated.revision = revision.value();
  updated.state = BaselineState::Retired;

  Status put = replace_entry(next.baselines, id, std::move(updated));
  if (!put.has_value()) {
    return put.error();
  }

  auto policy = advance_counter(next.policy_generation, "the policy generation");
  if (!policy.has_value()) {
    return policy.error();
  }
  next.policy_generation = policy.value();
  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const Baseline result = *next.baselines.find(id);

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

Result<std::vector<BaselineId>> BaselineManager::apply_policy_document(
    const PolicyDocument& document, const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  {
    Diagnostics diagnostics;
    Status valid = document.validate("/", diagnostics);
    if (!valid.has_value()) {
      return diagnostics.empty() ? Result<std::vector<BaselineId>>{valid.error()}
                                 : Result<std::vector<BaselineId>>{diagnostics.primary()};
    }
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  std::vector<BaselineId> applied;
  bool changed = false;

  for (const Baseline& authored : document.baselines()) {
    const Baseline* existing = next.baselines.find(authored.id);
    if (existing != nullptr && existing->state == authored.state &&
        existing->content_digest() == authored.content_digest()) {
      // Re-applying an identical document is idempotent: nothing changes, so no
      // generation advances and no authorization is fenced.
      applied.push_back(authored.id);
      continue;
    }

    Baseline baseline = authored;
    auto generation =
        advance_counter(existing != nullptr ? existing->generation : BaselineGeneration{},
                        "the baseline generation");
    if (!generation.has_value()) {
      return generation.error();
    }
    baseline.generation = generation.value();
    auto revision = advance_counter(existing != nullptr ? existing->revision : Revision{},
                                    "the baseline revision");
    if (!revision.has_value()) {
      return revision.error();
    }
    baseline.revision = revision.value();
    if (existing == nullptr) {
      baseline.created_at = context.now;
    }
    if (baseline.state != BaselineState::Draft && !baseline.published_at.is_set()) {
      baseline.published_at = context.now;
    }

    Status put = replace_entry(next.baselines, authored.id, std::move(baseline));
    if (!put.has_value()) {
      return put.error();
    }
    changed = true;
    applied.push_back(authored.id);
  }

  if (!changed) {
    return applied;
  }

  auto policy = advance_counter(next.policy_generation, "the policy generation");
  if (!policy.has_value()) {
    return policy.error();
  }
  next.policy_generation = policy.value();
  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return applied;
}

PolicyDocument BaselineManager::export_policy_document() const {
  auto snapshot = snapshot_now();
  std::vector<Baseline> baselines;
  baselines.reserve(snapshot->baselines.size());
  for (const auto& entry : snapshot->baselines.items()) {
    baselines.push_back(entry.second);
  }
  return PolicyDocument{std::move(baselines)};
}

// --- Evidence ----------------------------------------------------------------

Result<ObservationOutcome> BaselineManager::observe(const ObserveRequest& request) {
  MutationContext context;
  context.now = request.now;
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }
  if (!request.asset.is_set()) {
    return make_error(ErrorCode::InvalidArgument, "an asset identity is required", "/asset");
  }
  if (request.has_hardware == request.has_component) {
    return make_error(ErrorCode::InvalidArgument,
                      "exactly one of a hardware observation or a component observation must be "
                      "supplied",
                      "/observation");
  }
  if (!request.sequence.is_set()) {
    return make_error(ErrorCode::InvalidArgument,
                      "an observation sequence is required; evidence without an ordering is not "
                      "evidence",
                      "/sequence");
  }
  if (!request.evidence.is_set()) {
    return make_error(ErrorCode::InvalidArgument,
                      "evidence provenance is required for every observation", "/evidence");
  }
  if (request.has_component && !request.component.is_set()) {
    return make_error(ErrorCode::InvalidArgument,
                      "a component observation must name the component", "/component");
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  Result<ObservationOutcome> outcome = [&]() -> Result<ObservationOutcome> {
    if (request.has_hardware) {
      HardwareObservation observation;
      observation.id = ObservationId{request.asset.to_string() + ".profile"};
      observation.evidence = request.evidence;
      observation.asset = request.asset;
      observation.hardware = request.hardware;
      observation.hardware_generation = request.hardware_generation;
      observation.sequence = request.sequence;
      observation.observed_at = request.now;
      observation.reporter = request.reporter;
      return next.observations.record(std::move(observation));
    }
    FirmwareObservation observation;
    observation.id =
        ObservationId{request.asset.to_string() + "." + request.component.to_string()};
    observation.evidence = request.evidence;
    observation.asset = request.asset;
    observation.component = request.component;
    observation.version = request.version;
    observation.firmware_generation = request.firmware_generation;
    observation.sequence = request.sequence;
    observation.observed_at = request.now;
    observation.reporter = request.reporter;
    return next.observations.record(std::move(observation));
  }();

  if (!outcome.has_value()) {
    return outcome.error();
  }

  if (outcome.value() == ObservationOutcome::IdempotentReplay) {
    // A lost response retried: the stored evidence is already exactly this
    // observation, so nothing is written and no generation advances.
    return outcome.value();
  }

  auto revision = advance_counter(next.revision, "the durable revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  next.revision = revision.value();
  next.updated_at = request.now;

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return outcome.value();
}

// --- Exceptions --------------------------------------------------------------

Result<BaselineException> BaselineManager::grant_exception(const ExceptionDraft& draft,
                                                           const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }
  if (!draft.id.is_set()) {
    return make_error(ErrorCode::InvalidArgument, "an exception identity is required", "/id");
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  if (next.exceptions.find(draft.id) != nullptr) {
    return make_error(ErrorCode::SchemaDuplicateIdentifier,
                      "exception " + draft.id.to_string() + " already exists", "/id");
  }
  if (!next.policy_generation.is_set()) {
    // An exception waives drift against a baseline. With no baseline policy
    // generation in existence there is no drift to waive, and granting a waiver
    // against nothing would be authority without a subject.
    return make_error(ErrorCode::PolicyNoApplicableBaseline,
                      "no baseline policy generation exists yet, so an exception has no policy to "
                      "be granted under",
                      "/policy_generation");
  }

  BaselineException exception;
  exception.id = draft.id;
  exception.scope = draft.scope;
  exception.expiry = draft.expiry;
  exception.reason = draft.reason;
  exception.approval = context.approval;
  exception.granted_under = next.policy_generation;
  exception.state = ExceptionState::Active;
  exception.created_at = context.now;
  auto revision = advance_counter(Revision{}, "the exception revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  exception.revision = revision.value();

  Status put = next.exceptions.put(std::move(exception));
  if (!put.has_value()) {
    return put.error();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const BaselineException result = *next.exceptions.find(draft.id);

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

Result<BaselineException> BaselineManager::revoke_exception(const ExceptionId& id, Revision revision,
                                                            const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  const BaselineException* existing = next.exceptions.find(id);
  if (existing == nullptr) {
    return make_error(ErrorCode::IdentityUnknownException,
                      "no exception with identity " + id.to_string() + " exists", "/id");
  }
  if (!(existing->revision == revision)) {
    return make_error(ErrorCode::AuthorityStaleRevision,
                      "exception " + id.to_string() + " is at revision " +
                          std::to_string(existing->revision.value_or(0u)) +
                          ", not the requested revision " +
                          std::to_string(revision.value_or(0u)),
                      "/revision");
  }
  if (existing->state == ExceptionState::Revoked) {
    return make_error(ErrorCode::InvalidArgument,
                      "exception " + id.to_string() + " is already revoked", "/state");
  }

  BaselineException updated = *existing;
  auto next_revision = advance_counter(updated.revision, "the exception revision");
  if (!next_revision.has_value()) {
    return next_revision.error();
  }
  updated.revision = next_revision.value();
  updated.state = ExceptionState::Revoked;
  updated.revoked_at = context.now;

  Status put = replace_entry(next.exceptions, id, std::move(updated));
  if (!put.has_value()) {
    return put.error();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const BaselineException result = *next.exceptions.find(id);

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

// --- Cohorts -----------------------------------------------------------------

Result<Cohort> BaselineManager::create_cohort(const CohortDraft& draft,
                                              const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  if (next.cohorts.find(draft.id) != nullptr) {
    return make_error(ErrorCode::SchemaDuplicateIdentifier,
                      "cohort " + draft.id.to_string() + " already exists", "/id");
  }

  const Baseline* baseline = next.baselines.find(draft.baseline);
  if (baseline == nullptr) {
    return make_error(ErrorCode::IdentityUnknownBaseline,
                      "no baseline with identity " + draft.baseline.to_string() + " is defined",
                      "/baseline");
  }
  if (!(baseline->generation == draft.baseline_generation)) {
    return make_error(ErrorCode::AuthorityStaleGeneration,
                      "baseline " + draft.baseline.to_string() + " is at generation " +
                          std::to_string(baseline->generation.value_or(0u)) +
                          ", not the requested generation " +
                          std::to_string(draft.baseline_generation.value_or(0u)),
                      "/baseline_generation");
  }

  Cohort cohort{};
  cohort.id = draft.id;
  cohort.baseline = draft.baseline;
  cohort.baseline_generation = draft.baseline_generation;
  cohort.state = CohortState::Draft;
  cohort.members = draft.members;
  cohort.required_stages = baseline->gate.required_stages;
  cohort.note = draft.note;
  cohort.created_at = context.now;
  cohort.stage_entered_at = context.now;
  auto stage = advance_counter(StageIndex{}, "the stage index");
  if (!stage.has_value()) {
    return stage.error();
  }
  cohort.stage = stage.value();
  auto revision = advance_counter(Revision{}, "the cohort revision");
  if (!revision.has_value()) {
    return revision.error();
  }
  cohort.revision = revision.value();

  Status put = next.cohorts.put(std::move(cohort));
  if (!put.has_value()) {
    return put.error();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const Cohort result = *next.cohorts.find(draft.id);

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

Result<Cohort> BaselineManager::authorize_cohort(const CohortId& id, Revision revision,
                                                 const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  const Cohort* existing = next.cohorts.find(id);
  if (existing == nullptr) {
    return make_error(ErrorCode::IdentityUnknownCohort,
                      "no cohort with identity " + id.to_string() + " exists", "/id");
  }
  if (!(existing->revision == revision)) {
    return make_error(ErrorCode::AuthorityStaleRevision,
                      "cohort " + id.to_string() + " is at revision " +
                          std::to_string(existing->revision.value_or(0u)) +
                          ", not the requested revision " +
                          std::to_string(revision.value_or(0u)),
                      "/revision");
  }
  if (existing->state != CohortState::Draft) {
    return make_error(ErrorCode::InvalidArgument,
                      "cohort " + id.to_string() + " is not a draft and cannot be authorized again",
                      "/state");
  }

  const Baseline* baseline = next.baselines.find(existing->baseline);
  if (baseline == nullptr) {
    return make_error(ErrorCode::IdentityUnknownBaseline,
                      "cohort " + id.to_string() + " refers to an unknown baseline", "/baseline");
  }

  Cohort updated = *existing;
  updated.baseline_generation = baseline->generation;
  updated.baseline_digest = baseline->content_digest();
  updated.policy_generation = next.policy_generation;
  updated.authorized_epoch = next.control_epoch;
  updated.plan = PlanId{id.to_string() + ".plan"};
  updated.state = CohortState::Authorized;
  updated.stage_entered_at = context.now;
  auto next_revision = advance_counter(updated.revision, "the cohort revision");
  if (!next_revision.has_value()) {
    return next_revision.error();
  }
  updated.revision = next_revision.value();

  Status put = replace_entry(next.cohorts, id, std::move(updated));
  if (!put.has_value()) {
    return put.error();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const Cohort result = *next.cohorts.find(id);

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

Result<Cohort> BaselineManager::transition_cohort(const CohortId& id, Revision revision,
                                                     const MutationContext& context,
                                                     CohortState from_a, CohortState from_b,
                                                     CohortState to, bool restage) {
  Snapshot next = *snapshot_now();
  const Cohort* existing = next.cohorts.find(id);
  if (existing == nullptr) {
    return make_error(ErrorCode::IdentityUnknownCohort,
                      "no cohort with identity " + id.to_string() + " exists", "/id");
  }
  if (!(existing->revision == revision)) {
    return make_error(ErrorCode::AuthorityStaleRevision,
                      "cohort " + id.to_string() + " is at revision " +
                          std::to_string(existing->revision.value_or(0u)) +
                          ", not the requested revision " +
                          std::to_string(revision.value_or(0u)),
                      "/revision");
  }
  if (existing->state != from_a && existing->state != from_b) {
    return make_error(ErrorCode::InvalidArgument,
                      "cohort " + id.to_string() + " is in state " +
                          std::string{cohort_state_token(existing->state)} +
                          " and cannot make the requested transition",
                      "/state");
  }

  Cohort updated = *existing;
  updated.state = to;
  if (restage) {
    updated.stage_entered_at = context.now;
  }
  auto next_revision = advance_counter(updated.revision, "the cohort revision");
  if (!next_revision.has_value()) {
    return next_revision.error();
  }
  updated.revision = next_revision.value();

  Status put = replace_entry(next.cohorts, id, std::move(updated));
  if (!put.has_value()) {
    return put.error();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  const Cohort result = *next.cohorts.find(id);
  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return result;
}

Result<Cohort> BaselineManager::pause_cohort(const CohortId& id, Revision revision,
                                             const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }
  std::lock_guard<std::mutex> guard(writer_mutex_);
  return transition_cohort(id, revision, context, CohortState::Active, CohortState::Authorized,
                           CohortState::Paused, false);
}

Result<Cohort> BaselineManager::resume_cohort(const CohortId& id, Revision revision,
                                              const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }
  std::lock_guard<std::mutex> guard(writer_mutex_);
  return transition_cohort(id, revision, context, CohortState::Paused, CohortState::Paused,
                           CohortState::Active, true);
}

Result<Cohort> BaselineManager::cancel_cohort(const CohortId& id, Revision revision,
                                              const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }
  std::lock_guard<std::mutex> guard(writer_mutex_);
  return transition_cohort(id, revision, context, CohortState::Draft, CohortState::Paused,
                           CohortState::Cancelled, false);
}

Result<GateReport> BaselineManager::promote_cohort(const CohortId& id, Revision revision,
                                                   const EvaluationRequest& request,
                                                   const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  const Cohort* existing = next.cohorts.find(id);
  if (existing == nullptr) {
    return make_error(ErrorCode::IdentityUnknownCohort,
                      "no cohort with identity " + id.to_string() + " exists", "/id");
  }
  if (!(existing->revision == revision)) {
    return make_error(ErrorCode::AuthorityStaleRevision,
                      "cohort " + id.to_string() + " is at revision " +
                          std::to_string(existing->revision.value_or(0u)) +
                          ", not the requested revision " +
                          std::to_string(revision.value_or(0u)),
                      "/revision");
  }
  if (existing->state != CohortState::Active && existing->state != CohortState::Authorized) {
    return make_error(ErrorCode::InvalidArgument,
                      "cohort " + id.to_string() + " is not running and cannot be promoted",
                      "/state");
  }

  // Promotion is an exercise of the authorization that created the cohort, so
  // it is fenced exactly like minting is. A cohort authorized against baseline
  // generation 3 must not be promoted once the baseline has moved on, even
  // though the cohort record itself still looks well formed.
  const Baseline* promotion_baseline = next.baselines.find(existing->baseline);
  if (promotion_baseline == nullptr) {
    return make_error(ErrorCode::IdentityUnknownBaseline,
                      "cohort " + id.to_string() + " refers to an unknown baseline", "/baseline");
  }
  if (!(existing->baseline_generation == promotion_baseline->generation)) {
    return make_error(ErrorCode::AuthorityStaleGeneration,
                      "the cohort was authorized against baseline generation " +
                          std::to_string(existing->baseline_generation.value_or(0u)) +
                          " but the baseline is now at generation " +
                          std::to_string(promotion_baseline->generation.value_or(0u)),
                      "/baseline_generation");
  }
  if (!(existing->policy_generation == next.policy_generation)) {
    return make_error(ErrorCode::AuthorityStalePolicyGeneration,
                      "the cohort was authorized under policy generation " +
                          std::to_string(existing->policy_generation.value_or(0u)) +
                          " but the policy generation is now " +
                          std::to_string(next.policy_generation.value_or(0u)),
                      "/policy_generation");
  }
  if (!(existing->baseline_digest == promotion_baseline->content_digest())) {
    return make_error(ErrorCode::AuthorityDigestMismatch,
                      "the baseline content digest has changed since the cohort was authorized",
                      "/baseline_digest");
  }

  EvaluationRequest scoped = request;
  scoped.now = context.now.is_set() ? context.now : request.now;

  auto gate = engine_for(snapshot_now()).evaluate_cohort_gate(*existing, scoped);
  if (!gate.has_value()) {
    return gate.error();
  }
  if (!gate.value().satisfied) {
    // A failed gate is reported in full and changes nothing.
    return gate.value();
  }

  Cohort updated = *existing;
  const StageIndex required =
      updated.required_stages.is_set() ? updated.required_stages : StageIndex::first();
  // The stage index never exceeds the number of required stages, so a cohort
  // that has passed its last stage is complete rather than out of range.
  const StageIndex next_stage =
      gate.value().next_stage > required ? required : gate.value().next_stage;
  updated.stage = next_stage;
  updated.stage_entered_at = scoped.now;
  updated.last_promoted_at = scoped.now;
  updated.state =
      next_stage < required ? CohortState::Active : CohortState::Completed;

  auto next_revision = advance_counter(updated.revision, "the cohort revision");
  if (!next_revision.has_value()) {
    return next_revision.error();
  }
  updated.revision = next_revision.value();

  Status put = replace_entry(next.cohorts, id, std::move(updated));
  if (!put.has_value()) {
    return put.error();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = scoped.now;

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return gate.value();
}

Result<AuthorizationToken> BaselineManager::mint_cohort_token(const Snapshot& next,
                                                                const CohortId& id,
                                                                Revision revision,
                                                                const char* action,
                                                                const MutationContext& context) {
  const AuthorizationAuthority& authority = authority_;
  const bool require_signature = require_signature_;
  const Cohort* existing = next.cohorts.find(id);
  if (existing == nullptr) {
    return make_error(ErrorCode::IdentityUnknownCohort,
                      "no cohort with identity " + id.to_string() + " exists", "/id");
  }
  if (!(existing->revision == revision)) {
    return make_error(ErrorCode::AuthorityStaleRevision,
                      "cohort " + id.to_string() + " is at revision " +
                          std::to_string(existing->revision.value_or(0u)) +
                          ", not the requested revision " +
                          std::to_string(revision.value_or(0u)),
                      "/revision");
  }
  if (existing->state != CohortState::Active && existing->state != CohortState::Authorized) {
    return make_error(ErrorCode::InvalidArgument,
                      "cohort " + id.to_string() + " is not running, so no " +
                          std::string{action} + " can be authorized",
                      "/state");
  }
  if (!context.request.is_set()) {
    return make_error(ErrorCode::InvalidArgument,
                      "an authorization must carry a request identity so that a retried request is "
                      "recognized as a replay rather than a second grant",
                      "/request");
  }

  const Baseline* baseline = next.baselines.find(existing->baseline);
  if (baseline == nullptr) {
    return make_error(ErrorCode::IdentityUnknownBaseline,
                      "cohort " + id.to_string() + " refers to an unknown baseline", "/baseline");
  }
  if (!(existing->baseline_generation == baseline->generation)) {
    return make_error(ErrorCode::AuthorityStaleGeneration,
                      "the cohort was authorized against baseline generation " +
                          std::to_string(existing->baseline_generation.value_or(0u)) +
                          " but the baseline is now at generation " +
                          std::to_string(baseline->generation.value_or(0u)),
                      "/baseline_generation");
  }
  if (!(existing->policy_generation == next.policy_generation)) {
    return make_error(ErrorCode::AuthorityStalePolicyGeneration,
                      "the cohort was authorized under policy generation " +
                          std::to_string(existing->policy_generation.value_or(0u)) +
                          " but the policy generation is now " +
                          std::to_string(next.policy_generation.value_or(0u)),
                      "/policy_generation");
  }
  if (require_signature && !authority.is_signing()) {
    return make_error(ErrorCode::AuthorityNotAuthorized,
                      "this authority requires signed authorizations but no signing key is "
                      "configured",
                      "/signing_key");
  }

  AuthorityBinding binding;
  binding.scope = cohort_scope(id, action);
  binding.baseline = baseline->id;
  binding.baseline_generation = baseline->generation;
  binding.baseline_revision = baseline->revision;
  binding.baseline_digest = baseline->content_digest();
  binding.policy_generation = next.policy_generation;
  binding.control_epoch = next.control_epoch;
  binding.commit_sequence = next.commit_sequence;
  binding.plan = existing->plan;
  binding.request = context.request;
  binding.incarnation = next.incarnation;
  binding.subject_digest = subject_digest_for(*existing, binding.scope);
  binding.issued_at = context.now;
  binding.expiry = Expiry::never();
  binding.mode = authority.is_signing() ? SignatureMode::HmacSha256 : SignatureMode::None;

  return authority.mint(std::move(binding));
}

Result<AuthorizationToken> BaselineManager::authorize_rollout(const CohortId& id, Revision revision,
                                                              const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  auto token = mint_cohort_token(next, id, revision, "rollout", context);
  if (!token.has_value()) {
    return token.error();
  }

  auto recorded = next.authorizations.record(token.value());
  if (!recorded.has_value()) {
    return recorded.error();
  }
  if (recorded.value() == AuthorizationRegistry::RecordOutcome::IdempotentReplay) {
    return token.value();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return token.value();
}

Result<AuthorizationToken> BaselineManager::authorize_rollback(const CohortId& id, Revision revision,
                                                               const MutationContext& context) {
  Status time = require_time(context);
  if (!time.has_value()) {
    return time.error();
  }

  std::lock_guard<std::mutex> guard(writer_mutex_);
  Snapshot next = *snapshot_now();

  auto token = mint_cohort_token(next, id, revision, "rollback", context);
  if (!token.has_value()) {
    return token.error();
  }

  auto recorded = next.authorizations.record(token.value());
  if (!recorded.has_value()) {
    return recorded.error();
  }
  if (recorded.value() == AuthorizationRegistry::RecordOutcome::IdempotentReplay) {
    return token.value();
  }

  auto snapshot_revision = advance_counter(next.revision, "the durable revision");
  if (!snapshot_revision.has_value()) {
    return snapshot_revision.error();
  }
  next.revision = snapshot_revision.value();
  next.updated_at = context.now;

  Status published = publish_snapshot(std::move(next));
  if (!published.has_value()) {
    return published.error();
  }
  return token.value();
}

Status BaselineManager::verify_token(const AuthorizationToken& token, const std::string& scope,
                                     const PlanId& plan, Timestamp now) const {
  auto snapshot = snapshot_now();

  const AuthorizationToken* recorded = snapshot->authorizations.find(token.binding.request);
  if (recorded == nullptr) {
    return make_error(ErrorCode::AuthorityNotAuthorized,
                      "no authorization with request identity " +
                          token.binding.request.to_string() + " is recorded",
                      "/request");
  }
  if (!(recorded->mac == token.mac) ||
      !(recorded->binding.subject_digest == token.binding.subject_digest)) {
    return make_error(ErrorCode::AuthorityNotAuthorized,
                      "the presented authorization does not match the recorded authorization for "
                      "request identity " +
                          token.binding.request.to_string(),
                      "/request");
  }

  AuthorityBinding expected = token.binding;
  expected.scope = scope;
  expected.plan = plan;
  expected.policy_generation = snapshot->policy_generation;
  expected.control_epoch = snapshot->control_epoch;
  // The incarnation recorded in a token is provenance: which instance of the
  // authority minted it. It is deliberately not a fence, because an
  // authorization exists to be executed by a different process, possibly after
  // the authority has restarted. The fences that matter are the policy
  // generation, the baseline generation, revision, and content digest, and the
  // expiry, all of which are still compared below.
  expected.incarnation = token.binding.incarnation;
  expected.issued_at = now;
  if (const Baseline* baseline = snapshot->baselines.find(token.binding.baseline);
      baseline != nullptr) {
    expected.baseline_generation = baseline->generation;
    expected.baseline_revision = baseline->revision;
    expected.baseline_digest = baseline->content_digest();
  }
  expected.mode = require_signature_ ? SignatureMode::HmacSha256 : token.binding.mode;

  return authority_.verify(token, expected);
}

// --- Queries -----------------------------------------------------------------

Result<ConformanceVerdict> BaselineManager::evaluate(const EvaluationRequest& request) const {
  return make_engine().evaluate_conformance(request);
}

Result<EligibilityVerdict> BaselineManager::rollout_eligibility(
    const EvaluationRequest& request) const {
  return make_engine().evaluate_rollout_eligibility(request);
}

Result<EligibilityVerdict> BaselineManager::rollback_eligibility(
    const EvaluationRequest& request) const {
  return make_engine().evaluate_rollback_eligibility(request);
}

Result<std::vector<DriftResidual>> BaselineManager::list_drift(
    const EvaluationRequest& request) const {
  return make_engine().list_drift(request);
}

Result<std::string> BaselineManager::explain(const EvaluationRequest& request) const {
  return make_engine().explain(request);
}

std::vector<Baseline> BaselineManager::baselines() const {
  auto snapshot = snapshot_now();
  std::vector<Baseline> out;
  out.reserve(snapshot->baselines.size());
  for (const auto& entry : snapshot->baselines.items()) {
    out.push_back(entry.second);
  }
  return out;
}

std::vector<Cohort> BaselineManager::cohorts() const {
  auto snapshot = snapshot_now();
  std::vector<Cohort> out;
  out.reserve(snapshot->cohorts.size());
  for (const auto& entry : snapshot->cohorts.items()) {
    out.push_back(entry.second);
  }
  return out;
}

std::vector<BaselineException> BaselineManager::exceptions() const {
  auto snapshot = snapshot_now();
  std::vector<BaselineException> out;
  out.reserve(snapshot->exceptions.size());
  for (const auto& entry : snapshot->exceptions.items()) {
    out.push_back(entry.second);
  }
  return out;
}

std::vector<AssetId> BaselineManager::assets() const {
  return snapshot_now()->observations.assets();
}

}  // namespace summon::fbm
