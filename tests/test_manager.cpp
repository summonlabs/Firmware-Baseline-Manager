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

// End-to-end proofs for the composed authority: BaselineManager over the
// durable store and the evaluation engine. Every assertion is a property of the
// documented semantics, never of an incidental implementation detail, and no
// test reads a clock.

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "support.hpp"

namespace {

using namespace fbm_test;

// --- Fixture -----------------------------------------------------------------
//
// The shared fixture in tests/support.hpp is the entry point for the standard
// policy (publish_authority), and standard_draft() is the starting point for the
// policies these tests vary. The schema requires components ascending by
// component identity, and "bios" orders before "bmc", so every draft is sorted
// defensively before it is defined: sorting an already ordered draft is a no-op,
// and an out-of-order draft can never turn into an accidental schema error.

BaselineDraft schema_ordered(BaselineDraft draft) {
  std::sort(draft.selectors.begin(), draft.selectors.end(),
            [](const HardwareSelector& left, const HardwareSelector& right) {
              if (!(left.hardware_class == right.hardware_class)) {
                return left.hardware_class < right.hardware_class;
              }
              if (!(left.model == right.model)) {
                return left.model < right.model;
              }
              if (!(left.minimum_revision == right.minimum_revision)) {
                return left.minimum_revision < right.minimum_revision;
              }
              return left.maximum_revision < right.maximum_revision;
            });
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

// The shared fixture, adapted to the handles these tests pass around.
Authority publish_authority(const std::filesystem::path& directory,
                            const Timestamp& start = base_time(),
                            const char* baseline_id = "gpu-h100-train") {
  Fixture fixture = publish_fixture(directory, start, baseline_id);
  Authority authority;
  authority.manager = std::move(fixture.manager);
  authority.baseline = fixture.baseline;
  authority.generation = fixture.generation;
  authority.baseline_revision = fixture.baseline_revision;
  authority.asset = fixture.asset;
  authority.now = fixture.now;
  return authority;
}

// Opens a manager and publishes exactly the supplied draft. Used for the
// policies that differ from the shared standard baseline.
Authority publish_draft(const std::filesystem::path& directory, BaselineDraft draft,
                        const Timestamp& start = base_time()) {
  Authority authority;
  authority.now = start;
  authority.asset = AssetId{"node-01"};
  auto opened = BaselineManager::open(manager_options(directory, true, start));
  CHECK_OK(opened);
  authority.manager = opened.take();
  auto defined = authority.manager->define_baseline(schema_ordered(std::move(draft)),
                                                   context_at(start, "req-define"));
  CHECK_OK(defined);
  auto published = authority.manager->publish_baseline(defined.value().id, defined.value().generation,
                                                       context_at(start, "req-publish"));
  CHECK_OK(published);
  authority.baseline = published.value().id;
  authority.generation = published.value().generation;
  authority.baseline_revision = published.value().revision;
  return authority;
}

// The standard policy with no compatibility rules, so that an undecidable rule
// cannot contribute a second candidate to the resolution.
BaselineDraft rulefree_draft(const char* id) {
  BaselineDraft draft = standard_draft(id);
  draft.rules = CompatibilityRuleSet{};
  return draft;
}

// The standard gate with a third stage, so that a promotion can advance a
// stage without completing the cohort.
BaselineDraft staged_draft(const char* id) {
  BaselineDraft draft = standard_draft(id);
  draft.gate.required_stages = StageIndex{3};
  return draft;
}

// Publishes a second baseline identity for the same hardware class at a
// generation above every published baseline, so that it becomes the
// authoritative baseline for the class while the earlier identity keeps its own
// generation, revision, and digest. A cohort bound to the earlier identity is
// therefore intact (its baseline has not moved) while its members are evaluated
// against the authoritative generation.
Status publish_superseding_baseline(BaselineManager& manager, BaselineDraft draft,
                                    const Timestamp& now, const char* request_prefix) {
  auto authored = manager.define_baseline(schema_ordered(draft), context_at(now, request_prefix));
  if (!authored.has_value()) {
    return authored.error();
  }
  auto advanced = manager.define_baseline(schema_ordered(std::move(draft)),
                                          context_at(now, request_prefix));
  if (!advanced.has_value()) {
    return advanced.error();
  }
  auto published = manager.publish_baseline(advanced.value().id, advanced.value().generation,
                                            context_at(now, request_prefix));
  if (!published.has_value()) {
    return published.error();
  }
  return ok_status();
}

// A valid draft for a different hardware class. Publishing it advances the
// policy generation without touching gpu authority.
BaselineDraft other_class_draft(const char* id) {
  BaselineDraft draft = standard_draft(id);
  draft.selectors.front().hardware_class = HardwareClassId{"tpu"};
  draft.selectors.front().model = HardwareModelId{"t100"};
  return schema_ordered(draft);
}

// Publishes a baseline for the tpu class and returns the new policy generation.
PolicyGeneration publish_other_class(BaselineManager& manager, const char* id,
                                     const Timestamp& now, const char* request_prefix) {
  auto defined = manager.define_baseline(other_class_draft(id), context_at(now, request_prefix));
  CHECK_OK(defined);
  const std::string publish_request = std::string{request_prefix} + "-publish";
  auto published = manager.publish_baseline(defined.value().id, defined.value().generation,
                                            context_at(now, publish_request.c_str()));
  CHECK_OK(published);
  return manager.policy_generation();
}

EvaluationRequest request_for(const AssetId& asset, const Timestamp& now) {
  EvaluationRequest request;
  request.asset = asset;
  request.now = now;
  request.gates = open_gates();
  return request;
}

// Records a profile plus the two governed component versions in one step.
void observe_asset(BaselineManager& manager, const AssetId& asset, const char* bmc_version,
                   const char* bios_version, ObservationSequence first, const Timestamp& now) {
  CHECK_OK(observe_profile(manager, asset, profile_of(), first, now, "ev-profile"));
  const std::uint64_t base = first.value_or(0u);
  CHECK_OK(observe_component(manager, asset, "bmc",
                             std::optional<FirmwareVersion>{version(bmc_version)},
                             ObservationSequence{base + 1}, now, "ev-bmc"));
  CHECK_OK(observe_component(manager, asset, "bios",
                             std::optional<FirmwareVersion>{version(bios_version)},
                             ObservationSequence{base + 2}, now, "ev-bios"));
}

// The verdict fields that are a pure function of the durable state and the
// request. Commit-scoped counters (commit_sequence, control_epoch) are excluded
// because they legitimately advance on every open; everything that carries
// authority, evidence, or a decision is included byte for byte.
std::string decision_bytes(const ConformanceVerdict& verdict) {
  std::string out;
  out += std::string{conformance_state_token(verdict.state)};
  out += "|reason=" + verdict.reason_code_value;
  out += "|text=" + verdict.reason;
  out += "|asset=" + verdict.asset.to_string();
  out += "|baseline=" + verdict.baseline.to_string();
  out += "|generation=" + std::to_string(verdict.baseline_generation.value_or(0u));
  out += "|revision=" + std::to_string(verdict.baseline_revision.value_or(0u));
  out += "|digest=" + digest_to_hex(verdict.baseline_digest);
  out += "|policy=" + std::to_string(verdict.policy_generation.value_or(0u));
  out += "|evaluated_at=" + verdict.evaluated_at.to_rfc3339();
  out += "|exception=" + (verdict.has_applied_exception ? verdict.applied_exception.to_string()
                                                        : std::string{"<none>"});
  for (const ComponentEvaluation& component : verdict.components) {
    out += "\ncomponent=" + component.component.to_string();
    out += ",required=" + component.required.to_string();
    out += ",observed=" + (component.observed.has_value() ? component.observed->to_string()
                                                         : std::string{"<unset>"});
    out += ",present=" + std::string{component.evidence_present ? "true" : "false"};
    out += ",fresh=" + std::string{component.evidence_fresh ? "true" : "false"};
    out += ",conformant=" + std::string{component.conformant ? "true" : "false"};
    out += ",delta=" + (component.has_version_delta ? std::to_string(component.version_delta)
                                                    : std::string{"<none>"});
  }
  for (const DriftResidual& residual : verdict.residuals) {
    out += "\nresidual=" + residual.to_string();
  }
  for (const RuleEvaluation& rule : verdict.rules) {
    out += "\nrule=" + rule.rule.to_string();
    out += ",outcome=" + std::string{rule_outcome_token(rule.outcome)};
    out += ",requirement=" + std::string{requirement_outcome_token(rule.requirement_outcome)};
    out += ",detail=" + rule.detail;
  }
  return out;
}

const DriftResidual* residual_for(const ConformanceVerdict& verdict,
                                  const FirmwareComponentId& component, DriftKind kind) {
  for (const DriftResidual& residual : verdict.residuals) {
    if (residual.component == component && residual.kind == kind) {
      return &residual;
    }
  }
  return nullptr;
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

// One patch step of the documented (major, minor, patch, build) lattice:
// ((major * 2^32 + minor) * 2^32 + patch) * 2^32 + build_slot.
constexpr std::int64_t kPatchStep = 4294967296;

}  // namespace

// ---------------------------------------------------------------------------
// Policy: a draft is not authority, and publishing is what makes it authority.
// ---------------------------------------------------------------------------

FBM_TEST(draft_is_not_authoritative_until_published) {
  const std::filesystem::path directory = scratch_directory("manager-draft-authority");
  auto opened = BaselineManager::open(manager_options(directory, true));
  CHECK_OK(opened);
  std::unique_ptr<BaselineManager> manager = opened.take();

  // base-low is defined once and stays a draft at generation 1.
  auto low = manager->define_baseline(schema_ordered(standard_draft("base-low")),
                                      context_at(base_time(), "req-low-1"));
  CHECK_OK(low);
  CHECK_EQ(low.value().state, BaselineState::Draft);
  CHECK_EQ(low.value().generation, BaselineGeneration{1});
  CHECK_EQ(low.value().revision, Revision{1});

  // base-high is defined twice, so its draft generation is 2: strictly higher
  // than the published generation of base-low below.
  auto high_first = manager->define_baseline(schema_ordered(standard_draft("base-high")),
                                             context_at(base_time(), "req-high-1"));
  CHECK_OK(high_first);
  auto high = manager->define_baseline(schema_ordered(standard_draft("base-high")),
                                       context_at(base_time(), "req-high-2"));
  CHECK_OK(high);
  CHECK_EQ(high.value().state, BaselineState::Draft);
  CHECK_EQ(high.value().generation, BaselineGeneration{2});

  const AssetId asset{"node-01"};
  observe_asset(*manager, asset, "2.4.1", "3.1.0", ObservationSequence{1}, base_time());

  EvaluationRequest request = request_for(asset, base_time());

  // Two drafts cover the profile; no published baseline does. The verdict is
  // Unknown with the class absent - never a draft's verdict.
  auto before = manager->evaluate(request);
  CHECK_OK(before);
  CHECK_EQ(before.value().state, ConformanceState::Unknown);
  CHECK_EQ(before.value().reason_code_value, std::string{reason_code::kBaselineAbsent});
  CHECK(!before.value().baseline.is_set());

  // Publishing base-low at generation 1 makes exactly it authoritative, even
  // though base-high is a draft at generation 2.
  auto published_low = manager->publish_baseline(low.value().id, low.value().generation,
                                                 context_at(base_time(), "req-low-2"));
  CHECK_OK(published_low);
  CHECK_EQ(published_low.value().state, BaselineState::Published);
  CHECK_EQ(published_low.value().generation, BaselineGeneration{1});

  auto low_wins = manager->evaluate(request);
  CHECK_OK(low_wins);
  CHECK_EQ(low_wins.value().state, ConformanceState::Conformant);
  CHECK_EQ(low_wins.value().baseline, BaselineId{"base-low"});
  CHECK_EQ(low_wins.value().baseline_generation, BaselineGeneration{1});

  // Publishing the higher draft generation moves authority to it.
  auto published_high = manager->publish_baseline(high.value().id, high.value().generation,
                                                  context_at(base_time(), "req-high-3"));
  CHECK_OK(published_high);
  auto high_wins = manager->evaluate(request);
  CHECK_OK(high_wins);
  CHECK_EQ(high_wins.value().baseline, BaselineId{"base-high"});
  CHECK_EQ(high_wins.value().baseline_generation, BaselineGeneration{2});

  // Re-defining base-low turns it back into a draft; the previously published
  // generation is replaced, so it no longer wins even at generation 2.
  auto low_again = manager->define_baseline(schema_ordered(standard_draft("base-low")),
                                            context_at(base_time(), "req-low-3"));
  CHECK_OK(low_again);
  CHECK_EQ(low_again.value().state, BaselineState::Draft);
  CHECK_EQ(low_again.value().generation, BaselineGeneration{2});
  auto still_high = manager->evaluate(request);
  CHECK_OK(still_high);
  CHECK_EQ(still_high.value().baseline, BaselineId{"base-high"});
  CHECK_EQ(still_high.value().baseline_generation, BaselineGeneration{2});
}

FBM_TEST(authority_is_never_ambiguous_and_never_chosen_arbitrarily) {
  const std::filesystem::path directory = scratch_directory("manager-authority-ambiguity");
  Authority authority = publish_authority(directory, base_time(), "base-first");
  observe_asset(*authority.manager, authority.asset, "2.4.1", "3.1.0", ObservationSequence{1},
                base_time());
  EvaluationRequest request = request_for(authority.asset, base_time());

  auto first = authority.manager->evaluate(request);
  CHECK_OK(first);
  CHECK_EQ(first.value().baseline, BaselineId{"base-first"});

  // A second baseline defined and published at its own generation 1 would make
  // authority ambiguous for the gpu class: two published baselines covering the
  // same profile at the same generation. The durable schema refuses to
  // represent that state at all (BaselineRegistry::put and ::validate both
  // reject it, and BaselineRegistry::from_json goes through both), so the write
  // is rejected, nothing is published, and the first baseline stays
  // authoritative. Authority is therefore never resolved by a guess: the
  // ambiguous state cannot be published, and BaselineRegistry::authoritative
  // reports IdentityAmbiguousBaseline rather than choosing if it ever is.
  auto second_draft = authority.manager->define_baseline(schema_ordered(standard_draft("base-second")),
                                                        context_at(base_time(), "req-second-1"));
  CHECK_OK(second_draft);
  CHECK_EQ(second_draft.value().generation, BaselineGeneration{1});

  const CommitSequence before_sequence = authority.manager->commit_sequence();
  const Digest before_digest = authority.manager->published_digest();
  auto conflicting = authority.manager->publish_baseline(second_draft.value().id,
                                                         second_draft.value().generation,
                                                         context_at(base_time(), "req-second-2"));
  CHECK(!conflicting.has_value());
  CHECK_EQ(conflicting.error().code(), ErrorCode::PolicySelfContradiction);
  CHECK_EQ(authority.manager->commit_sequence(), before_sequence);
  CHECK_EQ(authority.manager->published_digest(), before_digest);

  auto after = authority.manager->evaluate(request);
  CHECK_OK(after);
  CHECK_EQ(after.value().state, ConformanceState::Conformant);
  CHECK_EQ(after.value().baseline, BaselineId{"base-first"});
  CHECK_EQ(after.value().baseline_generation, authority.generation);
}

FBM_TEST(uncovered_class_is_unknown_while_out_of_scope_selector_is_unsupported) {
  const std::filesystem::path directory = scratch_directory("manager-scope");
  Authority authority = publish_authority(directory);

  // The published baseline selects gpu/h100 revisions 1..4.
  const AssetId other_class{"node-tpu"};
  const AssetId other_model{"node-a100"};
  const AssetId other_revision{"node-h100-r9"};
  CHECK_OK(observe_profile(*authority.manager, other_class, profile_of("tpu", "t100", 2),
                           ObservationSequence{1}, authority.now, "ev-tpu"));
  CHECK_OK(observe_profile(*authority.manager, other_model, profile_of("gpu", "a100", 2),
                           ObservationSequence{1}, authority.now, "ev-a100"));
  CHECK_OK(observe_profile(*authority.manager, other_revision, profile_of("gpu", "h100", 9),
                           ObservationSequence{1}, authority.now, "ev-r9"));

  // No published baseline selects the tpu class at all: the class is unknown,
  // which is a different fact from a selector that does not cover the asset.
  auto unknown_class = authority.manager->evaluate(request_for(other_class, authority.now));
  CHECK_OK(unknown_class);
  CHECK_EQ(unknown_class.value().state, ConformanceState::Unknown);
  CHECK_EQ(unknown_class.value().reason_code_value, std::string{reason_code::kBaselineAbsent});
  CHECK(!unknown_class.value().baseline.is_set());

  // The class is known but the profile is outside every selector: Unsupported.
  for (const AssetId& asset : {other_model, other_revision}) {
    auto unsupported = authority.manager->evaluate(request_for(asset, authority.now));
    CHECK_OK(unsupported);
    CHECK_EQ(unsupported.value().state, ConformanceState::Unsupported);
    CHECK_EQ(unsupported.value().reason_code_value,
             std::string{reason_code::kSelectorOutOfScope});
    CHECK(!unsupported.value().baseline.is_set());
  }
}

// ---------------------------------------------------------------------------
// Policy generation fences: publishing advances it and invalidates authority
// that was granted under the previous generation.
// ---------------------------------------------------------------------------

FBM_TEST(publishing_fences_rollout_authorization_and_exception) {
  const std::filesystem::path directory = scratch_directory("manager-policy-fence");
  Authority authority = publish_authority(directory);

  // A cohort on another asset so that the fenced asset's own verdict is not
  // dominated by a pending rollout.
  CohortDraft cohort_draft;
  cohort_draft.id = CohortId{"wave-1"};
  cohort_draft.baseline = authority.baseline;
  cohort_draft.baseline_generation = authority.generation;
  cohort_draft.members = {AssetId{"node-02"}};
  cohort_draft.note = "fencing probe";
  auto cohort = authority.manager->create_cohort(cohort_draft, context_at(authority.now, "req-cohort"));
  CHECK_OK(cohort);

  auto authorized = authority.manager->authorize_cohort(cohort.value().id, cohort.value().revision,
                                                        context_at(authority.now, "req-auth"));
  CHECK_OK(authorized);
  CHECK_EQ(authorized.value().state, CohortState::Authorized);

  auto token = authority.manager->authorize_rollout(authorized.value().id, authorized.value().revision,
                                                    context_at(authority.now, "req-token"));
  CHECK_OK(token);
  CHECK_EQ(token.value().binding.scope, std::string{"cohort/wave-1/rollout"});
  CHECK_EQ(token.value().binding.policy_generation, authorized.value().policy_generation);
  CHECK_OK(authority.manager->verify_token(token.value(), "cohort/wave-1/rollout",
                                           authorized.value().plan, authority.now));

  // A drifted asset covered by an effective exception.
  observe_asset(*authority.manager, authority.asset, "2.5.0", "3.1.0", ObservationSequence{1},
                authority.now);
  EvaluationRequest request = request_for(authority.asset, authority.now);
  auto drifted = authority.manager->evaluate(request);
  CHECK_OK(drifted);
  CHECK_EQ(drifted.value().state, ConformanceState::Drifted);

  ExceptionDraft exception_draft;
  exception_draft.id = ExceptionId{"exc-1"};
  exception_draft.scope.hardware_class = HardwareClassId{"gpu"};
  exception_draft.scope.components = {FirmwareComponentId{"bmc"}};
  exception_draft.expiry = Expiry::never();
  exception_draft.reason = "vendor erratum";
  auto exception = authority.manager->grant_exception(exception_draft,
                                                      context_at(authority.now, "req-exc"));
  CHECK_OK(exception);
  const PolicyGeneration granted_under = exception.value().granted_under;

  auto waived = authority.manager->evaluate(request);
  CHECK_OK(waived);
  CHECK_EQ(waived.value().state, ConformanceState::Exception);
  CHECK_EQ(waived.value().reason_code_value, std::string{reason_code::kExceptionEffective});
  CHECK(waived.value().has_applied_exception);
  CHECK_EQ(waived.value().applied_exception, ExceptionId{"exc-1"});

  // Publishing any baseline advances the policy generation. That single change
  // fences the token and the exception, because both were granted under the
  // previous generation.
  const PolicyGeneration advanced = publish_other_class(*authority.manager, "tpu-train",
                                                         at(1769904000ull + 1), "req-next");
  CHECK_GT(advanced, granted_under);

  auto fenced_exception = authority.manager->evaluate(request);
  CHECK_OK(fenced_exception);
  CHECK_EQ(fenced_exception.value().state, ConformanceState::Drifted);
  CHECK_EQ(fenced_exception.value().reason_code_value, std::string{reason_code::kDrift});
  CHECK(!fenced_exception.value().has_applied_exception);

  auto fenced_token = authority.manager->verify_token(token.value(), "cohort/wave-1/rollout",
                                                      authorized.value().plan, authority.now);
  CHECK(!fenced_token.has_value());
  CHECK_EQ(fenced_token.error().code(), ErrorCode::AuthorityStalePolicyGeneration);

  // The exception is retained with the generation it was granted under, and it
  // is classified as fenced rather than deleted or silently renewed.
  const std::vector<BaselineException> exceptions = authority.manager->exceptions();
  CHECK_EQ(exceptions.size(), std::size_t{1});
  CHECK_EQ(exceptions.front().id, ExceptionId{"exc-1"});
  CHECK_EQ(exceptions.front().granted_under, granted_under);
  CHECK_EQ(exceptions.front().state, ExceptionState::Active);
  CHECK_EQ(classify_exception(exceptions.front(), authority.manager->policy_generation(),
                              authority.now),
           ExceptionStatus::StalePolicyGeneration);
}

// ---------------------------------------------------------------------------
// Conformance precedence.
// ---------------------------------------------------------------------------

FBM_TEST(conformance_precedence_is_documented_and_dominates) {
  // conformance.hpp numbers the resolution precedence from the strongest:
  // Unsupported, Unknown, Blocked, Exception, PendingRollback, PendingRollout,
  // Drifted, Conformant. The two strongest states are reached on disjoint
  // conditions (no evidence at all resolves before any scope question), and
  // both dominate every state that would otherwise decide the asset.
  const ConformanceState ordered[] = {
      ConformanceState::Unsupported,     ConformanceState::Unknown,
      ConformanceState::Blocked,         ConformanceState::Exception,
      ConformanceState::PendingRollback, ConformanceState::PendingRollout,
      ConformanceState::Drifted,         ConformanceState::Conformant,
  };
  for (std::size_t index = 1; index < std::size(ordered); ++index) {
    CHECK_GT(static_cast<int>(conformance_precedence(ordered[index - 1])),
             static_cast<int>(conformance_precedence(ordered[index])));
  }
  CHECK_GT(static_cast<int>(conformance_precedence(ConformanceState::Unknown)),
           static_cast<int>(conformance_precedence(ConformanceState::Blocked)));
  CHECK_GT(static_cast<int>(conformance_precedence(ConformanceState::Unsupported)),
           static_cast<int>(conformance_precedence(ConformanceState::Blocked)));

  const std::filesystem::path directory = scratch_directory("manager-precedence");
  Authority authority = publish_authority(directory);
  const AssetId asset = authority.asset;
  EvaluationRequest request = request_for(asset, authority.now);

  // Unknown beats everything: with no profile evidence at all, a closed
  // facility gate and a missing component cannot be reported as a decision.
  request.gates = FacilityGates{};
  auto unknown = authority.manager->evaluate(request);
  CHECK_OK(unknown);
  CHECK_EQ(unknown.value().state, ConformanceState::Unknown);
  CHECK_EQ(unknown.value().reason_code_value, std::string{reason_code::kEvidenceMissing});

  // Unsupported beats Blocked: the class is published, the profile is outside
  // every selector, and the gates are closed.
  const AssetId outside{"node-a100"};
  CHECK_OK(observe_profile(*authority.manager, outside, profile_of("gpu", "a100", 2),
                           ObservationSequence{1}, authority.now, "ev-a100"));
  auto unsupported = authority.manager->evaluate(request_for(outside, authority.now));
  CHECK_OK(unsupported);
  CHECK_EQ(unsupported.value().state, ConformanceState::Unsupported);
  CHECK_EQ(unsupported.value().reason_code_value,
           std::string{reason_code::kSelectorOutOfScope});

  request.gates = open_gates();

  // Unknown beats Drifted: the profile is observed, no governed component was
  // ever observed, so conformance is not established.
  CHECK_OK(observe_profile(*authority.manager, asset, profile_of(), ObservationSequence{1},
                           authority.now, "ev-profile"));
  auto missing = authority.manager->evaluate(request);
  CHECK_OK(missing);
  CHECK_EQ(missing.value().state, ConformanceState::Unknown);
  CHECK_EQ(missing.value().reason_code_value, std::string{reason_code::kEvidenceMissing});
  CHECK_EQ(missing.value().residuals.size(), std::size_t{2});
  for (const DriftResidual& residual : missing.value().residuals) {
    CHECK_EQ(residual.kind, DriftKind::MissingObservation);
    CHECK(!residual.observed.has_value());
  }

  // Drifted beats Conformant: a determinate version mismatch with no exception
  // and no cohort.
  observe_asset(*authority.manager, asset, "2.5.0", "3.1.0", ObservationSequence{1}, authority.now);
  auto drifted = authority.manager->evaluate(request);
  CHECK_OK(drifted);
  CHECK_EQ(drifted.value().state, ConformanceState::Drifted);
  CHECK_EQ(drifted.value().reason_code_value, std::string{reason_code::kDrift});

  // PendingRollout beats Drifted: the asset is a member of an authorized cohort
  // for the authoritative baseline.
  CohortDraft cohort_draft;
  cohort_draft.id = CohortId{"wave-1"};
  cohort_draft.baseline = authority.baseline;
  cohort_draft.baseline_generation = authority.generation;
  cohort_draft.members = {asset};
  auto cohort = authority.manager->create_cohort(cohort_draft, context_at(authority.now, "req-c1"));
  CHECK_OK(cohort);
  auto authorized = authority.manager->authorize_cohort(cohort.value().id, cohort.value().revision,
                                                        context_at(authority.now, "req-c2"));
  CHECK_OK(authorized);
  auto pending_rollout = authority.manager->evaluate(request);
  CHECK_OK(pending_rollout);
  CHECK_EQ(pending_rollout.value().state, ConformanceState::PendingRollout);
  CHECK_EQ(pending_rollout.value().reason_code_value, std::string{reason_code::kPendingRollout});

  // PendingRollback beats PendingRollout: an authorized rollback plan for the
  // same cohort targets the asset.
  auto rollback_token = authority.manager->authorize_rollback(authorized.value().id,
                                                              authorized.value().revision,
                                                              context_at(authority.now, "req-c3"));
  CHECK_OK(rollback_token);
  auto pending_rollback = authority.manager->evaluate(request);
  CHECK_OK(pending_rollback);
  CHECK_EQ(pending_rollback.value().state, ConformanceState::PendingRollback);
  CHECK_EQ(pending_rollback.value().reason_code_value,
           std::string{reason_code::kPendingRollback});

  // Exception beats PendingRollback and PendingRollout: an effective exception
  // covers every residual.
  ExceptionDraft exception_draft;
  exception_draft.id = ExceptionId{"exc-1"};
  exception_draft.scope.hardware_class = HardwareClassId{"gpu"};
  exception_draft.expiry = Expiry::never();
  exception_draft.reason = "vendor erratum";
  CHECK_OK(authority.manager->grant_exception(exception_draft,
                                              context_at(authority.now, "req-e1")));
  auto exception = authority.manager->evaluate(request);
  CHECK_OK(exception);
  CHECK_EQ(exception.value().state, ConformanceState::Exception);
  CHECK_EQ(exception.value().reason_code_value, std::string{reason_code::kExceptionEffective});

  // Blocked beats Exception: the evidence floor excludes the bmc observation,
  // so bmc is not decided, while bios still carries a residual an exception
  // waives. The block wins.
  const AssetId second{"node-02"};
  CHECK_OK(observe_profile(*authority.manager, second, profile_of(), ObservationSequence{1},
                           authority.now, "ev-p2"));
  CHECK_OK(observe_component(*authority.manager, second, "bmc", version("2.5.0"),
                             ObservationSequence{2}, authority.now, "ev-b2"));
  CHECK_OK(observe_component(*authority.manager, second, "bios", version("3.1.0"),
                             ObservationSequence{6}, authority.now, "ev-b3"));
  EvaluationRequest floored = request_for(second, authority.now);
  floored.evidence_floor = ObservationSequence{5};
  auto blocked = authority.manager->evaluate(floored);
  CHECK_OK(blocked);
  CHECK_EQ(blocked.value().state, ConformanceState::Blocked);
  CHECK_EQ(blocked.value().reason_code_value, std::string{reason_code::kEvidenceFloor});

  // Conformant is the weakest state and only when no residual remains.
  const AssetId clean{"node-03"};
  observe_asset(*authority.manager, clean, "2.4.1", "3.1.0", ObservationSequence{1}, authority.now);
  auto conformant = authority.manager->evaluate(request_for(clean, authority.now));
  CHECK_OK(conformant);
  CHECK_EQ(conformant.value().state, ConformanceState::Conformant);
  CHECK_EQ(conformant.value().reason_code_value, std::string{reason_code::kConformant});
  CHECK(conformant.value().residuals.empty());
}

// ---------------------------------------------------------------------------
// Approved is not installed; unknown is not conformant.
// ---------------------------------------------------------------------------

FBM_TEST(a_published_baseline_without_observations_is_unknown_not_conformant) {
  const std::filesystem::path directory = scratch_directory("manager-approved-not-installed");
  Authority authority = publish_authority(directory);
  EvaluationRequest request = request_for(authority.asset, authority.now);

  // The baseline is published and approves bmc 2.4.1 and bios 3.1.0. The asset
  // has never been observed, so nothing is installed and nothing is decided.
  auto never_observed = authority.manager->evaluate(request);
  CHECK_OK(never_observed);
  CHECK_EQ(never_observed.value().state, ConformanceState::Unknown);
  CHECK_EQ(never_observed.value().reason_code_value, std::string{reason_code::kEvidenceMissing});
  CHECK(!never_observed.value().is_conformant());
  // Nothing identifies the hardware, so not even a baseline is resolved: the
  // approved versions are not consulted at all.
  CHECK(!never_observed.value().baseline.is_set());
  CHECK(never_observed.value().components.empty());
  CHECK(never_observed.value().residuals.empty());

  // Observing only the hardware profile still installs nothing: both governed
  // components are missing, and the approved versions are never read as
  // observed versions.
  CHECK_OK(observe_profile(*authority.manager, authority.asset, profile_of(),
                           ObservationSequence{1}, authority.now, "ev-profile"));
  auto profile_only = authority.manager->evaluate(request);
  CHECK_OK(profile_only);
  CHECK_EQ(profile_only.value().state, ConformanceState::Unknown);
  CHECK_EQ(profile_only.value().reason_code_value, std::string{reason_code::kEvidenceMissing});
  CHECK(!profile_only.value().is_conformant());
  CHECK_EQ(profile_only.value().residuals.size(), std::size_t{2});
  for (const ComponentEvaluation& component : profile_only.value().components) {
    CHECK(!component.evidence_present);
    CHECK(!component.observed.has_value());
    CHECK(!component.conformant);
  }
  for (const DriftResidual& residual : profile_only.value().residuals) {
    CHECK_EQ(residual.kind, DriftKind::MissingObservation);
    CHECK(!residual.observed.has_value());
    CHECK_EQ(residual.required.value(), residual.component == FirmwareComponentId{"bmc"}
                                            ? version("2.4.1")
                                            : version("3.1.0"));
  }

  // Eligibility inherits the same uncertainty and never turns it into a yes.
  auto eligibility = authority.manager->rollout_eligibility(request);
  CHECK_OK(eligibility);
  CHECK_EQ(eligibility.value().eligibility, Eligibility::Unknown);
  CHECK_EQ(eligibility.value().reason_code_value, std::string{reason_code::kEvidenceMissing});

  // Only evidence makes it conformant.
  observe_asset(*authority.manager, authority.asset, "2.4.1", "3.1.0", ObservationSequence{1},
                authority.now);
  auto installed = authority.manager->evaluate(request);
  CHECK_OK(installed);
  CHECK_EQ(installed.value().state, ConformanceState::Conformant);
}

FBM_TEST(an_undetermined_version_is_never_conformant) {
  const std::filesystem::path directory = scratch_directory("manager-unknown-version");
  Authority authority = publish_authority(directory);
  const AssetId asset = authority.asset;
  CHECK_OK(observe_profile(*authority.manager, asset, profile_of(), ObservationSequence{1},
                           authority.now, "ev-profile"));
  // The component was observed; its version was not determined.
  CHECK_OK(observe_component(*authority.manager, asset, "bmc", std::nullopt,
                             ObservationSequence{2}, authority.now, "ev-bmc"));
  CHECK_OK(observe_component(*authority.manager, asset, "bios", version("3.1.0"),
                             ObservationSequence{3}, authority.now, "ev-bios"));

  auto verdict = authority.manager->evaluate(request_for(asset, authority.now));
  CHECK_OK(verdict);
  CHECK_EQ(verdict.value().state, ConformanceState::Unknown);
  CHECK(!verdict.value().is_conformant());
  // Two candidates carry Unknown here: the undetermined version and the rule
  // that the undetermined version leaves undecidable. The documented
  // tie-break is the lower reason code, so the reported code is the rule's.
  CHECK_EQ(verdict.value().reason_code_value, std::string{reason_code::kRuleUnverifiable});

  const ComponentEvaluation* bmc = component_for(verdict.value(), FirmwareComponentId{"bmc"});
  REQUIRE(bmc != nullptr);
  CHECK(bmc->evidence_present);           // it was observed
  CHECK(!bmc->observed.has_value());      // its version is still unknown
  CHECK(!bmc->conformant);
  CHECK(!bmc->has_version_delta);         // nothing is measured, so nothing is measured against
  CHECK_EQ(bmc->required, version("2.4.1"));

  const DriftResidual* residual =
      residual_for(verdict.value(), FirmwareComponentId{"bmc"}, DriftKind::UnknownVersion);
  REQUIRE(residual != nullptr);
  CHECK(!residual->observed.has_value());
  CHECK_EQ(residual->required.value(), version("2.4.1"));
  CHECK(residual->detail.find("not determined") != std::string::npos);

  // The rule that is triggered by bmc cannot be decided either.
  const DriftResidual* rule_residual =
      residual_for(verdict.value(), FirmwareComponentId{"bios"}, DriftKind::UnverifiableRule);
  CHECK(rule_residual != nullptr);

  // An exception must not convert uncertainty into a waiver.
  ExceptionDraft exception_draft;
  exception_draft.id = ExceptionId{"exc-1"};
  exception_draft.scope.hardware_class = HardwareClassId{"gpu"};
  exception_draft.expiry = Expiry::never();
  exception_draft.reason = "would like this waived";
  CHECK_OK(authority.manager->grant_exception(exception_draft,
                                              context_at(authority.now, "req-exc")));
  auto still_unknown = authority.manager->evaluate(request_for(asset, authority.now));
  CHECK_OK(still_unknown);
  CHECK_EQ(still_unknown.value().state, ConformanceState::Unknown);
  CHECK(!still_unknown.value().has_applied_exception);
  CHECK(residual_for(still_unknown.value(), FirmwareComponentId{"bmc"},
                     DriftKind::UnknownVersion) != nullptr);

  // Without a rule to leave undecidable, the undetermined version is the only
  // candidate and it names itself.
  const std::filesystem::path clean_directory = scratch_directory("manager-unknown-version-clean");
  Authority clean = publish_draft(clean_directory, rulefree_draft("gpu-h100-clean"));
  CHECK_OK(observe_profile(*clean.manager, clean.asset, profile_of(), ObservationSequence{1},
                           clean.now, "ev-profile"));
  CHECK_OK(observe_component(*clean.manager, clean.asset, "bmc", std::nullopt,
                             ObservationSequence{2}, clean.now, "ev-bmc"));
  CHECK_OK(observe_component(*clean.manager, clean.asset, "bios", version("3.1.0"),
                             ObservationSequence{3}, clean.now, "ev-bios"));
  auto exact = clean.manager->evaluate(request_for(clean.asset, clean.now));
  CHECK_OK(exact);
  CHECK_EQ(exact.value().state, ConformanceState::Unknown);
  CHECK_EQ(exact.value().reason_code_value, std::string{reason_code::kVersionUnknown});
  CHECK_EQ(exact.value().residuals.size(), std::size_t{1});
  CHECK_EQ(exact.value().residuals.front().kind, DriftKind::UnknownVersion);
}

// ---------------------------------------------------------------------------
// Drift residuals.
// ---------------------------------------------------------------------------

FBM_TEST(drift_residuals_keep_the_exact_versions_and_signed_distance) {
  const std::filesystem::path directory = scratch_directory("manager-drift-residuals");
  Authority authority = publish_authority(directory);
  const AssetId asset = authority.asset;
  CHECK_OK(observe_profile(*authority.manager, asset, profile_of(), ObservationSequence{1},
                           authority.now, "ev-profile"));
  CHECK_OK(observe_component(*authority.manager, asset, "bios", version("3.1.0"),
                             ObservationSequence{2}, authority.now, "ev-bios"));
  CHECK_OK(observe_component(*authority.manager, asset, "bmc", version("2.4.2"),
                             ObservationSequence{3}, authority.now, "ev-bmc"));
  EvaluationRequest request = request_for(asset, authority.now);

  auto ahead = authority.manager->evaluate(request);
  CHECK_OK(ahead);
  CHECK_EQ(ahead.value().state, ConformanceState::Drifted);
  const DriftResidual* residual =
      residual_for(ahead.value(), FirmwareComponentId{"bmc"}, DriftKind::VersionMismatch);
  REQUIRE(residual != nullptr);
  CHECK_EQ(residual->observed.value(), version("2.4.2"));
  CHECK_EQ(residual->required.value(), version("2.4.1"));
  CHECK(residual->has_version_delta);
  // One patch step above the required version, reported as a negative delta.
  CHECK_EQ(residual->version_delta, -kPatchStep);
  CHECK_EQ(residual->version_delta,
           version_distance(version("2.4.1"), version("2.4.2")));
  CHECK_EQ(residual->observed_at, authority.now);

  // Two patch steps stay exact: the distance is not clamped to a boolean.
  CHECK_OK(observe_component(*authority.manager, asset, "bmc", version("2.4.3"),
                             ObservationSequence{4}, authority.now, "ev-bmc"));
  auto two_steps = authority.manager->evaluate(request);
  CHECK_OK(two_steps);
  const DriftResidual* two = residual_for(two_steps.value(), FirmwareComponentId{"bmc"},
                                          DriftKind::VersionMismatch);
  REQUIRE(two != nullptr);
  CHECK_EQ(two->observed.value(), version("2.4.3"));
  CHECK_EQ(two->required.value(), version("2.4.1"));
  CHECK_EQ(two->version_delta, -2 * kPatchStep);

  // Below the approved version but still conformant: the evaluation retains the
  // signed distance even though no residual exists.
  CHECK_OK(observe_component(*authority.manager, asset, "bmc", version("2.4.0"),
                             ObservationSequence{5}, authority.now, "ev-bmc"));
  auto below = authority.manager->evaluate(request);
  CHECK_OK(below);
  CHECK_EQ(below.value().state, ConformanceState::Conformant);
  const ComponentEvaluation* component = component_for(below.value(), FirmwareComponentId{"bmc"});
  REQUIRE(component != nullptr);
  CHECK_EQ(component->observed.value(), version("2.4.0"));
  CHECK_EQ(component->required, version("2.4.1"));
  CHECK(component->has_version_delta);
  CHECK_EQ(component->version_delta, kPatchStep);
  CHECK(component->conformant);
}

FBM_TEST(a_stale_observation_is_stale_and_not_a_version_mismatch) {
  const std::filesystem::path directory = scratch_directory("manager-stale");
  Authority authority = publish_authority(directory);
  const AssetId asset = authority.asset;
  observe_asset(*authority.manager, asset, "2.4.2", "3.1.0", ObservationSequence{1}, authority.now);

  const Timestamp fresh_now = at(1769904000ull + 3600ull);           // one hour later
  const Timestamp stale_now = at(1769904000ull + 25ull * 3600ull);   // past the 24h bound

  auto fresh = authority.manager->evaluate(request_for(asset, fresh_now));
  CHECK_OK(fresh);
  CHECK_EQ(fresh.value().state, ConformanceState::Drifted);
  const DriftResidual* mismatch =
      residual_for(fresh.value(), FirmwareComponentId{"bmc"}, DriftKind::VersionMismatch);
  CHECK(mismatch != nullptr);

  auto stale = authority.manager->evaluate(request_for(asset, stale_now));
  CHECK_OK(stale);
  CHECK_EQ(stale.value().state, ConformanceState::Unknown);
  CHECK_EQ(stale.value().reason_code_value, std::string{reason_code::kEvidenceStale});
  CHECK(residual_for(stale.value(), FirmwareComponentId{"bmc"}, DriftKind::VersionMismatch) ==
        nullptr);
  const DriftResidual* stale_residual =
      residual_for(stale.value(), FirmwareComponentId{"bmc"}, DriftKind::StaleObservation);
  REQUIRE(stale_residual != nullptr);
  // The stale residual still carries the exact observed and required versions
  // and the evidence age it was judged against.
  CHECK_EQ(stale_residual->observed.value(), version("2.4.2"));
  CHECK_EQ(stale_residual->required.value(), version("2.4.1"));
  CHECK_EQ(stale_residual->observed_at, authority.now);
  CHECK_EQ(stale_residual->freshness.max_age_nanos(), 24ull * 3600ull * 1000000000ull);
  const ComponentEvaluation* bmc = component_for(stale.value(), FirmwareComponentId{"bmc"});
  REQUIRE(bmc != nullptr);
  CHECK(bmc->evidence_present);
  CHECK(!bmc->evidence_fresh);
  CHECK(!bmc->conformant);
  CHECK_EQ(bmc->observed_at, authority.now);

  // A stale observation is uncertainty, so an exception cannot waive it.
  ExceptionDraft exception_draft;
  exception_draft.id = ExceptionId{"exc-1"};
  exception_draft.scope.hardware_class = HardwareClassId{"gpu"};
  exception_draft.expiry = Expiry::never();
  exception_draft.reason = "vendor erratum";
  CHECK_OK(authority.manager->grant_exception(exception_draft,
                                              context_at(stale_now, "req-exc")));
  auto still_stale = authority.manager->evaluate(request_for(asset, stale_now));
  CHECK_OK(still_stale);
  CHECK_EQ(still_stale.value().state, ConformanceState::Unknown);
  CHECK_EQ(still_stale.value().reason_code_value, std::string{reason_code::kEvidenceStale});
  CHECK(!still_stale.value().has_applied_exception);
}

// ---------------------------------------------------------------------------
// Exceptions: effective, expired, revoked, fenced, partial.
// ---------------------------------------------------------------------------

FBM_TEST(only_a_live_matching_grant_turns_drift_into_an_exception) {
  const std::filesystem::path directory = scratch_directory("manager-exceptions");
  Authority authority = publish_authority(directory);
  const AssetId asset = authority.asset;
  observe_asset(*authority.manager, asset, "2.5.0", "3.1.0", ObservationSequence{1}, authority.now);
  EvaluationRequest request = request_for(asset, authority.now);

  auto drifted = authority.manager->evaluate(request);
  CHECK_OK(drifted);
  CHECK_EQ(drifted.value().state, ConformanceState::Drifted);

  auto grant = [&](const char* id, const Expiry& expiry) {
    ExceptionDraft draft;
    draft.id = ExceptionId{id};
    draft.scope.hardware_class = HardwareClassId{"gpu"};
    draft.scope.components = {FirmwareComponentId{"bmc"}};
    draft.expiry = expiry;
    draft.reason = "vendor erratum";
    const std::string request = std::string{"req-"} + id;
    return authority.manager->grant_exception(draft, context_at(authority.now, request.c_str()));
  };

  // Effective: an unexpired grant under the current policy generation.
  auto effective = grant("exc-effective", Expiry::never());
  CHECK_OK(effective);
  auto waived = authority.manager->evaluate(request);
  CHECK_OK(waived);
  CHECK_EQ(waived.value().state, ConformanceState::Exception);
  CHECK(waived.value().has_applied_exception);
  CHECK_EQ(waived.value().applied_exception, ExceptionId{"exc-effective"});

  // Expired: the expiry instant is exclusive, so the grant is already expired
  // at exactly that instant.
  auto expired = grant("exc-expired", Expiry::at(authority.now));
  CHECK_OK(expired);
  CHECK_EQ(classify_exception(expired.value(), authority.manager->policy_generation(),
                              authority.now),
           ExceptionStatus::Expired);
  auto after_expiry = authority.manager->evaluate(request);
  CHECK_OK(after_expiry);
  CHECK_EQ(after_expiry.value().state, ConformanceState::Exception);
  CHECK_EQ(after_expiry.value().applied_exception, ExceptionId{"exc-effective"});

  // Revoked: revocation is durable and removes the waiver.
  auto revoked = authority.manager->revoke_exception(effective.value().id, effective.value().revision,
                                                     context_at(authority.now, "req-revoke"));
  CHECK_OK(revoked);
  CHECK_EQ(revoked.value().state, ExceptionState::Revoked);
  CHECK(revoked.value().revoked_at.is_set());
  auto after_revocation = authority.manager->evaluate(request);
  CHECK_OK(after_revocation);
  CHECK_EQ(after_revocation.value().state, ConformanceState::Drifted);
  CHECK(!after_revocation.value().has_applied_exception);
  auto revoke_again = authority.manager->revoke_exception(revoked.value().id,
                                                          revoked.value().revision,
                                                          context_at(authority.now, "req-revoke-2"));
  CHECK(!revoke_again.has_value());
  CHECK_EQ(revoke_again.error().code(), ErrorCode::InvalidArgument);

  // Fenced: publishing advances the policy generation under which the grant was
  // made, so the grant no longer waives anything.
  auto live = grant("exc-live", Expiry::never());
  CHECK_OK(live);
  auto waived_again = authority.manager->evaluate(request);
  CHECK_OK(waived_again);
  CHECK_EQ(waived_again.value().state, ConformanceState::Exception);
  CHECK_GT(publish_other_class(*authority.manager, "tpu-train", at(1769904000ull + 1),
                               "req-next"),
           live.value().granted_under);
  CHECK_EQ(classify_exception(live.value(), authority.manager->policy_generation(), authority.now),
           ExceptionStatus::StalePolicyGeneration);
  auto after_fence = authority.manager->evaluate(request);
  CHECK_OK(after_fence);
  CHECK_EQ(after_fence.value().state, ConformanceState::Drifted);

  // A grant that covers only some of the residuals waives nothing: every
  // residual must be covered.
  const std::filesystem::path partial_directory = scratch_directory("manager-exceptions-partial");
  Authority partial = publish_authority(partial_directory);
  observe_asset(*partial.manager, partial.asset, "2.5.0", "9.9.9", ObservationSequence{1},
                partial.now);
  EvaluationRequest partial_request = request_for(partial.asset, partial.now);
  auto two_residuals = partial.manager->evaluate(partial_request);
  CHECK_OK(two_residuals);
  CHECK_EQ(two_residuals.value().state, ConformanceState::Drifted);
  CHECK_EQ(two_residuals.value().residuals.size(), std::size_t{2});

  ExceptionDraft only_bmc;
  only_bmc.id = ExceptionId{"exc-bmc"};
  only_bmc.scope.hardware_class = HardwareClassId{"gpu"};
  only_bmc.scope.components = {FirmwareComponentId{"bmc"}};
  only_bmc.expiry = Expiry::never();
  only_bmc.reason = "bmc only";
  CHECK_OK(partial.manager->grant_exception(only_bmc, context_at(partial.now, "req-partial-1")));
  auto still_drifted = partial.manager->evaluate(partial_request);
  CHECK_OK(still_drifted);
  CHECK_EQ(still_drifted.value().state, ConformanceState::Drifted);
  CHECK(!still_drifted.value().has_applied_exception);
  CHECK_EQ(still_drifted.value().residuals.size(), std::size_t{2});

  // Covering the remaining residual completes the waiver. The applied exception
  // is the lowest identity that covers the set, never the last one inserted.
  ExceptionDraft only_bios;
  only_bios.id = ExceptionId{"exc-bios"};
  only_bios.scope.hardware_class = HardwareClassId{"gpu"};
  only_bios.scope.components = {FirmwareComponentId{"bios"}};
  only_bios.expiry = Expiry::never();
  only_bios.reason = "bios only";
  CHECK_OK(partial.manager->grant_exception(only_bios, context_at(partial.now, "req-partial-2")));
  auto complete = partial.manager->evaluate(partial_request);
  CHECK_OK(complete);
  CHECK_EQ(complete.value().state, ConformanceState::Exception);
  CHECK_EQ(complete.value().applied_exception, ExceptionId{"exc-bios"});

  // An exception whose scope does not name the asset is not applied to it.
  ExceptionDraft other_asset;
  other_asset.id = ExceptionId{"exc-other"};
  other_asset.scope.hardware_class = HardwareClassId{"gpu"};
  other_asset.scope.asset = AssetId{"node-99"};
  other_asset.expiry = Expiry::never();
  other_asset.reason = "another asset";
  CHECK_OK(partial.manager->grant_exception(other_asset, context_at(partial.now, "req-partial-3")));
  auto unscoped = partial.manager->evaluate(partial_request);
  CHECK_OK(unscoped);
  CHECK_EQ(unscoped.value().state, ConformanceState::Exception);
  CHECK_EQ(unscoped.value().applied_exception, ExceptionId{"exc-bios"});
}

// ---------------------------------------------------------------------------
// Eligibility is a decision, never an execution.
// ---------------------------------------------------------------------------

FBM_TEST(rollout_eligibility_reports_unknown_and_closed_gates) {
  const std::filesystem::path directory = scratch_directory("manager-rollout-eligibility");
  Authority authority = publish_authority(directory);
  const AssetId asset = authority.asset;
  observe_asset(*authority.manager, asset, "2.5.0", "3.1.0", ObservationSequence{1}, authority.now);
  EvaluationRequest request = request_for(asset, authority.now);

  // Every gate explicitly open, a determinate drift: eligible, with the exact
  // target the residuals require.
  auto eligible = authority.manager->rollout_eligibility(request);
  CHECK_OK(eligible);
  CHECK_EQ(eligible.value().eligibility, Eligibility::Eligible);
  CHECK_EQ(eligible.value().reason_code_value, std::string{reason_code::kEligible});
  CHECK(eligible.value().blockers.empty());
  CHECK_EQ(eligible.value().rollout_target.value(), version("2.4.1"));
  CHECK_EQ(eligible.value().conformance.state, ConformanceState::Drifted);

  // Eligibility is a decision: evaluating it does not mutate anything.
  const CommitSequence sequence_before = authority.manager->commit_sequence();
  const Digest digest_before = authority.manager->published_digest();
  const std::size_t authorizations_before = authority.manager->snapshot().authorizations.size();
  const std::size_t cohorts_before = authority.manager->snapshot().cohorts.size();
  for (int iteration = 0; iteration < 3; ++iteration) {
    CHECK_OK(authority.manager->rollout_eligibility(request));
  }
  CHECK_EQ(authority.manager->commit_sequence(), sequence_before);
  CHECK_EQ(authority.manager->published_digest(), digest_before);
  CHECK_EQ(authority.manager->snapshot().authorizations.size(), authorizations_before);
  CHECK_EQ(authority.manager->snapshot().cohorts.size(), cohorts_before);
  const FirmwareObservation* stored =
      authority.manager->snapshot().observations.component(asset, FirmwareComponentId{"bmc"});
  REQUIRE(stored != nullptr);
  CHECK_EQ(stored->version.value(), version("2.5.0"));

  // One unknown gate makes the whole decision unknown.
  EvaluationRequest gate_unknown = request;
  gate_unknown.gates.capacity = GateState::Unknown;
  auto unknown = authority.manager->rollout_eligibility(gate_unknown);
  CHECK_OK(unknown);
  CHECK_EQ(unknown.value().eligibility, Eligibility::Unknown);
  CHECK_EQ(unknown.value().reason_code_value, std::string{reason_code::kGateUnknown});
  CHECK(!unknown.value().blockers.empty());
  CHECK_EQ(unknown.value().blockers.front(), std::string{"capacity gate is not established (unknown)"});

  // One closed gate refuses the rollout.
  EvaluationRequest gate_closed = request;
  gate_closed.gates.topology = GateState::Closed;
  auto closed = authority.manager->rollout_eligibility(gate_closed);
  CHECK_OK(closed);
  CHECK_EQ(closed.value().eligibility, Eligibility::NotEligible);
  CHECK_EQ(closed.value().reason_code_value, std::string{reason_code::kGateClosed});
  CHECK_EQ(closed.value().blockers.front(), std::string{"topology gate is closed"});

  // A conformant asset has nothing to roll forward.
  const AssetId clean{"node-02"};
  observe_asset(*authority.manager, clean, "2.4.1", "3.1.0", ObservationSequence{1}, authority.now);
  auto conformant = authority.manager->rollout_eligibility(request_for(clean, authority.now));
  CHECK_OK(conformant);
  CHECK_EQ(conformant.value().eligibility, Eligibility::NotEligible);
  CHECK_EQ(conformant.value().reason_code_value, std::string{reason_code::kConformant});

  // Unknown conformance is unknown eligibility, not an eligible rollout.
  const AssetId unobserved{"node-03"};
  auto unknown_asset = authority.manager->rollout_eligibility(request_for(unobserved, authority.now));
  CHECK_OK(unknown_asset);
  CHECK_EQ(unknown_asset.value().eligibility, Eligibility::Unknown);
  CHECK_EQ(unknown_asset.value().reason_code_value, std::string{reason_code::kEvidenceMissing});

  // An exception waives drift; it never authorizes a rollout.
  ExceptionDraft exception_draft;
  exception_draft.id = ExceptionId{"exc-1"};
  exception_draft.scope.hardware_class = HardwareClassId{"gpu"};
  exception_draft.expiry = Expiry::never();
  exception_draft.reason = "vendor erratum";
  CHECK_OK(authority.manager->grant_exception(exception_draft,
                                              context_at(authority.now, "req-exc")));
  auto waived = authority.manager->rollout_eligibility(request);
  CHECK_OK(waived);
  CHECK_EQ(waived.value().eligibility, Eligibility::NotEligible);
  CHECK_EQ(waived.value().reason_code_value, std::string{reason_code::kExceptionEffective});
}

// ---------------------------------------------------------------------------
// Rollback eligibility.
// ---------------------------------------------------------------------------

namespace {

// Adds a rule that fires for the declared rollback target bmc 2.3.9 and
// requires BIOS 3.0.x, so the projected combination can be incompatible.
BaselineDraft rollback_draft(const char* id) {
  BaselineDraft draft = standard_draft(id);
  CompatibilityRule rule;
  rule.id = RuleId{"r-bmc-legacy"};
  rule.when_component = FirmwareComponentId{"bmc"};
  rule.when_versions = range("2.3.0", "2.3.99");
  rule.requirement.kind = RequirementKind::ComponentVersionInRange;
  rule.requirement.component = FirmwareComponentId{"bios"};
  rule.requirement.versions = range("3.0.0", "3.0.9");
  rule.reason = "BMC 2.3 requires BIOS 3.0.x";
  draft.rules.add(rule);
  return schema_ordered(draft);
}

}  // namespace

FBM_TEST(rollback_eligibility_requires_a_declared_compatible_target) {
  const std::filesystem::path directory = scratch_directory("manager-rollback-eligibility");
  Authority authority = publish_draft(directory, rollback_draft("rb-train"));
  const AssetId asset = authority.asset;
  CHECK_OK(observe_profile(*authority.manager, asset, profile_of(), ObservationSequence{1},
                           authority.now, "ev-profile"));
  CHECK_OK(observe_component(*authority.manager, asset, "bmc", version("2.5.0"),
                             ObservationSequence{2}, authority.now, "ev-bmc"));
  CHECK_OK(observe_component(*authority.manager, asset, "bios", version("3.1.0"),
                             ObservationSequence{3}, authority.now, "ev-bios"));
  EvaluationRequest request = request_for(asset, authority.now);

  auto drifted = authority.manager->evaluate(request);
  CHECK_OK(drifted);
  CHECK_EQ(drifted.value().state, ConformanceState::Drifted);

  // Without a named target nothing can be rolled back to.
  auto unnamed = authority.manager->rollback_eligibility(request);
  CHECK_OK(unnamed);
  CHECK_EQ(unnamed.value().eligibility, Eligibility::Unknown);
  CHECK_EQ(unnamed.value().reason_code_value, std::string{reason_code::kRollbackTargetUnknown});

  // A version the baseline never declared as a rollback target is refused.
  EvaluationRequest not_declared = request;
  not_declared.requested_rollback_target = version("1.0.0");
  auto unknown_target = authority.manager->rollback_eligibility(not_declared);
  CHECK_OK(unknown_target);
  CHECK_EQ(unknown_target.value().eligibility, Eligibility::NotEligible);
  CHECK_EQ(unknown_target.value().reason_code_value,
           std::string{reason_code::kRollbackTargetUnknown});
  CHECK_EQ(unknown_target.value().rollback_target.value(), version("1.0.0"));

  // A target the asset already observes is not a rollback.
  EvaluationRequest declared = request;
  declared.requested_rollback_target = version("2.3.9");
  CHECK_OK(observe_component(*authority.manager, asset, "bmc", version("2.3.9"),
                             ObservationSequence{4}, authority.now, "ev-bmc"));
  auto already_there = authority.manager->rollback_eligibility(declared);
  CHECK_OK(already_there);
  CHECK_EQ(already_there.value().eligibility, Eligibility::NotEligible);
  CHECK_EQ(already_there.value().reason_code_value,
           std::string{reason_code::kRollbackTargetIncompatible});
  CHECK(!already_there.value().blockers.empty());
  CHECK(already_there.value().blockers.back().find("already at") != std::string::npos);

  // The projected combination is evaluated: bmc 2.3.9 triggers r-bmc-legacy,
  // which requires BIOS 3.0.x while BIOS 3.1.0 is observed.
  CHECK_OK(observe_component(*authority.manager, asset, "bmc", version("2.5.0"),
                             ObservationSequence{5}, authority.now, "ev-bmc"));
  auto incompatible = authority.manager->rollback_eligibility(declared);
  CHECK_OK(incompatible);
  CHECK_EQ(incompatible.value().eligibility, Eligibility::NotEligible);
  CHECK_EQ(incompatible.value().reason_code_value,
           std::string{reason_code::kRollbackTargetIncompatible});
  bool names_rule = false;
  for (const std::string& blocker : incompatible.value().blockers) {
    if (blocker.find("r-bmc-legacy") != std::string::npos) {
      names_rule = true;
    }
  }
  CHECK(names_rule);

  // Moving BIOS into the range the projected combination requires makes the
  // rollback eligible, and the verdict is bound to the current baseline
  // generation and revision.
  CHECK_OK(observe_component(*authority.manager, asset, "bios", version("3.0.5"),
                             ObservationSequence{6}, authority.now, "ev-bios"));
  auto eligible = authority.manager->rollback_eligibility(declared);
  CHECK_OK(eligible);
  CHECK_EQ(eligible.value().eligibility, Eligibility::Eligible);
  CHECK_EQ(eligible.value().reason_code_value, std::string{reason_code::kEligible});
  CHECK_EQ(eligible.value().rollback_target.value(), version("2.3.9"));
  CHECK_EQ(eligible.value().baseline_generation, authority.generation);
  CHECK_EQ(eligible.value().rollback_generation, RollbackGeneration{authority.generation.value()});
  CHECK_EQ(eligible.value().baseline_revision, authority.baseline_revision);
  CHECK(eligible.value().gates.all_open());

  // A new published generation of the same baseline is what the verdict now
  // binds to.
  auto redefined = authority.manager->define_baseline(rollback_draft("rb-train"),
                                                      context_at(at(1769904000ull + 1), "req-re"));
  CHECK_OK(redefined);
  CHECK_EQ(redefined.value().generation, BaselineGeneration{2});
  auto republished = authority.manager->publish_baseline(redefined.value().id,
                                                         redefined.value().generation,
                                                         context_at(at(1769904000ull + 2), "req-re2"));
  CHECK_OK(republished);
  auto rebound = authority.manager->rollback_eligibility(declared);
  CHECK_OK(rebound);
  CHECK_EQ(rebound.value().eligibility, Eligibility::Eligible);
  CHECK_EQ(rebound.value().baseline_generation, BaselineGeneration{2});
  CHECK_EQ(rebound.value().rollback_generation, RollbackGeneration{2});
  CHECK_EQ(rebound.value().baseline_revision, republished.value().revision);
}

// ---------------------------------------------------------------------------
// Conservation across a close and a reopen.
// ---------------------------------------------------------------------------

FBM_TEST(state_survives_a_close_and_reopen_byte_for_byte) {
  const std::filesystem::path directory = scratch_directory("manager-recovery");
  const Timestamp observation_time = base_time();
  const Timestamp verdict_time = at(1769904000ull + 25ull * 3600ull);

  BaselineId baseline;
  BaselineGeneration generation;
  Revision baseline_revision;
  PolicyGeneration policy_generation;
  std::string before_bytes;
  std::size_t baseline_count = 0;
  std::size_t cohort_count = 0;
  std::size_t exception_count = 0;
  std::size_t asset_count = 0;

  {
    Authority authority = publish_authority(directory, observation_time);
    baseline = authority.baseline;
    generation = authority.generation;
    baseline_revision = authority.baseline_revision;

    // A cohort, an exception, and two observed assets.
    CohortDraft cohort_draft;
    cohort_draft.id = CohortId{"wave-1"};
    cohort_draft.baseline = baseline;
    cohort_draft.baseline_generation = generation;
    cohort_draft.members = {AssetId{"node-01"}, AssetId{"node-02"}};
    cohort_draft.note = "conservation";
    auto cohort = authority.manager->create_cohort(cohort_draft,
                                                   context_at(observation_time, "req-cohort"));
    CHECK_OK(cohort);
    auto authorized = authority.manager->authorize_cohort(cohort.value().id, cohort.value().revision,
                                                          context_at(observation_time, "req-auth"));
    CHECK_OK(authorized);
    CHECK_OK(authority.manager->authorize_rollout(authorized.value().id, authorized.value().revision,
                                                  context_at(observation_time, "req-token")));

    ExceptionDraft exception_draft;
    exception_draft.id = ExceptionId{"exc-1"};
    exception_draft.scope.hardware_class = HardwareClassId{"gpu"};
    exception_draft.scope.components = {FirmwareComponentId{"bios"}};
    exception_draft.expiry = Expiry::never();
    exception_draft.reason = "conservation";
    CHECK_OK(authority.manager->grant_exception(exception_draft,
                                                context_at(observation_time, "req-exc")));

    observe_asset(*authority.manager, AssetId{"node-01"}, "2.5.0", "3.1.0", ObservationSequence{1},
                  observation_time);
    observe_asset(*authority.manager, AssetId{"node-02"}, "2.4.1", "3.1.0", ObservationSequence{1},
                  observation_time);

    // The evidence is older than the 24h freshness bound at verdict_time, so
    // the decision is stale uncertainty rather than a conformance claim.
    auto before = authority.manager->evaluate(request_for(AssetId{"node-01"}, verdict_time));
    CHECK_OK(before);
    CHECK_EQ(before.value().state, ConformanceState::Unknown);
    CHECK_EQ(before.value().reason_code_value, std::string{reason_code::kEvidenceStale});
    before_bytes = decision_bytes(before.value());
    policy_generation = authority.manager->policy_generation();
    baseline_count = authority.manager->baselines().size();
    cohort_count = authority.manager->cohorts().size();
    exception_count = authority.manager->exceptions().size();
    asset_count = authority.manager->assets().size();
    CHECK_EQ(asset_count, std::size_t{2});
  }

  // Reopen the same store from the same process, with a different open instant
  // so that a recovery that refreshed evidence would be visible.
  auto reopened = BaselineManager::open(
      manager_options(directory, false, at(1769904000ull + 40ull * 3600ull)));
  CHECK_OK(reopened);
  std::unique_ptr<BaselineManager> manager = reopened.take();

  CHECK_EQ(manager->incarnation(), IncarnationId{2});
  CHECK_EQ(manager->recovery().outcome, RecoveryOutcome::Recovered);
  CHECK(manager->recovery().fence_present);
  CHECK_EQ(manager->policy_generation(), policy_generation);
  CHECK_EQ(manager->baselines().size(), baseline_count);
  CHECK_EQ(manager->cohorts().size(), cohort_count);
  CHECK_EQ(manager->exceptions().size(), exception_count);
  CHECK_EQ(manager->assets().size(), asset_count);

  const Baseline* recovered = manager->snapshot().baselines.find(baseline);
  REQUIRE(recovered != nullptr);
  CHECK_EQ(recovered->state, BaselineState::Published);
  CHECK_EQ(recovered->generation, generation);
  CHECK_EQ(recovered->revision, baseline_revision);
  const Cohort* recovered_cohort = manager->snapshot().cohorts.find(CohortId{"wave-1"});
  REQUIRE(recovered_cohort != nullptr);
  CHECK_EQ(recovered_cohort->state, CohortState::Authorized);
  CHECK_EQ(recovered_cohort->members.size(), std::size_t{2});
  const BaselineException* recovered_exception =
      manager->snapshot().exceptions.find(ExceptionId{"exc-1"});
  REQUIRE(recovered_exception != nullptr);
  CHECK_EQ(recovered_exception->state, ExceptionState::Active);
  CHECK_EQ(recovered_exception->granted_under, policy_generation);
  const FirmwareObservation* recovered_observation =
      manager->snapshot().observations.component(AssetId{"node-01"}, FirmwareComponentId{"bmc"});
  REQUIRE(recovered_observation != nullptr);
  CHECK_EQ(recovered_observation->version.value(), version("2.5.0"));
  CHECK_EQ(recovered_observation->observed_at, observation_time);

  // The recovered state reproduces the same verdict byte for byte...
  auto after = manager->evaluate(request_for(AssetId{"node-01"}, verdict_time));
  CHECK_OK(after);
  CHECK_EQ(decision_bytes(after.value()), before_bytes);

  // ... and recovery is not fresh evidence: the same age is still stale, and it
  // is stale because of the recorded observation time, not the reopen time.
  CHECK_EQ(after.value().state, ConformanceState::Unknown);
  CHECK_EQ(after.value().reason_code_value, std::string{reason_code::kEvidenceStale});
  const DriftResidual* stale =
      residual_for(after.value(), FirmwareComponentId{"bmc"}, DriftKind::StaleObservation);
  REQUIRE(stale != nullptr);
  CHECK_EQ(stale->observed_at, observation_time);
  CHECK_EQ(stale->observed.value(), version("2.5.0"));
  CHECK_EQ(stale->required.value(), version("2.4.1"));

  // The environment the recovered store lives in is still the same one.
  CHECK_EQ(manager->directory(), directory);
}

// ---------------------------------------------------------------------------
// Cohort lifecycle.
// ---------------------------------------------------------------------------

FBM_TEST(cohort_gate_reports_exact_unmet_conditions_and_changes_nothing) {
  const std::filesystem::path directory = scratch_directory("manager-cohort-gate");
  Authority published = publish_draft(directory, staged_draft("gpu-h100-staged"));
  BaselineManager* manager = published.manager.get();

  // A newer baseline identity for the same class, published before the cohort
  // is authorized, so that the cohort's own authorization is not fenced by it.
  CHECK_OK(publish_superseding_baseline(*manager, staged_draft("gpu-h100-next"),
                                        at(1769904000ull + 10), "req-next"));

  CohortDraft cohort_draft;
  cohort_draft.id = CohortId{"wave-1"};
  cohort_draft.baseline = published.baseline;
  cohort_draft.baseline_generation = published.generation;
  cohort_draft.members = {AssetId{"node-01"}, AssetId{"node-02"}};
  auto cohort = manager->create_cohort(cohort_draft, context_at(base_time(), "req-c"));
  CHECK_OK(cohort);
  CHECK_EQ(cohort.value().state, CohortState::Draft);
  CHECK_EQ(cohort.value().stage, StageIndex{1});
  CHECK_EQ(cohort.value().required_stages, StageIndex{3});
  auto authorized = manager->authorize_cohort(cohort.value().id, cohort.value().revision,
                                              context_at(base_time(), "req-a"));
  CHECK_OK(authorized);

  const CommitSequence sequence_before = manager->commit_sequence();
  const Digest digest_before = manager->published_digest();
  auto unmet = manager->promote_cohort(authorized.value().id, authorized.value().revision,
                                       EvaluationRequest{}, context_at(base_time(), "req-promote"));
  CHECK_OK(unmet);
  CHECK(!unmet.value().satisfied);
  CHECK_EQ(unmet.value().counts.total_assets, std::uint32_t{2});
  CHECK_EQ(unmet.value().counts.decided_assets, std::uint32_t{0});
  CHECK_EQ(unmet.value().counts.conformant_assets, std::uint32_t{0});
  CHECK_EQ(unmet.value().counts.unknown_assets, std::uint32_t{2});
  CHECK_EQ(unmet.value().counts.conformant_basis_points, std::uint32_t{0});
  CHECK_EQ(unmet.value().next_stage, StageIndex{2});
  // No member has evidence, so no state is decided. Every threshold of the
  // standard gate is unmet, and the report names each one exactly, in the
  // documented order.
  REQUIRE(unmet.value().unmet_conditions.size() == 4);
  CHECK_EQ(unmet.value().unmet_conditions[0],
           std::string{"decided assets 0 is below the required minimum of 1"});
  CHECK_EQ(unmet.value().unmet_conditions[1],
           std::string{"conformant assets 0 is below the required minimum of 1"});
  CHECK_EQ(unmet.value().unmet_conditions[2],
           std::string{"conformant ratio 0.00% is below the required 100.00%"});
  CHECK_EQ(unmet.value().unmet_conditions[3],
           std::string{"2 asset(s) have an unknown conformance state"});

  // A failed gate changes nothing at all: no revision, no stage, no commit.
  CHECK_EQ(manager->commit_sequence(), sequence_before);
  CHECK_EQ(manager->published_digest(), digest_before);
  const Cohort* unchanged = manager->snapshot().cohorts.find(CohortId{"wave-1"});
  REQUIRE(unchanged != nullptr);
  CHECK_EQ(unchanged->revision, authorized.value().revision);
  CHECK_EQ(unchanged->stage, StageIndex{1});
  CHECK_EQ(unchanged->state, CohortState::Authorized);

  // One conformant member still leaves the other unknown.
  observe_asset(*manager, AssetId{"node-01"}, "2.4.1", "3.1.0", ObservationSequence{1},
                base_time());
  const CommitSequence sequence_after_observation = manager->commit_sequence();
  auto partly = manager->promote_cohort(authorized.value().id, authorized.value().revision,
                                        EvaluationRequest{}, context_at(base_time(), "req-promote-2"));
  CHECK_OK(partly);
  CHECK(!partly.value().satisfied);
  CHECK_EQ(partly.value().counts.decided_assets, std::uint32_t{1});
  CHECK_EQ(partly.value().counts.unknown_assets, std::uint32_t{1});
  // A member of a running cohort resolves as pending rollout, which is a
  // decided state but not by itself a conformance claim. Whatever the split,
  // the counts partition exactly: the decided states sum to the decided count,
  // and decided plus undecided states sum to the members.
  CHECK_EQ(partly.value().counts.conformant_assets + partly.value().counts.drifted_assets +
               partly.value().counts.exception_assets +
               partly.value().counts.pending_rollout_assets +
               partly.value().counts.pending_rollback_assets,
           partly.value().counts.decided_assets);
  CHECK_EQ(partly.value().counts.decided_assets + partly.value().counts.unknown_assets +
               partly.value().counts.unsupported_assets + partly.value().counts.blocked_assets,
           partly.value().counts.total_assets);
  // The undecided member is always reported, and it is the last condition.
  REQUIRE(!partly.value().unmet_conditions.empty());
  CHECK_EQ(partly.value().unmet_conditions.back(),
           std::string{"1 asset(s) have an unknown conformance state"});
  CHECK_EQ(manager->commit_sequence(), sequence_after_observation);

  // Every member observed conformant. Each of them is evaluated against the
  // authoritative generation of the class, where it is genuinely conformant,
  // while the cohort stays bound to its own unchanged baseline. The gate is
  // computed from those exact per-asset states, so it is satisfied.
  observe_asset(*manager, AssetId{"node-02"}, "2.4.1", "3.1.0", ObservationSequence{1},
                base_time());
  const Baseline* cohort_baseline = manager->snapshot().baselines.find(published.baseline);
  REQUIRE(cohort_baseline != nullptr);
  CHECK_EQ(cohort_baseline->generation, published.generation);
  CHECK_EQ(cohort_baseline->revision, published.baseline_revision);
  auto satisfied = manager->promote_cohort(authorized.value().id, authorized.value().revision,
                                           EvaluationRequest{}, context_at(base_time(), "req-promote-3"));
  CHECK_OK(satisfied);
  CHECK(satisfied.value().satisfied);
  CHECK(satisfied.value().unmet_conditions.empty());
  CHECK_EQ(satisfied.value().counts.decided_assets, std::uint32_t{2});
  CHECK_EQ(satisfied.value().counts.conformant_assets, std::uint32_t{2});
  CHECK_EQ(satisfied.value().counts.unknown_assets, std::uint32_t{0});
  CHECK_EQ(satisfied.value().counts.conformant_basis_points, std::uint32_t{10000});
  CHECK_EQ(satisfied.value().next_stage, StageIndex{2});
  const Cohort* promoted = manager->snapshot().cohorts.find(CohortId{"wave-1"});
  REQUIRE(promoted != nullptr);
  CHECK_EQ(promoted->stage, StageIndex{2});
  CHECK_EQ(promoted->state, CohortState::Active);
  CHECK_EQ(promoted->last_promoted_at, base_time());
  CHECK_GT(promoted->revision, authorized.value().revision);
}

FBM_TEST(cohort_lifecycle_transitions) {
  const std::filesystem::path directory = scratch_directory("manager-cohort-lifecycle");
  Authority published = publish_draft(directory, staged_draft("gpu-h100-staged"));
  BaselineManager* manager = published.manager.get();
  // A newer identity for the same class becomes authoritative. Every cohort
  // below is bound to the first identity, so its members are evaluated against
  // the authoritative generation while the cohort authorization stays intact.
  CHECK_OK(publish_superseding_baseline(*manager, staged_draft("gpu-h100-next"),
                                        at(1769904000ull + 10), "req-next"));

  CohortDraft cohort_draft;
  cohort_draft.id = CohortId{"wave-1"};
  cohort_draft.baseline = published.baseline;
  cohort_draft.baseline_generation = published.generation;
  cohort_draft.members = {AssetId{"node-01"}};
  auto cohort = manager->create_cohort(cohort_draft, context_at(base_time(), "req-c"));
  CHECK_OK(cohort);
  CHECK_EQ(cohort.value().revision, Revision{1});
  CHECK_EQ(cohort.value().required_stages, StageIndex{3});

  // A draft cannot be promoted, and a stale revision cannot transition.
  auto from_draft = manager->promote_cohort(cohort.value().id, cohort.value().revision,
                                            EvaluationRequest{}, context_at(base_time(), "req-x"));
  CHECK_ERROR(from_draft, ErrorCode::InvalidArgument);
  auto stale = manager->authorize_cohort(cohort.value().id, Revision{7},
                                         context_at(base_time(), "req-x2"));
  CHECK_ERROR(stale, ErrorCode::AuthorityStaleRevision);
  auto unknown_cohort = manager->authorize_cohort(CohortId{"wave-missing"}, Revision{1},
                                                  context_at(base_time(), "req-x3"));
  CHECK_ERROR(unknown_cohort, ErrorCode::IdentityUnknownCohort);

  auto authorized = manager->authorize_cohort(cohort.value().id, cohort.value().revision,
                                              context_at(base_time(), "req-a"));
  CHECK_OK(authorized);
  CHECK_EQ(authorized.value().state, CohortState::Authorized);
  CHECK_EQ(authorized.value().revision, Revision{2});
  CHECK_EQ(authorized.value().baseline, published.baseline);
  CHECK_EQ(authorized.value().baseline_generation, published.generation);
  const Baseline* authorized_against = manager->snapshot().baselines.find(published.baseline);
  REQUIRE(authorized_against != nullptr);
  CHECK_EQ(authorized.value().baseline_digest, authorized_against->content_digest());
  CHECK_EQ(authorized.value().policy_generation, manager->policy_generation());
  CHECK_EQ(authorized.value().authorized_epoch, manager->control_epoch());
  CHECK_EQ(authorized.value().plan, PlanId{"wave-1.plan"});
  CHECK(!authorized.value().baseline_digest.empty());
  CHECK(authorized.value().accepts_mutation());

  // Authorized is running, so it can be paused.
  auto paused_from_authorized = manager->pause_cohort(authorized.value().id,
                                                     authorized.value().revision,
                                                     context_at(base_time(), "req-pause"));
  CHECK_OK(paused_from_authorized);
  CHECK_EQ(paused_from_authorized.value().state, CohortState::Paused);
  CHECK(paused_from_authorized.value().accepts_mutation());  // paused is still driven

  // Paused can be cancelled, and a cancelled cohort stays cancelled.
  auto cancelled = manager->cancel_cohort(paused_from_authorized.value().id,
                                          paused_from_authorized.value().revision,
                                          context_at(base_time(), "req-cancel"));
  CHECK_OK(cancelled);
  CHECK_EQ(cancelled.value().state, CohortState::Cancelled);
  CHECK(!cancelled.value().accepts_mutation());  // cancelled is terminal
  auto resume_cancelled = manager->resume_cohort(cancelled.value().id, cancelled.value().revision,
                                                 context_at(base_time(), "req-resume"));
  CHECK_ERROR(resume_cancelled, ErrorCode::InvalidArgument);
  auto cancel_cancelled = manager->cancel_cohort(cancelled.value().id, cancelled.value().revision,
                                                 context_at(base_time(), "req-cancel-2"));
  CHECK_ERROR(cancel_cancelled, ErrorCode::InvalidArgument);

  // A second cohort runs the full staged lifecycle: authorize, promote to an
  // active stage, pause, resume, and complete at the required stage.
  CohortDraft second_draft;
  second_draft.id = CohortId{"wave-2"};
  second_draft.baseline = published.baseline;
  second_draft.baseline_generation = published.generation;
  second_draft.members = {AssetId{"node-01"}};
  auto second = manager->create_cohort(second_draft, context_at(base_time(), "req-c2"));
  CHECK_OK(second);
  auto second_authorized = manager->authorize_cohort(second.value().id, second.value().revision,
                                                     context_at(base_time(), "req-a2"));
  CHECK_OK(second_authorized);

  observe_asset(*manager, AssetId{"node-01"}, "2.4.1", "3.1.0", ObservationSequence{1},
                base_time());
  auto first_promotion = manager->promote_cohort(second_authorized.value().id,
                                                 second_authorized.value().revision,
                                                 EvaluationRequest{},
                                                 context_at(base_time(), "req-pr1"));
  CHECK_OK(first_promotion);
  CHECK(first_promotion.value().satisfied);
  CHECK_EQ(first_promotion.value().next_stage, StageIndex{2});
  const Cohort* active = manager->snapshot().cohorts.find(CohortId{"wave-2"});
  REQUIRE(active != nullptr);
  CHECK_EQ(active->state, CohortState::Active);
  CHECK_EQ(active->stage, StageIndex{2});

  auto paused = manager->pause_cohort(active->id, active->revision,
                                      context_at(base_time(), "req-pause2"));
  CHECK_OK(paused);
  CHECK_EQ(paused.value().state, CohortState::Paused);
  auto resumed = manager->resume_cohort(paused.value().id, paused.value().revision,
                                        context_at(base_time(), "req-resume2"));
  CHECK_OK(resumed);
  CHECK_EQ(resumed.value().state, CohortState::Active);
  CHECK_EQ(resumed.value().stage, StageIndex{2});
  CHECK_EQ(resumed.value().stage_entered_at, base_time());
  CHECK_GT(resumed.value().revision, paused.value().revision);

  auto second_promotion = manager->promote_cohort(resumed.value().id, resumed.value().revision,
                                                  EvaluationRequest{},
                                                  context_at(base_time(), "req-pr2"));
  CHECK_OK(second_promotion);
  CHECK(second_promotion.value().satisfied);
  CHECK_EQ(second_promotion.value().next_stage, StageIndex{3});
  const Cohort* completed = manager->snapshot().cohorts.find(CohortId{"wave-2"});
  REQUIRE(completed != nullptr);
  CHECK_EQ(completed->state, CohortState::Completed);
  CHECK_EQ(completed->stage, StageIndex{3});
  CHECK_EQ(completed->required_stages, StageIndex{3});

  // A completed cohort accepts no further transitions and cannot be promoted.
  auto promote_completed = manager->promote_cohort(completed->id, completed->revision,
                                                   EvaluationRequest{},
                                                   context_at(base_time(), "req-pr3"));
  CHECK_ERROR(promote_completed, ErrorCode::InvalidArgument);
  auto pause_completed = manager->pause_cohort(completed->id, completed->revision,
                                               context_at(base_time(), "req-pause3"));
  CHECK_ERROR(pause_completed, ErrorCode::InvalidArgument);
  auto resume_active = manager->resume_cohort(completed->id, completed->revision,
                                              context_at(base_time(), "req-resume3"));
  CHECK_ERROR(resume_active, ErrorCode::InvalidArgument);
}
