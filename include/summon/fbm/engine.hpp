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

#include <memory>
#include <string>
#include <vector>

#include "summon/fbm/cohort.hpp"
#include "summon/fbm/conformance.hpp"
#include "summon/fbm/exception.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/snapshot.hpp"

namespace summon::fbm {

// Query and evaluation engine.
//
// Every entry point is a pure function of an immutable snapshot plus the
// caller-supplied request. The engine never reads a clock, never takes a lock,
// never mutates state, and never allocates on behalf of another thread. The
// same snapshot and the same request therefore always produce byte-identical
// output, and a verdict computed by the library can be reproduced by a test
// without any timing assumptions.
class Engine {
 public:
  explicit Engine(std::shared_ptr<const Snapshot> snapshot);

  const Snapshot& snapshot() const noexcept { return *snapshot_; }

  // Resolves the conformance state of one asset using the documented precedence
  // in conformance.hpp.
  Result<ConformanceVerdict> evaluate_conformance(const EvaluationRequest& request) const;

  // Evaluates whether the asset may be rolled forward. Requires the asset to be
  // Drifted or PendingRollout, every facility gate to be explicitly Open, and
  // every compatibility rule to be decidable and satisfied. Eligibility is a
  // decision, never an execution.
  Result<EligibilityVerdict> evaluate_rollout_eligibility(const EvaluationRequest& request) const;

  // Evaluates whether the asset may be rolled back to the requested target.
  // The target must be a known rollback target of the authoritative baseline,
  // and the current observed state must still satisfy the rules that gate that
  // target.
  Result<EligibilityVerdict> evaluate_rollback_eligibility(const EvaluationRequest& request) const;

  // Every residual for one asset, in deterministic order.
  Result<std::vector<DriftResidual>> list_drift(const EvaluationRequest& request) const;

  // Evaluates a cohort's promotion gate from the exact per-asset states.
  Result<GateReport> evaluate_cohort_gate(const Cohort& cohort,
                                          const EvaluationRequest& request) const;

  // Human-readable explanation of the conformance verdict, including the
  // authority it was evaluated against and every residual.
  Result<std::string> explain(const EvaluationRequest& request) const;

 private:
  struct Resolution {
    const Baseline* baseline = nullptr;
    ConformanceState state = ConformanceState::Unknown;
    std::string reason_code;
    std::string reason;
    std::vector<ComponentEvaluation> components;
    std::vector<DriftResidual> residuals;
    std::vector<RuleEvaluation> rules;
    const BaselineException* exception = nullptr;
  };

  Result<Resolution> resolve(const EvaluationRequest& request) const;

  std::shared_ptr<const Snapshot> snapshot_;
};

}  // namespace summon::fbm
