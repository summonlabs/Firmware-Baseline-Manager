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

#include <cstdint>
#include <string>
#include <vector>

#include "check.hpp"
#include "support.hpp"

using namespace summon::fbm;
using namespace fbm_test;

FBM_TEST(conformance_state_tokens_round_trip_and_are_stable) {
  const ConformanceState states[] = {
      ConformanceState::Conformant,      ConformanceState::Drifted,
      ConformanceState::Unknown,         ConformanceState::Unsupported,
      ConformanceState::Blocked,         ConformanceState::Exception,
      ConformanceState::PendingRollout,  ConformanceState::PendingRollback,
  };
  const char* expected[] = {
      "conformant",      "drifted",       "unknown",  "unsupported",
      "blocked",         "exception",     "pending_rollout", "pending_rollback",
  };
  for (std::size_t index = 0; index < 8u; ++index) {
    CHECK_EQ(std::string{conformance_state_token(states[index])}, std::string{expected[index]});
    auto parsed = conformance_state_from_token(expected[index]);
    CHECK_OK(parsed);
    CHECK(parsed.value() == states[index]);
  }
  CHECK_ERROR(conformance_state_from_token("not_a_state"), ErrorCode::SchemaInvalidEnumValue);
  CHECK_ERROR(conformance_state_from_token(""), ErrorCode::SchemaInvalidEnumValue);
}

FBM_TEST(conformance_precedence_matches_the_published_table) {
  // The order is published in conformance.hpp and is a pure function of the
  // state, so the same evidence always resolves to the same primary state.
  CHECK_GT(conformance_precedence(ConformanceState::Unsupported),
           conformance_precedence(ConformanceState::Unknown));
  CHECK_GT(conformance_precedence(ConformanceState::Unknown),
           conformance_precedence(ConformanceState::Blocked));
  CHECK_GT(conformance_precedence(ConformanceState::Blocked),
           conformance_precedence(ConformanceState::Exception));
  CHECK_GT(conformance_precedence(ConformanceState::Exception),
           conformance_precedence(ConformanceState::PendingRollback));
  CHECK_GT(conformance_precedence(ConformanceState::PendingRollback),
           conformance_precedence(ConformanceState::PendingRollout));
  CHECK_GT(conformance_precedence(ConformanceState::PendingRollout),
           conformance_precedence(ConformanceState::Drifted));
  CHECK_GT(conformance_precedence(ConformanceState::Drifted),
           conformance_precedence(ConformanceState::Conformant));

  // Unknown must outrank Exception, so an exception can never launder
  // uncertainty into a waiver.
  CHECK_GT(conformance_precedence(ConformanceState::Unknown),
           conformance_precedence(ConformanceState::Exception));

  CHECK_EQ(conformance_precedence(static_cast<ConformanceState>(200)), 0);
}

FBM_TEST(conformance_drift_and_eligibility_tokens_are_stable) {
  const DriftKind kinds[] = {
      DriftKind::MissingObservation,     DriftKind::StaleObservation,
      DriftKind::UnknownVersion,         DriftKind::VersionMismatch,
      DriftKind::UnexpectedComponent,    DriftKind::IncompatibleCombination,
      DriftKind::UnverifiableRule,
  };
  const char* expected[] = {"missing_observation", "stale_observation",     "unknown_version",
                            "version_mismatch",    "unexpected_component",  "incompatible_combination",
                            "unverifiable_rule"};
  for (std::size_t index = 0; index < 7u; ++index) {
    CHECK_EQ(std::string{drift_kind_token(kinds[index])}, std::string{expected[index]});
  }
  CHECK(std::string{drift_kind_token(static_cast<DriftKind>(200))} != std::string{"version_mismatch"});

  CHECK_EQ(std::string{eligibility_token(Eligibility::Eligible)}, std::string{"eligible"});
  CHECK_EQ(std::string{eligibility_token(Eligibility::NotEligible)}, std::string{"not_eligible"});
  CHECK_EQ(std::string{eligibility_token(Eligibility::Unknown)}, std::string{"unknown"});
}

FBM_TEST(conformance_gate_tokens_and_order_are_stable) {
  for (const char* token : {"open", "closed", "unknown"}) {
    auto parsed = gate_state_from_token(token);
    CHECK_OK(parsed);
    CHECK_EQ(std::string{gate_state_token(parsed.value())}, std::string{token});
  }
  CHECK_ERROR(gate_state_from_token("maybe"), ErrorCode::SchemaInvalidEnumValue);

  FacilityGates gates;
  CHECK(!gates.all_open());
  CHECK_EQ(gates.not_open().size(), 4u);
  CHECK_EQ(gates.not_open()[0], std::string{"capacity"});
  CHECK_EQ(gates.not_open()[1], std::string{"dependency"});
  CHECK_EQ(gates.not_open()[2], std::string{"maintenance"});
  CHECK_EQ(gates.not_open()[3], std::string{"topology"});

  FacilityGates opened = open_gates();
  CHECK(opened.all_open());
  CHECK(opened.not_open().empty());

  opened.topology = GateState::Closed;
  CHECK_EQ(opened.not_open().size(), 1u);
  CHECK_EQ(opened.not_open()[0], std::string{"topology"});
}

FBM_TEST(conformance_gates_round_trip_through_json_and_reject_bad_documents) {
  const FacilityGates gates = open_gates();
  const std::string canonical = json::write_canonical(gates.to_json());
  auto parsed_value = json::parse(canonical);
  CHECK_OK(parsed_value);
  auto parsed = FacilityGates::from_json(parsed_value.value(), "/gates");
  CHECK_OK(parsed);
  CHECK(parsed.value().all_open());
  CHECK_EQ(parsed.value().capacity_generation.value(), 7u);
  CHECK_EQ(parsed.value().topology_generation.value(), 10u);
  CHECK_EQ(json::write_canonical(parsed.value().to_json()), canonical);

  {
    auto value = json::parse(
        "{\"capacity\":\"open\",\"capacity_generation\":1,"
        "\"dependency\":\"open\",\"dependency_generation\":1,"
        "\"maintenance\":\"open\",\"maintenance_generation\":1,"
        "\"topology\":\"maybe\",\"topology_generation\":1}");
    CHECK_OK(value);
    auto bad = FacilityGates::from_json(value.value(), "/gates");
    CHECK_ERROR(bad, ErrorCode::SchemaInvalidEnumValue);
  }
  {
    auto value = json::parse(
        "{\"capacity\":\"open\",\"capacity_generation\":1,"
        "\"dependency\":\"open\",\"dependency_generation\":1,"
        "\"maintenance\":\"open\",\"maintenance_generation\":1,"
        "\"topology\":\"open\"}");
    CHECK_OK(value);
    auto bad = FacilityGates::from_json(value.value(), "/gates");
    CHECK_ERROR(bad, ErrorCode::SchemaMissingField);
  }
  {
    auto value = json::parse(
        "{\"capacity\":\"open\",\"capacity_generation\":1,"
        "\"dependency\":\"open\",\"dependency_generation\":1,"
        "\"maintenance\":\"open\",\"maintenance_generation\":1,"
        "\"topology\":\"open\",\"topology_generation\":1,\"extra\":true}");
    CHECK_OK(value);
    auto bad = FacilityGates::from_json(value.value(), "/gates");
    CHECK_ERROR(bad, ErrorCode::SchemaUnknownField);
  }
}

FBM_TEST(conformance_drift_residual_keeps_the_exact_comparison) {
  DriftResidual residual;
  residual.kind = DriftKind::VersionMismatch;
  residual.component = FirmwareComponentId{"bmc"};
  residual.observed = version("2.3.0");
  residual.required = version("2.4.1");
  residual.has_version_delta = true;
  residual.version_delta = -1;
  residual.observed_at = base_time();
  residual.freshness = FreshnessBound::within(3600000000000ull);
  residual.detail = "bmc observed 2.3.0 requires 2.4.1";
  residual.path = "/components/bmc";

  const std::string text = residual.to_string();
  CHECK(text.find("2.3.0") != std::string::npos);
  CHECK(text.find("2.4.1") != std::string::npos);
  CHECK(text.find("bmc") != std::string::npos);

  const json::Value document = residual.to_json();
  CHECK(document.is_object());
  const json::Value* observed = document.find("observed");
  CHECK(observed != nullptr);
  CHECK_EQ(observed->as_string(), std::string{"2.3.0"});
  const json::Value* required = document.find("required");
  CHECK(required != nullptr);
  CHECK_EQ(required->as_string(), std::string{"2.4.1"});

  // An unknown observed version is omitted rather than written as a value.
  DriftResidual unknown;
  unknown.kind = DriftKind::MissingObservation;
  unknown.component = FirmwareComponentId{"bios"};
  unknown.required = version("3.1.0");
  unknown.detail = "bios has no recorded observation";
  const json::Value unknown_document = unknown.to_json();
  CHECK(unknown_document.find("observed") == nullptr);
  if (const json::Value* delta = unknown_document.find("version_delta"); delta != nullptr) {
    CHECK_EQ(delta->as_integer(), 0);
  }
  CHECK(unknown_document.find("kind") != nullptr);
  CHECK_EQ(unknown_document.find("kind")->as_string(), std::string{"missing_observation"});
}
