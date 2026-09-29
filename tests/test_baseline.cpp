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

#include "summon/fbm/baseline.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "check.hpp"
#include "summon/fbm/compatibility.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"
#include "summon/fbm/timestamp.hpp"

namespace {

using summon::fbm::Baseline;
using summon::fbm::BaselineGeneration;
using summon::fbm::BaselineId;
using summon::fbm::BaselineRegistry;
using summon::fbm::BaselineState;
using summon::fbm::ComponentRequirement;
using summon::fbm::Diagnostics;
using summon::fbm::ErrorCode;
using summon::fbm::FirmwareComponentId;
using summon::fbm::FirmwareVersion;
using summon::fbm::FreshnessBound;
using summon::fbm::HardwareClassId;
using summon::fbm::HardwareModelId;
using summon::fbm::HardwareProfile;
using summon::fbm::HardwareRevision;
using summon::fbm::HardwareSelector;
using summon::fbm::PromotionGate;
using summon::fbm::Result;
using summon::fbm::Revision;
using summon::fbm::StageIndex;
using summon::fbm::Status;
using summon::fbm::Timestamp;
namespace json = summon::fbm::json;

// --- builders ---------------------------------------------------------------

FirmwareVersion version(std::string_view text) {
  Result<FirmwareVersion> parsed = FirmwareVersion::parse(text, "/test/version");
  CHECK_OK(parsed);
  return parsed.take();
}

json::Value parse_json(std::string_view text) {
  Result<json::Value> parsed = json::parse(text, json::Limits{}, "/doc");
  CHECK_OK(parsed);
  return parsed.take();
}

std::string canonical(const json::Value& value) { return json::write_canonical(value); }

FirmwareComponentId component_id(std::string_view text) {
  Result<FirmwareComponentId> parsed =
      summon::fbm::make_id<FirmwareComponentId>(text, "/test/component");
  CHECK_OK(parsed);
  return parsed.take();
}

HardwareClassId hardware_class_id(std::string_view text) {
  Result<HardwareClassId> parsed =
      summon::fbm::make_id<HardwareClassId>(text, "/test/hardware_class");
  CHECK_OK(parsed);
  return parsed.take();
}

HardwareModelId hardware_model_id(std::string_view text) {
  Result<HardwareModelId> parsed = summon::fbm::make_id<HardwareModelId>(text, "/test/model");
  CHECK_OK(parsed);
  return parsed.take();
}

BaselineId baseline_id(std::string_view text) {
  Result<BaselineId> parsed = summon::fbm::make_id<BaselineId>(text, "/test/baseline");
  CHECK_OK(parsed);
  return parsed.take();
}

Timestamp moment(std::uint64_t unix_nanos) { return Timestamp::from_unix_nanos(unix_nanos); }

HardwareRevision revision_of(std::uint32_t value) { return HardwareRevision{value}; }

HardwareProfile make_profile(std::string_view hardware_class, std::string_view model,
                             std::optional<std::uint32_t> revision) {
  HardwareProfile profile;
  profile.hardware_class = hardware_class_id(hardware_class);
  profile.model = hardware_model_id(model);
  if (revision.has_value()) {
    profile.revision = revision_of(*revision);
  }
  profile.capabilities_observed = true;
  return profile;
}

HardwareSelector make_selector(std::string_view hardware_class,
                               std::optional<std::string_view> model,
                               std::optional<std::uint32_t> minimum,
                               std::optional<std::uint32_t> maximum) {
  HardwareSelector selector;
  selector.hardware_class = hardware_class_id(hardware_class);
  if (model.has_value()) {
    selector.model = hardware_model_id(*model);
  }
  if (minimum.has_value()) {
    selector.minimum_revision = revision_of(*minimum);
  }
  if (maximum.has_value()) {
    selector.maximum_revision = revision_of(*maximum);
  }
  return selector;
}

std::vector<FirmwareVersion> versions_of(
    std::initializer_list<std::string_view> items) {
  std::vector<FirmwareVersion> versions;
  versions.reserve(items.size());
  for (const std::string_view item : items) {
    versions.push_back(version(item));
  }
  return versions;
}

ComponentRequirement make_component_requirement(
    std::string_view component, std::string_view approved,
    std::initializer_list<std::string_view> conformant,
    std::initializer_list<std::string_view> rollback_targets, FreshnessBound freshness) {
  return ComponentRequirement{component_id(component),
                              version(approved),
                              versions_of(conformant),
                              versions_of(rollback_targets),
                              freshness};
}

PromotionGate make_gate(std::uint32_t basis_points, std::uint32_t decided,
                        std::uint32_t conformant, std::uint64_t soak_nanos,
                        std::uint32_t required_stages) {
  PromotionGate gate;
  gate.minimum_conformant_basis_points = basis_points;
  gate.minimum_decided_assets = decided;
  gate.minimum_conformant_assets = conformant;
  gate.soak_nanos = soak_nanos;
  gate.required_stages = StageIndex{required_stages};
  return gate;
}

ComponentRequirement default_component() {
  return make_component_requirement("bmc", "2.4.1", {"2.4.0", "2.4.1"}, {"2.3.9"},
                                    FreshnessBound::within(86400000000000ull));
}

Baseline make_baseline(std::string_view id, std::uint64_t generation, std::uint64_t revision,
                       BaselineState state, std::vector<HardwareSelector> selectors,
                       std::vector<ComponentRequirement> components) {
  Baseline baseline;
  baseline.id = baseline_id(id);
  baseline.generation = BaselineGeneration{generation};
  baseline.revision = Revision{revision};
  baseline.state = state;
  baseline.title = "a published baseline";
  baseline.selectors = std::move(selectors);
  baseline.components = std::move(components);
  baseline.gate = PromotionGate{};
  baseline.created_at = moment(1767225600000000000ull);
  if (state != BaselineState::Draft) {
    baseline.published_at = moment(1767312000000000000ull);
  }
  return baseline;
}

std::string digest_hex(const Baseline& baseline) {
  return summon::fbm::digest_to_hex(baseline.content_digest());
}

const char* const kBaselineJson = R"({
  "id": "gpu-h100-train",
  "generation": 3,
  "revision": 5,
  "state": "published",
  "title": "H100 training baseline",
  "selectors": [
    {"hardware_class": "gpu", "model": "h100", "minimum_revision": 1, "maximum_revision": 4}
  ],
  "components": [
    {"component": "bmc",
     "approved": "2.4.1",
     "conformant": ["2.4.1", "2.4.0"],
     "rollback_targets": ["2.3.9", "2.3.8"],
     "freshness": {"max_age_nanos": 86400000000000}}
  ],
  "rules": [],
  "gate": {"minimum_conformant_basis_points": 9900, "minimum_decided_assets": 2,
           "minimum_conformant_assets": 2, "soak_nanos": 0, "required_stages": 2},
  "created_at": "2026-01-01T00:00:00.000000000Z",
  "published_at": "2026-01-02T00:00:00.000000000Z"
})";

// The same document, authored with its members in a different order.
const char* const kBaselineJsonReordered = R"({
  "published_at": "2026-01-02T00:00:00.000000000Z",
  "created_at": "2026-01-01T00:00:00.000000000Z",
  "gate": {"required_stages": 2, "minimum_conformant_assets": 2,
           "minimum_decided_assets": 2, "minimum_conformant_basis_points": 9900,
           "soak_nanos": 0},
  "rules": [],
  "components": [
    {"freshness": {"max_age_nanos": 86400000000000},
     "rollback_targets": ["2.3.9", "2.3.8"],
     "conformant": ["2.4.1", "2.4.0"],
     "approved": "2.4.1",
     "component": "bmc"}
  ],
  "selectors": [
    {"maximum_revision": 4, "minimum_revision": 1, "model": "h100", "hardware_class": "gpu"}
  ],
  "title": "H100 training baseline",
  "state": "published",
  "revision": 5,
  "generation": 3,
  "id": "gpu-h100-train"
})";

Baseline parsed_baseline() {
  Result<Baseline> parsed = Baseline::from_json(parse_json(kBaselineJson), "/baseline");
  CHECK_OK(parsed);
  return parsed.take();
}

template <class T>
void check_round_trip(const T& value, std::string_view path) {
  const json::Value first = value.to_json();
  const std::string first_bytes = canonical(first);
  Result<json::Value> reparsed = json::parse(first_bytes, json::Limits{}, path);
  CHECK_OK(reparsed);
  Result<T> restored = T::from_json(reparsed.value(), path);
  CHECK_OK(restored);
  CHECK_EQ(canonical(restored.value().to_json()), first_bytes);
}

}  // namespace

// ---------------------------------------------------------------------------
// HardwareSelector
// ---------------------------------------------------------------------------

FBM_TEST(baseline_selector_coverage_matrix) {
  const HardwareSelector bounded = make_selector("gpu", "h100", 2u, 4u);
  CHECK(bounded.covers(make_profile("gpu", "h100", 3u)));
  CHECK(bounded.covers(make_profile("gpu", "h100", 2u)));
  CHECK(bounded.covers(make_profile("gpu", "h100", 4u)));
  CHECK(!bounded.covers(make_profile("gpu", "h100", 1u)));
  CHECK(!bounded.covers(make_profile("gpu", "h100", 5u)));
  // An unobserved revision cannot satisfy a bounded selector.
  CHECK(!bounded.covers(make_profile("gpu", "h100", std::nullopt)));
  CHECK(!bounded.covers(make_profile("gpu", "a100", 3u)));
  CHECK(!bounded.covers(make_profile("cpu", "h100", 3u)));

  const HardwareSelector minimum_only = make_selector("gpu", "h100", 2u, std::nullopt);
  CHECK(minimum_only.covers(make_profile("gpu", "h100", 2u)));
  CHECK(minimum_only.covers(make_profile("gpu", "h100", 99u)));
  CHECK(!minimum_only.covers(make_profile("gpu", "h100", 1u)));
  CHECK(!minimum_only.covers(make_profile("gpu", "h100", std::nullopt)));

  const HardwareSelector maximum_only = make_selector("gpu", "h100", std::nullopt, 4u);
  CHECK(maximum_only.covers(make_profile("gpu", "h100", 0u)));
  CHECK(maximum_only.covers(make_profile("gpu", "h100", 4u)));
  CHECK(!maximum_only.covers(make_profile("gpu", "h100", 5u)));
  CHECK(!maximum_only.covers(make_profile("gpu", "h100", std::nullopt)));

  // No revision bound at all means the selector does not restrict revisions, so
  // an unobserved revision is still covered.
  const HardwareSelector any_revision = make_selector("gpu", "h100", std::nullopt, std::nullopt);
  CHECK(any_revision.covers(make_profile("gpu", "h100", 3u)));
  CHECK(any_revision.covers(make_profile("gpu", "h100", std::nullopt)));
  CHECK(!any_revision.covers(make_profile("gpu", "a100", std::nullopt)));
  CHECK(!any_revision.covers(make_profile("cpu", "h100", std::nullopt)));

  // An unset model does not restrict the model.
  const HardwareSelector any_model = make_selector("gpu", std::nullopt, 1u, 4u);
  CHECK(any_model.covers(make_profile("gpu", "h100", 3u)));
  CHECK(any_model.covers(make_profile("gpu", "a100", 3u)));
  CHECK(!any_model.covers(make_profile("cpu", "a100", 3u)));

  // A selector with no hardware class selects nothing at all.
  HardwareSelector classless = make_selector("gpu", "h100", std::nullopt, std::nullopt);
  classless.hardware_class = HardwareClassId{};
  CHECK(!classless.covers(make_profile("gpu", "h100", 3u)));

  Diagnostics diagnostics;
  CHECK_OK(bounded.validate("/selector", diagnostics));
  CHECK(!classless.validate("/selector", diagnostics).has_value());
  CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaMissingField);
}

FBM_TEST(baseline_selector_json_round_trip_and_rejections) {
  check_round_trip(make_selector("gpu", "h100", 1u, 4u), "/selector");
  check_round_trip(make_selector("gpu", std::nullopt, std::nullopt, std::nullopt), "/selector");
  check_round_trip(make_selector("gpu", "h100", 3u, std::nullopt), "/selector");

  {
    const json::Value document = parse_json(R"({"model": "h100"})");
    CHECK_ERROR(HardwareSelector::from_json(document, "/selector"),
                ErrorCode::SchemaMissingField);
  }
  {
    const json::Value document =
        parse_json(R"({"hardware_class": "gpu", "minimum_revision": 5, "maximum_revision": 1})");
    CHECK_ERROR(HardwareSelector::from_json(document, "/selector"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(R"({"hardware_class": "gpu", "revisions": 1})");
    CHECK_ERROR(HardwareSelector::from_json(document, "/selector"),
                ErrorCode::SchemaUnknownField);
  }
  {
    const json::Value document =
        parse_json(R"({"hardware_class": "-gpu", "model": "h100"})");
    CHECK_ERROR(HardwareSelector::from_json(document, "/selector"),
                ErrorCode::SchemaInvalidIdentifier);
  }
  {
    const json::Value document = parse_json(R"({"hardware_class": 3})");
    CHECK_ERROR(HardwareSelector::from_json(document, "/selector"), ErrorCode::SchemaWrongType);
  }
  {
    const json::Value document = parse_json(R"({"hardware_class": "gpu", "minimum_revision": -1})");
    CHECK_ERROR(HardwareSelector::from_json(document, "/selector"),
                ErrorCode::SchemaValueOutOfRange);
  }
}

// ---------------------------------------------------------------------------
// ComponentRequirement
// ---------------------------------------------------------------------------

FBM_TEST(baseline_component_requirement_membership) {
  const ComponentRequirement requirement = make_component_requirement(
      "bmc", "2.4.1", {"2.4.0", "2.4.1"}, {"2.3.9", "2.3.8"},
      FreshnessBound::within(1000ull));
  CHECK(requirement.is_conformant(version("2.4.0")));
  CHECK(requirement.is_conformant(version("2.4.1")));
  CHECK(!requirement.is_conformant(version("2.4.2")));
  CHECK(!requirement.is_conformant(version("2.3.9")));
  CHECK(requirement.is_rollback_target(version("2.3.9")));
  CHECK(requirement.is_rollback_target(version("2.3.8")));
  CHECK(!requirement.is_rollback_target(version("2.4.0")));

  Diagnostics diagnostics;
  CHECK_OK(requirement.validate("/requirement", diagnostics));
  check_round_trip(requirement, "/requirement");
}

FBM_TEST(baseline_component_requirement_validation_rejections) {
  {
    // conformant must contain the approved version.
    Diagnostics diagnostics;
    const ComponentRequirement requirement =
        make_component_requirement("bmc", "2.4.2", {"2.4.0", "2.4.1"}, {},
                                   FreshnessBound::unbounded());
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/conformant"});
  }
  {
    // conformant must not be empty.
    Diagnostics diagnostics;
    const ComponentRequirement requirement = make_component_requirement(
        "bmc", "2.4.1", {}, {}, FreshnessBound::unbounded());
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaEmptyCollection);
  }
  {
    // conformant must be sorted ascending.
    Diagnostics diagnostics;
    const ComponentRequirement requirement = make_component_requirement(
        "bmc", "2.4.1", {"2.4.1", "2.4.0"}, {}, FreshnessBound::unbounded());
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/conformant/1"});
  }
  {
    // A version cannot be both conformant and a rollback target.
    Diagnostics diagnostics;
    const ComponentRequirement requirement =
        make_component_requirement("bmc", "2.4.1", {"2.4.1"}, {"2.4.1"},
                                   FreshnessBound::unbounded());
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/rollback_targets/0"});
  }
  {
    // freshness is required: an absent bound is not an unbounded one.
    Diagnostics diagnostics;
    const ComponentRequirement requirement = make_component_requirement(
        "bmc", "2.4.1", {"2.4.1"}, {}, FreshnessBound{});
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaMissingField);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/freshness"});
  }
}

FBM_TEST(baseline_component_requirement_json_rejections) {
  {
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1"],
            "freshness": {"unbounded": true}})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaMissingField);
  }
  {
    // Duplicate conformant versions are rejected after normalisation.
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1", "2.4.1"],
            "rollback_targets": [], "freshness": {"unbounded": true}})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  {
    // Duplicate rollback targets are rejected, and their authored order is kept.
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1"],
            "rollback_targets": ["2.3.9", "2.3.8", "2.3.9"],
            "freshness": {"unbounded": true}})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  {
    // A rollback target that is also conformant is an impossible combination.
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1"],
            "rollback_targets": ["2.4.1"], "freshness": {"unbounded": true}})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    // freshness requires exactly one encoding.
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1"],
            "rollback_targets": [], "freshness": {"max_age_nanos": 10, "unbounded": true}})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1"],
            "rollback_targets": [], "freshness": {}})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaMissingField);
  }
  {
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1"],
            "rollback_targets": [], "freshness": {"unbounded": true}, "note": "x"})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaUnknownField);
  }
  {
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4", "conformant": ["2.4"],
            "rollback_targets": [], "freshness": {"unbounded": true}})");
    CHECK_ERROR(ComponentRequirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInvalidVersionText);
  }
  {
    // The authored rollback order is preserved exactly.
    const json::Value document = parse_json(
        R"({"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1"],
            "rollback_targets": ["2.3.7", "2.3.9", "2.3.8"],
            "freshness": {"max_age_nanos": 5}})");
    Result<ComponentRequirement> parsed =
        ComponentRequirement::from_json(document, "/requirement");
    CHECK_OK(parsed);
    CHECK_EQ(parsed.value().rollback_targets.size(), std::size_t{3});
    CHECK_EQ(parsed.value().rollback_targets[0].to_string(), std::string{"2.3.7"});
    CHECK_EQ(parsed.value().rollback_targets[1].to_string(), std::string{"2.3.9"});
    CHECK_EQ(parsed.value().rollback_targets[2].to_string(), std::string{"2.3.8"});
    CHECK_EQ(parsed.value().freshness.max_age_nanos(), std::uint64_t{5});
  }
}

// ---------------------------------------------------------------------------
// PromotionGate
// ---------------------------------------------------------------------------

FBM_TEST(baseline_promotion_gate_bounds) {
  Diagnostics diagnostics;
  CHECK_OK(make_gate(10000u, 1u, 1u, 0u, 1u).validate("/gate", diagnostics));
  CHECK_OK(make_gate(0u, 3u, 2u, 5000u, 4u).validate("/gate", diagnostics));
  CHECK_OK(make_gate(9900u, 2u, 2u, 0u, 2u).validate("/gate", diagnostics));

  {
    Diagnostics bounds;
    Status status = make_gate(10001u, 2u, 2u, 0u, 2u).validate("/gate", bounds);
    CHECK(!status.has_value());
    CHECK_EQ(bounds.primary().code(), ErrorCode::SchemaValueOutOfRange);
    CHECK_EQ(bounds.primary().path(), std::string{"/gate/minimum_conformant_basis_points"});
  }
  {
    Diagnostics bounds;
    Status status = make_gate(10000u, 2u, 2u, 0u, 0u).validate("/gate", bounds);
    CHECK(!status.has_value());
    CHECK_EQ(bounds.primary().code(), ErrorCode::SchemaValueOutOfRange);
    CHECK_EQ(bounds.primary().path(), std::string{"/gate/required_stages"});
  }
  {
    // A gate is allowed to demand no conformant assets at all; the decided
    // minimum is what keeps a gate from promoting on nothing, and the gate
    // evaluator independently reports every unknown, unsupported, or blocked
    // member as an unmet condition.
    Diagnostics relaxed;
    CHECK_OK(make_gate(10000u, 1u, 0u, 0u, 1u).validate("/gate", relaxed));
  }
  {
    Diagnostics bounds;
    Status status = make_gate(10000u, 0u, 0u, 0u, 1u).validate("/gate", bounds);
    CHECK(!status.has_value());
    CHECK_EQ(bounds.primary().code(), ErrorCode::SchemaValueOutOfRange);
    CHECK_EQ(bounds.primary().path(), std::string{"/gate/minimum_decided_assets"});
  }
  {
    // The decided minimum can never be below the conformant minimum.
    Diagnostics bounds;
    Status status = make_gate(10000u, 1u, 2u, 0u, 1u).validate("/gate", bounds);
    CHECK(!status.has_value());
    CHECK_EQ(bounds.primary().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(bounds.primary().path(), std::string{"/gate/minimum_decided_assets"});
  }
  {
    // An unset required stage count is missing, never one.
    Diagnostics bounds;
    PromotionGate gate = make_gate(10000u, 1u, 1u, 0u, 1u);
    gate.required_stages = StageIndex{};
    Status status = gate.validate("/gate", bounds);
    CHECK(!status.has_value());
    CHECK_EQ(bounds.primary().code(), ErrorCode::SchemaMissingField);
  }

  check_round_trip(make_gate(9900u, 2u, 2u, 86400000000000ull, 3u), "/gate");
}

FBM_TEST(baseline_promotion_gate_json_rejections) {
  {
    const json::Value document = parse_json(
        R"({"minimum_conformant_basis_points": 9900, "minimum_decided_assets": 2,
            "minimum_conformant_assets": 2, "soak_nanos": 0})");
    CHECK_ERROR(PromotionGate::from_json(document, "/gate"), ErrorCode::SchemaMissingField);
  }
  {
    const json::Value document = parse_json(
        R"({"minimum_conformant_basis_points": 10001, "minimum_decided_assets": 2,
            "minimum_conformant_assets": 2, "soak_nanos": 0, "required_stages": 2})");
    CHECK_ERROR(PromotionGate::from_json(document, "/gate"), ErrorCode::SchemaValueOutOfRange);
  }
  {
    const json::Value document = parse_json(
        R"({"minimum_conformant_basis_points": 10000, "minimum_decided_assets": 1,
            "minimum_conformant_assets": 2, "soak_nanos": 0, "required_stages": 2})");
    CHECK_ERROR(PromotionGate::from_json(document, "/gate"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"minimum_conformant_basis_points": 10000, "minimum_decided_assets": 1,
            "minimum_conformant_assets": 1, "soak_nanos": 0, "required_stages": 1,
            "note": "x"})");
    CHECK_ERROR(PromotionGate::from_json(document, "/gate"), ErrorCode::SchemaUnknownField);
  }
  {
    const json::Value document = parse_json(
        R"({"minimum_conformant_basis_points": "many", "minimum_decided_assets": 1,
            "minimum_conformant_assets": 1, "soak_nanos": 0, "required_stages": 1})");
    CHECK_ERROR(PromotionGate::from_json(document, "/gate"), ErrorCode::SchemaWrongType);
  }
}

// ---------------------------------------------------------------------------
// Baseline: coverage, lookup, JSON
// ---------------------------------------------------------------------------

FBM_TEST(baseline_covers_and_find_component) {
  const Baseline baseline = make_baseline(
      "gpu-h100-train", 3u, 5u, BaselineState::Published,
      {make_selector("gpu", "a100", std::nullopt, std::nullopt),
       make_selector("gpu", "h100", 1u, 4u)},
      {make_component_requirement("bios", "3.1.0", {"3.1.0"}, {},
                                  FreshnessBound::unbounded()),
       default_component()});

  CHECK(baseline.covers(make_profile("gpu", "h100", 3u)));
  CHECK(baseline.covers(make_profile("gpu", "a100", 77u)));
  CHECK(!baseline.covers(make_profile("gpu", "v100", 3u)));
  CHECK(!baseline.covers(make_profile("cpu", "h100", 3u)));

  CHECK(baseline.find_component(component_id("bmc")) != nullptr);
  CHECK_EQ(baseline.find_component(component_id("bmc"))->approved_version.to_string(),
           std::string{"2.4.1"});
  CHECK(baseline.find_component(component_id("bios")) != nullptr);
  CHECK(baseline.find_component(component_id("nic")) == nullptr);

  Diagnostics diagnostics;
  CHECK_OK(baseline.validate("/baseline", diagnostics));
  check_round_trip(baseline, "/baseline");
}

FBM_TEST(baseline_json_round_trip) {
  const Baseline baseline = parsed_baseline();
  CHECK_EQ(baseline.id.to_string(), std::string{"gpu-h100-train"});
  CHECK_EQ(baseline.generation.value(), std::uint64_t{3});
  CHECK_EQ(baseline.revision.value(), std::uint64_t{5});
  CHECK(baseline.state == BaselineState::Published);
  CHECK_EQ(baseline.title, std::string{"H100 training baseline"});
  CHECK_EQ(baseline.selectors.size(), std::size_t{1});
  CHECK_EQ(baseline.components.size(), std::size_t{1});
  CHECK(baseline.rules.empty());
  CHECK_EQ(baseline.gate.minimum_conformant_basis_points, std::uint32_t{9900});
  CHECK_EQ(baseline.gate.required_stages.value(), std::uint32_t{2});
  CHECK(baseline.created_at.is_set());
  CHECK(baseline.published_at.is_set());

  check_round_trip(baseline, "/baseline");

  // A draft has no published_at and round trips without one.
  Baseline draft = baseline;
  draft.state = BaselineState::Draft;
  draft.published_at = Timestamp{};
  check_round_trip(draft, "/baseline");
  CHECK(!draft.to_json().has("published_at"));
}

FBM_TEST(baseline_json_normalises_collections) {
  // Selectors and components arrive unsorted; conformant versions arrive
  // unsorted. Parsing normalises all three and keeps them duplicate free.
  const json::Value document = parse_json(R"({
    "id": "gpu-mixed",
    "generation": 1,
    "revision": 1,
    "state": "published",
    "selectors": [
      {"hardware_class": "gpu", "model": "h100", "minimum_revision": 2},
      {"hardware_class": "cpu"},
      {"hardware_class": "gpu", "model": "h100", "minimum_revision": 1}
    ],
    "components": [
      {"component": "nic", "approved": "1.0.0", "conformant": ["1.0.0"], "rollback_targets": [],
       "freshness": {"unbounded": true}},
      {"component": "bmc", "approved": "2.4.1", "conformant": ["2.4.1", "2.4.0"],
       "rollback_targets": [], "freshness": {"unbounded": true}}
    ],
    "rules": [],
    "gate": {"minimum_conformant_basis_points": 10000, "minimum_decided_assets": 1,
             "minimum_conformant_assets": 1, "soak_nanos": 0, "required_stages": 1},
    "created_at": "2026-01-01T00:00:00.000000000Z",
    "published_at": "2026-01-02T00:00:00.000000000Z"
  })");
  Result<Baseline> parsed = Baseline::from_json(document, "/baseline");
  CHECK_OK(parsed);
  const Baseline& baseline = parsed.value();
  CHECK_EQ(baseline.selectors.size(), std::size_t{3});
  CHECK_EQ(baseline.selectors[0].hardware_class.to_string(), std::string{"cpu"});
  CHECK_EQ(baseline.selectors[1].hardware_class.to_string(), std::string{"gpu"});
  CHECK(baseline.selectors[1].model.to_string() == "h100");
  CHECK(baseline.selectors[1].minimum_revision.value() == 1u);
  CHECK_EQ(baseline.selectors[2].minimum_revision.value(), std::uint32_t{2});
  CHECK_EQ(baseline.components.size(), std::size_t{2});
  CHECK_EQ(baseline.components[0].component.to_string(), std::string{"bmc"});
  CHECK_EQ(baseline.components[1].component.to_string(), std::string{"nic"});
  CHECK_EQ(baseline.components[0].conformant_versions.size(), std::size_t{2});
  CHECK_EQ(baseline.components[0].conformant_versions[0].to_string(), std::string{"2.4.0"});
  CHECK_EQ(baseline.components[0].conformant_versions[1].to_string(), std::string{"2.4.1"});
}

FBM_TEST(baseline_json_rejections) {
  const Baseline baseline = parsed_baseline();
  {
    json::Value document = baseline.to_json();
    document.erase("id");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("generation");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("revision");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("state");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("selectors");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("components");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("rules");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("gate");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.erase("created_at");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    json::Value document = baseline.to_json();
    document.set("state", json::Value{std::string{"archived"}});
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaInvalidEnumValue);
  }
  {
    json::Value document = baseline.to_json();
    document.set("selectors", json::Value::make_array());
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaEmptyCollection);
  }
  {
    json::Value document = baseline.to_json();
    document.set("components", json::Value::make_array());
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaEmptyCollection);
  }
  {
    json::Value document = baseline.to_json();
    const json::Value selector = document.find("selectors")->as_array()[0];
    json::Value selectors = *document.find("selectors");
    selectors.push_back(selector);
    document.set("selectors", std::move(selectors));
    CHECK_ERROR(Baseline::from_json(document, "/baseline"),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  {
    json::Value document = baseline.to_json();
    const json::Value requirement = document.find("components")->as_array()[0];
    json::Value components = *document.find("components");
    components.push_back(requirement);
    document.set("components", std::move(components));
    CHECK_ERROR(Baseline::from_json(document, "/baseline"),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  {
    json::Value document = baseline.to_json();
    document.set("unexpected", json::Value{1});
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaUnknownField);
  }
  {
    json::Value document = baseline.to_json();
    document.set("id", json::Value{std::string{"bad id"}});
    CHECK_ERROR(Baseline::from_json(document, "/baseline"),
                ErrorCode::SchemaInvalidIdentifier);
  }
  {
    json::Value document = baseline.to_json();
    document.set("selectors", json::Value::make_object());
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaWrongType);
  }
  {
    // published_at is required exactly when the baseline is not a draft.
    json::Value document = baseline.to_json();
    document.erase("published_at");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaMissingField);
  }
  {
    // ... and must be absent for a draft.
    json::Value document = baseline.to_json();
    document.set("state", json::Value{std::string{"draft"}});
    CHECK_ERROR(Baseline::from_json(document, "/baseline"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    json::Value document = baseline.to_json();
    document.set("created_at", json::Value{std::string{"2026-01-01 00:00:00"}});
    CHECK_ERROR(Baseline::from_json(document, "/baseline"),
                ErrorCode::SchemaInvalidTimestampText);
  }
  {
    json::Value document = baseline.to_json();
    document.set("generation", json::Value{static_cast<std::int64_t>(-1)});
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaValueOutOfRange);
  }
  {
    json::Value document = baseline.to_json();
    json::Value component = document.find("components")->as_array()[0];
    // The approved version is no longer among the conformant versions.
    component.set("approved", json::Value{std::string{"9.9.9"}});
    json::Value replaced = json::Value::make_array();
    replaced.push_back(std::move(component));
    document.set("components", std::move(replaced));
    CHECK_ERROR(Baseline::from_json(document, "/baseline"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    // A baseline whose gate can never be met is rejected.
    json::Value document = baseline.to_json();
    json::Value gate = *document.find("gate");
    gate.set("minimum_conformant_assets", json::Value{static_cast<std::int64_t>(0)});
    gate.set("minimum_decided_assets", json::Value{static_cast<std::int64_t>(0)});
    document.set("gate", std::move(gate));
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaValueOutOfRange);
  }
  {
    const json::Value document = parse_json("[]");
    CHECK_ERROR(Baseline::from_json(document, "/baseline"), ErrorCode::SchemaWrongType);
  }
}

// ---------------------------------------------------------------------------
// Content digest
// ---------------------------------------------------------------------------

FBM_TEST(baseline_content_digest_changes_with_every_field) {
  const Baseline baseline = parsed_baseline();
  const std::string original = digest_hex(baseline);
  CHECK_EQ(original.size(), std::size_t{64});

  {
    Baseline changed = baseline;
    changed.title = "another title";
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.generation = BaselineGeneration{4};
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.revision = Revision{6};
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.state = BaselineState::Retired;
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.selectors.push_back(make_selector("cpu", std::nullopt, std::nullopt, std::nullopt));
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.components[0].approved_version = version("2.4.0");
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.components[0].rollback_targets.push_back(version("2.3.7"));
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.components[0].freshness = FreshnessBound::unbounded();
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.gate = make_gate(9900u, 3u, 2u, 0u, 2u);
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.created_at = moment(1u);
    CHECK_NE(digest_hex(changed), original);
  }
  {
    Baseline changed = baseline;
    changed.published_at = moment(2u);
    CHECK_NE(digest_hex(changed), original);
  }
  {
    // A compatibility rule is part of the content the digest covers.
    Baseline changed = baseline;
    summon::fbm::CompatibilityRule rule;
    rule.id = summon::fbm::make_id<summon::fbm::RuleId>("r-1", "/rule").value();
    rule.when_component = component_id("bmc");
    Result<summon::fbm::VersionRange> range = summon::fbm::VersionRange::make(
        version("1.0.0"), true, version("2.0.0"), false, "/range");
    CHECK_OK(range);
    rule.when_versions = range.take();
    summon::fbm::Requirement requirement;
    requirement.kind = summon::fbm::RequirementKind::CapabilityPresent;
    requirement.capability =
        summon::fbm::make_id<summon::fbm::CapabilityId>("sriov", "/cap").value();
    rule.requirement = requirement;
    rule.reason = "because";
    CHECK_OK(changed.rules.add(std::move(rule)));
    CHECK_NE(digest_hex(changed), original);
  }

  // The digest is stable across a canonical round trip.
  Result<Baseline> restored = Baseline::from_json(parse_json(canonical(baseline.to_json())),
                                                  "/baseline");
  CHECK_OK(restored);
  CHECK_EQ(digest_hex(restored.value()), original);
}

FBM_TEST(baseline_content_digest_is_identical_for_reordered_json_input) {
  Result<Baseline> first = Baseline::from_json(parse_json(kBaselineJson), "/baseline");
  CHECK_OK(first);
  Result<Baseline> second =
      Baseline::from_json(parse_json(kBaselineJsonReordered), "/baseline");
  CHECK_OK(second);
  CHECK_EQ(canonical(first.value().to_json()), canonical(second.value().to_json()));
  CHECK_EQ(digest_hex(first.value()), digest_hex(second.value()));
}

// ---------------------------------------------------------------------------
// BaselineRegistry
// ---------------------------------------------------------------------------

FBM_TEST(baseline_registry_put_and_find) {
  BaselineRegistry registry;
  CHECK(registry.empty());

  const Baseline draft = make_baseline("gpu-h100-train", 1u, 1u, BaselineState::Draft,
                                       {make_selector("gpu", "h100", std::nullopt, std::nullopt)},
                                       {default_component()});
  CHECK_OK(registry.put(draft));
  CHECK_EQ(registry.size(), std::size_t{1});
  CHECK(registry.find(baseline_id("gpu-h100-train")) != nullptr);
  CHECK_EQ(registry.find(baseline_id("gpu-h100-train"))->id.to_string(),
           std::string{"gpu-h100-train"});
  CHECK(registry.find(baseline_id("missing")) == nullptr);

  // The same identity cannot be registered twice.
  Status duplicate = registry.put(draft);
  CHECK(!duplicate.has_value());
  CHECK_EQ(duplicate.error().code(), ErrorCode::SchemaDuplicateIdentifier);
  CHECK_EQ(registry.size(), std::size_t{1});

  // Iteration is ascending by identity.
  CHECK_OK(registry.put(make_baseline("aaa-train", 1u, 1u, BaselineState::Draft,
                                      {make_selector("gpu", "h100", std::nullopt, std::nullopt)},
                                      {default_component()})));
  CHECK_EQ(registry.items().begin()->first.to_string(), std::string{"aaa-train"});

  CHECK(registry.erase(baseline_id("aaa-train")));
  CHECK(!registry.erase(baseline_id("aaa-train")));
  CHECK_EQ(registry.size(), std::size_t{1});
}

FBM_TEST(baseline_registry_put_rejections) {
  {
    BaselineRegistry registry;
    Baseline published = make_baseline("no-selectors", 1u, 1u, BaselineState::Published, {},
                                       {default_component()});
    Diagnostics diagnostics;
    CHECK(!published.validate("/baseline", diagnostics).has_value());
    Status status = registry.put(std::move(published));
    CHECK(!status.has_value());
    CHECK_EQ(status.error().code(), ErrorCode::SchemaEmptyCollection);
  }
  {
    BaselineRegistry registry;
    CHECK_OK(registry.put(make_baseline(
        "gpu-train", 3u, 1u, BaselineState::Published,
        {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
    // The same hardware class may not publish the same generation twice, even
    // for a different model.
    Status conflict = registry.put(make_baseline(
        "gpu-a100-train", 3u, 1u, BaselineState::Published,
        {make_selector("gpu", "a100", std::nullopt, std::nullopt)}, {default_component()}));
    CHECK(!conflict.has_value());
    CHECK_EQ(conflict.error().code(), ErrorCode::PolicySelfContradiction);

    // A different generation is a new publication.
    CHECK_OK(registry.put(make_baseline(
        "gpu-next", 4u, 1u, BaselineState::Published,
        {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
    // A different hardware class is independent.
    CHECK_OK(registry.put(make_baseline(
        "cpu-train", 3u, 1u, BaselineState::Published,
        {make_selector("cpu", "xeon", std::nullopt, std::nullopt)}, {default_component()})));
    // A non-published baseline does not claim authority.
    CHECK_OK(registry.put(make_baseline(
        "gpu-draft", 3u, 1u, BaselineState::Draft,
        {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
    CHECK_OK(registry.put(make_baseline(
        "gpu-retired", 3u, 1u, BaselineState::Retired,
        {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
    CHECK_EQ(registry.size(), std::size_t{5});
  }
}

FBM_TEST(baseline_registry_authoritative_selects_highest_generation) {
  BaselineRegistry registry;
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen1", 1u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen3", 3u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen2", 2u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen9-draft", 9u, 1u, BaselineState::Draft,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen9-retired", 9u, 1u, BaselineState::Retired,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "cpu-gen7", 7u, 1u, BaselineState::Published,
      {make_selector("cpu", "xeon", std::nullopt, std::nullopt)}, {default_component()})));

  Result<const Baseline*> gpu = registry.authoritative(make_profile("gpu", "h100", 1u));
  CHECK_OK(gpu);
  CHECK(gpu.value() != nullptr);
  CHECK_EQ(gpu.value()->id.to_string(), std::string{"gpu-gen3"});

  Result<const Baseline*> cpu = registry.authoritative(make_profile("cpu", "xeon", 1u));
  CHECK_OK(cpu);
  CHECK(cpu.value() != nullptr);
  CHECK_EQ(cpu.value()->id.to_string(), std::string{"cpu-gen7"});

  // No covering baseline is reported as a null pointer, not as an error and not
  // as an empty decision.
  Result<const Baseline*> none = registry.authoritative(make_profile("tpu", "tpu-v4", 1u));
  CHECK_OK(none);
  CHECK(none.value() == nullptr);

  // A profile whose revision is outside every selector is not covered.
  Result<const Baseline*> bounded = registry.authoritative(make_profile("gpu", "h100", 1u));
  CHECK_OK(bounded);
  CHECK(bounded.value() != nullptr);
}

FBM_TEST(baseline_registry_authoritative_reports_ambiguity) {
  BaselineRegistry registry;
  Baseline first = make_baseline("gpu-a", 5u, 1u, BaselineState::Published,
                                 {make_selector("gpu", "h100", std::nullopt, std::nullopt)},
                                 {default_component()});
  Baseline second = first;
  second.id = baseline_id("gpu-b");
  // Neither publication states a generation, so neither outranks the other and
  // authority cannot be decided by picking one.
  first.generation = BaselineGeneration{};
  second.generation = BaselineGeneration{};
  CHECK_OK(registry.put(first));
  CHECK_OK(registry.put(second));

  Result<const Baseline*> ambiguous = registry.authoritative(make_profile("gpu", "h100", 1u));
  CHECK(!ambiguous.has_value());
  CHECK_EQ(ambiguous.error().code(), ErrorCode::IdentityAmbiguousBaseline);
  CHECK(ambiguous.error().message().find("gpu-a") != std::string::npos);
  CHECK(ambiguous.error().message().find("gpu-b") != std::string::npos);

  // Removing one of the two restores a single answer.
  CHECK(registry.erase(baseline_id("gpu-a")));
  Result<const Baseline*> resolved = registry.authoritative(make_profile("gpu", "h100", 1u));
  CHECK_OK(resolved);
  CHECK(resolved.value() != nullptr);
  CHECK_EQ(resolved.value()->id.to_string(), std::string{"gpu-b"});
}

FBM_TEST(baseline_registry_candidates_ordering) {
  BaselineRegistry registry;
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen3", 3u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen1", 1u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen2", 2u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-draft", 4u, 1u, BaselineState::Draft,
      {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "cpu-gen9", 9u, 1u, BaselineState::Published,
      {make_selector("cpu", "xeon", std::nullopt, std::nullopt)}, {default_component()})));

  const std::vector<const Baseline*> covering =
      registry.candidates(make_profile("gpu", "h100", 1u));
  CHECK_EQ(covering.size(), std::size_t{3});
  CHECK_EQ(covering[0]->id.to_string(), std::string{"gpu-gen1"});
  CHECK_EQ(covering[1]->id.to_string(), std::string{"gpu-gen2"});
  CHECK_EQ(covering[2]->id.to_string(), std::string{"gpu-gen3"});
  for (const Baseline* baseline : covering) {
    CHECK(baseline->state == BaselineState::Published);
  }

  // Without a stated generation, candidates with equal generations are ordered
  // by identity.
  BaselineRegistry tied;
  Baseline tied_b = make_baseline("gpu-b", 1u, 1u, BaselineState::Published,
                                  {make_selector("gpu", "h100", std::nullopt, std::nullopt)},
                                  {default_component()});
  Baseline tied_a = tied_b;
  tied_a.id = baseline_id("gpu-a");
  tied_b.generation = BaselineGeneration{};
  tied_a.generation = BaselineGeneration{};
  CHECK_OK(tied.put(tied_b));
  CHECK_OK(tied.put(tied_a));
  const std::vector<const Baseline*> tied_covering =
      tied.candidates(make_profile("gpu", "h100", 1u));
  CHECK_EQ(tied_covering.size(), std::size_t{2});
  CHECK_EQ(tied_covering[0]->id.to_string(), std::string{"gpu-a"});
  CHECK_EQ(tied_covering[1]->id.to_string(), std::string{"gpu-b"});

  CHECK(registry.candidates(make_profile("tpu", "tpu-v4", 1u)).empty());
}

FBM_TEST(baseline_registry_json_round_trip_and_rejections) {
  BaselineRegistry registry;
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen2", 2u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", 1u, 4u)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "gpu-gen1", 1u, 1u, BaselineState::Published,
      {make_selector("gpu", "h100", 1u, 4u)}, {default_component()})));
  CHECK_OK(registry.put(make_baseline(
      "cpu-draft", 1u, 1u, BaselineState::Draft,
      {make_selector("cpu", "xeon", std::nullopt, std::nullopt)}, {default_component()})));

  const json::Value document = registry.to_json();
  CHECK(document.is_array());
  CHECK_EQ(document.size(), std::size_t{3});
  // Serialization is ascending by identity, so the same state always produces
  // the same bytes.
  CHECK_EQ(document.as_array()[0].find("id")->as_string(), std::string{"cpu-draft"});
  CHECK_EQ(document.as_array()[1].find("id")->as_string(), std::string{"gpu-gen1"});
  CHECK_EQ(document.as_array()[2].find("id")->as_string(), std::string{"gpu-gen2"});

  Result<BaselineRegistry> restored =
      BaselineRegistry::from_json(parse_json(canonical(document)), "/registry");
  CHECK_OK(restored);
  CHECK_EQ(restored.value().size(), std::size_t{3});
  CHECK_EQ(canonical(restored.value().to_json()), canonical(document));

  {
    // A repeated identity in one document is rejected.
    json::Value repeated = json::Value::make_array();
    repeated.push_back(document.as_array()[1]);
    repeated.push_back(document.as_array()[1]);
    CHECK_ERROR(BaselineRegistry::from_json(repeated, "/registry"),
                ErrorCode::SchemaDuplicateIdentifier);
  }
  {
    // A published baseline with no selectors is rejected by the registry.
    Baseline published = make_baseline(
        "empty-selectors", 1u, 1u, BaselineState::Published,
        {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()});
    json::Value array = json::Value::make_array();
    json::Value baseline_json = published.to_json();
    baseline_json.set("selectors", json::Value::make_array());
    array.push_back(std::move(baseline_json));
    CHECK_ERROR(BaselineRegistry::from_json(array, "/registry"),
                ErrorCode::SchemaEmptyCollection);
  }
  {
    // Two published baselines that claim the same class and generation are
    // rejected as a contradiction rather than silently accepted.
    Baseline first = make_baseline(
        "gpu-a", 3u, 1u, BaselineState::Published,
        {make_selector("gpu", "h100", std::nullopt, std::nullopt)}, {default_component()});
    Baseline second = first;
    second.id = baseline_id("gpu-b");
    json::Value array = json::Value::make_array();
    array.push_back(first.to_json());
    array.push_back(second.to_json());
    CHECK_ERROR(BaselineRegistry::from_json(array, "/registry"),
                ErrorCode::PolicySelfContradiction);
  }
  {
    const json::Value object = parse_json("{}");
    CHECK_ERROR(BaselineRegistry::from_json(object, "/registry"), ErrorCode::SchemaWrongType);
  }
  {
    const json::Value invalid_element = parse_json(R"([{"id": "x"}])");
    CHECK_ERROR(BaselineRegistry::from_json(invalid_element, "/registry"),
                ErrorCode::SchemaMissingField);
  }
}

FBM_TEST(baseline_state_tokens) {
  CHECK_EQ(summon::fbm::baseline_state_token(BaselineState::Draft), std::string_view{"draft"});
  CHECK_EQ(summon::fbm::baseline_state_token(BaselineState::Published),
           std::string_view{"published"});
  CHECK_EQ(summon::fbm::baseline_state_token(BaselineState::Retired),
           std::string_view{"retired"});
  Result<BaselineState> draft = summon::fbm::baseline_state_from_token("draft");
  CHECK_OK(draft);
  CHECK(draft.value() == BaselineState::Draft);
  Result<BaselineState> published = summon::fbm::baseline_state_from_token("published");
  CHECK_OK(published);
  CHECK(published.value() == BaselineState::Published);
  Result<BaselineState> retired = summon::fbm::baseline_state_from_token("retired");
  CHECK_OK(retired);
  CHECK(retired.value() == BaselineState::Retired);
  CHECK_ERROR(summon::fbm::baseline_state_from_token("Published"),
              ErrorCode::SchemaInvalidEnumValue);
  CHECK_ERROR(summon::fbm::baseline_state_from_token(""),
              ErrorCode::SchemaInvalidEnumValue);
}
