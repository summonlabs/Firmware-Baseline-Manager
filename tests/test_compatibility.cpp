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

#include "summon/fbm/compatibility.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "check.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/result.hpp"

namespace {

using summon::fbm::CapabilityId;
using summon::fbm::CompatibilityRule;
using summon::fbm::CompatibilityRuleSet;
using summon::fbm::ComponentEvidenceMap;
using summon::fbm::Diagnostics;
using summon::fbm::ErrorCode;
using summon::fbm::FirmwareComponentId;
using summon::fbm::FirmwareVersion;
using summon::fbm::HardwareClassId;
using summon::fbm::HardwareModelId;
using summon::fbm::HardwareProfile;
using summon::fbm::HardwareRevision;
using summon::fbm::Requirement;
using summon::fbm::RequirementKind;
using summon::fbm::RequirementOutcome;
using summon::fbm::Result;
using summon::fbm::RuleEvaluation;
using summon::fbm::RuleId;
using summon::fbm::RuleOutcome;
using summon::fbm::Status;
using summon::fbm::VersionRange;
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
  Result<FirmwareComponentId> parsed = summon::fbm::make_id<FirmwareComponentId>(text, "/test/component");
  CHECK_OK(parsed);
  return parsed.take();
}

CapabilityId capability_id(std::string_view text) {
  Result<CapabilityId> parsed = summon::fbm::make_id<CapabilityId>(text, "/test/capability");
  CHECK_OK(parsed);
  return parsed.take();
}

RuleId rule_id(std::string_view text) {
  Result<RuleId> parsed = summon::fbm::make_id<RuleId>(text, "/test/rule");
  CHECK_OK(parsed);
  return parsed.take();
}

HardwareRevision revision_of(std::uint32_t value) { return HardwareRevision{value}; }

HardwareProfile make_profile(std::string_view hardware_class, std::string_view model,
                             std::optional<std::uint32_t> revision, bool capabilities_observed,
                             std::vector<CapabilityId> capabilities = {}) {
  HardwareProfile profile;
  Result<HardwareClassId> parsed_class =
      summon::fbm::make_id<HardwareClassId>(hardware_class, "/test/hardware_class");
  CHECK_OK(parsed_class);
  profile.hardware_class = parsed_class.take();
  Result<HardwareModelId> parsed_model =
      summon::fbm::make_id<HardwareModelId>(model, "/test/model");
  CHECK_OK(parsed_model);
  profile.model = parsed_model.take();
  if (revision.has_value()) {
    profile.revision = revision_of(*revision);
  }
  profile.capabilities_observed = capabilities_observed;
  profile.capabilities = std::move(capabilities);
  return profile;
}

ComponentEvidenceMap evidence_with(
    std::initializer_list<std::pair<std::string_view, std::optional<std::string_view>>> entries) {
  ComponentEvidenceMap evidence;
  for (const auto& entry : entries) {
    const FirmwareComponentId id = component_id(entry.first);
    if (entry.second.has_value()) {
      evidence.emplace(id, version(*entry.second));
    } else {
      evidence.emplace(id, std::nullopt);
    }
  }
  return evidence;
}

Requirement component_requirement(RequirementKind kind, std::string_view component,
                                  std::string_view minimum, bool minimum_inclusive,
                                  std::string_view maximum, bool maximum_inclusive) {
  Requirement requirement;
  requirement.kind = kind;
  requirement.component = component_id(component);
  Result<VersionRange> range = VersionRange::make(version(minimum), minimum_inclusive,
                                                  version(maximum), maximum_inclusive, "/test/range");
  CHECK_OK(range);
  requirement.versions = range.take();
  return requirement;
}

Requirement capability_requirement(RequirementKind kind, std::string_view capability) {
  Requirement requirement;
  requirement.kind = kind;
  requirement.capability = capability_id(capability);
  return requirement;
}

Requirement hardware_requirement(std::optional<std::uint32_t> minimum,
                                 std::optional<std::uint32_t> maximum) {
  Requirement requirement;
  requirement.kind = RequirementKind::HardwareRevisionInRange;
  if (minimum.has_value()) {
    requirement.minimum_revision = revision_of(*minimum);
  }
  if (maximum.has_value()) {
    requirement.maximum_revision = revision_of(*maximum);
  }
  return requirement;
}

CompatibilityRule make_rule(std::string_view id, std::string_view when_component,
                            std::string_view minimum, std::string_view maximum,
                            Requirement requirement) {
  CompatibilityRule rule;
  rule.id = rule_id(id);
  rule.when_component = component_id(when_component);
  Result<VersionRange> range = VersionRange::make(version(minimum), true, version(maximum), false,
                                                  "/test/when_versions");
  CHECK_OK(range);
  rule.when_versions = range.take();
  rule.requirement = std::move(requirement);
  rule.reason = "declared by the test";
  return rule;
}

std::string detail_of(const std::vector<RuleEvaluation>& evaluations, std::string_view id) {
  for (const RuleEvaluation& evaluation : evaluations) {
    if (evaluation.rule.to_string() == id) {
      return evaluation.detail;
    }
  }
  return std::string{};
}

std::optional<RuleOutcome> outcome_of(const std::vector<RuleEvaluation>& evaluations,
                                      std::string_view id) {
  for (const RuleEvaluation& evaluation : evaluations) {
    if (evaluation.rule.to_string() == id) {
      return evaluation.outcome;
    }
  }
  return std::nullopt;
}

// Compares a value against itself after a canonical JSON round trip.
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
// HardwareProfile
// ---------------------------------------------------------------------------

FBM_TEST(compatibility_hardware_profile_round_trip) {
  HardwareProfile profile = make_profile("gpu", "h100", 4u, true,
                                         {capability_id("nvlink4"), capability_id("sriov")});
  CHECK(profile.is_identified());
  CHECK(profile.has_capability(capability_id("sriov")));
  CHECK(!profile.has_capability(capability_id("rdma")));

  Diagnostics diagnostics;
  CHECK_OK(profile.validate("/hardware", diagnostics));
  check_round_trip(profile, "/hardware");

  HardwareProfile unknown_revision = make_profile("gpu", "h100", std::nullopt, false);
  CHECK(!unknown_revision.is_identified());
  CHECK_OK(unknown_revision.validate("/hardware", diagnostics));
  check_round_trip(unknown_revision, "/hardware");
}

FBM_TEST(compatibility_hardware_profile_rejects_inconsistent_capabilities) {
  {
    Diagnostics diagnostics;
    HardwareProfile profile = make_profile("gpu", "h100", 4u, false, {capability_id("sriov")});
    Status status = profile.validate("/hardware", diagnostics);
    CHECK(!status.has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/hardware/capabilities"});
  }
  {
    Diagnostics diagnostics;
    HardwareProfile profile =
        make_profile("gpu", "h100", 4u, true, {capability_id("sriov"), capability_id("nvlink4")});
    Status status = profile.validate("/hardware", diagnostics);
    CHECK(!status.has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/hardware/capabilities/1"});
  }
  {
    Diagnostics diagnostics;
    HardwareProfile profile =
        make_profile("gpu", "h100", 4u, true, {capability_id("sriov"), capability_id("sriov")});
    Status status = profile.validate("/hardware", diagnostics);
    CHECK(!status.has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
  }
}

FBM_TEST(compatibility_hardware_profile_json_rejections) {
  {
    // hardware_class and model are required.
    const json::Value document = parse_json(R"({"capabilities_observed": true})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"), ErrorCode::SchemaMissingField);
  }
  {
    const json::Value document = parse_json(R"({"hardware_class": "gpu", "capabilities_observed": true})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"), ErrorCode::SchemaMissingField);
  }
  {
    // Unknown fields are never accepted.
    const json::Value document = parse_json(
        R"({"hardware_class": "gpu", "model": "h100", "capabilities_observed": true, "extra": 1})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"), ErrorCode::SchemaUnknownField);
  }
  {
    // A wrong JSON type is a schema defect, not a coercion.
    const json::Value document =
        parse_json(R"({"hardware_class": "gpu", "model": "h100", "capabilities_observed": "true"})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"), ErrorCode::SchemaWrongType);
  }
  {
    // An invalid identifier is rejected, not normalised.
    const json::Value document = parse_json(
        R"({"hardware_class": "-gpu", "model": "h100", "capabilities_observed": true})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"),
                ErrorCode::SchemaInvalidIdentifier);
  }
  {
    const json::Value document = parse_json(
        R"({"hardware_class": "gpu", "model": "h100", "capabilities_observed": true,
            "capabilities": ["sriov", "nvlink4"]})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"hardware_class": "gpu", "model": "h100", "capabilities_observed": false,
            "capabilities": ["sriov"]})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    // A revision that does not fit the hardware revision representation.
    const json::Value document = parse_json(
        R"({"hardware_class": "gpu", "model": "h100", "revision": 4294967296,
            "capabilities_observed": true})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"),
                ErrorCode::SchemaValueOutOfRange);
  }
  {
    const json::Value document = parse_json(
        R"({"hardware_class": "gpu", "model": "h100", "capabilities_observed": true,
            "capabilities": ["bad~cap"]})");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"),
                ErrorCode::SchemaInvalidIdentifier);
  }
  {
    // A non-object document is rejected with the exact path.
    const json::Value document = parse_json("[]");
    CHECK_ERROR(HardwareProfile::from_json(document, "/hardware"), ErrorCode::SchemaWrongType);
  }
}

// ---------------------------------------------------------------------------
// Requirement: evaluation
// ---------------------------------------------------------------------------

FBM_TEST(compatibility_requirement_component_version_evaluation) {
  const ComponentEvidenceMap evidence =
      evidence_with({{"bmc", std::optional<std::string_view>{"2.5.0"}}});
  const HardwareProfile profile = make_profile("gpu", "h100", 1u, true);

  {
    const Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionInRange, "bmc", "2.0.0", true, "3.0.0", false);
    std::string detail;
    CHECK(requirement.evaluate(profile, evidence, detail) == RequirementOutcome::Satisfied);
    CHECK(detail.find("bmc") != std::string::npos);
    CHECK(detail.find("2.5.0") != std::string::npos);
  }
  {
    const Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionInRange, "bmc", "3.0.0", true, "4.0.0", false);
    std::string detail;
    CHECK(requirement.evaluate(profile, evidence, detail) == RequirementOutcome::Violated);
    CHECK(detail.find("3.0.0") != std::string::npos);
    CHECK(detail.find("2.5.0") != std::string::npos);
  }
  {
    const Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionNotInRange, "bmc", "2.0.0", true, "3.0.0", false);
    std::string detail;
    CHECK(requirement.evaluate(profile, evidence, detail) == RequirementOutcome::Violated);
    CHECK(detail.find("2.5.0") != std::string::npos);
  }
  {
    const Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionNotInRange, "bmc", "3.0.0", true, "4.0.0", false);
    std::string detail;
    CHECK(requirement.evaluate(profile, evidence, detail) == RequirementOutcome::Satisfied);
  }
  {
    // A component that was never observed cannot be decided.
    const Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionInRange, "nic", "1.0.0", true, "2.0.0", false);
    std::string detail;
    CHECK(requirement.evaluate(profile, evidence, detail) == RequirementOutcome::Unverifiable);
    CHECK(detail.find("nic") != std::string::npos);
    CHECK(detail.find("not observed") != std::string::npos);
  }
  {
    // A component observed without a determined version cannot be decided.
    const ComponentEvidenceMap unknown_version =
        evidence_with({{"bmc", std::optional<std::string_view>{}}});
    const Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionInRange, "bmc", "1.0.0", true, "2.0.0", false);
    std::string detail;
    CHECK(requirement.evaluate(profile, unknown_version, detail) == RequirementOutcome::Unverifiable);
    CHECK(detail.find("not determined") != std::string::npos);
  }
}

FBM_TEST(compatibility_requirement_hardware_revision_evaluation) {
  const ComponentEvidenceMap no_evidence;
  {
    const HardwareProfile profile = make_profile("gpu", "h100", 4u, true);
    const Requirement requirement = hardware_requirement(1u, 4u);
    std::string detail;
    CHECK(requirement.evaluate(profile, no_evidence, detail) == RequirementOutcome::Satisfied);
    CHECK(detail.find("hardware revision 4") != std::string::npos);
  }
  {
    const HardwareProfile profile = make_profile("gpu", "h100", 7u, true);
    const Requirement requirement = hardware_requirement(1u, 4u);
    std::string detail;
    CHECK(requirement.evaluate(profile, no_evidence, detail) == RequirementOutcome::Violated);
    CHECK(detail.find("7") != std::string::npos);
  }
  {
    const HardwareProfile profile = make_profile("gpu", "h100", std::nullopt, true);
    const Requirement requirement = hardware_requirement(1u, 4u);
    std::string detail;
    CHECK(requirement.evaluate(profile, no_evidence, detail) == RequirementOutcome::Unverifiable);
    CHECK(detail.find("not observed") != std::string::npos);
  }
  {
    // Only a lower bound.
    const HardwareProfile profile = make_profile("gpu", "h100", 1u, true);
    const Requirement requirement = hardware_requirement(2u, std::nullopt);
    std::string detail;
    CHECK(requirement.evaluate(profile, no_evidence, detail) == RequirementOutcome::Violated);
  }
  {
    // Only an upper bound.
    const HardwareProfile profile = make_profile("gpu", "h100", 2u, true);
    const Requirement requirement = hardware_requirement(std::nullopt, 1u);
    std::string detail;
    CHECK(requirement.evaluate(profile, no_evidence, detail) == RequirementOutcome::Violated);
  }
}

FBM_TEST(compatibility_requirement_capability_evaluation) {
  const ComponentEvidenceMap no_evidence;
  const HardwareProfile observed =
      make_profile("gpu", "h100", 1u, true, {capability_id("sriov")});
  const HardwareProfile observed_without =
      make_profile("gpu", "h100", 1u, true, {capability_id("nvlink4")});
  {
    const Requirement present = capability_requirement(RequirementKind::CapabilityPresent, "sriov");
    std::string detail;
    CHECK(present.evaluate(observed, no_evidence, detail) == RequirementOutcome::Satisfied);
    CHECK(present.evaluate(observed_without, no_evidence, detail) == RequirementOutcome::Violated);
    CHECK(detail.find("sriov") != std::string::npos);
  }
  {
    const Requirement absent = capability_requirement(RequirementKind::CapabilityAbsent, "sriov");
    std::string detail;
    CHECK(absent.evaluate(observed, no_evidence, detail) == RequirementOutcome::Violated);
    CHECK(absent.evaluate(observed_without, no_evidence, detail) == RequirementOutcome::Satisfied);
  }
  {
    // An unobserved capability set is undecidable, never a violation.
    const HardwareProfile unobserved = make_profile("gpu", "h100", 1u, false);
    const Requirement present = capability_requirement(RequirementKind::CapabilityPresent, "sriov");
    const Requirement absent = capability_requirement(RequirementKind::CapabilityAbsent, "sriov");
    std::string detail;
    CHECK(present.evaluate(unobserved, no_evidence, detail) == RequirementOutcome::Unverifiable);
    CHECK(detail.find("not observed") != std::string::npos);
    CHECK(absent.evaluate(unobserved, no_evidence, detail) == RequirementOutcome::Unverifiable);
  }
}

FBM_TEST(compatibility_requirement_tokens) {
  CHECK_EQ(summon::fbm::requirement_kind_token(RequirementKind::ComponentVersionInRange),
           std::string_view{"component_version_in_range"});
  CHECK_EQ(summon::fbm::requirement_kind_token(RequirementKind::ComponentVersionNotInRange),
           std::string_view{"component_version_not_in_range"});
  CHECK_EQ(summon::fbm::requirement_kind_token(RequirementKind::HardwareRevisionInRange),
           std::string_view{"hardware_revision_in_range"});
  CHECK_EQ(summon::fbm::requirement_kind_token(RequirementKind::CapabilityPresent),
           std::string_view{"capability_present"});
  CHECK_EQ(summon::fbm::requirement_kind_token(RequirementKind::CapabilityAbsent),
           std::string_view{"capability_absent"});
  for (const RequirementKind kind :
       {RequirementKind::ComponentVersionInRange, RequirementKind::ComponentVersionNotInRange,
        RequirementKind::HardwareRevisionInRange, RequirementKind::CapabilityPresent,
        RequirementKind::CapabilityAbsent}) {
    Result<RequirementKind> parsed =
        summon::fbm::requirement_kind_from_token(summon::fbm::requirement_kind_token(kind));
    CHECK_OK(parsed);
    CHECK(parsed.value() == kind);
  }
  CHECK_ERROR(summon::fbm::requirement_kind_from_token("ComponentVersionInRange"),
              ErrorCode::SchemaInvalidEnumValue);
  CHECK_EQ(summon::fbm::requirement_outcome_token(RequirementOutcome::Satisfied),
           std::string_view{"satisfied"});
  CHECK_EQ(summon::fbm::requirement_outcome_token(RequirementOutcome::Violated),
           std::string_view{"violated"});
  CHECK_EQ(summon::fbm::requirement_outcome_token(RequirementOutcome::Unverifiable),
           std::string_view{"unverifiable"});
  CHECK_EQ(summon::fbm::rule_outcome_token(RuleOutcome::NotTriggered),
           std::string_view{"not_triggered"});
  CHECK_EQ(summon::fbm::rule_outcome_token(RuleOutcome::TriggerUnknown),
           std::string_view{"trigger_unknown"});
}

// ---------------------------------------------------------------------------
// Requirement: validation and JSON
// ---------------------------------------------------------------------------

FBM_TEST(compatibility_requirement_validation_rejections) {
  {
    Diagnostics diagnostics;
    Requirement requirement;  // component_version_in_range with nothing set
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/component"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement;
    requirement.component = component_id("bmc");
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/versions"});
  }
  {
    // A range with no members cannot even be built, so a requirement can never
    // carry one.
    Result<VersionRange> empty = VersionRange::make(version("2.0.0"), true, version("2.0.0"),
                                                    false, "/requirement/versions");
    CHECK(!empty.has_value());
    CHECK_EQ(empty.error().code(), ErrorCode::SchemaInconsistentDocument);
    CHECK_EQ(empty.error().path(), std::string{"/requirement/versions"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionInRange, "bmc", "2.0.0", true, "3.0.0", false);
    requirement.capability = capability_id("sriov");
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/capability"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement = component_requirement(
        RequirementKind::ComponentVersionInRange, "bmc", "2.0.0", true, "3.0.0", false);
    requirement.minimum_revision = revision_of(1u);
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/minimum_revision"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement;
    requirement.kind = RequirementKind::HardwareRevisionInRange;
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/minimum_revision"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement = hardware_requirement(5u, 1u);
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/maximum_revision"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement = hardware_requirement(1u, 4u);
    requirement.component = component_id("bmc");
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/component"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement;
    requirement.kind = RequirementKind::CapabilityPresent;
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/capability"});
  }
  {
    Diagnostics diagnostics;
    Requirement requirement = capability_requirement(RequirementKind::CapabilityAbsent, "sriov");
    requirement.minimum_revision = revision_of(1u);
    CHECK(!requirement.validate("/requirement", diagnostics).has_value());
    CHECK_EQ(diagnostics.primary().path(), std::string{"/requirement/minimum_revision"});
  }
}

FBM_TEST(compatibility_requirement_json_round_trip) {
  const std::vector<Requirement> requirements = {
      component_requirement(RequirementKind::ComponentVersionInRange, "bmc", "2.0.0", true,
                            "3.0.0", false),
      component_requirement(RequirementKind::ComponentVersionNotInRange, "bmc", "2.0.0", true,
                            "3.0.0", true),
      hardware_requirement(1u, 4u),
      hardware_requirement(1u, std::nullopt),
      capability_requirement(RequirementKind::CapabilityPresent, "sriov"),
      capability_requirement(RequirementKind::CapabilityAbsent, "rdma"),
  };
  for (const Requirement& requirement : requirements) {
    check_round_trip(requirement, "/requirement");
  }
  // A requirement parsed from text keeps its exact meaning.
  const json::Value document = parse_json(
      R"({"kind": "component_version_not_in_range", "component": "bios",
          "versions": {"min": "3.0.0", "min_inclusive": false, "max": "4.0.0",
                       "max_inclusive": true}})");
  Result<Requirement> parsed = Requirement::from_json(document, "/requirement");
  CHECK_OK(parsed);
  CHECK(parsed.value().kind == RequirementKind::ComponentVersionNotInRange);
  CHECK(!parsed.value().versions.minimum_inclusive());
  CHECK(parsed.value().versions.maximum_inclusive());
}

FBM_TEST(compatibility_requirement_json_rejections) {
  {
    const json::Value document = parse_json(R"({"component": "bmc"})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"), ErrorCode::SchemaMissingField);
  }
  {
    const json::Value document = parse_json(R"({"kind": "component_version_in_ranges"})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInvalidEnumValue);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "component_version_in_range", "versions": {"min": "1.0.0",
            "min_inclusive": true}})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "component_version_in_range", "component": "bmc"})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "component_version_in_range", "component": "bmc",
            "versions": {"min": "2.0.0", "min_inclusive": true, "max": "2.0.0",
                         "max_inclusive": false}})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "hardware_revision_in_range"})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "hardware_revision_in_range", "minimum_revision": 5,
            "maximum_revision": 1})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "hardware_revision_in_range", "minimum_revision": 1,
            "maximum_revision": 4, "component": "bmc"})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(R"({"kind": "capability_present"})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "capability_present", "capability": "sriov",
            "versions": {"min": "1.0.0", "min_inclusive": true}})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "capability_present", "capability": "sriov", "unknown": 1})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"), ErrorCode::SchemaUnknownField);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "capability_present", "capability": "sriov", "minimum_revision": 2})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    // min without min_inclusive is a missing field, not an implicit default.
    const json::Value document = parse_json(
        R"({"kind": "component_version_in_range", "component": "bmc",
            "versions": {"min": "1.0.0"}})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"), ErrorCode::SchemaMissingField);
  }
  {
    // max_inclusive without max is an impossible combination.
    const json::Value document = parse_json(
        R"({"kind": "component_version_in_range", "component": "bmc",
            "versions": {"min": "1.0.0", "min_inclusive": true, "max_inclusive": true}})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "component_version_in_range", "component": "-bad",
            "versions": {"min": "1.0.0", "min_inclusive": true}})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInvalidIdentifier);
  }
  {
    const json::Value document = parse_json(
        R"({"kind": "component_version_in_range", "component": "bmc",
            "versions": {"min": "1.0", "min_inclusive": true}})");
    CHECK_ERROR(Requirement::from_json(document, "/requirement"),
                ErrorCode::SchemaInvalidVersionText);
  }
}

// ---------------------------------------------------------------------------
// CompatibilityRule and CompatibilityRuleSet
// ---------------------------------------------------------------------------

FBM_TEST(compatibility_rule_json_round_trip) {
  const json::Value document = parse_json(
      R"({
        "id": "r-bmc-bios",
        "when_component": "bmc",
        "when_versions": {"min": "2.4.0", "min_inclusive": true, "max": "3.0.0",
                          "max_inclusive": false},
        "when_minimum_revision": 1,
        "when_maximum_revision": 3,
        "requirement": {"kind": "component_version_in_range", "component": "bios",
                        "versions": {"min": "3.0.0", "min_inclusive": true}},
        "reason": "BMC 2.4 requires BIOS 3.x"
      })");
  Result<CompatibilityRule> parsed = CompatibilityRule::from_json(document, "/rule");
  CHECK_OK(parsed);
  CHECK_EQ(parsed.value().id.to_string(), std::string{"r-bmc-bios"});
  CHECK_EQ(parsed.value().reason, std::string{"BMC 2.4 requires BIOS 3.x"});
  CHECK(parsed.value().when_minimum_revision.is_set());
  CHECK(parsed.value().when_maximum_revision.is_set());
  check_round_trip(parsed.value(), "/rule");
}

FBM_TEST(compatibility_rule_json_rejections) {
  {
    const json::Value document = parse_json(
        R"({"id": "r-1", "when_component": "bmc", "when_versions": {"min": "1.0.0",
            "min_inclusive": true}, "requirement": {"kind": "capability_present",
            "capability": "sriov"}})");
    CHECK_ERROR(CompatibilityRule::from_json(document, "/rule"), ErrorCode::SchemaMissingField);
  }
  {
    const json::Value document = parse_json(
        R"({"id": "r-1", "when_component": "bmc", "when_versions": {"min": "1.0.0",
            "min_inclusive": true}, "requirement": {"kind": "capability_present",
            "capability": "sriov"}, "reason": ""})");
    CHECK_ERROR(CompatibilityRule::from_json(document, "/rule"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"id": "r-1", "when_component": "bmc", "when_versions": {"min": "1.0.0",
            "min_inclusive": true, "max": "1.0.0", "max_inclusive": false},
            "requirement": {"kind": "capability_present", "capability": "sriov"},
            "reason": "empty trigger"})");
    CHECK_ERROR(CompatibilityRule::from_json(document, "/rule"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"id": "r-1", "when_component": "bmc", "when_versions": {"min": "1.0.0",
            "min_inclusive": true}, "when_minimum_revision": 5, "when_maximum_revision": 1,
            "requirement": {"kind": "capability_present", "capability": "sriov"},
            "reason": "inverted"})");
    CHECK_ERROR(CompatibilityRule::from_json(document, "/rule"),
                ErrorCode::SchemaInconsistentDocument);
  }
  {
    const json::Value document = parse_json(
        R"({"id": "r-1", "when_component": "bmc", "when_versions": {"min": "1.0.0",
            "min_inclusive": true}, "requirement": {"kind": "capability_present",
            "capability": "sriov"}, "reason": "ok", "surprise": true})");
    CHECK_ERROR(CompatibilityRule::from_json(document, "/rule"), ErrorCode::SchemaUnknownField);
  }
  {
    const json::Value document = parse_json(
        R"({"id": "r-1", "when_component": "bmc", "when_versions": {"min": "1.0.0",
            "min_inclusive": true}, "requirement": {"kind": "capability_present",
            "capability": "sriov"}, "reason": "ok", "when_versions_extra": 1})");
    CHECK_ERROR(CompatibilityRule::from_json(document, "/rule"), ErrorCode::SchemaUnknownField);
  }
  {
    const json::Value document = parse_json(
        R"({"id": "bad id", "when_component": "bmc", "when_versions": {"min": "1.0.0",
            "min_inclusive": true}, "requirement": {"kind": "capability_present",
            "capability": "sriov"}, "reason": "ok"})");
    CHECK_ERROR(CompatibilityRule::from_json(document, "/rule"),
                ErrorCode::SchemaInvalidIdentifier);
  }
}

FBM_TEST(compatibility_ruleset_add_rejects_duplicates_and_stays_sorted) {
  CompatibilityRuleSet set;
  const Requirement capability =
      capability_requirement(RequirementKind::CapabilityPresent, "sriov");
  CHECK_OK(set.add(make_rule("r-c", "bmc", "1.0.0", "2.0.0", capability)));
  CHECK_OK(set.add(make_rule("r-a", "bmc", "1.0.0", "2.0.0", capability)));
  CHECK_OK(set.add(make_rule("r-b", "bmc", "1.0.0", "2.0.0", capability)));
  CHECK_EQ(set.size(), std::size_t{3});
  CHECK_EQ(set.rules()[0].id.to_string(), std::string{"r-a"});
  CHECK_EQ(set.rules()[1].id.to_string(), std::string{"r-b"});
  CHECK_EQ(set.rules()[2].id.to_string(), std::string{"r-c"});
  CHECK(set.find(rule_id("r-b")) != nullptr);
  CHECK(set.find(rule_id("r-z")) == nullptr);

  Status duplicate = set.add(make_rule("r-b", "bmc", "1.0.0", "2.0.0", capability));
  CHECK(!duplicate.has_value());
  CHECK_EQ(duplicate.error().code(), ErrorCode::SchemaDuplicateIdentifier);
  CHECK_EQ(set.size(), std::size_t{3});

  // A document that repeats a rule identity is rejected.
  const json::Value document = parse_json(
      R"([
        {"id": "r-1", "when_component": "bmc",
         "when_versions": {"min": "1.0.0", "min_inclusive": true},
         "requirement": {"kind": "capability_present", "capability": "sriov"},
         "reason": "first"},
        {"id": "r-1", "when_component": "bmc",
         "when_versions": {"min": "2.0.0", "min_inclusive": true},
         "requirement": {"kind": "capability_absent", "capability": "rdma"},
         "reason": "second"}
      ])");
  CHECK_ERROR(CompatibilityRuleSet::from_json(document, "/rules"),
              ErrorCode::SchemaDuplicateIdentifier);
}

FBM_TEST(compatibility_ruleset_evaluation_order_is_ascending) {
  CompatibilityRuleSet set;
  const Requirement capability =
      capability_requirement(RequirementKind::CapabilityPresent, "sriov");
  CHECK_OK(set.add(make_rule("r-z", "bmc", "1.0.0", "2.0.0", capability)));
  CHECK_OK(set.add(make_rule("r-m", "bmc", "1.0.0", "2.0.0", capability)));
  CHECK_OK(set.add(make_rule("r-a", "bmc", "1.0.0", "2.0.0", capability)));

  const HardwareProfile profile = make_profile("gpu", "h100", 1u, true);
  const ComponentEvidenceMap evidence =
      evidence_with({{"bmc", std::optional<std::string_view>{"1.5.0"}}});
  const std::vector<RuleEvaluation> evaluations = set.evaluate(profile, evidence);
  CHECK_EQ(evaluations.size(), std::size_t{3});
  CHECK_EQ(evaluations[0].rule.to_string(), std::string{"r-a"});
  CHECK_EQ(evaluations[1].rule.to_string(), std::string{"r-m"});
  CHECK_EQ(evaluations[2].rule.to_string(), std::string{"r-z"});
  for (const RuleEvaluation& evaluation : evaluations) {
    CHECK(!evaluation.detail.empty());
  }
}

FBM_TEST(compatibility_ruleset_reports_self_contradictions_stably) {
  // The trigger range and the required range share no version.
  const CompatibilityRule contradictory_a =
      make_rule("r-a", "bmc", "1.0.0", "2.0.0",
                component_requirement(RequirementKind::ComponentVersionInRange, "bmc", "3.0.0",
                                      true, "4.0.0", false));
  const CompatibilityRule contradictory_b =
      make_rule("r-b", "nic", "1.0.0", "2.0.0",
                component_requirement(RequirementKind::ComponentVersionInRange, "nic", "3.0.0",
                                      true, "4.0.0", false));
  const CompatibilityRule consistent =
      make_rule("r-c", "bmc", "1.0.0", "2.0.0",
                component_requirement(RequirementKind::ComponentVersionInRange, "bmc", "1.5.0",
                                      true, "2.5.0", false));
  const CompatibilityRule other_component =
      make_rule("r-d", "bmc", "1.0.0", "2.0.0",
                component_requirement(RequirementKind::ComponentVersionInRange, "bios", "3.0.0",
                                      true, "4.0.0", false));

  CompatibilityRuleSet forward;
  CHECK_OK(forward.add(contradictory_a));
  CHECK_OK(forward.add(contradictory_b));
  CHECK_OK(forward.add(consistent));
  CHECK_OK(forward.add(other_component));

  CompatibilityRuleSet reversed;
  CHECK_OK(reversed.add(other_component));
  CHECK_OK(reversed.add(consistent));
  CHECK_OK(reversed.add(contradictory_b));
  CHECK_OK(reversed.add(contradictory_a));

  const std::vector<RuleId> contradictions = forward.self_contradictions();
  CHECK_EQ(contradictions.size(), std::size_t{2});
  CHECK_EQ(contradictions[0].to_string(), std::string{"r-a"});
  CHECK_EQ(contradictions[1].to_string(), std::string{"r-b"});
  CHECK_EQ(reversed.self_contradictions().size(), std::size_t{2});

  Diagnostics forward_diagnostics;
  Status forward_status = forward.validate("/rules", forward_diagnostics);
  CHECK(!forward_status.has_value());
  CHECK_EQ(forward_diagnostics.primary().code(), ErrorCode::PolicySelfContradiction);
  CHECK(forward_diagnostics.primary().message().find("r-a") != std::string::npos);
  CHECK_EQ(forward_diagnostics.primary().path(), std::string{"/rules/0"});

  // The same policy always selects the same primary error, whatever the order
  // the rules were added in.
  Diagnostics reversed_diagnostics;
  Status reversed_status = reversed.validate("/rules", reversed_diagnostics);
  CHECK(!reversed_status.has_value());
  CHECK_EQ(reversed_diagnostics.primary().code(), forward_diagnostics.primary().code());
  CHECK_EQ(reversed_diagnostics.primary().path(), forward_diagnostics.primary().path());
  CHECK_EQ(reversed_diagnostics.primary().message(), forward_diagnostics.primary().message());

  // Repeating the validation produces the identical primary error.
  Diagnostics repeat_diagnostics;
  CHECK(!forward.validate("/rules", repeat_diagnostics).has_value());
  CHECK_EQ(repeat_diagnostics.primary().code(), forward_diagnostics.primary().code());
  CHECK_EQ(repeat_diagnostics.primary().message(), forward_diagnostics.primary().message());
}

FBM_TEST(compatibility_ruleset_self_contradiction_json_is_rejected) {
  const json::Value document = parse_json(
      R"([
        {"id": "r-a", "when_component": "bmc",
         "when_versions": {"min": "1.0.0", "min_inclusive": true, "max": "2.0.0",
                           "max_inclusive": false},
         "requirement": {"kind": "component_version_in_range", "component": "bmc",
                         "versions": {"min": "3.0.0", "min_inclusive": true}},
         "reason": "impossible by construction"}
      ])");
  CHECK_ERROR(CompatibilityRuleSet::from_json(document, "/rules"),
              ErrorCode::PolicySelfContradiction);
}

FBM_TEST(compatibility_ruleset_evaluation_covers_every_outcome) {
  CompatibilityRuleSet set;
  CHECK_OK(set.add(make_rule(
      "r-absent", "tpm", "1.0.0", "2.0.0",
      capability_requirement(RequirementKind::CapabilityPresent, "sriov"))));
  CHECK_OK(set.add(make_rule(
      "r-unknown", "psu", "1.0.0", "2.0.0",
      capability_requirement(RequirementKind::CapabilityPresent, "sriov"))));
  CHECK_OK(set.add(make_rule(
      "r-outside", "bmc", "3.0.0", "4.0.0",
      capability_requirement(RequirementKind::CapabilityPresent, "sriov"))));
  CHECK_OK(set.add(make_rule(
      "r-satisfied", "bmc", "1.0.0", "2.0.0",
      component_requirement(RequirementKind::ComponentVersionInRange, "bios", "3.0.0", true,
                            "4.0.0", false))));
  CHECK_OK(set.add(make_rule(
      "r-violated", "bmc", "1.0.0", "2.0.0",
      component_requirement(RequirementKind::ComponentVersionInRange, "nic", "1.0.0", true,
                            "2.0.0", false))));
  CHECK_OK(set.add(make_rule(
      "r-unverifiable", "bmc", "1.0.0", "2.0.0",
      component_requirement(RequirementKind::ComponentVersionInRange, "gpu", "1.0.0", true,
                            "2.0.0", false))));

  CompatibilityRule revision_trigger = make_rule(
      "r-revision", "bmc", "1.0.0", "2.0.0",
      capability_requirement(RequirementKind::CapabilityPresent, "sriov"));
  revision_trigger.when_minimum_revision = revision_of(5u);
  CHECK_OK(set.add(std::move(revision_trigger)));

  const HardwareProfile profile = make_profile("gpu", "h100", 1u, true);
  const ComponentEvidenceMap evidence = evidence_with({
      {"bmc", std::optional<std::string_view>{"1.5.0"}},
      {"nic", std::optional<std::string_view>{"5.0.0"}},
      {"bios", std::optional<std::string_view>{"3.2.0"}},
      {"psu", std::optional<std::string_view>{}},
  });

  const std::vector<RuleEvaluation> evaluations = set.evaluate(profile, evidence);
  CHECK_EQ(evaluations.size(), std::size_t{7});
  CHECK(outcome_of(evaluations, "r-absent").value() == RuleOutcome::NotTriggered);
  CHECK(outcome_of(evaluations, "r-unknown").value() == RuleOutcome::TriggerUnknown);
  CHECK(outcome_of(evaluations, "r-outside").value() == RuleOutcome::NotTriggered);
  CHECK(outcome_of(evaluations, "r-satisfied").value() == RuleOutcome::Satisfied);
  CHECK(outcome_of(evaluations, "r-violated").value() == RuleOutcome::Violated);
  CHECK(outcome_of(evaluations, "r-unverifiable").value() == RuleOutcome::Unverifiable);
  CHECK(outcome_of(evaluations, "r-revision").value() == RuleOutcome::NotTriggered);

  for (const RuleEvaluation& evaluation : evaluations) {
    CHECK(!evaluation.detail.empty());
    // A rule that fired names itself, the trigger version it fired on, and the
    // residual. A trigger with no determined version has no version to name.
    if (evaluation.outcome == RuleOutcome::Satisfied ||
        evaluation.outcome == RuleOutcome::Violated ||
        evaluation.outcome == RuleOutcome::Unverifiable) {
      CHECK(evaluation.detail.find(evaluation.rule.to_string()) != std::string::npos);
      CHECK(evaluation.detail.find("1.5.0") != std::string::npos);
      CHECK(evaluation.detail.find("residual") != std::string::npos);
    }
    if (evaluation.outcome == RuleOutcome::TriggerUnknown) {
      CHECK(evaluation.detail.find(evaluation.rule.to_string()) != std::string::npos);
    }
  }
  CHECK(detail_of(evaluations, "r-satisfied").find("3.2.0") != std::string::npos);
  CHECK(detail_of(evaluations, "r-violated").find("5.0.0") != std::string::npos);
  CHECK(detail_of(evaluations, "r-unverifiable").find("gpu") != std::string::npos);
}

FBM_TEST(compatibility_ruleset_trigger_unknown_is_distinct_from_not_triggered) {
  CompatibilityRuleSet set;
  const Requirement capability =
      capability_requirement(RequirementKind::CapabilityPresent, "sriov");
  CHECK_OK(set.add(make_rule("r-bmc", "bmc", "1.0.0", "2.0.0", capability)));
  CHECK_OK(set.add(make_rule("r-nic", "nic", "1.0.0", "2.0.0", capability)));

  const HardwareProfile profile = make_profile("gpu", "h100", 1u, true);
  // bmc was observed without a version; nic was not observed at all.
  const ComponentEvidenceMap evidence = evidence_with({{"bmc", std::nullopt}});
  const std::vector<RuleEvaluation> evaluations = set.evaluate(profile, evidence);
  CHECK_EQ(evaluations.size(), std::size_t{2});
  CHECK(outcome_of(evaluations, "r-bmc").value() == RuleOutcome::TriggerUnknown);
  CHECK(outcome_of(evaluations, "r-nic").value() == RuleOutcome::NotTriggered);
  CHECK(detail_of(evaluations, "r-bmc").find("not determined") != std::string::npos);

  // The requirement outcome of a rule that never fired stays undecided.
  CHECK_EQ(static_cast<int>(evaluations[0].requirement_outcome),
           static_cast<int>(RequirementOutcome::Unverifiable));
}

FBM_TEST(compatibility_ruleset_json_round_trip) {
  const json::Value document = parse_json(
      R"([
        {"id": "r-bios", "when_component": "bmc",
         "when_versions": {"min": "2.4.0", "min_inclusive": true, "max": "3.0.0",
                           "max_inclusive": false},
         "requirement": {"kind": "component_version_in_range", "component": "bios",
                         "versions": {"min": "3.0.0", "min_inclusive": true}},
         "reason": "BMC 2.4 requires BIOS 3.x"},
        {"id": "r-cap", "when_component": "nic",
         "when_versions": {"min": "1.0.0", "min_inclusive": true},
         "when_minimum_revision": 2, "when_maximum_revision": 4,
         "requirement": {"kind": "capability_absent", "capability": "rdma"},
         "reason": "RDMA is not permitted on this NIC"}
      ])");
  Result<CompatibilityRuleSet> parsed = CompatibilityRuleSet::from_json(document, "/rules");
  CHECK_OK(parsed);
  CHECK_EQ(parsed.value().size(), std::size_t{2});
  check_round_trip(parsed.value(), "/rules");

  // An empty rule set is a valid document.
  const json::Value empty_document = parse_json("[]");
  Result<CompatibilityRuleSet> empty = CompatibilityRuleSet::from_json(empty_document, "/rules");
  CHECK_OK(empty);
  CHECK(empty.value().empty());
  CHECK_EQ(canonical(empty.value().to_json()), std::string{"[]"});

  // An unsorted document is normalised into ascending rule identity order.
  const json::Value unsorted = parse_json(
      R"([
        {"id": "r-z", "when_component": "bmc",
         "when_versions": {"min": "1.0.0", "min_inclusive": true},
         "requirement": {"kind": "capability_present", "capability": "sriov"},
         "reason": "z"},
        {"id": "r-a", "when_component": "bmc",
         "when_versions": {"min": "1.0.0", "min_inclusive": true},
         "requirement": {"kind": "capability_present", "capability": "sriov"},
         "reason": "a"}
      ])");
  Result<CompatibilityRuleSet> normalised = CompatibilityRuleSet::from_json(unsorted, "/rules");
  CHECK_OK(normalised);
  CHECK_EQ(normalised.value().rules()[0].id.to_string(), std::string{"r-a"});
  CHECK_EQ(normalised.value().rules()[1].id.to_string(), std::string{"r-z"});
}

FBM_TEST(compatibility_ruleset_json_rejections) {
  {
    const json::Value document = parse_json("{}");
    CHECK_ERROR(CompatibilityRuleSet::from_json(document, "/rules"), ErrorCode::SchemaWrongType);
  }
  {
    const json::Value document = parse_json(
        R"([{"id": "r-1", "when_component": "bmc",
             "when_versions": {"min": "1.0.0", "min_inclusive": true},
             "requirement": {"kind": "capability_present", "capability": "sriov"}}])");
    CHECK_ERROR(CompatibilityRuleSet::from_json(document, "/rules"),
                ErrorCode::SchemaMissingField);
  }
  {
    // An unknown member inside a rule is reported with the element path.
    const json::Value document = parse_json(
        R"([{"id": "r-1", "when_component": "bmc",
             "when_versions": {"min": "1.0.0", "min_inclusive": true},
             "requirement": {"kind": "capability_present", "capability": "sriov"},
             "reason": "ok", "extra": 0}])");
    CHECK_ERROR(CompatibilityRuleSet::from_json(document, "/rules"),
                ErrorCode::SchemaUnknownField);
  }
}

FBM_TEST(compatibility_find_component_evidence_distinguishes_absence) {
  const ComponentEvidenceMap evidence =
      evidence_with({{"bmc", std::optional<std::string_view>{"1.0.0"}},
                     {"nic", std::optional<std::string_view>{}}});
  const std::optional<FirmwareVersion>* bmc =
      summon::fbm::find_component_evidence(evidence, component_id("bmc"));
  CHECK(bmc != nullptr);
  CHECK(bmc->has_value());
  const std::optional<FirmwareVersion>* nic =
      summon::fbm::find_component_evidence(evidence, component_id("nic"));
  CHECK(nic != nullptr);
  CHECK(!nic->has_value());
  CHECK(summon::fbm::find_component_evidence(evidence, component_id("gpu")) == nullptr);
}
