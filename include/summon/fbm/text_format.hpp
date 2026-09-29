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

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "summon/fbm/conformance.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/store.hpp"

namespace summon::fbm::text {

// Deterministic rendering helpers. None of them read a clock or a locale.

// Durations are rendered in nanoseconds with a unit suffix chosen by magnitude,
// always with three fractional digits, so the same value always renders the
// same way.
std::string format_duration_nanos(std::uint64_t nanos);

// Basis points rendered as a percentage with exactly two fractional digits.
std::string format_basis_points(std::uint32_t basis_points);

std::string format_optional_version(const std::optional<FirmwareVersion>& version);
std::string format_timestamp(const Timestamp& timestamp);

// A fixed-width column table. Column widths are computed from the content and
// the result is byte-stable for a given set of rows.
class Table {
 public:
  Table(std::vector<std::string> headers, std::vector<std::size_t> right_aligned_columns = {});

  void add_row(std::vector<std::string> cells);
  std::string render() const;

 private:
  std::vector<std::string> headers_;
  std::vector<std::size_t> right_aligned_;
  std::vector<std::vector<std::string>> rows_;
};

std::string format_conformance_report(const ConformanceVerdict& verdict);
std::string format_eligibility_report(const EligibilityVerdict& verdict);
std::string format_gate_report(const GateReport& report);
std::string format_drift_table(const std::vector<DriftResidual>& residuals);
std::string format_recovery_report(const RecoveryReport& report);

}  // namespace summon::fbm::text
