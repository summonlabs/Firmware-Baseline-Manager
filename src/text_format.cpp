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

#include "summon/fbm/text_format.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/cohort.hpp"
#include "summon/fbm/conformance.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/store.hpp"
#include "summon/fbm/timestamp.hpp"

namespace summon::fbm::text {
namespace {

// Exact nanosecond multiples of every unit named in the published rendering.
constexpr std::uint64_t kNanosPerMicrosecond = 1000ull;
constexpr std::uint64_t kNanosPerMillisecond = 1000ull * kNanosPerMicrosecond;
constexpr std::uint64_t kNanosPerSecond = 1000ull * kNanosPerMillisecond;
constexpr std::uint64_t kNanosPerMinute = 60ull * kNanosPerSecond;
constexpr std::uint64_t kNanosPerHour = 60ull * kNanosPerMinute;
constexpr std::uint64_t kNanosPerDay = 24ull * kNanosPerHour;

// Renders value / unit_nanos with exactly three fractional digits. The
// division is exact integer arithmetic, so the rendering never depends on the
// floating point rounding mode or on the process locale.
std::string scaled_text(std::uint64_t value, std::uint64_t unit_nanos, std::string_view suffix) {
  const std::uint64_t whole = value / unit_nanos;
  const std::uint64_t fraction = (value % unit_nanos) / (unit_nanos / 1000ull);
  std::string digits = std::to_string(fraction);
  std::string out = std::to_string(whole);
  out += '.';
  out.append(3u - digits.size(), '0');
  out += digits;
  out += suffix;
  return out;
}

// A scalar rendering shared by the reports: the exact value, or the explicit
// statement that the value was never established. An unset counter is never
// shown as zero.
template <class ScalarT>
std::string scalar_text(const ScalarT& value) {
  if (!value.is_set()) {
    return std::string{"<unset>"};
  }
  return std::to_string(value.value());
}

std::string text_or_unset(const std::string& value) {
  return value.empty() ? std::string{"<unset>"} : value;
}

std::string signed_text(std::int64_t value) {
  std::string out;
  if (value > 0) {
    out += '+';
  }
  out += std::to_string(value);
  return out;
}

std::string freshness_text(const FreshnessBound& bound) {
  if (!bound.is_set()) {
    return std::string{"<unset>"};
  }
  if (bound.is_unbounded()) {
    return std::string{"unbounded"};
  }
  return "max_age_nanos=" + std::to_string(bound.max_age_nanos());
}

// Table cells are single-line: a control byte inside a cell would break the
// column layout, so newlines and tabs are folded to spaces before measuring.
void fold_control_bytes(std::string& cell) {
  for (char& byte : cell) {
    if (byte == '\n' || byte == '\r' || byte == '\t') {
      byte = ' ';
    }
  }
}

void append_section(std::string& out, std::string_view title,
                    const std::vector<std::string>& items) {
  if (items.empty()) {
    out += title;
    out += ": none\n";
    return;
  }
  out += title;
  out += ":\n";
  for (const std::string& item : items) {
    out += "- ";
    out += text_or_unset(item);
    out += '\n';
  }
}

}  // namespace

std::string format_duration_nanos(std::uint64_t nanos) {
  if (nanos < kNanosPerMicrosecond) {
    return std::to_string(nanos) + "ns";
  }
  if (nanos < kNanosPerMillisecond) {
    return scaled_text(nanos, kNanosPerMicrosecond, "us");
  }
  if (nanos < kNanosPerSecond) {
    return scaled_text(nanos, kNanosPerMillisecond, "ms");
  }
  if (nanos < kNanosPerMinute) {
    return scaled_text(nanos, kNanosPerSecond, "s");
  }
  if (nanos < kNanosPerHour) {
    return scaled_text(nanos, kNanosPerMinute, "min");
  }
  if (nanos < kNanosPerDay) {
    return scaled_text(nanos, kNanosPerHour, "h");
  }
  return scaled_text(nanos, kNanosPerDay, "d");
}

std::string format_basis_points(std::uint32_t basis_points) {
  const std::uint32_t whole = basis_points / 100u;
  const std::uint32_t fraction = basis_points % 100u;
  std::string out = std::to_string(whole);
  out += '.';
  if (fraction < 10u) {
    out += '0';
  }
  out += std::to_string(fraction);
  out += '%';
  return out;
}

std::string format_optional_version(const std::optional<FirmwareVersion>& version) {
  if (!version.has_value()) {
    return std::string{"<unknown>"};
  }
  return version->to_string();
}

std::string format_timestamp(const Timestamp& timestamp) {
  if (!timestamp.is_set()) {
    return std::string{"<unset>"};
  }
  return timestamp.to_rfc3339();
}

Table::Table(std::vector<std::string> headers, std::vector<std::size_t> right_aligned_columns)
    : headers_(std::move(headers)), right_aligned_(std::move(right_aligned_columns)) {
  for (std::string& header : headers_) {
    fold_control_bytes(header);
  }
}

void Table::add_row(std::vector<std::string> cells) {
  // A row always describes exactly the declared columns: missing cells are
  // empty and surplus cells are not part of the layout.
  cells.resize(headers_.size());
  for (std::string& cell : cells) {
    fold_control_bytes(cell);
  }
  rows_.push_back(std::move(cells));
}

std::string Table::render() const {
  if (headers_.empty()) {
    return std::string{};
  }
  std::vector<std::size_t> widths(headers_.size());
  for (std::size_t column = 0; column < headers_.size(); ++column) {
    widths[column] = headers_[column].size();
  }
  for (const std::vector<std::string>& row : rows_) {
    for (std::size_t column = 0; column < headers_.size(); ++column) {
      widths[column] = std::max(widths[column], row[column].size());
    }
  }

  const auto is_right_aligned = [this](std::size_t column) {
    return std::find(right_aligned_.begin(), right_aligned_.end(), column) !=
           right_aligned_.end();
  };
  const auto render_line = [&widths, &is_right_aligned](const std::vector<std::string>& cells) {
    std::string line;
    for (std::size_t column = 0; column < cells.size(); ++column) {
      if (column != 0) {
        line += "  ";
      }
      const std::size_t padding = widths[column] - cells[column].size();
      if (is_right_aligned(column)) {
        line.append(padding, ' ');
        line += cells[column];
      } else {
        line += cells[column];
        // A left-aligned column is padded on the right so that the following
        // columns line up; the final column is never padded, which is what
        // keeps every line free of trailing whitespace.
        if (column + 1 != cells.size()) {
          line.append(padding, ' ');
        }
      }
    }
    // No line ever carries trailing whitespace, including a line whose final
    // right-aligned cell is empty.
    while (!line.empty() && line.back() == ' ') {
      line.pop_back();
    }
    line += '\n';
    return line;
  };

  std::string out = render_line(headers_);
  std::vector<std::string> separator(headers_.size());
  for (std::size_t column = 0; column < headers_.size(); ++column) {
    separator[column] = std::string(widths[column], '-');
  }
  out += render_line(separator);
  for (const std::vector<std::string>& row : rows_) {
    out += render_line(row);
  }
  return out;
}

std::string format_conformance_report(const ConformanceVerdict& verdict) {
  return verdict.to_string();
}

std::string format_eligibility_report(const EligibilityVerdict& verdict) {
  return verdict.to_string();
}

std::string format_gate_report(const GateReport& report) {
  const std::vector<std::string> headers{"metric", "value"};
  const std::vector<std::size_t> right_aligned{1u};
  Table table(headers, right_aligned);
  table.add_row({"satisfied", report.satisfied ? "true" : "false"});
  table.add_row({"total_assets", std::to_string(report.counts.total_assets)});
  table.add_row({"decided_assets", std::to_string(report.counts.decided_assets)});
  table.add_row({"conformant_assets", std::to_string(report.counts.conformant_assets)});
  table.add_row({"drifted_assets", std::to_string(report.counts.drifted_assets)});
  table.add_row({"unknown_assets", std::to_string(report.counts.unknown_assets)});
  table.add_row({"unsupported_assets", std::to_string(report.counts.unsupported_assets)});
  table.add_row({"blocked_assets", std::to_string(report.counts.blocked_assets)});
  table.add_row({"exception_assets", std::to_string(report.counts.exception_assets)});
  table.add_row({"pending_rollout_assets", std::to_string(report.counts.pending_rollout_assets)});
  table.add_row({"pending_rollback_assets", std::to_string(report.counts.pending_rollback_assets)});
  table.add_row({"conformant_basis_points", format_basis_points(report.counts.conformant_basis_points)});
  // The exact nanosecond count is retained next to the human rendering, so the
  // report never trades precision for readability.
  table.add_row({"soak_remaining_nanos", std::to_string(report.soak_remaining_nanos)});
  table.add_row({"soak_remaining", format_duration_nanos(report.soak_remaining_nanos)});
  table.add_row({"next_stage", scalar_text(report.next_stage)});

  std::string out = table.render();
  append_section(out, "unmet_conditions", report.unmet_conditions);
  return out;
}

std::string format_drift_table(const std::vector<DriftResidual>& residuals) {
  const std::vector<std::string> headers{"kind",      "component", "rule",  "observed",
                                         "required",  "delta",     "observed_at",
                                         "freshness", "detail"};
  const std::vector<std::size_t> right_aligned{5u};
  Table table(headers, right_aligned);
  for (const DriftResidual& residual : residuals) {
    table.add_row({std::string{drift_kind_token(residual.kind)},
                   residual.component.to_string(),
                   residual.rule.to_string(),
                   format_optional_version(residual.observed),
                   format_optional_version(residual.required),
                   residual.has_version_delta ? signed_text(residual.version_delta)
                                              : std::string{"<unset>"},
                   format_timestamp(residual.observed_at),
                   freshness_text(residual.freshness),
                   text_or_unset(residual.detail)});
  }
  return table.render();
}

std::string format_recovery_report(const RecoveryReport& report) {
  const std::vector<std::string> headers{"field", "value"};
  Table table(headers, {});
  table.add_row({"outcome", std::string{recovery_outcome_token(report.outcome)}});
  table.add_row({"fence_present", report.fence_present ? "true" : "false"});
  table.add_row({"fence_valid", report.fence_valid ? "true" : "false"});
  table.add_row({"active_slot", std::to_string(report.active_slot)});
  table.add_row({"unpublished_slot_present", report.unpublished_slot_present ? "true" : "false"});
  if (report.unpublished_slot_present) {
    // The slot number is only meaningful when a slot was actually found; an
    // unset slot is left out rather than reported as slot zero.
    table.add_row({"unpublished_slot", std::to_string(report.unpublished_slot)});
  }
  table.add_row({"commit_sequence", scalar_text(report.commit_sequence)});
  table.add_row({"control_epoch", scalar_text(report.control_epoch)});
  table.add_row({"digest", digest_to_hex(report.digest)});

  std::string out = table.render();
  append_section(out, "notes", report.notes);
  return out;
}

}  // namespace summon::fbm::text
