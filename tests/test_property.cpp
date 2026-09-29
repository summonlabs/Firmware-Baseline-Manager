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

// Property tests. Every property is checked over a deterministic, seeded
// corpus produced by a linear congruential generator. Nothing here reads
// std::random_device, the clock, or the ambient environment, so the same build
// always explores exactly the same inputs. Every failure message names the
// seed, the iteration index, and the exact input that produced it.

#include "check.hpp"
#include "support.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/baseline.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/manager.hpp"
#include "summon/fbm/policy_document.hpp"
#include "summon/fbm/snapshot.hpp"
#include "summon/fbm/store.hpp"

using namespace summon::fbm;
using namespace fbm_test;

namespace json = summon::fbm::json;

namespace {

// --- deterministic generator ------------------------------------------------

// Knuth's MMIX linear congruential generator. Deterministic and seedable; this
// is the only source of variation in this file.
class Generator {
 public:
  explicit Generator(std::uint64_t seed) noexcept : state_(seed) {}

  std::uint64_t next() noexcept {
    state_ = state_ * 6364136223846793005ull + 1442695040888963407ull;
    return state_;
  }

  // The high bits of an LCG are the well-behaved ones, so bounds are drawn from
  // those rather than from the low bits.
  std::uint64_t below(std::uint64_t bound) noexcept { return (next() >> 17u) % bound; }

  std::uint64_t between(std::uint64_t low, std::uint64_t high) noexcept {
    return low + below(high - low + 1u);
  }

 private:
  std::uint64_t state_;
};

std::string hex_of(std::string_view text) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(text.size() * 2u);
  for (const char raw : text) {
    const auto byte = static_cast<unsigned char>(raw);
    out.push_back(kDigits[(byte >> 4u) & 0x0Fu]);
    out.push_back(kDigits[byte & 0x0Fu]);
  }
  return out;
}

std::string seed_text(std::uint64_t seed) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out{"0x"};
  for (int shift = 60; shift >= 0; shift -= 4) {
    out.push_back(kDigits[(seed >> static_cast<unsigned>(shift)) & 0x0Fu]);
  }
  return out;
}

// A failure accumulator for the bulk loops. The first violation is retained
// with a complete reproduction record; later violations are counted so that a
// systematically wrong property cannot hide behind the first case.
class Violations {
 public:
  void note(std::string message) {
    if (count_ == 0u) {
      first_ = std::move(message);
    }
    ++count_;
  }

  bool any() const noexcept { return count_ != 0u; }
  std::size_t count() const noexcept { return count_; }
  const std::string& first() const noexcept { return first_; }

  std::string summary() const {
    std::string out = std::to_string(count_) + " violation(s); first: " + first_;
    return out;
  }

 private:
  std::size_t count_ = 0;
  std::string first_;
};

// --- JSON corpus ------------------------------------------------------------

constexpr std::size_t kPieceCount = 17;
const std::string_view kPieces[kPieceCount] = {
    std::string_view{"alpha"},
    std::string_view{"Bravo9"},
    std::string_view{"x-y_z"},
    std::string_view{"0"},
    std::string_view{""},
    std::string_view{"a b c"},
    std::string_view{"\"quoted\""},
    std::string_view{"back\\slash"},
    std::string_view{"tab\there"},
    std::string_view{"line\nbreak"},
    std::string_view{"nul\0byte", 8},
    std::string_view{"ctrl\x01\x02", 6},
    std::string_view{"caf\xC3\xA9", 5},
    std::string_view{"arrow\xE2\x86\x92", 8},
    std::string_view{"emoji\xF0\x9F\x98\x80", 9},
    std::string_view{"dotted.name"},
    std::string_view{"-leading-dash"},
};

constexpr std::size_t kRealCount = 14;
const double kReals[kRealCount] = {
    0.0, 1.0, -1.5, 2.25, 0.1, 3.141592653589793, 1e-7, 1e7,
    123456.789, 6.02e23, -0.5, 1e-300, 1.7976931348623157e308, 0.0009765625,
};

constexpr std::size_t kKeyCount = 10;
const char* const kKeys[kKeyCount] = {"a",   "b",  "c",     "id",  "name",
                                      "value", "z", "list", "nested", "A"};

std::string generate_string(Generator& gen) {
  std::string out;
  const auto count = static_cast<std::size_t>(gen.below(4u));
  for (std::size_t index = 0; index < count; ++index) {
    const auto pick = static_cast<std::size_t>(gen.below(kPieceCount));
    out.append(kPieces[pick]);
  }
  return out;
}

json::Value generate_scalar(Generator& gen) {
  switch (gen.below(7u)) {
    case 0u:
      return json::Value{};
    case 1u:
      return json::Value{gen.below(2u) == 0u};
    case 2u: {
      const auto magnitude = static_cast<std::int64_t>(gen.below(4000000000000ull));
      const auto sign = gen.below(2u) == 0u ? 1 : -1;
      return json::Value{sign * magnitude};
    }
    case 3u:
      return json::Value{kReals[gen.below(kRealCount)]};
    default:
      return json::Value{generate_string(gen)};
  }
}

json::Value generate_value(Generator& gen, unsigned depth) {
  if (depth == 0u) {
    return generate_scalar(gen);
  }
  switch (gen.below(10u)) {
    case 0u:
    case 1u:
    case 2u: {
      json::Value out = json::Value::make_array();
      const auto count = static_cast<std::size_t>(gen.below(4u));
      for (std::size_t index = 0; index < count; ++index) {
        out.push_back(generate_value(gen, depth - 1u));
      }
      return out;
    }
    case 3u:
    case 4u:
    case 5u:
    case 6u: {
      json::Value out = json::Value::make_object();
      std::vector<std::string> used;
      const auto count = static_cast<std::size_t>(gen.below(5u));
      for (std::size_t index = 0; index < count; ++index) {
        const std::string key{kKeys[gen.below(kKeyCount)]};
        if (std::find(used.begin(), used.end(), key) != used.end()) {
          continue;  // duplicate keys are rejected by the reader, so never emit one
        }
        used.push_back(key);
        out.set(key, generate_value(gen, depth - 1u));
      }
      return out;
    }
    default:
      return generate_scalar(gen);
  }
}

json::Value generate_object(Generator& gen, unsigned depth) {
  json::Value out = json::Value::make_object();
  std::vector<std::string> used;
  const auto count = static_cast<std::size_t>(1u + gen.below(5u));
  for (std::size_t index = 0; index < count; ++index) {
    const std::string key{kKeys[gen.below(kKeyCount)]};
    if (std::find(used.begin(), used.end(), key) != used.end()) {
      continue;
    }
    used.push_back(key);
    out.set(key, generate_value(gen, depth));
  }
  return out;
}

// Re-emits a value with object members shuffled by the generator, so that the
// text differs only in member order from the canonical rendering.
void emit_with_shuffled_members(const json::Value& value, Generator& gen, std::string& out) {
  if (value.is_object()) {
    json::Value::Object members = value.as_object();
    for (std::size_t index = members.size(); index > 1u; --index) {
      const auto other = static_cast<std::size_t>(gen.below(index));
      std::swap(members[index - 1u], members[other]);
    }
    out.push_back('{');
    for (std::size_t index = 0; index < members.size(); ++index) {
      if (index != 0u) {
        out.push_back(',');
      }
      out += json::write_canonical(json::Value{members[index].first});
      out.push_back(':');
      emit_with_shuffled_members(members[index].second, gen, out);
    }
    out.push_back('}');
    return;
  }
  if (value.is_array()) {
    out.push_back('[');
    const json::Value::Array& elements = value.as_array();
    for (std::size_t index = 0; index < elements.size(); ++index) {
      if (index != 0u) {
        out.push_back(',');
      }
      emit_with_shuffled_members(elements[index], gen, out);
    }
    out.push_back(']');
    return;
  }
  out += json::write_canonical(value);
}

// --- version corpus ---------------------------------------------------------

std::vector<FirmwareVersion> generate_versions(Generator& gen, std::size_t count) {
  constexpr std::size_t kPrereleaseCount = 8;
  const std::string_view kPrereleases[kPrereleaseCount] = {
      std::string_view{""},     std::string_view{"alpha"}, std::string_view{"alpha.0"},
      std::string_view{"alpha.1"}, std::string_view{"alpha.beta"}, std::string_view{"beta"},
      std::string_view{"rc.1"}, std::string_view{"0"}};
  constexpr std::size_t kMetadataCount = 3;
  const std::string_view kMetadata[kMetadataCount] = {std::string_view{""},
                                                      std::string_view{"build.1"},
                                                      std::string_view{"x.7"}};
  std::vector<FirmwareVersion> out;
  out.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    // The corpus is biased so that equal-precedence pairs (differing only in
    // metadata) and build-presence pairs both occur.
    const auto major = gen.below(4u);
    const auto minor = gen.below(4u);
    const auto patch = gen.below(4u);
    std::string text = std::to_string(major) + "." + std::to_string(minor) + "." +
                       std::to_string(patch);
    if (gen.below(2u) == 0u) {
      text += "." + std::to_string(gen.below(3u));
    }
    const std::string_view prerelease = kPrereleases[gen.below(kPrereleaseCount)];
    if (!prerelease.empty()) {
      text += "-";
      text.append(prerelease);
    }
    const std::string_view metadata = kMetadata[gen.below(kMetadataCount)];
    if (!metadata.empty()) {
      text += "+";
      text.append(metadata);
    }
    auto parsed = FirmwareVersion::parse(text, "/corpus");
    REQUIRE(parsed.has_value());
    out.push_back(parsed.take());
  }
  return out;
}

int compare_identifier_text(std::string_view left, std::string_view right) {
  if (left == right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

int compare_numeric_identifier(std::string_view left, std::string_view right) {
  if (left.size() != right.size()) {
    return left.size() < right.size() ? -1 : 1;
  }
  return compare_identifier_text(left, right);
}

// Independently written SemVer precedence comparison: it uses only the public
// accessors and its own dot-splitting, so it shares no code with the library.
int compare_prerelease_text(std::string_view left, std::string_view right) {
  if (left.empty() || right.empty()) {
    if (left.empty() && right.empty()) {
      return 0;
    }
    return left.empty() ? 1 : -1;  // a release outranks any prerelease
  }
  std::size_t left_pos = 0;
  std::size_t right_pos = 0;
  while (left_pos <= left.size() && right_pos <= right.size()) {
    const std::size_t left_end = left.find('.', left_pos);
    const std::size_t right_end = right.find('.', right_pos);
    const std::string_view left_field =
        left.substr(left_pos, left_end == std::string_view::npos ? std::string_view::npos
                                                                 : left_end - left_pos);
    const std::string_view right_field =
        right.substr(right_pos, right_end == std::string_view::npos ? std::string_view::npos
                                                                    : right_end - right_pos);
    const bool left_numeric =
        !left_field.empty() && left_field.find_first_not_of("0123456789") == std::string_view::npos;
    const bool right_numeric = !right_field.empty() &&
                               right_field.find_first_not_of("0123456789") == std::string_view::npos;
    int order = 0;
    if (left_numeric && right_numeric) {
      order = compare_numeric_identifier(left_field, right_field);
    } else if (left_numeric != right_numeric) {
      order = left_numeric ? -1 : 1;  // numeric identifiers sort below alphanumeric ones
    } else {
      order = compare_identifier_text(left_field, right_field);
    }
    if (order != 0) {
      return order;
    }
    if (left_end == std::string_view::npos || right_end == std::string_view::npos) {
      if (left_end == right_end) {
        return 0;
      }
      return left_end == std::string_view::npos ? -1 : 1;  // fewer fields sorts lower
    }
    left_pos = left_end + 1u;
    right_pos = right_end + 1u;
  }
  return 0;
}

int independent_precedence(const FirmwareVersion& left, const FirmwareVersion& right) {
  if (left.major() != right.major()) {
    return left.major() < right.major() ? -1 : 1;
  }
  if (left.minor() != right.minor()) {
    return left.minor() < right.minor() ? -1 : 1;
  }
  if (left.patch() != right.patch()) {
    return left.patch() < right.patch() ? -1 : 1;
  }
  if (left.has_build() != right.has_build()) {
    return left.has_build() ? 1 : -1;
  }
  if (left.has_build() && left.build() != right.build()) {
    return left.build() < right.build() ? -1 : 1;
  }
  return compare_prerelease_text(left.prerelease(), right.prerelease());
}

bool independent_contains(const VersionRange& range, const FirmwareVersion& probe) {
  if (range.has_minimum()) {
    const int order = independent_precedence(probe, *range.minimum());
    if (order < 0) {
      return false;
    }
    if (order == 0 && !range.minimum_inclusive()) {
      return false;
    }
  }
  if (range.has_maximum()) {
    const int order = independent_precedence(probe, *range.maximum());
    if (order > 0) {
      return false;
    }
    if (order == 0 && !range.maximum_inclusive()) {
      return false;
    }
  }
  return true;
}

// --- identifier corpus ------------------------------------------------------

// Independently written predicate for the documented identifier rule: 1..128
// ASCII bytes, first byte [A-Za-z0-9], remaining [A-Za-z0-9._-].
bool independent_identifier(std::string_view text) {
  if (text.empty() || text.size() > kMaxIdentifierBytes) {
    return false;
  }
  const auto is_alphanumeric = [](unsigned char byte) {
    return (byte >= static_cast<unsigned char>('0') && byte <= static_cast<unsigned char>('9')) ||
           (byte >= static_cast<unsigned char>('A') && byte <= static_cast<unsigned char>('Z')) ||
           (byte >= static_cast<unsigned char>('a') && byte <= static_cast<unsigned char>('z'));
  };
  if (!is_alphanumeric(static_cast<unsigned char>(text[0]))) {
    return false;
  }
  for (std::size_t index = 1; index < text.size(); ++index) {
    const auto byte = static_cast<unsigned char>(text[index]);
    if (!is_alphanumeric(byte) && byte != static_cast<unsigned char>('.') &&
        byte != static_cast<unsigned char>('_') && byte != static_cast<unsigned char>('-')) {
      return false;
    }
  }
  return true;
}

std::vector<std::string> generate_identifier_candidates(Generator& gen) {
  std::vector<std::string> out;
  const std::string_view pool{"abzAZ09._- :/\\\t"};
  for (std::size_t iteration = 0; iteration < 600; ++iteration) {
    const auto length = static_cast<std::size_t>(gen.below(140u));
    std::string text;
    text.reserve(length);
    for (std::size_t index = 0; index < length; ++index) {
      const auto pick = static_cast<std::size_t>(gen.below(pool.size() + 6u));
      if (pick < pool.size()) {
        text.push_back(pool[pick]);
      } else {
        // Non-ASCII bytes, including bytes that are invalid UTF-8 on their own.
        text.push_back(static_cast<char>(0x80u + gen.below(0x80u)));
      }
    }
    out.push_back(std::move(text));
  }
  // Fixed edge cases that a generator is unlikely to reach. The explicit
  // lengths keep embedded NUL bytes in the corpus instead of truncating them.
  const std::string_view fixed[] = {
      std::string_view{""},
      std::string_view{"a"},
      std::string_view{"A"},
      std::string_view{"0"},
      std::string_view{"_a"},
      std::string_view{"-a"},
      std::string_view{".a"},
      std::string_view{"a b"},
      std::string_view{"a:b"},
      std::string_view{"../x"},
      std::string_view{".."},
      std::string_view{"."},
      std::string_view{"a/b"},
      std::string_view{"a\\b"},
      std::string_view{"C:\\x"},
      std::string_view{"a\x00" "b", 3},
      std::string_view{"\x00" "a", 2},
      std::string_view{"a\x00", 2},
      std::string_view{"caf\xC3\xA9"},
      std::string_view{"\xE2\x86\x92"},
      std::string_view{"..\\..\\evil"},
      std::string_view{"ads:stream"},
      std::string_view{"a."},
      std::string_view{"a-"},
      std::string_view{"a_"},
      std::string_view{"gpu.h100-train_1"},
      std::string_view{"\xFF\xFE"},
      std::string_view{"\xC3\x28"}};
  for (const std::string_view text : fixed) {
    out.emplace_back(text);
  }
  out.emplace_back(std::string(128, 'a'));
  out.emplace_back(std::string(129, 'a'));
  out.emplace_back("a" + std::string(126, 'b') + "c");
  out.emplace_back("a" + std::string(127, 'b') + "c");
  return out;
}

// --- baseline corpus --------------------------------------------------------

Baseline generate_baseline(Generator& gen, std::size_t index) {
  Baseline baseline;
  baseline.id = BaselineId{"baseline-" + std::to_string(index)};
  baseline.generation = BaselineGeneration{gen.between(1u, 1000000u)};
  baseline.revision = Revision{gen.between(1u, 1000000u)};
  const bool draft = gen.below(3u) == 0u;
  baseline.state = draft ? BaselineState::Draft : BaselineState::Published;
  baseline.title = "title \"quoted\" " + std::to_string(gen.below(1000u)) + "\\tail";

  HardwareSelector selector;
  selector.hardware_class = HardwareClassId{"gpu"};
  selector.model = HardwareModelId{"h100"};
  selector.minimum_revision = HardwareRevision{static_cast<std::uint32_t>(gen.below(4u))};
  selector.maximum_revision = HardwareRevision{static_cast<std::uint32_t>(gen.between(4u, 8u))};
  baseline.selectors.push_back(selector);

  // Components are held in ascending identity order, which is what the schema
  // requires: "bios" precedes "bmc". FirmwareVersion is deliberately not
  // default constructible, so every member is stated explicitly.
  const auto major = gen.between(2u, 4u);
  const auto bios_patch = gen.between(1u, 9u);
  const FirmwareVersion bios_approved =
      version((std::to_string(major) + "." + std::to_string(gen.below(4u)) + "." +
               std::to_string(bios_patch))
                  .c_str());
  std::vector<FirmwareVersion> bios_conformant{bios_approved};
  if (bios_patch > 1u) {
    bios_conformant.push_back(
        version((std::to_string(major) + "." + std::to_string(gen.below(4u)) + "." +
                 std::to_string(bios_patch - 1u))
                    .c_str()));
    std::sort(bios_conformant.begin(), bios_conformant.end());
  }
  baseline.components.push_back(ComponentRequirement{
      .component = FirmwareComponentId{"bios"},
      .approved_version = bios_approved,
      .conformant_versions = std::move(bios_conformant),
      .rollback_targets = {version("1.0.0")},
      .freshness = FreshnessBound::within(gen.between(1u, 900000000000000u))});
  baseline.components.push_back(ComponentRequirement{
      .component = FirmwareComponentId{"bmc"},
      .approved_version = version("2.4.1"),
      .conformant_versions = {version("2.4.0"), version("2.4.1")},
      .rollback_targets = {version("2.3.9")},
      .freshness = FreshnessBound::within(24ull * 3600ull * 1000000000ull)});

  baseline.gate.minimum_conformant_basis_points =
      static_cast<std::uint32_t>(gen.between(1u, 10000u));
  baseline.gate.minimum_decided_assets = static_cast<std::uint32_t>(gen.between(1u, 40u));
  baseline.gate.minimum_conformant_assets =
      static_cast<std::uint32_t>(gen.between(1u, baseline.gate.minimum_decided_assets));
  baseline.gate.soak_nanos = gen.between(0u, 1000000000u);
  baseline.gate.required_stages = StageIndex{static_cast<std::uint32_t>(gen.between(1u, 6u))};

  const std::uint64_t base_seconds = 1769904000ull + gen.below(1000000u);
  baseline.created_at = at(base_seconds);
  if (!draft) {
    baseline.published_at = at(base_seconds + 1u);
  }
  return baseline;
}

// --- store helpers ----------------------------------------------------------

StoreOptions store_options(const std::filesystem::path& directory, bool create) {
  StoreOptions options;
  options.directory = directory;
  options.create_if_missing = create;
  options.take_writer_lock = true;
  return options;
}

}  // namespace

// ---------------------------------------------------------------------------
// JSON canonical round trip
// ---------------------------------------------------------------------------

FBM_TEST(property_json_canonical_round_trip) {
  constexpr std::uint64_t kSeed = 0x9E3779B97F4A7C15ull;
  constexpr std::size_t kIterations = 240;
  Generator gen(kSeed);
  Violations violations;

  for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
    const json::Value document = generate_value(gen, 4u);
    const std::string canonical = json::write_canonical(document);
    auto parsed = json::parse(canonical, json::Limits{}, "/document");
    if (!parsed.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " canonical text did not re-parse: " + parsed.error().to_string() +
                      " text=" + canonical);
      continue;
    }
    if (!(parsed.value() == document)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " re-parsed value is not structurally equal; text=" + canonical);
      continue;
    }
    const std::string again = json::write_canonical(parsed.value());
    if (again != canonical) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " canonical form is not idempotent; first=" + canonical +
                      " second=" + again);
      continue;
    }
    // A third pass must be byte-identical as well: canonical form is a fixed
    // point, not merely a two-cycle.
    auto reparsed = json::parse(again, json::Limits{}, "/document");
    if (!reparsed.has_value() || json::write_canonical(reparsed.value()) != again) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " canonical form is not a fixed point; text=" + again);
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());
}

FBM_TEST(property_json_key_order_independence) {
  constexpr std::uint64_t kSeed = 0xD1B54A32D192ED03ull;
  constexpr std::size_t kIterations = 160;
  Generator gen(kSeed);
  Violations violations;

  for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
    const json::Value document = generate_object(gen, 4u);
    const std::string canonical = json::write_canonical(document);

    std::string shuffled;
    emit_with_shuffled_members(document, gen, shuffled);

    auto from_canonical = json::parse(canonical, json::Limits{}, "/canonical");
    auto from_shuffled = json::parse(shuffled, json::Limits{}, "/shuffled");
    if (!from_canonical.has_value() || !from_shuffled.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " one of the two member orders did not parse; canonical=" + canonical +
                      " shuffled=" + shuffled);
      continue;
    }
    if (!(from_canonical.value() == from_shuffled.value())) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " member order changed the parsed value; canonical=" + canonical +
                      " shuffled=" + shuffled);
      continue;
    }
    const std::string canonical_a = json::write_canonical(from_canonical.value());
    const std::string canonical_b = json::write_canonical(from_shuffled.value());
    if (canonical_a != canonical_b) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " member order changed the canonical bytes; left=" + canonical_a +
                      " right=" + canonical_b);
      continue;
    }
    if (canonical_b != canonical) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " canonical bytes are not the sorted-member rendering; canonical=" +
                      canonical + " shuffled canonically=" + canonical_b);
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());
}

// ---------------------------------------------------------------------------
// Firmware version ordering
// ---------------------------------------------------------------------------

FBM_TEST(property_firmware_version_ordering_is_total) {
  constexpr std::uint64_t kSeed = 0x243F6A8885A308D3ull;
  Generator gen(kSeed);
  const std::vector<FirmwareVersion> corpus = generate_versions(gen, 96u);
  REQUIRE(corpus.size() >= 60u);

  Violations violations;
  const auto describe_at = [&corpus](std::size_t index) {
    return "[" + std::to_string(index) + "]=\"" + corpus[index].to_string() + "\"";
  };
  const auto context = [&](const char* property, std::size_t i, std::size_t j) {
    return std::string{"seed="} + seed_text(kSeed) + " property=" + property + " " +
           describe_at(i) + " " + describe_at(j);
  };

  // Reflexivity: every version is equivalent to itself under the precedence
  // order, and the defaulted equality is reflexive as well.
  for (std::size_t index = 0; index < corpus.size(); ++index) {
    if ((corpus[index] <=> corpus[index]) != 0) {
      violations.note(context("reflexivity(<=>)", index, index));
    }
    if (!(corpus[index] == corpus[index])) {
      violations.note(context("reflexivity(==)", index, index));
    }
  }

  // The order matrix is computed through the library's own operator<=>, and
  // each entry is cross-checked against the independently written precedence
  // comparison. Equality of the order is precedence equivalence; operator== is
  // additionally the exact-text comparison, which metadata makes different.
  const std::size_t size = corpus.size();
  std::vector<std::vector<int>> order(size, std::vector<int>(size, 0));
  for (std::size_t i = 0; i < size; ++i) {
    for (std::size_t j = 0; j < size; ++j) {
      const std::strong_ordering result = corpus[i] <=> corpus[j];
      order[i][j] = (result == std::strong_ordering::less)
                        ? -1
                        : ((result == std::strong_ordering::greater) ? 1 : 0);
      const int expected = independent_precedence(corpus[i], corpus[j]);
      if (order[i][j] != expected) {
        violations.note(context("library<=>==independent", i, j) + " library=" +
                        std::to_string(order[i][j]) + " independent=" + std::to_string(expected));
      }
    }
  }

  // Totality and antisymmetry: exactly one of less, equal, greater holds for an
  // ordered pair, and the reverse comparison is its negation. This is checked
  // after the whole matrix is filled, because the reverse entry of a pair is
  // only final once both directions have been evaluated.
  for (std::size_t i = 0; i < size; ++i) {
    for (std::size_t j = 0; j < size; ++j) {
      const int reverse = order[j][i];
      if (order[i][j] != -reverse) {
        violations.note(context("antisymmetry", i, j) + " forward=" +
                        std::to_string(order[i][j]) + " reverse=" + std::to_string(reverse));
      }
    }
  }

  // Transitivity over every triple. The matrix makes this cheap enough to check
  // exhaustively rather than by sampling.
  for (std::size_t i = 0; i < size; ++i) {
    for (std::size_t j = 0; j < size; ++j) {
      for (std::size_t k = 0; k < size; ++k) {
        if (order[i][j] <= 0 && order[j][k] <= 0 && !(order[i][k] <= 0)) {
          violations.note(context("transitivity", i, k) + " through " + describe_at(j));
          if (violations.count() > 8u) {
            break;
          }
        }
      }
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());

  // The documented build extension: an absent fourth component orders before
  // every present fourth component, including ".0".
  auto absent = FirmwareVersion::parse("1.2.3", "/v");
  auto present_zero = FirmwareVersion::parse("1.2.3.0", "/v");
  REQUIRE(absent.has_value());
  REQUIRE(present_zero.has_value());
  CHECK((absent.value() <=> present_zero.value()) == std::strong_ordering::less);
}

// ---------------------------------------------------------------------------
// VersionRange containment
// ---------------------------------------------------------------------------

FBM_TEST(property_version_range_contains_matches_independent_predicate) {
  constexpr std::uint64_t kSeed = 0x13198A2E03707344ull;
  Generator gen(kSeed);
  std::vector<FirmwareVersion> corpus = generate_versions(gen, 20u);
  corpus.push_back(version("0.0.0"));
  corpus.push_back(version("1.2.3"));
  corpus.push_back(version("1.2.3.0"));
  corpus.push_back(version("1.2.3-alpha"));
  REQUIRE(corpus.size() >= 16u);

  Violations violations;
  std::size_t ranges_built = 0;
  std::size_t ranges_rejected = 0;

  const std::size_t bound_count = corpus.size() + 1u;  // the extra entry means "unbounded"
  for (std::size_t min_index = 0; min_index < bound_count; ++min_index) {
    for (std::size_t max_index = 0; max_index < bound_count; ++max_index) {
      for (unsigned inclusivity = 0; inclusivity < 4u; ++inclusivity) {
        const bool minimum_inclusive = (inclusivity & 1u) != 0u;
        const bool maximum_inclusive = (inclusivity & 2u) != 0u;
        std::optional<FirmwareVersion> minimum;
        std::optional<FirmwareVersion> maximum;
        if (min_index < corpus.size()) {
          minimum = corpus[min_index];
        }
        if (max_index < corpus.size()) {
          maximum = corpus[max_index];
        }
        auto made = VersionRange::make(minimum, minimum_inclusive, maximum, maximum_inclusive,
                                       "/range");
        if (!made.has_value()) {
          // Only a genuinely empty range may be rejected, and an empty range
          // must contain nothing at all.
          ++ranges_rejected;
          if (made.error().code() != ErrorCode::SchemaInconsistentDocument) {
            violations.note("seed=" + seed_text(kSeed) + " empty range rejected with " +
                            made.error().to_string());
            continue;
          }
          for (const FirmwareVersion& probe : corpus) {
            // The independent predicate is evaluated against the same bounds
            // directly rather than through a constructed range.
            bool contained = true;
            if (minimum.has_value()) {
              const int order = independent_precedence(probe, *minimum);
              if (order < 0 || (order == 0 && !minimum_inclusive)) {
                contained = false;
              }
            }
            if (maximum.has_value()) {
              const int order = independent_precedence(probe, *maximum);
              if (order > 0 || (order == 0 && !maximum_inclusive)) {
                contained = false;
              }
            }
            if (contained) {
              violations.note("seed=" + seed_text(kSeed) + " a rejected range contains " +
                              probe.to_string());
              break;
            }
          }
          continue;
        }
        ++ranges_built;
        const VersionRange range = made.value();
        if (range.is_empty()) {
          violations.note("seed=" + seed_text(kSeed) + " a constructed range reports empty: " +
                          range.to_string());
        }
        for (const FirmwareVersion& probe : corpus) {
          const bool expected = independent_contains(range, probe);
          const bool actual = range.contains(probe);
          if (expected != actual) {
            violations.note("seed=" + seed_text(kSeed) + " range " + range.to_string() +
                            " probe " + probe.to_string() + " contains=" +
                            (actual ? "true" : "false") + " independent=" +
                            (expected ? "true" : "false") +
                            " min_index=" + std::to_string(min_index) +
                            " max_index=" + std::to_string(max_index) +
                            " min_inclusive=" + (minimum_inclusive ? "true" : "false") +
                            " max_inclusive=" + (maximum_inclusive ? "true" : "false"));
          }
        }
      }
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());
  // Both branches must actually have been exercised: a corpus that never
  // produced a rejected (empty) range would leave half of the property
  // unchecked.
  CHECK_GT(ranges_built, std::size_t{1000});
  CHECK_GT(ranges_rejected, std::size_t{0});
}

// ---------------------------------------------------------------------------
// Streaming digests
// ---------------------------------------------------------------------------

FBM_TEST(property_streaming_digests_match_one_shot) {
  constexpr std::uint64_t kSeed = 0xA4093822299F31D0ull;
  Generator gen(kSeed);
  std::vector<std::size_t> sizes = {0u,  1u,   2u,   3u,   55u,  56u,  57u,   63u,
                                    64u, 65u,  119u, 120u, 121u, 127u, 128u,  129u,
                                    255u, 256u, 257u, 511u, 512u, 1000u, 1024u, 1025u};
  while (sizes.size() < 40u) {
    sizes.push_back(static_cast<std::size_t>(gen.between(0u, 4096u)));
  }

  Violations violations;
  for (std::size_t iteration = 0; iteration < sizes.size(); ++iteration) {
    const std::size_t size = sizes[iteration];
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t index = 0; index < size; ++index) {
      bytes[index] = static_cast<std::uint8_t>(gen.below(256u));
    }
    const Digest digest_one_shot = Sha256::of(bytes.data(), bytes.size());
    const std::uint32_t crc_one_shot = Crc32c::of(bytes.data(), bytes.size());

    // Cut points chosen by the generator, sorted so the chunks tile the buffer.
    std::vector<std::size_t> cuts;
    const auto cut_count = static_cast<std::size_t>(gen.below(6u));
    for (std::size_t cut = 0; cut < cut_count && size > 0u; ++cut) {
      cuts.push_back(static_cast<std::size_t>(gen.below(size)));
    }
    std::sort(cuts.begin(), cuts.end());
    cuts.erase(std::unique(cuts.begin(), cuts.end()), cuts.end());

    Sha256 hasher;
    Crc32c crc;
    std::size_t position = 0;
    for (const std::size_t cut : cuts) {
      hasher.update(bytes.data() + position, cut - position);
      crc.update(bytes.data() + position, cut - position);
      position = cut;
    }
    hasher.update(bytes.data() + position, size - position);
    crc.update(bytes.data() + position, size - position);

    if (digest_to_hex(hasher.finish()) != digest_to_hex(digest_one_shot) ||
        crc.value() != crc_one_shot) {
      std::string cuts_text;
      for (const std::size_t cut : cuts) {
        cuts_text += (cuts_text.empty() ? "" : ",") + std::to_string(cut);
      }
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " size=" + std::to_string(size) + " cut_count=" +
                      std::to_string(cut_count) + " cuts=[" + cuts_text +
                      "] content=" + hex_of(std::string_view{
                                        reinterpret_cast<const char*>(bytes.data()), bytes.size()}));
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());
}

FBM_TEST(property_digest_hex_round_trip) {
  constexpr std::uint64_t kSeed = 0x082EFA98EC4E6C89ull;
  constexpr std::size_t kIterations = 96;
  Generator gen(kSeed);
  Violations violations;

  for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
    Digest digest{};
    for (std::size_t index = 0; index < digest.size(); ++index) {
      digest[index] = static_cast<std::uint8_t>(gen.below(256u));
    }
    const std::string text = digest_to_hex(digest);
    if (text.size() != 64u) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " rendered digest is " + std::to_string(text.size()) + " characters");
      continue;
    }
    auto parsed = digest_from_hex(text, "/digest");
    if (!parsed.has_value() || !(parsed.value() == digest)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " round trip changed the digest; text=" + text);
      continue;
    }
    std::string upper = text;
    for (char& character : upper) {
      if (character >= 'a' && character <= 'f') {
        character = static_cast<char>(character - 'a' + 'A');
      }
    }
    auto parsed_upper = digest_from_hex(upper, "/digest");
    if (!parsed_upper.has_value() || !(parsed_upper.value() == digest)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " upper-case round trip changed the digest; text=" + upper);
      continue;
    }
    // The strict reader must reject every neighbouring length.
    if (digest_from_hex(text.substr(0, 63), "/digest").has_value() ||
        digest_from_hex(text + "0", "/digest").has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " a 63- or 65-character digest was accepted; text=" + text);
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());
}

// ---------------------------------------------------------------------------
// Baseline content digest stability
// ---------------------------------------------------------------------------

FBM_TEST(property_baseline_content_digest_is_stable) {
  constexpr std::uint64_t kSeed = 0x452821E638D01377ull;
  constexpr std::size_t kIterations = 40;
  Generator gen(kSeed);
  Violations violations;

  for (std::size_t iteration = 0; iteration < kIterations; ++iteration) {
    const Baseline baseline = generate_baseline(gen, iteration);
    Diagnostics diagnostics;
    Status valid = baseline.validate("/baseline", diagnostics);
    if (!valid.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " generated baseline is not valid: " + diagnostics.primary().to_string());
      continue;
    }

    const Digest digest = baseline.content_digest();
    const std::string canonical = json::write_canonical(baseline.to_json());
    auto parsed = json::parse(canonical, json::Limits{}, "/baseline");
    if (!parsed.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " serialized baseline did not parse: " + parsed.error().to_string());
      continue;
    }
    auto decoded = Baseline::from_json(parsed.value(), "/baseline");
    if (!decoded.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " serialized baseline did not decode: " + decoded.error().to_string() +
                      " text=" + canonical);
      continue;
    }
    const std::string reserialized = json::write_canonical(decoded.value().to_json());
    if (reserialized != canonical) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " re-serialization changed the bytes; first=" + canonical +
                      " second=" + reserialized);
    }
    if (!(decoded.value().content_digest() == digest)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " the digest changed across a round trip; expected=" +
                      digest_to_hex(digest) + " actual=" +
                      digest_to_hex(decoded.value().content_digest()));
    }
    // A second cycle must also be stable.
    auto parsed_again = json::parse(reserialized, json::Limits{}, "/baseline");
    if (!parsed_again.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " second parse failed");
      continue;
    }
    auto decoded_again = Baseline::from_json(parsed_again.value(), "/baseline");
    if (!decoded_again.has_value() ||
        !(decoded_again.value().content_digest() == digest)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " the digest changed on the second cycle");
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());

  // Content addressing is meaningful only if a semantic change moves the
  // digest. A title change must be visible.
  Baseline altered = generate_baseline(gen, 7u);
  const Digest before = altered.content_digest();
  altered.title += "!";
  CHECK(!(altered.content_digest() == before));
}

// ---------------------------------------------------------------------------
// Store round trip
// ---------------------------------------------------------------------------

FBM_TEST(property_store_round_trip_recovers_only_the_last_commit) {
  constexpr std::uint64_t kSeed = 0xBE5466CF34E90C6Cull;
  constexpr std::size_t kCommits = 12;
  Generator gen(kSeed);
  const std::filesystem::path directory = scratch_directory("property-store-round-trip");
  const StoreOptions options = store_options(directory, true);

  auto store = DurableStore::open(options);
  REQUIRE(store.has_value());

  std::vector<Revision> seen;
  Violations violations;

  for (std::size_t iteration = 0; iteration < kCommits; ++iteration) {
    Snapshot next = store.value()->snapshot();
    next.revision = Revision{gen.between(1u, 1000000000u)};
    next.policy_generation = PolicyGeneration{gen.between(1u, 1000u)};
    Snapshot expected = next;

    auto outcome = store.value()->commit(std::move(next));
    if (!outcome.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " commit failed: " + outcome.error().to_string());
      break;
    }
    expected.commit_sequence = outcome.value().commit_sequence;
    expected.control_epoch = outcome.value().control_epoch;

    store.value().reset();
    auto reopened = DurableStore::open(options);
    if (!reopened.has_value()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " reopen failed: " + reopened.error().to_string());
      break;
    }
    const Snapshot& recovered = reopened.value()->snapshot();
    if (!(recovered.revision == expected.revision)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " recovered revision " + std::to_string(recovered.revision.value_or(0u)) +
                      " is not the last committed " +
                      std::to_string(expected.revision.value_or(0u)));
    }
    if (!(recovered.commit_sequence == expected.commit_sequence)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " recovered commit sequence " +
                      std::to_string(recovered.commit_sequence.value_or(0u)) +
                      " is not the last committed " +
                      std::to_string(expected.commit_sequence.value_or(0u)));
    }
    if (recovered.canonical_bytes() != expected.canonical_bytes()) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " recovered snapshot bytes differ from the committed generation");
    }
    if (!(reopened.value()->published_digest() == outcome.value().digest)) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " recovered digest is not the committed digest");
    }
    // An unfenced slot ahead of the fence would be a second, newer generation.
    if (reopened.value()->recovery().outcome != RecoveryOutcome::Recovered) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " recovery outcome is not Recovered: " +
                      std::string{recovery_outcome_token(reopened.value()->recovery().outcome)});
    }
    for (const Revision& earlier : seen) {
      if (earlier == recovered.revision) {
        violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                        " recovered an intermediate generation: revision " +
                        std::to_string(recovered.revision.value_or(0u)));
      }
    }
    seen.push_back(expected.revision);
    store = std::move(reopened);
  }

  CHECK_MSG(!violations.any(), violations.summary());
  CHECK_EQ(seen.size(), kCommits);
}

// ---------------------------------------------------------------------------
// Identifier validation
// ---------------------------------------------------------------------------

FBM_TEST(property_identifier_validation_matches_independent_predicate) {
  constexpr std::uint64_t kSeed = 0xC0AC29B7C97C50DDull;
  Generator gen(kSeed);
  const std::vector<std::string> candidates = generate_identifier_candidates(gen);
  REQUIRE(candidates.size() > 600u);

  Violations violations;
  for (std::size_t iteration = 0; iteration < candidates.size(); ++iteration) {
    const std::string& candidate = candidates[iteration];
    const bool expected = independent_identifier(candidate);
    const bool actual = is_valid_identifier(candidate);
    const Status status = validate_identifier(candidate, "/identity");
    const bool validated = status.has_value();
    if (expected != actual || expected != validated) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " input=\"" + candidate + "\" hex=" + hex_of(candidate) +
                      " bytes=" + std::to_string(candidate.size()) +
                      " independent=" + (expected ? "true" : "false") +
                      " is_valid_identifier=" + (actual ? "true" : "false") +
                      " validate_identifier ok=" + (validated ? "true" : "false"));
      continue;
    }
    // A rejected identifier must be reported with the documented code and the
    // caller's path, never as a silent default.
    if (!validated &&
        (status.error().code() != ErrorCode::SchemaInvalidIdentifier ||
         status.error().path() != std::string{"/identity"})) {
      violations.note("seed=" + seed_text(kSeed) + " iteration=" + std::to_string(iteration) +
                      " rejection used " + status.error().to_string());
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());

  // The two documented boundaries are exact: 128 bytes is accepted, 129 is not.
  CHECK(is_valid_identifier(std::string(128, 'a')));
  CHECK(!is_valid_identifier(std::string(129, 'a')));
  // A colon is never a valid identifier byte (Windows alternate data streams).
  CHECK(!is_valid_identifier("ads:stream"));
  CHECK(!is_valid_identifier("a:b"));
  // Traversal forms are rejected.
  CHECK(!is_valid_identifier(".."));
  CHECK(!is_valid_identifier("."));
  CHECK(!is_valid_identifier("../x"));
  CHECK(!is_valid_identifier("..\\x"));
  CHECK(!is_valid_identifier("a/b"));
  CHECK(!is_valid_identifier("a\\b"));
  // An embedded NUL is one byte that the rule excludes.
  CHECK(!is_valid_identifier(std::string_view{"a\0b", 3}));
}

// ---------------------------------------------------------------------------
// Policy document identity
// ---------------------------------------------------------------------------

FBM_TEST(property_policy_document_canonical_identity_is_order_independent) {
  constexpr std::uint64_t kSeed = 0x3F84D5B5B5470917ull;
  Generator gen(kSeed);
  std::vector<Baseline> baselines;
  for (std::size_t index = 0; index < 4u; ++index) {
    Baseline baseline = generate_baseline(gen, index);
    Diagnostics diagnostics;
    Status valid = baseline.validate("/baseline", diagnostics);
    REQUIRE(valid.has_value());
    baselines.push_back(std::move(baseline));
  }
  std::sort(baselines.begin(), baselines.end(),
            [](const Baseline& left, const Baseline& right) { return left.id < right.id; });

  const PolicyDocument document{baselines};
  const std::string canonical = document.canonical_bytes();
  const Digest digest = document.content_digest();

  auto parsed = PolicyDocument::parse(canonical, "/policy");
  REQUIRE(parsed.has_value());
  CHECK_EQ(parsed.value().canonical_bytes(), canonical);
  CHECK(parsed.value().content_digest() == digest);

  // The same document with object members emitted in a different order has the
  // same identity: only the canonical bytes are hashed.
  std::string shuffled;
  emit_with_shuffled_members(document.to_json(), gen, shuffled);
  auto parsed_shuffled = PolicyDocument::parse(shuffled, "/policy");
  REQUIRE(parsed_shuffled.has_value());
  CHECK_EQ(parsed_shuffled.value().canonical_bytes(), canonical);
  CHECK(parsed_shuffled.value().content_digest() == digest);

  // Whitespace and member order are not identity: the pretty rendering parses
  // back to the same canonical bytes.
  CHECK_EQ(json::write_canonical(document.to_json()), canonical);
  auto pretty = json::parse(json::write_pretty(document.to_json()), json::Limits{}, "/policy");
  REQUIRE(pretty.has_value());
  CHECK_EQ(json::write_canonical(pretty.value()), canonical);
}

// ---------------------------------------------------------------------------
// Manager store reload
// ---------------------------------------------------------------------------

FBM_TEST(property_manager_reload_recovers_last_committed_generation) {
  const std::filesystem::path directory = scratch_directory("property-manager-reload");

  Fixture fixture = publish_fixture(directory);
  Violations violations;

  for (std::size_t iteration = 0; iteration < 6u; ++iteration) {
    const std::uint64_t second = 1769904000ull + 100u + iteration;
    const AssetId asset{"node-" + std::to_string(iteration)};
    auto recorded = observe_profile(*fixture.manager, asset, profile_of(), ObservationSequence{1},
                                    at(second), "ev-profile");
    if (!recorded.has_value()) {
      violations.note("iteration=" + std::to_string(iteration) +
                      " observation failed: " + recorded.error().to_string());
      break;
    }
    const CommitSequence committed = fixture.manager->commit_sequence();
    const Revision revision = fixture.manager->snapshot().revision;
    const Digest digest = fixture.manager->published_digest();

    Status reloaded = fixture.manager->reload();
    if (!reloaded.has_value()) {
      violations.note("iteration=" + std::to_string(iteration) +
                      " reload failed: " + reloaded.error().to_string());
      break;
    }
    if (!(fixture.manager->commit_sequence() == committed)) {
      violations.note("iteration=" + std::to_string(iteration) +
                      " reload changed the commit sequence");
    }
    if (!(fixture.manager->snapshot().revision == revision)) {
      violations.note("iteration=" + std::to_string(iteration) + " reload changed the revision");
    }
    if (!(fixture.manager->published_digest() == digest)) {
      violations.note("iteration=" + std::to_string(iteration) + " reload changed the digest");
    }
    // The asset written before the reload must still be present afterwards, and
    // its sequence must be exactly the one written.
    const HardwareObservation* observed = fixture.manager->snapshot().observations.profile(asset);
    if (observed == nullptr || !(observed->sequence == ObservationSequence{1})) {
      violations.note("iteration=" + std::to_string(iteration) +
                      " the reloaded snapshot does not hold the committed evidence for " +
                      asset.to_string());
    }
  }

  CHECK_MSG(!violations.any(), violations.summary());
}
