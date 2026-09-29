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

#include "summon/fbm/cli.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "summon/fbm/authority.hpp"
#include "summon/fbm/baseline.hpp"
#include "summon/fbm/cohort.hpp"
#include "summon/fbm/conformance.hpp"
#include "summon/fbm/crypto.hpp"
#include "summon/fbm/error.hpp"
#include "summon/fbm/exception.hpp"
#include "summon/fbm/firmware_version.hpp"
#include "summon/fbm/identifier.hpp"
#include "summon/fbm/json.hpp"
#include "summon/fbm/manager.hpp"
#include "summon/fbm/platform.hpp"
#include "summon/fbm/policy_document.hpp"
#include "summon/fbm/store.hpp"
#include "summon/fbm/text_format.hpp"
#include "summon/fbm/timestamp.hpp"
#include "summon/fbm/version.hpp"

namespace summon::fbm {
namespace {

// The default store directory. Every command except init opens the store with
// create_if_missing false, so a mistyped path fails loudly instead of silently
// creating a new empty store.
constexpr const char* kDefaultStoreDirectory = ".fbm-store";

// A signing key larger than this is a mistake, not a key. The bound keeps a
// runaway file from being read into memory.
constexpr std::uint64_t kMaxSigningKeyBytes = 64ull * 1024ull;

// ---------------------------------------------------------------------------
// Argument readers return one of these: either a value or the text of the usage
// error that explains why the value could not be read. A missing or unreadable
// option is never represented as a value.
// ---------------------------------------------------------------------------

template <class T>
struct Outcome {
  std::optional<T> value;
  std::string message;
};

template <class T>
Outcome<T> outcome_ok(T value) {
  return Outcome<T>{std::optional<T>{std::move(value)}, std::string{}};
}

template <class T>
Outcome<T> outcome_fail(std::string message) {
  return Outcome<T>{std::nullopt, std::move(message)};
}

// ---------------------------------------------------------------------------
// Output helpers. run_cli never writes to std::cout or std::cerr: every byte
// goes to the streams the caller supplied.
// ---------------------------------------------------------------------------

struct RunState {
  std::ostream* out = nullptr;
  std::ostream* err = nullptr;
  bool json = false;
  std::filesystem::path store{kDefaultStoreDirectory};
  std::optional<std::filesystem::path> key_file;
  std::optional<std::string> signing_key;
  bool require_signature = false;
  std::optional<Timestamp> at;
  Timestamp now;
  bool now_resolved = false;
};

// The instant every operation is evaluated at. A missing --at reads the system
// clock exactly once for the whole run.
const Timestamp& instant(RunState& state) {
  if (!state.now_resolved) {
    state.now = state.at.has_value() ? state.at.value() : Timestamp::system_now();
    state.now_resolved = true;
  }
  return state.now;
}

void print_text(RunState& state, const std::string& text) {
  std::ostream& out = *state.out;
  out << text;
  if (text.empty() || text.back() != '\n') {
    out << '\n';
  }
}

void print_json(RunState& state, const json::Value& value) {
  *state.out << json::write_canonical(value) << '\n';
}

int report_error(RunState& state, const Error& error, int exit_code) {
  if (state.json) {
    json::Value::Object fields;
    fields.emplace_back("message", json::Value{error.message()});
    fields.emplace_back("path", json::Value{error.path()});
    fields.emplace_back("token", json::Value{std::string{error_code_token(error.code())}});
    *state.err << json::write_canonical(json::Value{std::move(fields)}) << '\n';
  } else {
    *state.err << "error: " << error.to_string() << '\n';
  }
  return exit_code;
}

int report_usage(RunState& state, std::string message) {
  return report_error(state, Error{ErrorCode::InvalidArgument, std::move(message), std::string{}}, 2);
}

int report_rejection(RunState& state, const Error& error) {
  return report_error(state, error, 1);
}

// ---------------------------------------------------------------------------
// Scalars, versions, and expiries rendered for output. An unset counter is
// printed and serialized as unset, never as zero.
// ---------------------------------------------------------------------------

template <class ScalarT>
std::string counter_text(const ScalarT& value) {
  if (!value.is_set()) {
    return std::string{"<unset>"};
  }
  return std::to_string(value.value());
}

template <class ScalarT>
json::Value json_counter(const ScalarT& value) {
  if (!value.is_set()) {
    return json::Value{};
  }
  return json::Value{static_cast<std::int64_t>(value.value())};
}

json::Value json_optional_version(const std::optional<FirmwareVersion>& version) {
  if (!version.has_value()) {
    return json::Value{};
  }
  return json::Value{version->to_string()};
}

std::string expiry_text(const Expiry& expiry) {
  if (!expiry.is_set()) {
    return std::string{"<unset>"};
  }
  return expiry.to_string();
}

// ---------------------------------------------------------------------------
// Option model.
//
// Global options are removed before a command is parsed, so every option that
// remains belongs to exactly one command. An option that is not declared for the
// command is a usage error: a typo is never silently ignored.
// ---------------------------------------------------------------------------

struct OptionSpec {
  std::string_view name;
  bool takes_value = false;
};

struct CommandArgs {
  std::vector<std::pair<std::string, std::string>> options;
  std::vector<std::string> positional;

  bool has(std::string_view name) const {
    for (const auto& entry : options) {
      if (entry.first == name) {
        return true;
      }
    }
    return false;
  }

  // The last occurrence wins, which keeps a repeated option deterministic.
  const std::string* find(std::string_view name) const {
    const std::string* found = nullptr;
    for (const auto& entry : options) {
      if (entry.first == name) {
        found = &entry.second;
      }
    }
    return found;
  }

  std::vector<std::string> gather(std::string_view name) const {
    std::vector<std::string> found;
    for (const auto& entry : options) {
      if (entry.first == name) {
        found.push_back(entry.second);
      }
    }
    return found;
  }
};

bool looks_like_an_option(const std::string& token) {
  return token.size() > 2u && token[0] == '-' && token[1] == '-';
}

Outcome<CommandArgs> parse_command_args(const std::vector<std::string>& tokens,
                                        const std::vector<OptionSpec>& specs,
                                        std::string_view label) {
  CommandArgs args;
  for (std::size_t index = 0; index < tokens.size(); ++index) {
    const std::string& token = tokens[index];
    if (!looks_like_an_option(token)) {
      args.positional.push_back(token);
      continue;
    }
    const OptionSpec* spec = nullptr;
    for (const OptionSpec& candidate : specs) {
      if (candidate.name == token) {
        spec = &candidate;
        break;
      }
    }
    if (spec == nullptr) {
      return outcome_fail<CommandArgs>(std::string{label} + ": unknown option " + token);
    }
    if (!spec->takes_value) {
      args.options.emplace_back(token, std::string{});
      continue;
    }
    if (index + 1u >= tokens.size() || looks_like_an_option(tokens[index + 1u])) {
      return outcome_fail<CommandArgs>(std::string{label} + ": option " + token +
                                       " requires a value");
    }
    args.options.emplace_back(token, tokens[index + 1u]);
    ++index;
  }
  return outcome_ok(std::move(args));
}

// ---------------------------------------------------------------------------
// Value readers.
// ---------------------------------------------------------------------------

Outcome<std::string> require_value(const CommandArgs& args, std::string_view option) {
  const std::string* found = args.find(option);
  if (found == nullptr) {
    return outcome_fail<std::string>("missing required option " + std::string{option});
  }
  return outcome_ok(*found);
}

Outcome<std::uint64_t> parse_count(const std::string& text, std::string_view option) {
  const std::string prefix = "option " + std::string{option} + " ";
  if (text.empty()) {
    return outcome_fail<std::uint64_t>(prefix + "requires a non-negative integer");
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') {
      return outcome_fail<std::uint64_t>(prefix + "requires a non-negative integer, not \"" + text +
                                         "\"");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
      return outcome_fail<std::uint64_t>(prefix + "is out of range");
    }
    value = value * 10u + digit;
  }
  return outcome_ok(value);
}

Outcome<std::uint64_t> require_count(const CommandArgs& args, std::string_view option) {
  auto text = require_value(args, option);
  if (!text.value.has_value()) {
    return outcome_fail<std::uint64_t>(text.message);
  }
  return parse_count(text.value.value(), option);
}

// A count that may be absent. Absence is a distinct state and is never recorded
// as zero.
struct CountOption {
  bool present = false;
  std::uint64_t value = 0;
};

Outcome<CountOption> read_count_option(const CommandArgs& args, std::string_view option) {
  const std::string* text = args.find(option);
  if (text == nullptr) {
    return outcome_ok(CountOption{});
  }
  auto parsed = parse_count(*text, option);
  if (!parsed.value.has_value()) {
    return outcome_fail<CountOption>(parsed.message);
  }
  return outcome_ok(CountOption{true, parsed.value.value()});
}

template <class Id>
Outcome<Id> make_identifier(const std::string& text, std::string_view option) {
  auto made = make_id<Id>(text, option);
  if (!made.has_value()) {
    return outcome_fail<Id>("option " + std::string{option} + ": " + made.error().message());
  }
  return outcome_ok(made.value());
}

template <class Id>
Outcome<Id> require_identifier(const CommandArgs& args, std::string_view option) {
  const std::string* text = args.find(option);
  if (text == nullptr) {
    return outcome_fail<Id>("missing required option " + std::string{option});
  }
  return make_identifier<Id>(*text, option);
}

Outcome<Timestamp> parse_timestamp(const std::string& text, std::string_view option) {
  auto parsed = Timestamp::parse_rfc3339(text, option);
  if (!parsed.has_value()) {
    return outcome_fail<Timestamp>("option " + std::string{option} + ": " +
                                   parsed.error().message());
  }
  return outcome_ok(parsed.value());
}

Outcome<FirmwareVersion> parse_version(const std::string& text, std::string_view option) {
  auto parsed = FirmwareVersion::parse(text, option);
  if (!parsed.has_value()) {
    return outcome_fail<FirmwareVersion>("option " + std::string{option} + ": " +
                                         parsed.error().message());
  }
  return outcome_ok(parsed.value());
}

// ---------------------------------------------------------------------------
// The manager and the mutation context.
// ---------------------------------------------------------------------------

Result<std::unique_ptr<BaselineManager>> open_store(RunState& state, bool create_if_missing) {
  ManagerOptions options;
  options.directory = state.store;
  options.create_if_missing = create_if_missing;
  options.signing_key = state.signing_key;
  options.require_signature = state.require_signature;
  options.opened_at = instant(state);
  return BaselineManager::open(options);
}

MutationContext make_context(const Timestamp& now, const std::optional<RequestId>& request,
                             const std::optional<ApprovalId>& approval) {
  MutationContext context;
  context.now = now;
  if (request.has_value()) {
    context.request = request.value();
  }
  if (approval.has_value()) {
    context.approval = approval.value();
  }
  context.actor = "cli";
  return context;
}

// ---------------------------------------------------------------------------
// Facility gates. Every gate defaults to unknown; an absent option is never
// read as open.
// ---------------------------------------------------------------------------

template <class ScalarT>
Outcome<ScalarT> read_gate_generation(const CommandArgs& args, std::string_view option) {
  const std::string* text = args.find(option);
  if (text == nullptr) {
    return outcome_ok(ScalarT{});
  }
  auto parsed = parse_count(*text, option);
  if (!parsed.value.has_value()) {
    return outcome_fail<ScalarT>(parsed.message);
  }
  return outcome_ok(ScalarT{parsed.value.value()});
}

Outcome<FacilityGates> read_gates(const CommandArgs& args) {
  FacilityGates gates;
  const std::pair<std::string_view, GateState*> states[] = {
      {"--capacity", &gates.capacity},
      {"--dependency", &gates.dependency},
      {"--maintenance", &gates.maintenance},
      {"--topology", &gates.topology},
  };
  for (const auto& entry : states) {
    const std::string* text = args.find(entry.first);
    if (text == nullptr) {
      continue;
    }
    auto parsed = gate_state_from_token(*text);
    if (!parsed.has_value()) {
      return outcome_fail<FacilityGates>("option " + std::string{entry.first} +
                                         " must be one of open, closed, unknown");
    }
    *entry.second = parsed.value();
  }

  auto capacity = read_gate_generation<CapacityGeneration>(args, "--capacity-generation");
  auto dependency = read_gate_generation<DependencyGeneration>(args, "--dependency-generation");
  auto maintenance = read_gate_generation<MaintenanceGeneration>(args, "--maintenance-generation");
  auto topology = read_gate_generation<TopologyGeneration>(args, "--topology-generation");
  if (!capacity.value.has_value()) {
    return outcome_fail<FacilityGates>(capacity.message);
  }
  if (!dependency.value.has_value()) {
    return outcome_fail<FacilityGates>(dependency.message);
  }
  if (!maintenance.value.has_value()) {
    return outcome_fail<FacilityGates>(maintenance.message);
  }
  if (!topology.value.has_value()) {
    return outcome_fail<FacilityGates>(topology.message);
  }
  gates.capacity_generation = capacity.value.value();
  gates.dependency_generation = dependency.value.value();
  gates.maintenance_generation = maintenance.value.value();
  gates.topology_generation = topology.value.value();
  if (const std::string* reason = args.find("--closed-reason"); reason != nullptr) {
    gates.closed_reason = *reason;
  }
  return outcome_ok(gates);
}

// ---------------------------------------------------------------------------
// Deterministic table renderings.
// ---------------------------------------------------------------------------

std::string field_table(const std::vector<std::pair<std::string, std::string>>& rows) {
  text::Table table({"field", "value"});
  for (const auto& row : rows) {
    table.add_row({row.first, row.second});
  }
  return table.render();
}

std::string baseline_table(const std::vector<const Baseline*>& baselines) {
  text::Table table({"id", "generation", "revision", "state", "title"});
  for (const Baseline* baseline : baselines) {
    table.add_row({baseline->id.to_string(), counter_text(baseline->generation),
                   counter_text(baseline->revision),
                   std::string{baseline_state_token(baseline->state)}, baseline->title});
  }
  return table.render();
}

std::string baseline_summary_table(const Baseline& baseline) {
  return field_table({{"id", baseline.id.to_string()},
                      {"generation", counter_text(baseline.generation)},
                      {"revision", counter_text(baseline.revision)},
                      {"state", std::string{baseline_state_token(baseline.state)}},
                      {"title", baseline.title},
                      {"created_at", text::format_timestamp(baseline.created_at)},
                      {"published_at", text::format_timestamp(baseline.published_at)},
                      {"content_digest", digest_to_hex(baseline.content_digest())}});
}

std::string exception_table(const std::vector<const BaselineException*>& exceptions) {
  text::Table table({"id", "state", "revision", "granted_under", "expires", "approval", "reason"});
  for (const BaselineException* exception : exceptions) {
    table.add_row({exception->id.to_string(),
                   std::string{exception_state_token(exception->state)},
                   counter_text(exception->revision), counter_text(exception->granted_under),
                   expiry_text(exception->expiry), exception->approval.to_string(),
                   exception->reason});
  }
  return table.render();
}

std::string cohort_table(const std::vector<const Cohort*>& cohorts) {
  text::Table table(
      {"id", "state", "baseline", "generation", "revision", "stage", "stages", "members", "plan"});
  for (const Cohort* cohort : cohorts) {
    table.add_row({cohort->id.to_string(), std::string{cohort_state_token(cohort->state)},
                   cohort->baseline.to_string(), counter_text(cohort->baseline_generation),
                   counter_text(cohort->revision), counter_text(cohort->stage),
                   counter_text(cohort->required_stages),
                   std::to_string(cohort->members.size()), cohort->plan.to_string()});
  }
  return table.render();
}

json::Value baseline_summary_json(const Baseline& baseline) {
  json::Value::Object fields;
  fields.emplace_back("id", json::Value{baseline.id.value()});
  fields.emplace_back("generation", json_counter(baseline.generation));
  fields.emplace_back("revision", json_counter(baseline.revision));
  fields.emplace_back("state", json::Value{std::string{baseline_state_token(baseline.state)}});
  fields.emplace_back("title", json::Value{baseline.title});
  return json::Value{std::move(fields)};
}

// The identity of one baseline as far as a listing command reports it. A
// baseline the manager no longer holds is reported as unset rather than
// invented.
json::Value applied_baseline_json(const BaselineId& id, const Baseline* baseline) {
  if (baseline == nullptr) {
    json::Value::Object fields;
    fields.emplace_back("id", json::Value{id.value()});
    fields.emplace_back("generation", json::Value{});
    fields.emplace_back("revision", json::Value{});
    fields.emplace_back("state", json::Value{});
    return json::Value{std::move(fields)};
  }
  return baseline_summary_json(*baseline);
}

const Baseline* lookup_baseline(const std::vector<Baseline>& baselines, const BaselineId& id) {
  for (const Baseline& baseline : baselines) {
    if (baseline.id == id) {
      return &baseline;
    }
  }
  return nullptr;
}

const Cohort* lookup_cohort(const std::vector<Cohort>& cohorts, const CohortId& id) {
  for (const Cohort& cohort : cohorts) {
    if (cohort.id == id) {
      return &cohort;
    }
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Command handlers.
// ---------------------------------------------------------------------------

int handle_version(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "version takes no arguments");
  }
  if (state.json) {
    json::Value::Object fields;
    fields.emplace_back("product", json::Value{std::string{kProductName}});
    fields.emplace_back("version", json::Value{version_string()});
    fields.emplace_back("durable_format_version",
                        json::Value{static_cast<std::int64_t>(kDurableFormatVersion)});
    fields.emplace_back("build", json::Value{build_info()});
    print_json(state, json::Value{std::move(fields)});
    return 0;
  }
  text::Table table({"field", "value"});
  table.add_row({"product", kProductName});
  table.add_row({"version", version_string()});
  table.add_row({"durable_format_version", std::to_string(kDurableFormatVersion)});
  table.add_row({"build", build_info()});
  print_text(state, table.render());
  return 0;
}

struct HelpEntry {
  std::string_view topic;
  std::string_view text;
};

const HelpEntry kHelpEntries[] = {
    {"",
     R"(usage: fbm [global options] <group> <command> [options]

Global options, accepted anywhere before or after the command:
  --store <dir>        store directory (default .fbm-store)
  --json               emit canonical machine-readable JSON instead of text
  --at <rfc3339>       instant the operation is evaluated at; unset reads the
                       system clock exactly once
  --key-file <path>    operator-supplied HMAC-SHA256 key file for authorizations
  --require-signature  reject every authorization that is not hmac_sha256

Commands:
  version
  help [command]
  init                     create the store if it does not exist
  status                   recovery report, generation counters, incarnation
  verify                   read-only inspection without taking the writer lock
  policy export --out <file>
  policy apply --file <file> [--signature <file>]
  baseline define --file <file>
  baseline list
  baseline publish <id> --generation <n>
  baseline retire <id> --generation <n>
  observe --asset <id> --evidence <id> --sequence <n> [--generation <n>]
          ( --component <c> [--version <v>]
          | --hardware-class <c> --model <m> [--revision <n>] [--capability <c>]... )
  evaluate --asset <id>
  rollout-eligibility --asset <id> [gate options]
  rollback-eligibility --asset <id> --target <version> [gate options]
  drift --asset <id>
  explain --asset <id>
  exception list
  exception add --id <i> --hardware-class <c> [--model <m>] [--asset <a>]
                [--component <c>]... --reason <r> --approval <ap>
                ( --expires-at <rfc3339> | --expires never )
  exception revoke --id <i> --revision <n>
  cohort list
  cohort create --id <i> --baseline <b> --generation <n> --asset <a> [--asset <a>]...
  cohort authorize --id <i> --revision <n>
  cohort promote --id <i> --revision <n> [gate options]
  cohort pause <id> --revision <n>
  cohort resume <id> --revision <n>
  cohort cancel <id> --revision <n>
  authorize rollout --id <i> --revision <n> --request <r>
  authorize rollback --id <i> --revision <n> --request <r>
  token verify --scope <s> --plan <p> --token <file>

Gate options, each of which defaults to unknown and is never assumed open:
  --capacity open|closed|unknown        --capacity-generation <n>
  --dependency open|closed|unknown      --dependency-generation <n>
  --maintenance open|closed|unknown     --maintenance-generation <n>
  --topology open|closed|unknown        --topology-generation <n>
  --closed-reason <text>

Exit codes: 0 success, 1 rejected request, 2 usage error.
A rejected request prints one line "error: <token>: <message>"; with --json the
error is an object with the fields token, message, and path.
)"},
    {"version", R"(usage: fbm version

Prints the product name, the version string, the durable record format version,
and the build description. Reads no store and no clock.
)"},
    {"help", R"(usage: fbm help [command]

Prints the command overview, or the help of one command. An unknown topic is a
usage error.
)"},
    {"init", R"(usage: fbm init

Creates the store directory if it does not exist and opens it. Opening the store
mints a new incarnation, so every authorization minted by a previous incarnation
is fenced.
)"},
    {"status", R"(usage: fbm status

Opens the store and prints the recovery outcome, the active slot, the commit
sequence, the control epoch, the incarnation, the policy generation, and every
recovery note. Opening the store requires the writer lock.
)"},
    {"verify", R"(usage: fbm verify

Read-only inspection through DurableStore::inspect. Takes no writer lock and
modifies nothing. A store held by another writer is reported as it is on disk.
)"},
    {"policy", R"(usage: fbm policy export --out <file>
       fbm policy apply --file <file> [--signature <file>]

export writes the canonical policy document (no insignificant whitespace, sorted
members) to the file. apply parses the document, verifies the detached signature
when one is supplied and a key is configured, and applies every baseline.

A supplied signature without a configured key is rejected: an unverifiable
signature is never reported as valid.
)"},
    {"baseline", R"(usage: fbm baseline define --file <file>
       fbm baseline list
       fbm baseline publish <id> --generation <n>
       fbm baseline retire <id> --generation <n>

define applies a policy document whose baselines are drafts. list prints every
baseline in ascending identity order. publish and retire move one baseline and
advance the policy generation, which fences every authorization and exception
granted under the previous generation.
)"},
    {"observe", R"(usage: fbm observe --asset <id> --evidence <id> --sequence <n> [--generation <n>]
              ( --component <c> [--version <v>]
              | --hardware-class <c> --model <m> [--revision <n>] [--capability <c>]... )

Records one evidence submission. Exactly one of the component form and the
hardware form must be given. Without --version the component is recorded as
observed with an undetermined version, which is a different fact from never
having observed it. A capability set is recorded as observed only when at least
one --capability is supplied, so an unreported set never becomes an observed
absence. --generation is the hardware or firmware generation of the evidence and
is left unset when it is not supplied.
)"},
    {"evaluate", R"(usage: fbm evaluate --asset <id>

Evaluates conformance against the authoritative baseline. Any verdict, including
a drifted or unknown one, is a successful evaluation.
)"},
    {"rollout-eligibility", R"(usage: fbm rollout-eligibility --asset <id> [gate options]

Decides whether the asset may be rolled forward. Every facility gate must be
explicitly open; an unset gate is unknown and eligibility is undecidable.
)"},
    {"rollback-eligibility", R"(usage: fbm rollback-eligibility --asset <id> --target <version> [gate options]

Decides whether the asset may be rolled back to the named target. The target must
be a declared rollback target of the authoritative baseline.
)"},
    {"drift", R"(usage: fbm drift --asset <id>

Lists every residual for the asset: the observed version, the required version,
the signed distance, the evidence age, and the rule that produced the residual.
)"},
    {"explain", R"(usage: fbm explain --asset <id>

Human-readable explanation of the conformance verdict, the authority it was
evaluated against, and every residual.
)"},
    {"exception", R"(usage: fbm exception list
       fbm exception add --id <i> --hardware-class <c> [--model <m>] [--asset <a>]
                         [--component <c>]... --reason <r> --approval <ap>
                         ( --expires-at <rfc3339> | --expires never )
       fbm exception revoke --id <i> --revision <n>

An exception is a time-bounded, scope-bounded waiver of drift. It is fenced by
the policy generation it was granted under: a policy change makes every existing
exception ineffective until it is re-granted. An empty component list means every
component in scope, which is a deliberate widening.
)"},
    {"cohort", R"(usage: fbm cohort list
       fbm cohort create --id <i> --baseline <b> --generation <n> --asset <a> [--asset <a>]...
       fbm cohort authorize --id <i> --revision <n>
       fbm cohort promote --id <i> --revision <n> [gate options]
       fbm cohort pause <id> --revision <n>
       fbm cohort resume <id> --revision <n>
       fbm cohort cancel <id> --revision <n>

A cohort is a staged rollout over an exact baseline generation. Authorizing binds
it to the baseline generation, its content digest, the policy generation, the
control epoch, and its revision; any of those advancing fences the authorization.
create sorts the member assets and rejects a repeated --asset. promote exits 1
when the promotion gate is not satisfied and prints the gate report.
)"},
    {"authorize", R"(usage: fbm authorize rollout --id <i> --revision <n> --request <r>
       fbm authorize rollback --id <i> --revision <n> --request <r>

Mints an authorization token bound to the cohort revision, the baseline
generation, revision and digest, the policy generation, the control epoch, the
incarnation, and the request identity. The canonical token JSON is printed, in
text mode on a line beginning "token=". A signing key is never printed.
)"},
    {"token", R"(usage: fbm token verify --scope <s> --plan <p> --token <file>

Verifies a token that was written by authorize against the state this store
holds. The scope and the plan must match the token, and the token must not be
fenced by a later generation, epoch, revision, digest, or incarnation.
)"},
};

constexpr std::size_t kHelpEntryCount = sizeof(kHelpEntries) / sizeof(kHelpEntries[0]);

const std::string_view* find_help(std::string_view topic) {
  for (std::size_t index = 0; index < kHelpEntryCount; ++index) {
    if (kHelpEntries[index].topic == topic) {
      return &kHelpEntries[index].text;
    }
  }
  return nullptr;
}

int handle_help(RunState& state, const CommandArgs& args) {
  std::string topic;
  for (const std::string& word : args.positional) {
    if (!topic.empty()) {
      topic += ' ';
    }
    topic += word;
  }
  const std::string_view* body = find_help(topic);
  if (body == nullptr && args.positional.size() == 2u) {
    // A command-specific topic that is not spelled out falls back to the group.
    body = find_help(args.positional.front());
  }
  if (body == nullptr) {
    return report_usage(state, "unknown help topic: " + topic);
  }
  if (state.json) {
    json::Value::Object fields;
    fields.emplace_back("command", json::Value{topic});
    fields.emplace_back("text", json::Value{std::string{*body}});
    print_json(state, json::Value{std::move(fields)});
    return 0;
  }
  print_text(state, std::string{*body});
  return 0;
}

// The recovery report plus the counters that live in the snapshot rather than in
// the durable frame.
int report_store_state(RunState& state, const BaselineManager& manager) {
  const RecoveryReport& report = manager.recovery();
  if (state.json) {
    json::Value::Object fields;
    fields.emplace_back("recovery", report.to_json());
    fields.emplace_back("incarnation", json_counter(manager.incarnation()));
    fields.emplace_back("policy_generation", json_counter(manager.policy_generation()));
    fields.emplace_back("control_epoch", json_counter(manager.control_epoch()));
    fields.emplace_back("commit_sequence", json_counter(manager.commit_sequence()));
    print_json(state, json::Value{std::move(fields)});
    return 0;
  }
  std::string body = text::format_recovery_report(report);
  text::Table counters({"field", "value"});
  counters.add_row({"incarnation", counter_text(manager.incarnation())});
  counters.add_row({"policy_generation", counter_text(manager.policy_generation())});
  counters.add_row({"control_epoch", counter_text(manager.control_epoch())});
  counters.add_row({"commit_sequence", counter_text(manager.commit_sequence())});
  body += counters.render();
  print_text(state, body);
  return 0;
}

int handle_init(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "init takes no arguments");
  }
  auto manager = open_store(state, true);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  return report_store_state(state, *manager.value());
}

int handle_status(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "status takes no arguments");
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  return report_store_state(state, *manager.value());
}

int handle_verify(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "verify takes no arguments");
  }
  auto report = DurableStore::inspect(state.store);
  if (!report.has_value()) {
    return report_rejection(state, report.error());
  }
  if (state.json) {
    print_json(state, report.value().to_json());
    return 0;
  }
  print_text(state, text::format_recovery_report(report.value()));
  return 0;
}

Result<std::string> read_text_file(const std::filesystem::path& path) {
  return platform::read_file(path, json::Limits{}.max_bytes);
}

// Reports the baselines an apply produced, in the order the operation returned
// them.
int report_applied_baselines(RunState& state, const BaselineManager& manager,
                             const std::vector<BaselineId>& applied, const char* json_key) {
  const std::vector<Baseline> baselines = manager.baselines();
  if (state.json) {
    json::Value::Array items;
    items.reserve(applied.size());
    for (const BaselineId& id : applied) {
      items.push_back(applied_baseline_json(id, lookup_baseline(baselines, id)));
    }
    json::Value::Object root;
    root.emplace_back(json_key, json::Value{std::move(items)});
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  text::Table table({"id", "generation", "revision", "state"});
  for (const BaselineId& id : applied) {
    const Baseline* baseline = lookup_baseline(baselines, id);
    if (baseline == nullptr) {
      table.add_row({id.to_string(), "<unset>", "<unset>", "<unset>"});
      continue;
    }
    table.add_row({baseline->id.to_string(), counter_text(baseline->generation),
                   counter_text(baseline->revision),
                   std::string{baseline_state_token(baseline->state)}});
  }
  print_text(state, table.render());
  return 0;
}

// Reads and verifies a detached signature when one was supplied. An absent
// --signature is not a failure; a supplied signature that cannot be verified
// always is.
Outcome<bool> check_detached_signature(RunState& state, const CommandArgs& args,
                                       const PolicyDocument& document) {
  const std::string* signature_path = args.find("--signature");
  if (signature_path == nullptr) {
    return outcome_ok(false);
  }
  if (!state.signing_key.has_value()) {
    return outcome_fail<bool>(
        "a detached signature was supplied but no signing key is configured, so the signature "
        "cannot be verified");
  }
  auto signature_text = read_text_file(std::filesystem::path{*signature_path});
  if (!signature_text.has_value()) {
    return outcome_fail<bool>(signature_text.error().to_string());
  }
  auto signature = DetachedSignature::parse(signature_text.value(), "/signature");
  if (!signature.has_value()) {
    return outcome_fail<bool>(signature.error().to_string());
  }
  const std::string canonical = document.canonical_bytes();
  const SignatureCheck check =
      verify_policy_signature(canonical, signature.value(), state.signing_key.value());
  if (check != SignatureCheck::Valid) {
    return outcome_fail<bool>("the detached signature does not verify against the policy document");
  }
  return outcome_ok(true);
}

int handle_policy_export(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "policy export takes no positional arguments");
  }
  auto out_path = require_value(args, "--out");
  if (!out_path.value.has_value()) {
    return report_usage(state, out_path.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  const PolicyDocument document = manager.value()->export_policy_document();
  const std::string canonical = json::write_canonical(document.to_json());
  Status written =
      platform::write_file_flushed(std::filesystem::path{out_path.value.value()}, canonical);
  if (!written.has_value()) {
    return report_rejection(state, written.error());
  }
  const std::string digest = digest_to_hex(document.content_digest());
  if (state.json) {
    json::Value::Object fields;
    fields.emplace_back("out", json::Value{out_path.value.value()});
    fields.emplace_back("baselines",
                        json::Value{static_cast<std::int64_t>(document.baselines().size())});
    fields.emplace_back("sha256", json::Value{digest});
    print_json(state, json::Value{std::move(fields)});
    return 0;
  }
  print_text(state, field_table({{"out", out_path.value.value()},
                                 {"baselines", std::to_string(document.baselines().size())},
                                 {"sha256", digest}}));
  return 0;
}

int handle_policy_apply(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "policy apply takes no positional arguments");
  }
  auto file = require_value(args, "--file");
  if (!file.value.has_value()) {
    return report_usage(state, file.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto content = read_text_file(std::filesystem::path{file.value.value()});
  if (!content.has_value()) {
    return report_rejection(state, content.error());
  }
  auto document = PolicyDocument::parse(content.value(), "/file");
  if (!document.has_value()) {
    return report_rejection(state, document.error());
  }
  auto signature = check_detached_signature(state, args, document.value());
  if (!signature.value.has_value()) {
    return report_rejection(state, Error{ErrorCode::AuthorityNotAuthorized, signature.message,
                                         std::string{"/signature"}});
  }
  auto applied = manager.value()->apply_policy_document(
      document.value(), make_context(instant(state), std::nullopt, std::nullopt));
  if (!applied.has_value()) {
    return report_rejection(state, applied.error());
  }
  return report_applied_baselines(state, *manager.value(), applied.value(), "applied");
}

int handle_baseline_define(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "baseline define takes no positional arguments");
  }
  auto file = require_value(args, "--file");
  if (!file.value.has_value()) {
    return report_usage(state, file.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto content = read_text_file(std::filesystem::path{file.value.value()});
  if (!content.has_value()) {
    return report_rejection(state, content.error());
  }
  auto document = PolicyDocument::parse(content.value(), "/file");
  if (!document.has_value()) {
    return report_rejection(state, document.error());
  }
  if (document.value().baselines().empty()) {
    return report_rejection(
        state, Error{ErrorCode::SchemaEmptyCollection,
                     "baseline define requires a policy document with at least one baseline",
                     std::string{"/baselines"}});
  }
  for (const Baseline& authored : document.value().baselines()) {
    if (authored.state != BaselineState::Draft) {
      return report_rejection(
          state,
          Error{ErrorCode::SchemaInconsistentDocument,
                "baseline define applies draft baselines only, and baseline " +
                    authored.id.to_string() + " is " +
                    std::string{baseline_state_token(authored.state)},
                std::string{"/baselines"}});
    }
  }
  auto applied = manager.value()->apply_policy_document(
      document.value(), make_context(instant(state), std::nullopt, std::nullopt));
  if (!applied.has_value()) {
    return report_rejection(state, applied.error());
  }
  return report_applied_baselines(state, *manager.value(), applied.value(), "defined");
}

int handle_baseline_list(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "baseline list takes no arguments");
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  const std::vector<Baseline> baselines = manager.value()->baselines();
  if (state.json) {
    json::Value::Array items;
    items.reserve(baselines.size());
    for (const Baseline& baseline : baselines) {
      items.push_back(baseline.to_json());
    }
    json::Value::Object root;
    root.emplace_back("baselines", json::Value{std::move(items)});
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  std::vector<const Baseline*> pointers;
  pointers.reserve(baselines.size());
  for (const Baseline& baseline : baselines) {
    pointers.push_back(&baseline);
  }
  print_text(state, baseline_table(pointers));
  return 0;
}

// Resolves the <id> argument of a command that documents it positionally. --id
// is accepted as an equivalent spelling; supplying both is a usage error.
template <class Id>
Outcome<Id> resolve_positional_id(const CommandArgs& args, std::string_view label) {
  const std::string* flagged = args.find("--id");
  if (!args.positional.empty() && flagged != nullptr) {
    return outcome_fail<Id>("the " + std::string{label} +
                            " identity was supplied both as an argument and as --id");
  }
  if (args.positional.size() > 1u) {
    return outcome_fail<Id>(std::string{label} + " takes exactly one identity argument");
  }
  if (flagged != nullptr) {
    return make_identifier<Id>(*flagged, "--id");
  }
  if (args.positional.empty()) {
    return outcome_fail<Id>("missing required argument <id>");
  }
  return make_identifier<Id>(args.positional.front(), "<id>");
}

int handle_baseline_transition(RunState& state, const CommandArgs& args, bool publish) {
  auto id = resolve_positional_id<BaselineId>(args, "baseline");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto generation = require_count(args, "--generation");
  if (!generation.value.has_value()) {
    return report_usage(state, generation.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  const MutationContext context = make_context(instant(state), std::nullopt, std::nullopt);
  const BaselineGeneration target{generation.value.value()};
  Result<Baseline> transitioned =
      publish ? manager.value()->publish_baseline(id.value.value(), target, context)
              : manager.value()->retire_baseline(id.value.value(), target, context);
  if (!transitioned.has_value()) {
    return report_rejection(state, transitioned.error());
  }
  if (state.json) {
    print_json(state, transitioned.value().to_json());
    return 0;
  }
  print_text(state, baseline_summary_table(transitioned.value()));
  return 0;
}

int handle_baseline_publish(RunState& state, const CommandArgs& args) {
  return handle_baseline_transition(state, args, true);
}

int handle_baseline_retire(RunState& state, const CommandArgs& args) {
  return handle_baseline_transition(state, args, false);
}

int handle_observe(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "observe takes no positional arguments");
  }
  auto asset = require_identifier<AssetId>(args, "--asset");
  if (!asset.value.has_value()) {
    return report_usage(state, asset.message);
  }
  auto evidence = require_identifier<EvidenceId>(args, "--evidence");
  if (!evidence.value.has_value()) {
    return report_usage(state, evidence.message);
  }
  auto sequence = require_count(args, "--sequence");
  if (!sequence.value.has_value()) {
    return report_usage(state, sequence.message);
  }
  auto generation = read_count_option(args, "--generation");
  if (!generation.value.has_value()) {
    return report_usage(state, generation.message);
  }
  if (args.has("--component") == args.has("--hardware-class")) {
    return report_usage(
        state, "observe requires exactly one of --component or --hardware-class (with --model)");
  }

  ObserveRequest request;
  request.now = instant(state);
  request.asset = asset.value.value();
  request.evidence = evidence.value.value();
  request.sequence = ObservationSequence{sequence.value.value()};

  if (args.has("--component")) {
    if (args.has("--model") || args.has("--revision") || args.has("--capability")) {
      return report_usage(
          state, "--model, --revision, and --capability describe a hardware observation, not a "
                 "component observation");
    }
    auto component = require_identifier<FirmwareComponentId>(args, "--component");
    if (!component.value.has_value()) {
      return report_usage(state, component.message);
    }
    request.has_component = true;
    request.component = component.value.value();
    if (const std::string* text = args.find("--version"); text != nullptr) {
      auto parsed = parse_version(*text, "--version");
      if (!parsed.value.has_value()) {
        return report_usage(state, parsed.message);
      }
      request.version = parsed.value.value();
    }
    if (generation.value.value().present) {
      request.firmware_generation = FirmwareGeneration{generation.value.value().value};
    }
  } else {
    if (args.has("--version")) {
      return report_usage(state, "--version describes a component observation, not a hardware one");
    }
    auto hardware_class = require_identifier<HardwareClassId>(args, "--hardware-class");
    if (!hardware_class.value.has_value()) {
      return report_usage(state, hardware_class.message);
    }
    auto model = require_identifier<HardwareModelId>(args, "--model");
    if (!model.value.has_value()) {
      return report_usage(state, model.message);
    }
    request.has_hardware = true;
    request.hardware.hardware_class = hardware_class.value.value();
    request.hardware.model = model.value.value();
    if (const std::string* text = args.find("--revision"); text != nullptr) {
      auto parsed = parse_count(*text, "--revision");
      if (!parsed.value.has_value()) {
        return report_usage(state, parsed.message);
      }
      if (parsed.value.value() > std::numeric_limits<std::uint32_t>::max()) {
        return report_usage(state, "option --revision is out of range");
      }
      request.hardware.revision = HardwareRevision{static_cast<std::uint32_t>(parsed.value.value())};
    }
    std::vector<CapabilityId> capabilities;
    for (const std::string& text : args.gather("--capability")) {
      auto made = make_identifier<CapabilityId>(text, "--capability");
      if (!made.value.has_value()) {
        return report_usage(state, made.message);
      }
      capabilities.push_back(made.value.value());
    }
    std::sort(capabilities.begin(), capabilities.end());
    capabilities.erase(std::unique(capabilities.begin(), capabilities.end()), capabilities.end());
    // A capability set is recorded as observed only when it was reported. An
    // unreported set stays unobserved, so a capability requirement remains
    // undecidable rather than being read as an absent capability.
    request.hardware.capabilities_observed = !capabilities.empty();
    request.hardware.capabilities = std::move(capabilities);
    if (generation.value.value().present) {
      request.hardware_generation = HardwareGeneration{generation.value.value().value};
    }
  }

  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  request.reporter = manager.value()->incarnation();
  auto outcome = manager.value()->observe(request);
  if (!outcome.has_value()) {
    return report_rejection(state, outcome.error());
  }
  const std::string outcome_token{observation_outcome_token(outcome.value())};
  if (state.json) {
    json::Value::Object fields;
    fields.emplace_back("outcome", json::Value{outcome_token});
    fields.emplace_back("asset", json::Value{request.asset.value()});
    fields.emplace_back("evidence", json::Value{request.evidence.value()});
    fields.emplace_back("sequence", json_counter(request.sequence));
    if (request.has_hardware) {
      fields.emplace_back("kind", json::Value{std::string{"hardware"}});
      fields.emplace_back("hardware", request.hardware.to_json());
      fields.emplace_back("hardware_generation", json_counter(request.hardware_generation));
    } else {
      fields.emplace_back("kind", json::Value{std::string{"component"}});
      fields.emplace_back("component", json::Value{request.component.value()});
      fields.emplace_back("version", json_optional_version(request.version));
      fields.emplace_back("firmware_generation", json_counter(request.firmware_generation));
    }
    fields.emplace_back("observed_at", json::Value{request.now.to_rfc3339()});
    fields.emplace_back("reporter", json_counter(request.reporter));
    print_json(state, json::Value{std::move(fields)});
    return 0;
  }
  std::vector<std::pair<std::string, std::string>> rows;
  rows.emplace_back("outcome", outcome_token);
  rows.emplace_back("asset", request.asset.to_string());
  rows.emplace_back("evidence", request.evidence.to_string());
  rows.emplace_back("sequence", counter_text(request.sequence));
  if (request.has_hardware) {
    rows.emplace_back("kind", "hardware");
    rows.emplace_back("hardware_class", request.hardware.hardware_class.to_string());
    rows.emplace_back("model", request.hardware.model.to_string());
    rows.emplace_back("revision", counter_text(request.hardware.revision));
    rows.emplace_back("capabilities_observed",
                      request.hardware.capabilities_observed ? "true" : "false");
    std::string capabilities;
    for (const CapabilityId& capability : request.hardware.capabilities) {
      if (!capabilities.empty()) {
        capabilities += ", ";
      }
      capabilities += capability.to_string();
    }
    rows.emplace_back("capabilities", capabilities.empty() ? "none" : capabilities);
    rows.emplace_back("hardware_generation", counter_text(request.hardware_generation));
  } else {
    rows.emplace_back("kind", "component");
    rows.emplace_back("component", request.component.to_string());
    rows.emplace_back("version", text::format_optional_version(request.version));
    rows.emplace_back("firmware_generation", counter_text(request.firmware_generation));
  }
  rows.emplace_back("observed_at", text::format_timestamp(request.now));
  rows.emplace_back("reporter", counter_text(request.reporter));
  print_text(state, field_table(rows));
  return 0;
}

// Builds the evaluation request shared by the query commands. Gate options are
// only accepted where the command documents them.
Outcome<EvaluationRequest> read_evaluation_request(const CommandArgs& args,
                                                   const std::optional<FacilityGates>& gates,
                                                   bool target_allowed, bool target_required,
                                                   const Timestamp& now) {
  EvaluationRequest request;
  auto asset = require_identifier<AssetId>(args, "--asset");
  if (!asset.value.has_value()) {
    return outcome_fail<EvaluationRequest>(asset.message);
  }
  request.asset = asset.value.value();
  request.now = now;
  if (gates.has_value()) {
    request.gates = gates.value();
  }
  if (const std::string* text = args.find("--target"); text != nullptr) {
    if (!target_allowed) {
      return outcome_fail<EvaluationRequest>("option --target is not accepted by this command");
    }
    auto parsed = parse_version(*text, "--target");
    if (!parsed.value.has_value()) {
      return outcome_fail<EvaluationRequest>(parsed.message);
    }
    request.requested_rollback_target = parsed.value.value();
  } else if (target_required) {
    return outcome_fail<EvaluationRequest>("missing required option --target");
  }
  return outcome_ok(std::move(request));
}

int handle_evaluate(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "evaluate takes no positional arguments");
  }
  auto request = read_evaluation_request(args, std::nullopt, false, false, instant(state));
  if (!request.value.has_value()) {
    return report_usage(state, request.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto verdict = manager.value()->evaluate(request.value.value());
  if (!verdict.has_value()) {
    return report_rejection(state, verdict.error());
  }
  if (state.json) {
    print_json(state, verdict.value().to_json());
    return 0;
  }
  print_text(state, text::format_conformance_report(verdict.value()));
  return 0;
}

int handle_eligibility(RunState& state, const CommandArgs& args, bool rollback) {
  if (!args.positional.empty()) {
    return report_usage(state, rollback ? "rollback-eligibility takes no positional arguments"
                                        : "rollout-eligibility takes no positional arguments");
  }
  auto gates = read_gates(args);
  if (!gates.value.has_value()) {
    return report_usage(state, gates.message);
  }
  auto request =
      read_evaluation_request(args, gates.value.value(), rollback, rollback, instant(state));
  if (!request.value.has_value()) {
    return report_usage(state, request.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  Result<EligibilityVerdict> verdict =
      rollback ? manager.value()->rollback_eligibility(request.value.value())
               : manager.value()->rollout_eligibility(request.value.value());
  if (!verdict.has_value()) {
    return report_rejection(state, verdict.error());
  }
  if (state.json) {
    print_json(state, verdict.value().to_json());
    return 0;
  }
  print_text(state, text::format_eligibility_report(verdict.value()));
  return 0;
}

int handle_rollout_eligibility(RunState& state, const CommandArgs& args) {
  return handle_eligibility(state, args, false);
}

int handle_rollback_eligibility(RunState& state, const CommandArgs& args) {
  return handle_eligibility(state, args, true);
}

int handle_drift(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "drift takes no positional arguments");
  }
  auto request = read_evaluation_request(args, std::nullopt, false, false, instant(state));
  if (!request.value.has_value()) {
    return report_usage(state, request.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto residuals = manager.value()->list_drift(request.value.value());
  if (!residuals.has_value()) {
    return report_rejection(state, residuals.error());
  }
  if (state.json) {
    json::Value::Array items;
    items.reserve(residuals.value().size());
    for (const DriftResidual& residual : residuals.value()) {
      items.push_back(residual.to_json());
    }
    json::Value::Object root;
    root.emplace_back("asset", json::Value{request.value.value().asset.value()});
    root.emplace_back("residuals", json::Value{std::move(items)});
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  print_text(state, text::format_drift_table(residuals.value()));
  return 0;
}

int handle_explain(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "explain takes no positional arguments");
  }
  auto request = read_evaluation_request(args, std::nullopt, false, false, instant(state));
  if (!request.value.has_value()) {
    return report_usage(state, request.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto explanation = manager.value()->explain(request.value.value());
  if (!explanation.has_value()) {
    return report_rejection(state, explanation.error());
  }
  if (state.json) {
    json::Value::Object root;
    root.emplace_back("asset", json::Value{request.value.value().asset.value()});
    root.emplace_back("explanation", json::Value{explanation.value()});
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  print_text(state, explanation.value());
  return 0;
}

int handle_exception_list(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "exception list takes no arguments");
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  const std::vector<BaselineException> exceptions = manager.value()->exceptions();
  if (state.json) {
    json::Value::Array items;
    items.reserve(exceptions.size());
    for (const BaselineException& exception : exceptions) {
      items.push_back(exception.to_json());
    }
    json::Value::Object root;
    root.emplace_back("exceptions", json::Value{std::move(items)});
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  std::vector<const BaselineException*> pointers;
  pointers.reserve(exceptions.size());
  for (const BaselineException& exception : exceptions) {
    pointers.push_back(&exception);
  }
  print_text(state, exception_table(pointers));
  return 0;
}

int report_exception(RunState& state, const BaselineException& exception) {
  if (state.json) {
    print_json(state, exception.to_json());
    return 0;
  }
  print_text(state, exception_table({&exception}));
  return 0;
}

int handle_exception_add(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "exception add takes no positional arguments");
  }
  auto id = require_identifier<ExceptionId>(args, "--id");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto hardware_class = require_identifier<HardwareClassId>(args, "--hardware-class");
  if (!hardware_class.value.has_value()) {
    return report_usage(state, hardware_class.message);
  }
  auto reason = require_value(args, "--reason");
  if (!reason.value.has_value()) {
    return report_usage(state, reason.message);
  }
  if (reason.value.value().empty()) {
    return report_usage(state, "option --reason must not be empty");
  }
  auto approval = require_identifier<ApprovalId>(args, "--approval");
  if (!approval.value.has_value()) {
    return report_usage(state, approval.message);
  }
  const bool has_expires_at = args.has("--expires-at");
  const bool has_expires = args.has("--expires");
  if (has_expires_at == has_expires) {
    return report_usage(state,
                        "exception add requires exactly one of --expires-at <rfc3339> or "
                        "--expires never");
  }
  Expiry expiry;
  if (has_expires_at) {
    const std::string* text = args.find("--expires-at");
    auto parsed = parse_timestamp(*text, "--expires-at");
    if (!parsed.value.has_value()) {
      return report_usage(state, parsed.message);
    }
    expiry = Expiry::at(parsed.value.value());
  } else {
    const std::string* text = args.find("--expires");
    if (*text != "never") {
      return report_usage(state, "option --expires accepts only the value never");
    }
    expiry = Expiry::never();
  }

  ExceptionScope scope;
  scope.hardware_class = hardware_class.value.value();
  if (const std::string* model = args.find("--model"); model != nullptr) {
    auto made = make_identifier<HardwareModelId>(*model, "--model");
    if (!made.value.has_value()) {
      return report_usage(state, made.message);
    }
    scope.model = made.value.value();
  }
  if (const std::string* asset = args.find("--asset"); asset != nullptr) {
    auto made = make_identifier<AssetId>(*asset, "--asset");
    if (!made.value.has_value()) {
      return report_usage(state, made.message);
    }
    scope.asset = made.value.value();
  }
  for (const std::string& text : args.gather("--component")) {
    auto made = make_identifier<FirmwareComponentId>(text, "--component");
    if (!made.value.has_value()) {
      return report_usage(state, made.message);
    }
    scope.components.push_back(made.value.value());
  }
  std::sort(scope.components.begin(), scope.components.end());
  scope.components.erase(std::unique(scope.components.begin(), scope.components.end()),
                         scope.components.end());

  ExceptionDraft draft;
  draft.id = id.value.value();
  draft.scope = scope;
  draft.expiry = expiry;
  draft.reason = reason.value.value();

  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto granted = manager.value()->grant_exception(
      draft, make_context(instant(state), std::nullopt, approval.value.value()));
  if (!granted.has_value()) {
    return report_rejection(state, granted.error());
  }
  return report_exception(state, granted.value());
}

int handle_exception_revoke(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "exception revoke takes no positional arguments");
  }
  auto id = require_identifier<ExceptionId>(args, "--id");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto revision = require_count(args, "--revision");
  if (!revision.value.has_value()) {
    return report_usage(state, revision.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto revoked = manager.value()->revoke_exception(
      id.value.value(), Revision{revision.value.value()},
      make_context(instant(state), std::nullopt, std::nullopt));
  if (!revoked.has_value()) {
    return report_rejection(state, revoked.error());
  }
  return report_exception(state, revoked.value());
}

int report_cohort(RunState& state, const Cohort& cohort) {
  if (state.json) {
    json::Value::Object root;
    root.emplace_back("cohort", cohort.to_json());
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  print_text(state, cohort_table({&cohort}));
  return 0;
}

int handle_cohort_list(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "cohort list takes no arguments");
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  const std::vector<Cohort> cohorts = manager.value()->cohorts();
  if (state.json) {
    json::Value::Array items;
    items.reserve(cohorts.size());
    for (const Cohort& cohort : cohorts) {
      items.push_back(cohort.to_json());
    }
    json::Value::Object root;
    root.emplace_back("cohorts", json::Value{std::move(items)});
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  std::vector<const Cohort*> pointers;
  pointers.reserve(cohorts.size());
  for (const Cohort& cohort : cohorts) {
    pointers.push_back(&cohort);
  }
  print_text(state, cohort_table(pointers));
  return 0;
}

int handle_cohort_create(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "cohort create takes no positional arguments");
  }
  auto id = require_identifier<CohortId>(args, "--id");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto baseline = require_identifier<BaselineId>(args, "--baseline");
  if (!baseline.value.has_value()) {
    return report_usage(state, baseline.message);
  }
  auto generation = require_count(args, "--generation");
  if (!generation.value.has_value()) {
    return report_usage(state, generation.message);
  }
  std::vector<AssetId> members;
  for (const std::string& text : args.gather("--asset")) {
    auto made = make_identifier<AssetId>(text, "--asset");
    if (!made.value.has_value()) {
      return report_usage(state, made.message);
    }
    members.push_back(made.value.value());
  }
  if (members.empty()) {
    return report_usage(state, "cohort create requires at least one --asset");
  }
  std::sort(members.begin(), members.end());
  for (std::size_t index = 1; index < members.size(); ++index) {
    if (members[index - 1u] == members[index]) {
      return report_usage(state, "cohort create was given the asset " + members[index].to_string() +
                                     " more than once");
    }
  }

  CohortDraft draft;
  draft.id = id.value.value();
  draft.baseline = baseline.value.value();
  draft.baseline_generation = BaselineGeneration{generation.value.value()};
  draft.members = std::move(members);

  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto created = manager.value()->create_cohort(
      draft, make_context(instant(state), std::nullopt, std::nullopt));
  if (!created.has_value()) {
    return report_rejection(state, created.error());
  }
  return report_cohort(state, created.value());
}

int handle_cohort_authorize(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "cohort authorize takes no positional arguments");
  }
  auto id = require_identifier<CohortId>(args, "--id");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto revision = require_count(args, "--revision");
  if (!revision.value.has_value()) {
    return report_usage(state, revision.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  auto authorized = manager.value()->authorize_cohort(
      id.value.value(), Revision{revision.value.value()},
      make_context(instant(state), std::nullopt, std::nullopt));
  if (!authorized.has_value()) {
    return report_rejection(state, authorized.error());
  }
  return report_cohort(state, authorized.value());
}

int handle_cohort_promote(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "cohort promote takes no positional arguments");
  }
  auto id = require_identifier<CohortId>(args, "--id");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto revision = require_count(args, "--revision");
  if (!revision.value.has_value()) {
    return report_usage(state, revision.message);
  }
  auto gates = read_gates(args);
  if (!gates.value.has_value()) {
    return report_usage(state, gates.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  EvaluationRequest request;
  request.now = instant(state);
  request.gates = gates.value.value();
  auto gate = manager.value()->promote_cohort(id.value.value(), Revision{revision.value.value()},
                                              request,
                                              make_context(instant(state), std::nullopt, std::nullopt));
  if (!gate.has_value()) {
    return report_rejection(state, gate.error());
  }
  if (!gate.value().satisfied) {
    // The gate report is printed in full so the exact unmet conditions are
    // visible, and the request is reported as rejected: nothing was promoted.
    if (state.json) {
      print_json(state, gate.value().to_json());
    } else {
      print_text(state, text::format_gate_report(gate.value()));
    }
    return report_rejection(
        state, Error{ErrorCode::PolicyGateNotSatisfied,
                     "the promotion gate of cohort " + id.value.value().to_string() +
                         " is not satisfied",
                     std::string{"/cohorts"}});
  }
  // The cohort list is materialized into a named local first. Passing the
  // temporary returned by cohorts() straight into the lookup would leave the
  // returned pointer aimed at a vector that dies at the end of the statement.
  const std::vector<Cohort> promoted_cohorts = manager.value()->cohorts();
  const Cohort* promoted = lookup_cohort(promoted_cohorts, id.value.value());
  if (promoted == nullptr) {
    return report_rejection(state, Error{ErrorCode::IdentityUnknownCohort,
                                         "cohort " + id.value.value().to_string() +
                                             " disappeared during promotion",
                                         std::string{"/id"}});
  }
  if (state.json) {
    json::Value::Object root;
    root.emplace_back("cohort", promoted->to_json());
    root.emplace_back("gate", gate.value().to_json());
    print_json(state, json::Value{std::move(root)});
    return 0;
  }
  std::string body = text::format_gate_report(gate.value());
  body += cohort_table({promoted});
  print_text(state, body);
  return 0;
}

int handle_cohort_transition(RunState& state, const CommandArgs& args, int action) {
  auto id = resolve_positional_id<CohortId>(args, "cohort");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto revision = require_count(args, "--revision");
  if (!revision.value.has_value()) {
    return report_usage(state, revision.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  const MutationContext context = make_context(instant(state), std::nullopt, std::nullopt);
  const Revision target{revision.value.value()};
  Result<Cohort> transitioned =
      action == 0 ? manager.value()->pause_cohort(id.value.value(), target, context)
                  : (action == 1 ? manager.value()->resume_cohort(id.value.value(), target, context)
                                 : manager.value()->cancel_cohort(id.value.value(), target, context));
  if (!transitioned.has_value()) {
    return report_rejection(state, transitioned.error());
  }
  return report_cohort(state, transitioned.value());
}

int handle_cohort_pause(RunState& state, const CommandArgs& args) {
  return handle_cohort_transition(state, args, 0);
}

int handle_cohort_resume(RunState& state, const CommandArgs& args) {
  return handle_cohort_transition(state, args, 1);
}

int handle_cohort_cancel(RunState& state, const CommandArgs& args) {
  return handle_cohort_transition(state, args, 2);
}

// The token is printed as canonical JSON. In text mode it is the last line and
// carries the "token=" prefix so that it can be captured and handed to
// "token verify"; the signing key itself never appears anywhere.
int report_token(RunState& state, const AuthorizationToken& token) {
  if (state.json) {
    print_json(state, token.to_json());
    return 0;
  }
  const AuthorityBinding& binding = token.binding;
  text::Table table({"field", "value"});
  table.add_row({"request", binding.request.to_string()});
  table.add_row({"scope", binding.scope});
  table.add_row({"plan", binding.plan.to_string()});
  table.add_row({"signature_mode", std::string{signature_mode_token(binding.mode)}});
  table.add_row({"baseline", binding.baseline.to_string()});
  table.add_row({"baseline_generation", counter_text(binding.baseline_generation)});
  table.add_row({"baseline_revision", counter_text(binding.baseline_revision)});
  table.add_row({"baseline_digest", digest_to_hex(binding.baseline_digest)});
  table.add_row({"policy_generation", counter_text(binding.policy_generation)});
  table.add_row({"control_epoch", counter_text(binding.control_epoch)});
  table.add_row({"commit_sequence", counter_text(binding.commit_sequence)});
  table.add_row({"incarnation", counter_text(binding.incarnation)});
  table.add_row({"issued_at", text::format_timestamp(binding.issued_at)});
  table.add_row({"expires", expiry_text(binding.expiry)});
  std::string body = table.render();
  body += "token=";
  body += json::write_canonical(token.to_json());
  body += '\n';
  print_text(state, body);
  return 0;
}

int handle_authorize(RunState& state, const CommandArgs& args, bool rollback) {
  if (!args.positional.empty()) {
    return report_usage(state, rollback ? "authorize rollback takes no positional arguments"
                                        : "authorize rollout takes no positional arguments");
  }
  auto id = require_identifier<CohortId>(args, "--id");
  if (!id.value.has_value()) {
    return report_usage(state, id.message);
  }
  auto revision = require_count(args, "--revision");
  if (!revision.value.has_value()) {
    return report_usage(state, revision.message);
  }
  auto request_id = require_identifier<RequestId>(args, "--request");
  if (!request_id.value.has_value()) {
    return report_usage(state, request_id.message);
  }
  auto manager = open_store(state, false);
  if (!manager.has_value()) {
    return report_rejection(state, manager.error());
  }
  const MutationContext context =
      make_context(instant(state), request_id.value.value(), std::nullopt);
  const Revision target{revision.value.value()};
  Result<AuthorizationToken> token =
      rollback ? manager.value()->authorize_rollback(id.value.value(), target, context)
               : manager.value()->authorize_rollout(id.value.value(), target, context);
  if (!token.has_value()) {
    return report_rejection(state, token.error());
  }
  return report_token(state, token.value());
}

int handle_authorize_rollout(RunState& state, const CommandArgs& args) {
  return handle_authorize(state, args, false);
}

int handle_authorize_rollback(RunState& state, const CommandArgs& args) {
  return handle_authorize(state, args, true);
}

int handle_token_verify(RunState& state, const CommandArgs& args) {
  if (!args.positional.empty()) {
    return report_usage(state, "token verify takes no positional arguments");
  }
  auto scope = require_value(args, "--scope");
  if (!scope.value.has_value()) {
    return report_usage(state, scope.message);
  }
  auto plan = require_identifier<PlanId>(args, "--plan");
  if (!plan.value.has_value()) {
    return report_usage(state, plan.message);
  }
  auto token_file = require_value(args, "--token");
  if (!token_file.value.has_value()) {
    return report_usage(state, token_file.message);
  }
  // Verification reads the durable state without opening a new authority
  // incarnation. Opening a BaselineManager would advance the control epoch,
  // which is exactly the fence a token is checked against, so a read-only
  // verification that moved the epoch would invalidate the token it is about to
  // verify. This mirrors BaselineManager::verify_token's fence list: scope,
  // baseline identity, generation, revision and digest, policy generation,
  // control epoch, plan, subject digest, and expiry.
  StoreOptions store_options;
  store_options.directory = state.store;
  store_options.create_if_missing = false;
  store_options.take_writer_lock = true;
  auto store = DurableStore::open(store_options);
  if (!store.has_value()) {
    return report_rejection(state, store.error());
  }
  auto content = read_text_file(std::filesystem::path{token_file.value.value()});
  if (!content.has_value()) {
    return report_rejection(state, content.error());
  }
  auto parsed = json::parse(content.value(), json::Limits{}, "/token");
  if (!parsed.has_value()) {
    return report_rejection(state, parsed.error());
  }
  auto token = AuthorizationToken::from_json(parsed.value(), "/token");
  if (!token.has_value()) {
    return report_rejection(state, token.error());
  }
  const Snapshot& snapshot = store.value()->snapshot();
  const AuthorizationToken* recorded = snapshot.authorizations.find(token.value().binding.request);
  if (recorded == nullptr) {
    return report_rejection(
        state, Error{ErrorCode::AuthorityNotAuthorized,
                     "no authorization with request identity " +
                         token.value().binding.request.to_string() + " is recorded",
                     std::string{"/request"}});
  }
  if (!(recorded->mac == token.value().mac) ||
      !(recorded->binding.subject_digest == token.value().binding.subject_digest)) {
    return report_rejection(
        state, Error{ErrorCode::AuthorityNotAuthorized,
                     "the presented authorization does not match the recorded authorization for "
                     "request identity " +
                         token.value().binding.request.to_string(),
                     std::string{"/request"}});
  }
  const Timestamp now = instant(state);
  const AuthorizationAuthority authority =
      state.signing_key.has_value()
          ? AuthorizationAuthority::hmac_authority(state.signing_key.value())
          : AuthorizationAuthority::unsigned_authority();
  AuthorityBinding expected = token.value().binding;
  expected.scope = scope.value.value();
  expected.plan = plan.value.value();
  expected.policy_generation = snapshot.policy_generation;
  expected.control_epoch = snapshot.control_epoch;
  // The incarnation recorded in a token is provenance, not a fence.
  expected.incarnation = token.value().binding.incarnation;
  expected.issued_at = now;
  if (const Baseline* baseline = snapshot.baselines.find(token.value().binding.baseline);
      baseline != nullptr) {
    expected.baseline_generation = baseline->generation;
    expected.baseline_revision = baseline->revision;
    expected.baseline_digest = baseline->content_digest();
  }
  expected.mode = state.require_signature ? SignatureMode::HmacSha256 : token.value().binding.mode;
  Status verified = authority.verify(token.value(), expected);
  if (!verified.has_value()) {
    return report_rejection(state, verified.error());
  }
  const AuthorityBinding& binding = token.value().binding;
  if (state.json) {
    json::Value::Object fields;
    fields.emplace_back("valid", json::Value{true});
    fields.emplace_back("request", json::Value{binding.request.value()});
    fields.emplace_back("scope", json::Value{binding.scope});
    fields.emplace_back("plan", json::Value{binding.plan.value()});
    fields.emplace_back("signature_mode",
                        json::Value{std::string{signature_mode_token(binding.mode)}});
    fields.emplace_back("baseline", json::Value{binding.baseline.value()});
    fields.emplace_back("baseline_generation", json_counter(binding.baseline_generation));
    fields.emplace_back("baseline_revision", json_counter(binding.baseline_revision));
    fields.emplace_back("policy_generation", json_counter(binding.policy_generation));
    fields.emplace_back("control_epoch", json_counter(binding.control_epoch));
    fields.emplace_back("incarnation", json_counter(binding.incarnation));
    fields.emplace_back("issued_at", json::Value{binding.issued_at.to_rfc3339()});
    fields.emplace_back("expires", json::Value{expiry_text(binding.expiry)});
    print_json(state, json::Value{std::move(fields)});
    return 0;
  }
  print_text(state, field_table({{"valid", "true"},
                                 {"request", binding.request.to_string()},
                                 {"scope", binding.scope},
                                 {"plan", binding.plan.to_string()},
                                 {"signature_mode",
                                  std::string{signature_mode_token(binding.mode)}},
                                 {"baseline", binding.baseline.to_string()},
                                 {"baseline_generation", counter_text(binding.baseline_generation)},
                                 {"baseline_revision", counter_text(binding.baseline_revision)},
                                 {"policy_generation", counter_text(binding.policy_generation)},
                                 {"control_epoch", counter_text(binding.control_epoch)},
                                 {"incarnation", counter_text(binding.incarnation)},
                                 {"issued_at", text::format_timestamp(binding.issued_at)},
                                 {"expires", expiry_text(binding.expiry)}}));
  return 0;
}
// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

using Handler = int (*)(RunState&, const CommandArgs&);

std::vector<std::string> tail(const std::vector<std::string>& tokens, std::size_t skip) {
  if (skip >= tokens.size()) {
    return {};
  }
  return std::vector<std::string>(tokens.begin() + static_cast<std::ptrdiff_t>(skip), tokens.end());
}

int run_command(RunState& state, const std::vector<std::string>& tokens,
                const std::vector<OptionSpec>& specs, Handler handler, std::string_view label) {
  auto args = parse_command_args(tokens, specs, label);
  if (!args.value.has_value()) {
    return report_usage(state, args.message);
  }
  return handler(state, args.value.value());
}

const std::vector<OptionSpec> kGateSpecs = {
    {"--capacity", true},
    {"--capacity-generation", true},
    {"--dependency", true},
    {"--dependency-generation", true},
    {"--maintenance", true},
    {"--maintenance-generation", true},
    {"--topology", true},
    {"--topology-generation", true},
    {"--closed-reason", true},
};

std::vector<OptionSpec> with_gates(std::vector<OptionSpec> specs) {
  specs.insert(specs.end(), kGateSpecs.begin(), kGateSpecs.end());
  return specs;
}

int dispatch(RunState& state, const std::vector<std::string>& tokens) {
  const std::string& first = tokens.front();
  if (first == "version") {
    return run_command(state, tail(tokens, 1u), {}, handle_version, "version");
  }
  if (first == "help") {
    return run_command(state, tail(tokens, 1u), {}, handle_help, "help");
  }
  if (first == "init") {
    return run_command(state, tail(tokens, 1u), {}, handle_init, "init");
  }
  if (first == "status") {
    return run_command(state, tail(tokens, 1u), {}, handle_status, "status");
  }
  if (first == "verify") {
    return run_command(state, tail(tokens, 1u), {}, handle_verify, "verify");
  }
  if (first == "observe") {
    return run_command(state, tail(tokens, 1u),
                       {{"--asset", true},
                        {"--evidence", true},
                        {"--sequence", true},
                        {"--generation", true},
                        {"--component", true},
                        {"--version", true},
                        {"--hardware-class", true},
                        {"--model", true},
                        {"--revision", true},
                        {"--capability", true}},
                       handle_observe, "observe");
  }
  if (first == "evaluate") {
    return run_command(state, tail(tokens, 1u), {{"--asset", true}}, handle_evaluate, "evaluate");
  }
  if (first == "rollout-eligibility") {
    return run_command(state, tail(tokens, 1u), with_gates({{"--asset", true}}),
                       handle_rollout_eligibility, "rollout-eligibility");
  }
  if (first == "rollback-eligibility") {
    return run_command(state, tail(tokens, 1u),
                       with_gates({{"--asset", true}, {"--target", true}}),
                       handle_rollback_eligibility, "rollback-eligibility");
  }
  if (first == "drift") {
    return run_command(state, tail(tokens, 1u), {{"--asset", true}}, handle_drift, "drift");
  }
  if (first == "explain") {
    return run_command(state, tail(tokens, 1u), {{"--asset", true}}, handle_explain, "explain");
  }

  const bool is_group = first == "policy" || first == "baseline" || first == "exception" ||
                        first == "cohort" || first == "authorize" || first == "token";
  if (!is_group) {
    return report_usage(state, "unknown command: " + first);
  }
  if (tokens.size() < 2u) {
    return report_usage(state, "the " + first + " group requires a command");
  }
  const std::string& second = tokens[1];
  const std::vector<std::string> rest = tail(tokens, 2u);
  const std::string label = first + " " + second;

  if (first == "policy") {
    if (second == "export") {
      return run_command(state, rest, {{"--out", true}}, handle_policy_export, label);
    }
    if (second == "apply") {
      return run_command(state, rest, {{"--file", true}, {"--signature", true}},
                         handle_policy_apply, label);
    }
    return report_usage(state, "unknown command: " + label);
  }
  if (first == "baseline") {
    if (second == "define") {
      return run_command(state, rest, {{"--file", true}}, handle_baseline_define, label);
    }
    if (second == "list") {
      return run_command(state, rest, {}, handle_baseline_list, label);
    }
    if (second == "publish") {
      return run_command(state, rest, {{"--generation", true}, {"--id", true}},
                         handle_baseline_publish, label);
    }
    if (second == "retire") {
      return run_command(state, rest, {{"--generation", true}, {"--id", true}},
                         handle_baseline_retire, label);
    }
    return report_usage(state, "unknown command: " + label);
  }
  if (first == "exception") {
    if (second == "list") {
      return run_command(state, rest, {}, handle_exception_list, label);
    }
    if (second == "add") {
      return run_command(state, rest,
                         {{"--id", true},
                          {"--hardware-class", true},
                          {"--model", true},
                          {"--asset", true},
                          {"--component", true},
                          {"--reason", true},
                          {"--approval", true},
                          {"--expires-at", true},
                          {"--expires", true}},
                         handle_exception_add, label);
    }
    if (second == "revoke") {
      return run_command(state, rest, {{"--id", true}, {"--revision", true}},
                         handle_exception_revoke, label);
    }
    return report_usage(state, "unknown command: " + label);
  }
  if (first == "cohort") {
    if (second == "list") {
      return run_command(state, rest, {}, handle_cohort_list, label);
    }
    if (second == "create") {
      return run_command(state, rest,
                         {{"--id", true},
                          {"--baseline", true},
                          {"--generation", true},
                          {"--asset", true}},
                         handle_cohort_create, label);
    }
    if (second == "authorize") {
      return run_command(state, rest, {{"--id", true}, {"--revision", true}},
                         handle_cohort_authorize, label);
    }
    if (second == "promote") {
      return run_command(state, rest, with_gates({{"--id", true}, {"--revision", true}}),
                         handle_cohort_promote, label);
    }
    if (second == "pause") {
      return run_command(state, rest, {{"--revision", true}, {"--id", true}},
                         handle_cohort_pause, label);
    }
    if (second == "resume") {
      return run_command(state, rest, {{"--revision", true}, {"--id", true}},
                         handle_cohort_resume, label);
    }
    if (second == "cancel") {
      return run_command(state, rest, {{"--revision", true}, {"--id", true}},
                         handle_cohort_cancel, label);
    }
    return report_usage(state, "unknown command: " + label);
  }
  if (first == "authorize") {
    if (second == "rollout") {
      return run_command(state, rest, {{"--id", true}, {"--revision", true}, {"--request", true}},
                         handle_authorize_rollout, label);
    }
    if (second == "rollback") {
      return run_command(state, rest, {{"--id", true}, {"--revision", true}, {"--request", true}},
                         handle_authorize_rollback, label);
    }
    return report_usage(state, "unknown command: " + label);
  }
  if (first == "token") {
    if (second == "verify") {
      return run_command(state, rest, {{"--scope", true}, {"--plan", true}, {"--token", true}},
                         handle_token_verify, label);
    }
    return report_usage(state, "unknown command: " + label);
  }
  return report_usage(state, "unknown command: " + label);
}

}  // namespace

int run_cli(const std::vector<std::string>& arguments, std::ostream& out, std::ostream& err) {
  RunState state;
  state.out = &out;
  state.err = &err;

  // Global options are accepted anywhere, so they are removed from the token
  // stream before any command sees it.
  std::vector<std::string> remaining;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const std::string& token = arguments[index];
    if (token == "--json") {
      state.json = true;
      continue;
    }
    if (token == "--require-signature") {
      state.require_signature = true;
      continue;
    }
    if (token == "--store" || token == "--at" || token == "--key-file") {
      if (index + 1u >= arguments.size() || looks_like_an_option(arguments[index + 1u])) {
        return report_usage(state, "option " + token + " requires a value");
      }
      const std::string& value = arguments[index + 1u];
      ++index;
      if (token == "--store") {
        if (value.empty()) {
          return report_usage(state, "option --store requires a non-empty directory");
        }
        state.store = std::filesystem::path{value};
        continue;
      }
      if (token == "--key-file") {
        if (value.empty()) {
          return report_usage(state, "option --key-file requires a non-empty path");
        }
        state.key_file = std::filesystem::path{value};
        continue;
      }
      auto parsed = parse_timestamp(value, "--at");
      if (!parsed.value.has_value()) {
        return report_usage(state, parsed.message);
      }
      state.at = parsed.value.value();
      continue;
    }
    remaining.push_back(token);
  }

  if (state.key_file.has_value()) {
    auto content = platform::read_file(state.key_file.value(), kMaxSigningKeyBytes);
    if (!content.has_value()) {
      return report_rejection(state, content.error());
    }
    std::string key = content.take();
    if (!key.empty() && key.back() == '\n') {
      key.pop_back();
      if (!key.empty() && key.back() == '\r') {
        key.pop_back();
      }
    }
    if (key.empty()) {
      return report_rejection(state,
                              Error{ErrorCode::InvalidArgument,
                                    "the signing key file holds no key bytes, so no signing key is "
                                    "configured",
                                    std::string{"/key-file"}});
    }
    state.signing_key = std::move(key);
  }

  if (remaining.empty()) {
    return report_usage(state, "no command was given; run \"fbm help\" for the command list");
  }
  return dispatch(state, remaining);
}

}  // namespace summon::fbm

