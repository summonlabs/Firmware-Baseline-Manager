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

// Independent-process harness for the durable store.
//
// Every command runs in its own operating-system process so that the test suite
// can make real multiprocess claims about lock exclusion, lock release on
// process death, and cross-process visibility of committed generations.
//
// Output is a deterministic sequence of key=value lines.
//
// Exit codes: 0 success, 2 usage error, 3 store failure, 4 lock busy.

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "summon/fbm/platform.hpp"
#include "summon/fbm/store.hpp"

namespace {

int fail(const std::string& message) {
  std::cerr << "error: " << message << "\n";
  return 3;
}

struct Arguments {
  std::string command;
  std::string directory;
  std::string marker_file;
  std::string millis = "0";
  std::string marker_nanos = "0";
};

bool parse(int argc, char** argv, Arguments& out) {
  if (argc < 2) {
    return false;
  }
  out.command = argv[1];
  for (int index = 2; index < argc; ++index) {
    const std::string argument = argv[index];
    const auto value_for = [&](const char* name) -> std::string {
      const std::string prefix = std::string{name} + "=";
      if (argument.rfind(prefix, 0) == 0) {
        return argument.substr(prefix.size());
      }
      if (argument == name && index + 1 < argc) {
        return argv[++index];
      }
      return {};
    };
    if (argument.rfind("--dir", 0) == 0) {
      out.directory = value_for("--dir");
    } else if (argument.rfind("--marker-file", 0) == 0) {
      out.marker_file = value_for("--marker-file");
    } else if (argument.rfind("--millis", 0) == 0) {
      out.millis = value_for("--millis");
    } else if (argument.rfind("--marker-nanos", 0) == 0) {
      out.marker_nanos = value_for("--marker-nanos");
    } else {
      std::cerr << "unknown argument: " << argument << "\n";
      return false;
    }
  }
  return !out.directory.empty();
}

}  // namespace

int main(int argc, char** argv) {
  Arguments arguments;
  if (!parse(argc, argv, arguments)) {
    std::cerr << "usage: fbm_proc_tool <lock-hold|lock-try|commit|status|read> --dir <directory> "
                 "[--millis n] [--marker-file f] [--marker-nanos n]\n";
    return 2;
  }

  const summon::fbm::StorePaths paths =
      summon::fbm::StorePaths::for_directory(arguments.directory);

  if (arguments.command == "lock-hold") {
    summon::fbm::StoreOptions options;
    options.directory = arguments.directory;
    options.create_if_missing = true;
    options.take_writer_lock = true;
    auto store = summon::fbm::DurableStore::open(options);
    if (!store.has_value()) {
      return fail(store.error().to_string());
    }
    if (!arguments.marker_file.empty()) {
      const std::string body = "pid=" + std::to_string(summon::fbm::platform::current_process_id()) +
                               "\n";
      auto written = summon::fbm::platform::write_file_flushed(arguments.marker_file, body);
      if (!written.has_value()) {
        return fail(written.error().to_string());
      }
    }
    std::cout << "locked=true\n";
    std::cout.flush();
    summon::fbm::platform::sleep_millis(std::stoull(arguments.millis));
    std::cout << "released=true\n";
    return 0;
  }

  if (arguments.command == "lock-try") {
    auto lock = summon::fbm::platform::FileLock::acquire(paths.lock_file);
    if (!lock.has_value()) {
      if (lock.error().code() == summon::fbm::ErrorCode::IoLockBusy) {
        std::cout << "acquired=false\n";
        std::cout << "reason=busy\n";
        return 4;
      }
      return fail(lock.error().to_string());
    }
    std::cout << "acquired=true\n";
    lock.value().release();
    return 0;
  }

  // Rendezvous probe: waits until some other process holds the store lock and
  // then reports that fact and exits. This is how a test synchronizes with a
  // peer process deterministically instead of guessing at a sleep. The wait is
  // an inter-process handshake internal to this harness; it is not a timeout on
  // a test or a validation command, and a failed handshake is reported as a
  // failure rather than being treated as success.
  if (arguments.command == "lock-observe") {
    const std::uint64_t limit_millis = std::stoull(arguments.millis);
    std::uint64_t waited = 0;
    while (true) {
      auto lock = summon::fbm::platform::FileLock::acquire(paths.lock_file);
      if (!lock.has_value()) {
        if (lock.error().code() == summon::fbm::ErrorCode::IoLockBusy) {
          std::cout << "busy=true\n";
          std::cout << "waited_millis=" << waited << "\n";
          return 0;
        }
        return fail(lock.error().to_string());
      }
      lock.value().release();
      if (waited >= limit_millis) {
        std::cout << "busy=false\n";
        std::cout << "waited_millis=" << waited << "\n";
        return 5;
      }
      summon::fbm::platform::sleep_millis(5);
      waited += 5;
    }
  }

  if (arguments.command == "status") {
    auto report = summon::fbm::DurableStore::inspect(arguments.directory);
    if (!report.has_value()) {
      return fail(report.error().to_string());
    }
    const auto counter_text = [](bool is_set, std::uint64_t value) {
      return is_set ? std::to_string(value) : std::string{"unset"};
    };
    std::cout << "outcome=" << summon::fbm::recovery_outcome_token(report.value().outcome) << "\n";
    std::cout << "commit_sequence="
              << counter_text(report.value().commit_sequence.is_set(),
                              report.value().commit_sequence.value_or(0u))
              << "\n";
    std::cout << "control_epoch="
              << counter_text(report.value().control_epoch.is_set(),
                              report.value().control_epoch.value_or(0u))
              << "\n";
    std::cout << "active_slot=" << report.value().active_slot << "\n";
    std::cout << "unpublished_slot_present="
              << (report.value().unpublished_slot_present ? "true" : "false") << "\n";
    std::cout << "digest=" << summon::fbm::digest_to_hex(report.value().digest) << "\n";
    return 0;
  }

  summon::fbm::StoreOptions options;
  options.directory = arguments.directory;
  options.create_if_missing = true;
  options.take_writer_lock = true;
  auto store = summon::fbm::DurableStore::open(options);
  if (!store.has_value()) {
    return fail(store.error().to_string());
  }

  if (arguments.command == "read") {
    const summon::fbm::Snapshot& snapshot = store.value()->snapshot();
    std::cout << "outcome="
              << summon::fbm::recovery_outcome_token(store.value()->recovery().outcome) << "\n";
    std::cout << "commit_sequence="
              << (snapshot.commit_sequence.is_set() ? std::to_string(snapshot.commit_sequence.value())
                                                    : std::string{"unset"})
              << "\n";
    std::cout << "control_epoch="
              << (snapshot.control_epoch.is_set() ? std::to_string(snapshot.control_epoch.value())
                                                  : std::string{"unset"})
              << "\n";
    std::cout << "revision="
              << (snapshot.revision.is_set() ? std::to_string(snapshot.revision.value())
                                             : std::string{"unset"})
              << "\n";
    std::cout << "incarnation="
              << (snapshot.incarnation.is_set() ? std::to_string(snapshot.incarnation.value())
                                                : std::string{"unset"})
              << "\n";
    std::cout << "updated_at=" << snapshot.updated_at.unix_nanos() << "\n";
    std::cout << "baselines=" << snapshot.baselines.size() << "\n";
    std::cout << "assets=" << snapshot.observations.assets().size() << "\n";
    return 0;
  }

  if (arguments.command == "commit") {
    summon::fbm::Snapshot next = store.value()->snapshot();
    next.revision = summon::fbm::Revision{next.revision.value_or(0u) + 1u};
    next.updated_at = summon::fbm::Timestamp::from_unix_nanos(
        static_cast<std::uint64_t>(std::stoull(arguments.marker_nanos)));
    auto outcome = store.value()->commit(std::move(next));
    if (!outcome.has_value()) {
      return fail(outcome.error().to_string());
    }
    std::cout << "commit_sequence=" << outcome.value().commit_sequence.value_or(0u) << "\n";
    std::cout << "control_epoch=" << outcome.value().control_epoch.value_or(0u) << "\n";
    std::cout << "slot=" << outcome.value().slot << "\n";
    return 0;
  }

  std::cerr << "unknown command: " << arguments.command << "\n";
  return 2;
}
