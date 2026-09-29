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

// Crash harness for the durable store.
//
// Performs one real commit and, when a crash point is named, terminates the
// process at exactly that point with no cleanup, no destructor, and no atexit
// handler. This is what makes crash consistency a measured property: the next
// process to open the store is a genuinely independent process reading
// whatever the kernel actually made durable.
//
// Exit codes:
//   0   the commit completed
//   97  the process was terminated at the requested commit point
//   2   usage error
//   3   the store could not be opened or the commit failed

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "summon/fbm/store.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

void terminate_now(int code) {
#ifdef _WIN32
  ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(code));
  // TerminateProcess does not return for the calling process; this is a guard
  // against a future platform where it might.
  std::_Exit(code);
#else
  std::_Exit(code);
#endif
}

class CrashingObserver final : public summon::fbm::ICommitObserver {
 public:
  explicit CrashingObserver(summon::fbm::CommitPoint point) : point_(point) {}

  void on_commit_point(summon::fbm::CommitPoint point) override {
    if (point == point_) {
      std::cout << "crash_point=" << summon::fbm::commit_point_token(point) << "\n";
      std::cout.flush();
      terminate_now(97);
    }
  }

 private:
  summon::fbm::CommitPoint point_;
};

bool parse_commit_point(const std::string& text, summon::fbm::CommitPoint& out) {
  const summon::fbm::CommitPoint points[] = {
      summon::fbm::CommitPoint::BeforeStageWrite, summon::fbm::CommitPoint::AfterStageFlush,
      summon::fbm::CommitPoint::AfterStageVerify, summon::fbm::CommitPoint::AfterPublish,
      summon::fbm::CommitPoint::BeforeFenceWrite, summon::fbm::CommitPoint::AfterFenceWrite,
  };
  for (const summon::fbm::CommitPoint point : points) {
    if (summon::fbm::commit_point_token(point) == text) {
      out = point;
      return true;
    }
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  std::string directory;
  std::string crash_at;
  std::string marker_nanos;

  for (int index = 1; index < argc; ++index) {
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
      directory = value_for("--dir");
    } else if (argument.rfind("--crash-at", 0) == 0) {
      crash_at = value_for("--crash-at");
    } else if (argument.rfind("--marker-nanos", 0) == 0) {
      marker_nanos = value_for("--marker-nanos");
    } else {
      std::cerr << "unknown argument: " << argument << "\n";
      return 2;
    }
  }

  if (directory.empty() || marker_nanos.empty()) {
    std::cerr << "usage: fbm_crash_tool --dir <directory> --marker-nanos <n> "
                 "[--crash-at <point>]\n";
    return 2;
  }

  summon::fbm::StoreOptions options;
  options.directory = directory;
  options.create_if_missing = true;
  options.take_writer_lock = true;

  if (crash_at.empty()) {
    auto store = summon::fbm::DurableStore::open(options);
    if (!store.has_value()) {
      std::cerr << "open failed: " << store.error().to_string() << "\n";
      return 3;
    }
    summon::fbm::Snapshot next = store.value()->snapshot();
    next.revision = summon::fbm::Revision{next.revision.value_or(0u) + 1u};
    next.updated_at =
        summon::fbm::Timestamp::from_unix_nanos(static_cast<std::uint64_t>(std::stoull(marker_nanos)));
    auto outcome = store.value()->commit(std::move(next));
    if (!outcome.has_value()) {
      std::cerr << "commit failed: " << outcome.error().to_string() << "\n";
      return 3;
    }
    std::cout << "commit_sequence=" << outcome.value().commit_sequence.value_or(0u) << "\n";
    std::cout << "control_epoch=" << outcome.value().control_epoch.value_or(0u) << "\n";
    std::cout << "slot=" << outcome.value().slot << "\n";
    return 0;
  }

  summon::fbm::CommitPoint point = summon::fbm::CommitPoint::BeforeStageWrite;
  if (!parse_commit_point(crash_at, point)) {
    std::cerr << "unknown crash point: " << crash_at << "\n";
    return 2;
  }

  CrashingObserver observer{point};
  auto store = summon::fbm::DurableStore::open(options, &observer);
  if (!store.has_value()) {
    std::cerr << "open failed: " << store.error().to_string() << "\n";
    return 3;
  }

  summon::fbm::Snapshot next = store.value()->snapshot();
  next.revision = summon::fbm::Revision{next.revision.value_or(0u) + 1u};
  next.updated_at =
      summon::fbm::Timestamp::from_unix_nanos(static_cast<std::uint64_t>(std::stoull(marker_nanos)));

  auto outcome = store.value()->commit(std::move(next));
  if (!outcome.has_value()) {
    std::cerr << "commit failed: " << outcome.error().to_string() << "\n";
    return 3;
  }
  std::cerr << "the requested crash point was never reached\n";
  return 3;
}
