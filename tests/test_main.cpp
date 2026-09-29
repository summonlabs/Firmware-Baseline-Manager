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

#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "check.hpp"

namespace fbm_test {

void report_failure(const char* file, int line, const std::string& message) {
  failure_count() += 1;
  std::cout << "  FAIL " << current_test() << "\n"
            << "       at " << file << ":" << line << "\n"
            << "       " << message << "\n";
}

std::filesystem::path scratch_root() {
  // Absolute, always: a harness child process is started with the scratch
  // directory as its working directory, so a relative scratch root would be
  // resolved twice and would name a different place for the parent and the
  // child.
  std::error_code ec;
  if (const char* from_env = std::getenv("FBM_TEST_SCRATCH");
      from_env != nullptr && *from_env != '\0') {
    return std::filesystem::absolute(std::filesystem::path{from_env}, ec);
  }
  return std::filesystem::absolute(std::filesystem::path{"test-scratch"}, ec);
}

void remove_tree(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
}

std::filesystem::path scratch_directory(const std::string& name) {
  std::filesystem::path root = scratch_root();
  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  std::filesystem::path target = root / name;
  remove_tree(target);
  std::filesystem::create_directories(target, ec);
  return target;
}

}  // namespace fbm_test

int main(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--list") {
      list_only = true;
    } else if (arg.rfind("--filter=", 0) == 0) {
      filter = arg.substr(9);
    } else if (arg == "--help") {
      std::cout << "usage: fbm_tests [--list] [--filter=SUBSTRING]\n";
      return 0;
    } else {
      std::cout << "unknown argument: " << arg << "\n";
      return 2;
    }
  }

  int executed = 0;
  int skipped = 0;
  for (const auto& test : fbm_test::registry()) {
    const std::string name = test.name;
    if (list_only) {
      std::cout << name << "\n";
      continue;
    }
    if (!filter.empty() && name.find(filter) == std::string::npos) {
      ++skipped;
      continue;
    }
    fbm_test::current_test() = test.name;
    ++executed;
    const int before = fbm_test::failure_count();
    std::cout << "RUN  " << name << std::flush;
    try {
      test.function();
    } catch (const fbm_test::Abort&) {
      // Failure already reported by REQUIRE / CHECK_OK / CHECK_ERROR.
    } catch (const std::exception& ex) {
      fbm_test::report_failure("<test>", 0, std::string{"unexpected exception: "} + ex.what());
    } catch (...) {
      fbm_test::report_failure("<test>", 0, "unexpected non-standard exception");
    }
    const bool ok = fbm_test::failure_count() == before;
    std::cout << (ok ? "\rPASS " : "\rFAIL ") << name << "\n";
  }

  if (list_only) {
    return 0;
  }

  std::cout << "\n"
            << executed << " test(s) executed, " << skipped << " skipped, "
            << fbm_test::check_count() << " check(s), " << fbm_test::failure_count()
            << " failure(s)\n";
  return fbm_test::failure_count() == 0 ? 0 : 1;
}
