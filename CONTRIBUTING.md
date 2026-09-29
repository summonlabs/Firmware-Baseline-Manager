# Contributing to Firmware Baseline Manager

Thank you for your interest in contributing to Firmware Baseline Manager. This
document describes the contribution terms for this project.

## License

By contributing to this project, you agree that your contributions are
licensed under the **Apache License, Version 2.0**. See the `LICENSE`
file for the full license text and the `NOTICE` file for attribution
and license notices. There is **no separate Contributor License
Agreement (CLA)** requirement: you retain ownership of your
contributions and grant the project a license to use them under the
terms of the Apache License 2.0.

## License headers

New source files should carry the following header:

```
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
```

## Build and test expectations

Every change must build cleanly and pass the full test suite before it is
proposed for review.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Requirements:

- **C++20**, no compiler extensions.
- **Zero first-party warnings** under `/W4 /WX` (MSVC) or
  `-Wall -Wextra -Wpedantic -Werror` (GCC/Clang).
- **No new third-party dependencies** without a compelling systems reason
  recorded in the pull request description.
- **Tests are proof obligations.** A behavior change requires a test that
  fails before the change and passes after it. Do not weaken or delete an
  existing test to make a change land.
- **Determinism.** New behavior must be deterministic: identical inputs and
  identical durable state must produce identical outputs, independent of map
  iteration order, thread scheduling, or allocation addresses.
- **No telemetry.** Do not add code that transmits data off the machine.
- **No machine-specific absolute paths**, hidden credentials, or
  development-only endpoints in committed files.
- **Persistence format changes** must bump the on-disk format version and
  keep the strict-parsing and recovery guarantees described in the README.

## Review checklist

Pull requests are reviewed against the project doctrine, in particular:

- Observation is not authority; requested state is not observed state.
- Missing, unknown, or unmeasured values must never be silently converted to
  zero, false, healthy, ready, safe, or permitted.
- Every externally meaningful mutation must bind to the exact identity,
  generation, epoch, and revision it was planned against.

## Commit messages

Commit messages must be concise, neutral, and public-facing. Do not add
`Co-authored-by` trailers, AI attribution, or references to internal
tooling or workflow constraints.
