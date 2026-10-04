# Firmware Baseline Manager

Firmware Baseline Manager is the Data Center Control Plane (DCCP) authority for
facility-level firmware baseline policy and conformance state. It answers three
questions and refuses to answer any others:

1. Which firmware baseline is authoritative for a given hardware class, model,
   and revision?
2. Is a given asset conformant, eligible for a staged rollout, or eligible for a
   rollback under the current compatibility and facility constraints?
3. Where exactly does drift or uncertainty remain, in terms of the observed
   version, the required version, and the signed distance between them?

It evaluates observed version evidence against published baselines and emits
bounded rollout and rollback eligibility decisions for external executors. It
never flashes firmware, never reboots a device, never reads firmware from
hardware, and never executes maintenance.

---

## Systems boundary and explicit non-ownership

### What this repository owns

- Facility-level firmware **baseline policy**: which firmware versions are
  approved for which hardware class, model, and revision range.
- **Compatibility constraints** between firmware components, hardware
  revisions, and observed hardware capabilities.
- **Conformance state** for assets: Conformant, Drifted, Unknown, Unsupported,
  Blocked, Exception, PendingRollout, PendingRollback.
- **Drift detection** with exact observed-versus-required residuals.
- **Staged rollout cohorts** and promotion gates.
- **Exception authority** with explicit scope, reason, approval identity, and
  expiry.
- **Rollback eligibility** bound to known-compatible targets and current
  device and baseline generations.
- **Generation-bound baseline authority**, including the fencing of every
  authorization and exception when the policy generation changes.
- A crash-consistent, single-writer **durable store** for the above.

### What this repository explicitly does not own

- It does not flash firmware and does not drive update tooling.
- It does not reboot, drain, or otherwise mutate a device.
- It does not discover firmware from hardware; firmware versions enter only as
  evidence submitted by an external observer.
- It does not own vendor update services, update packages, or signing keys.
- It does not own hardware lifecycle, maintenance windows, capacity, or
  topology. Those arrive as facility gates owned by other facility repositories.
- It does not own physical asset identity, rack layout, or site topology.
- It does not decide that a rollout should happen; it decides whether a
  rollout is **eligible**, which is a different and strictly weaker claim.

Rollout eligibility is not rollout execution. Rollback eligibility is not a
rollback. A published baseline is not an installed firmware image. An observed
version is not a promise that the version is still installed.

---

## Build

Requirements: a C++20 compiler and CMake 3.25 or newer. There are no
third-party dependencies; the library uses only the C++ standard library and,
on Windows, the documented Win32 API for file locking, durable flushing, and
child processes.

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ctest --test-dir build --output-on-failure

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `FBM_WARNINGS_AS_ERRORS` | `ON` | Treat first-party warnings as errors (`/W4 /WX` on MSVC, `-Werror` elsewhere) |
| `FBM_ENABLE_SANITIZERS` | `OFF` | Build with AddressSanitizer and, on GCC/Clang, UndefinedBehaviorSanitizer |
| `FBM_BUILD_BENCHMARKS` | `OFF` | Build the `fbm_bench` benchmark executable |
| `BUILD_TESTING` | `ON` | Build the test suite and the two process harness executables |

The test suite is a single executable, `fbm_tests`, plus a CTest packaging
test that installs the library and builds an out-of-tree consumer against the
installed package. `fbm_tests` accepts `--filter=SUBSTRING` and `--list`.

---

## Installation and downstream consumption

    cmake --install build --prefix /some/prefix

This installs:

- the static library and public headers,
- the `fbm` command-line tool,
- a CMake package configuration at
  `<prefix>/lib/cmake/FirmwareBaselineManager/`,
- the `README.md`, `NOTICE`, and `LICENSE` files under
  `<prefix>/share/FirmwareBaselineManager/`.

An independent project consumes it through a namespaced imported target:

    find_package(FirmwareBaselineManager 1.0 CONFIG REQUIRED)
    target_link_libraries(my_tool PRIVATE Summon::FirmwareBaselineManager)

A complete, buildable example lives in `examples/consumer/`. The CTest test
`fbm.packaging.consumer` installs this project into a staging prefix,
configures and builds `examples/consumer` against that prefix with
`find_package`, and runs the resulting executable. The consumer exercises store
creation, policy publication, evidence recording, conformance evaluation,
drift detection, and a close-and-reopen recovery cycle against the installed
artifact only.

---

## Repository layout

    include/summon/fbm/   public headers; every declaration the library exports
    src/                  implementation
    apps/                 the fbm CLI and two process harness executables
    tests/                the proof suite
    examples/consumer/    out-of-tree consumer used by the packaging test
    docs/schema.md        normative description of every JSON document
    cmake/                package configuration and the packaging test driver

---

## Domain model

### Identities and generations

Every identity is a distinct type. Passing an `AssetId` where a `BaselineId` is
required is a compile error, not a review comment. Identities are 1 to 128
ASCII bytes matching `[A-Za-z0-9][A-Za-z0-9._-]*`. The rule deliberately
excludes the colon, which on Windows names an alternate data stream, and
excludes the dot-only forms that could be read as a relative path component.

Generations and counters are distinct scalar types that carry an explicit
"unset" state. An unset generation orders **before** every set generation and
is omitted from JSON rather than written as zero, so "unknown" can never be
read as "generation 0". The types include `BaselineGeneration`,
`HardwareGeneration`, `FirmwareGeneration`, `PolicyGeneration`,
`RollbackGeneration`, `DependencyGeneration`, `CapacityGeneration`,
`TopologyGeneration`, `MaintenanceGeneration`, `ControlEpoch`, `IncarnationId`,
`Revision`, `CommitSequence`, `ObservationSequence`, and `StageIndex`.

### Firmware versions

A firmware version is `major.minor.patch[.build][-prerelease][+metadata]`.
Parsing is strict: no leading zeroes in numeric components, no empty
identifiers, ASCII only. Ordering follows Semantic Versioning precedence with
one documented extension: an absent fourth component is *unset* and orders
before every present fourth component, including `.0`. It is never read as
zero. Ordering is used for reporting residuals and for selecting rollback
candidates; it never decides compatibility, because newer is not automatically
compatible.

`FirmwareVersion::operator==` is the exact-text comparison and therefore also
compares build metadata. Precedence equivalence is the named function
`same_precedence(a, b)`, and that is the relation the range and conformance
logic uses. A range is built through `VersionRange::make`, which rejects an
empty interval, so every constructible range has at least one member.

### Baselines

A baseline carries an identity, a generation, a revision, a state
(`draft`, `published`, `retired`), hardware selectors, per-component
requirements, a compatibility rule set, and a promotion gate. It is
authoritative only while it is `published`. The **content digest** is the
SHA-256 of the canonical serialization of the baseline document, so any
semantic change changes the digest and any change in key order does not.

The authoritative baseline for a hardware profile is the published baseline
with the highest generation that covers the profile. When two published
baselines share that highest generation, authority is **ambiguous** and the
query fails with `IdentityAmbiguousBaseline` rather than choosing one. That
situation cannot even be constructed through the registry for stated
generations, because publishing a second baseline for the same hardware class
at the same generation is rejected.

Each component requirement states the approved version, the set of conformant
versions (which always contains the approved version), an ordered list of
known-compatible rollback targets disjoint from the conformant set, and an
explicit freshness bound for evidence.

### Compatibility rules

A rule states: *when* a trigger component's version lies in a range (and,
optionally, the hardware revision lies in a range), *then* a requirement must
hold. Requirement kinds are component-version-in-range,
component-version-not-in-range, hardware-revision-in-range,
capability-present, and capability-absent. A requirement may only populate the
fields belonging to its kind; any other combination is rejected as an
impossible document.

Rules are constraints, not upgrade instructions. A rule whose trigger fires but
whose requirement inputs are missing yields `Unverifiable`, never `Satisfied`.

### Evidence

Hardware profile evidence and per-component firmware evidence are recorded
separately, each with an identity, a provenance identity (`EvidenceId`), an
observation sequence, an observation instant, and the reporting incarnation.

A component that was observed with an **undetermined version** is recorded with
an empty version. That is a different fact from never having observed the
component at all, and the two are never collapsed.

Observation ordering is enforced per key:

| Condition | Outcome |
| --- | --- |
| incoming sequence lower than the stored sequence | `EvidenceOutOfOrder`, rejected |
| incoming sequence equal, byte-identical content | `IdempotentReplay`, accepted, nothing written |
| incoming sequence equal, any difference | `EvidenceConflicting`, rejected |
| incoming sequence greater | `Recorded` |

The idempotent replay case is checked **before** ordinary stale rejection, so a
retry of a request whose response was lost is not mistaken for a stale request.

### Facility gates

Capacity, dependency, maintenance, and topology are owned by other
repositories. Each arrives as one of `open`, `closed`, or `unknown`, together
with its generation. An unset gate is `unknown`, and unknown is never read as
open anywhere in the library.

### Conformance states and resolution precedence

The reported state is the highest-precedence state that applies. The order is
published in `conformance.hpp` and implemented as a pure function of the state:

| Rank | State | Meaning |
| --- | --- | --- |
| 8 | `Unsupported` | The asset is outside every authoritative baseline scope |
| 7 | `Unknown` | No authoritative baseline, or required evidence is missing, stale, or undetermined, or a rule cannot be decided |
| 6 | `Blocked` | A facility gate denies mutation, or the evidence floor excludes the available evidence |
| 5 | `Exception` | An effective exception covers every outstanding residual |
| 4 | `PendingRollback` | An authorized rollback plan targets this asset |
| 3 | `PendingRollout` | An authorized rollout plan targets this asset |
| 2 | `Drifted` | At least one determinate drift residual remains |
| 1 | `Conformant` | No residual remains |

Because missing, stale, and undetermined evidence all resolve to `Unknown`
rather than to `Drifted`, absence is never converted into a determinate answer.
Because `Unknown` outranks `Exception`, an exception cannot launder
uncertainty: only a determinate drift residual is waivable.

### Drift residuals

Drift is never collapsed to a boolean. Every residual carries its kind, the
component, the rule when one produced it, the **observed** version when known,
the **required** version, the signed distance between them, the observation
instant, the freshness bound in force, a human-readable detail string that
names both sides of the comparison, and a JSON pointer path.

Residual kinds are `missing_observation`, `stale_observation`,
`unknown_version`, `version_mismatch`, `unexpected_component`,
`incompatible_combination`, and `unverifiable_rule`.

### Cohorts and promotion gates

A cohort is a staged rollout group. Creating it produces a draft. Authorizing
it binds the cohort to the exact baseline generation, baseline content digest,
policy generation, control epoch, and its own revision, and mints a plan
identity. From that point on, any advance of the baseline generation, the
baseline revision, the baseline digest, the policy generation, or the control
epoch fences the authorization.

A promotion gate is evaluated from the exact per-asset states of the cohort
members. The report retains the full count breakdown, the conformant ratio in
basis points, every unmet condition as an exact sentence, and the remaining
soak time. A failed gate changes nothing; the cohort revision does not move.
Assets whose state is unknown, unsupported, or blocked never count toward the
conformant numerator and can never promote a stage by being ignored.

### Exceptions

An exception carries scope (hardware class, optional model, optional asset, and
an optional component list where an empty list means every component in scope),
a mandatory reason, the approval identity that granted it, an explicit expiry,
and the policy generation it was granted under.

The expiry must be stated. A document either names an expiry instant or states
`never`; a missing expiry is a rejected document, because a missing expiry read
as "never" would convert an unknown into a permanent permission. Expiry is
exclusive: the grant is expired at exactly the stated instant.

An exception is effective only while it is active, unexpired, and granted under
the **current** policy generation. A policy change therefore makes every
existing exception ineffective until it is re-granted. That is deliberate: an
exception is authority, and stale authority is fenced rather than silently
inherited.

---

## Authority, generations, and fencing

Three counters move independently and mean different things:

- **`CommitSequence`** advances once per successful durable commit.
- **`ControlEpoch`** advances with it and is the durable epoch an authorization
  binds to.
- **`PolicyGeneration`** advances whenever baseline policy changes: defining,
  publishing, retiring, or applying a policy document that changes anything.

Opening the store mints a new **`IncarnationId`**. Every authorization minted
by a previous incarnation is fenced from that point on, which is how a stale
asynchronous completion is refused rather than inherited.

An authorization token binds to the scope, the baseline identity and
generation, the baseline revision, the baseline content digest, the policy
generation, the control epoch, the commit sequence, the plan identity, the
request identity, the incarnation, a digest over the exact planned mutation,
the issue instant, and an expiry. Verification performs twelve checks in a
fixed published order and returns the **first** failure, so the same token
against the same state always produces the same error.

When a signing key is supplied by the operator, tokens are HMAC-SHA256 signed.
When no key is configured, the token records its signature mode as `none`
rather than pretending to be signed, and an authority configured to require a
signature rejects an unsigned token outright. The library never generates,
stores, logs, or transmits a key.

---

## Persistence, recovery, and crash consistency

### On-disk layout

    <store>/store.lock          the cross-process writer lock
    <store>/store.fence         the fence record naming the active slot
    <store>/store.0.slot        slot record for generation in slot 0
    <store>/store.1.slot        slot record for generation in slot 1
    <store>/store.<n>.stage     a staging file, never authoritative

File names are fixed. No identity is ever used as a path component, so no
identity can escape the store directory.

### Record framing

Every durable record is one frame:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `0x314D4246` |
| 4 | 2 | format version, must equal the version this build writes |
| 6 | 2 | record kind: 1 snapshot, 2 fence |
| 8 | 4 | reserved, must be zero |
| 12 | 8 | commit sequence |
| 20 | 8 | control epoch |
| 28 | 8 | slot |
| 36 | 4 | payload length |
| 40 | 4 | payload CRC-32C |
| 44 | 32 | payload SHA-256 |
| 76 | n | payload: canonical JSON |
| 76+n | 4 | frame CRC-32C over bytes [0, 76+n) |
| 80+n | 4 | trailer magic |

The frame length is fully determined by the declared payload length, so a
truncated file and a file with trailing bytes are both detected rather than
tolerated. Decoding rejects, in a fixed order: a frame shorter than the
minimum, a wrong magic, an unsupported format version, an unknown record kind,
a non-zero reserved field, a length above the maximum, a length that does not
match the file, a wrong trailer magic, a wrong frame checksum, a wrong payload
checksum, and a wrong payload digest.

### Commit protocol

1. **Stage.** Write the framed record for the inactive slot to a staging file
   and flush it to stable storage.
2. **Verify.** Read the staging file back and prove that it decodes to exactly
   the snapshot that was intended, including its digest.
3. **Publish.** Atomically replace the inactive slot with the staging file.
4. **Fence.** Only after publication, atomically replace the fence record that
   names the active slot and its digest.

The **fence, not the rename, decides which slot is authoritative.**

### Recovery

On open, the store reads the fence. If the fence is valid, the slot it names
becomes authoritative, and that slot must verify against the fenced digest and
against its own commit sequence and control epoch; anything else is
`RecoveryInconsistentState` and the store refuses to open rather than guess.

A complete slot whose commit sequence is **ahead** of the fence is a commit
that was published but never fenced. It is reported as an unpublished slot,
and it is **not adopted**. The inactive slot normally holds the previous
generation, which is a complete and valid record, so the recovery logic
distinguishes the two by comparing commit sequences rather than by presence.

If no fence has ever been written, no generation has ever been authoritative.
The store recovers as empty and reports that any slot present was not adopted,
because a record that no fence names never becomes authority by being first on
disk.

Staging files are removed on open and are never read as a source of truth.

### Crash consistency

`apps/fbm_crash_tool.cpp` performs one real commit and terminates its own
process at a named commit point with no cleanup, no destructor, and no `atexit`
handler. Crash consistency is therefore measured, not claimed. The six
observable points are `before_stage_write`, `after_stage_flush`,
`after_stage_verify`, `after_publish`, `before_fence_write`, and
`after_fence_write`.

Because the fence gates authority, a crash before it recovers the previous
generation and discards nothing that was authoritative; a crash after it
recovers the new generation. No partially committed state is ever merged, and
the tests assert the recovered generation and the recovered content marker for
every point.

### Cross-process exclusion

The writer lock is a real operating-system lock on `store.lock`: `LockFileEx`
with an exclusive, non-waiting whole-file range on Windows, and `flock` with
`LOCK_EX | LOCK_NB` on POSIX. The kernel releases it when the holding process
exits, however it exits. The test suite proves this by killing a real holder
process and observing a different process acquire the lock.

---

## Concurrency model

- **Readers** acquire the published snapshot through one atomic load and then
  work on their own immutable value. Readers never take a lock, never block on
  a writer, and never observe a partially applied mutation.
- **Writers** serialize on a single mutex, build a complete new snapshot,
  commit it durably, and only then publish it with one atomic store. A commit
  that fails leaves the previously published snapshot in place and unchanged.
- **No callback, event, or user code ever runs while the writer mutex is
  held.** The library has no event bus and no user callbacks. The one
  instrumentation hook, `ICommitObserver`, is used only by the crash harness
  against a store directly, and its documentation states that an implementation
  must not re-enter the store.
- The cross-process writer lock is acquired exactly once, at open, and held for
  the lifetime of the object. There is therefore no lock nesting anywhere in
  the library, and consequently no lock-order inversion is possible. The manual
  audit recorded in this repository covers self-deadlock, reentrancy, inversion,
  callbacks under lock, joins while holding state, shutdown waits, and
  cancellation-order inversion; the single-lock design removes all of them
  structurally rather than by convention.

---

## Error model

Every error carries a code, a human-readable message, and the field path within
the request or document where the defect was found. Codes are grouped:

| Category | Meaning |
| --- | --- |
| 1xx | Durable record framing and integrity |
| 2xx | Text and JSON encoding |
| 3xx | Schema shape of a document |
| 4xx | Resolution of identities |
| 5xx | Authority, generations, and fencing |
| 6xx | Policy semantics |
| 7xx | Evidence |
| 8xx | Operational failures against the host |

Validation collects every defect into a `Diagnostics` accumulator and then
selects exactly one **primary** error. The rank is a pure function of the code
(`category * 100 + member`), so the 1xx class always outranks 2xx, which
outranks 3xx, and so on. Remaining ties break on the field path, then the
message, then the code. The result therefore never depends on map iteration
order, thread scheduling, allocation addresses, or the order in which defects
happened to be discovered, and the same invalid request always resolves to the
same primary error.

Every code has a stable lowercase token, such as `format_checksum_mismatch` or
`authority_stale_policy_generation`. Tokens are part of the command-line
contract and are never reused with a different meaning.

---

## Command-line interface

    fbm [global options] <group> <command> [options]

Global options:

| Option | Meaning |
| --- | --- |
| `--store <dir>` | Store directory. Defaults to `.fbm-store` |
| `--json` | Emit canonical machine-readable JSON |
| `--at <rfc3339>` | The instant an operation is evaluated at |
| `--key-file <path>` | Operator-supplied HMAC key for authorizations |
| `--require-signature` | Reject any authorization that is not HMAC-signed |

Exit codes: `0` success, `1` the library rejected the request, `2` usage error.

A complete worked example:

    fbm --store ./fleet init
    fbm --store ./fleet baseline define --file baseline.json
    fbm --store ./fleet baseline list
    fbm --store ./fleet baseline publish gpu-h100-train --generation 1

    fbm --store ./fleet observe --asset node-01 \
        --evidence ev-profile-1 --sequence 1 \
        --hardware-class gpu --model h100 --revision 2

    fbm --store ./fleet observe --asset node-01 \
        --evidence ev-bmc-1 --sequence 2 --component bmc --version 2.4.0

    fbm --store ./fleet evaluate --asset node-01
    fbm --store ./fleet drift --asset node-01
    fbm --store ./fleet explain --asset node-01

    fbm --store ./fleet exception add --id exc-1 --hardware-class gpu \
        --asset node-01 --component bmc --reason "vendor field notice" \
        --approval approval-7 --expires-at 2026-03-01T00:00:00.000000000Z

    fbm --store ./fleet cohort create --id wave-1 \
        --baseline gpu-h100-train --generation 1 --asset node-01
    fbm --store ./fleet cohort authorize --id wave-1 --revision 1

    fbm --store ./fleet cohort promote --id wave-1 --revision 2 \
        --capacity open --capacity-generation 7 \
        --dependency open --dependency-generation 8 \
        --maintenance open --maintenance-generation 9 \
        --topology open --topology-generation 10

    fbm --store ./fleet authorize rollout --id wave-1 --revision 3 --request req-1
    fbm --store ./fleet rollout-eligibility --asset node-01 \
        --capacity open --capacity-generation 7 \
        --dependency open --dependency-generation 8 \
        --maintenance open --maintenance-generation 9 \
        --topology open --topology-generation 10

    fbm --store ./fleet rollback-eligibility --asset node-01 --target 2.3.9
    fbm --store ./fleet status
    fbm --store ./fleet verify

Every command that writes prints the resulting state, and every command that
evaluates prints the authority it evaluated against: the baseline identity,
generation, revision, and content digest, plus the policy generation, control
epoch, and commit sequence.

---

## Policy documents and schema

A policy document is strict JSON with an exact schema:

    {
      "schema": "summon.fbm.policy",
      "schema_version": 1,
      "baselines": [ ... ]
    }

Its identity is the SHA-256 of its canonical serialization. Canonical form has
no insignificant whitespace and sorts object members by key byte order, so two
documents that differ only in key order or whitespace have the same identity and
any semantic change produces a different one. Applying an identical document
again is idempotent: nothing changes, no generation advances, and no
authorization is fenced.

A detached HMAC-SHA256 signature may accompany a document. Verification reports
one of three outcomes and never conflates them: `not_configured` when no key was
supplied, `valid`, or `invalid`. `docs/schema.md` is the normative description
of every document the library reads or writes, including the policy document,
the snapshot, observations, cohorts, exceptions, authorization tokens, and
facility gates. Anything not described there is rejected as an unknown field;
nothing is accepted by guessing.

---

## Hardening

The library was attacked deliberately and the defects that were found were
fixed at the root. The current suite covers, as executable tests: malformed and
truncated frames at every length and every byte position, single-byte
corruption at every offset, torn fences, corrupt active slots, missing fences,
staging files that must never be adopted, absurd and boundary numeric values,
integer overflow in every counter, duplicate identifiers at every level, stale
generations and stale authority, reordered and conflicting evidence, invalid
Unicode and embedded NUL bytes, path traversal and Windows alternate-data-stream
forms in identifiers, repeated open and close, a second writer in the same
process, hostile documents that exceed every configured limit, and repeated
crash and recovery cycles.

---

## Contributing

See `CONTRIBUTING.md`.

## Validation performed

Everything below was executed on the host described in each line. Nothing in
this section is projected, estimated, or inferred.

### Toolchain

- Windows, Microsoft Visual Studio 2022 Community, MSVC 19.44.35207, C++20, no
  compiler extensions.
- CMake 4.3.2, Ninja 1.13.2.

### Release configuration

    cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DFBM_BUILD_BENCHMARKS=ON
    cmake --build build-release
    ctest --test-dir build-release --output-on-failure

Result: the whole tree, including every first-party source and test, compiled
with zero warnings under `/W4 /permissive- /WX`. `ctest` reported:

    Test #1: fbm.unit ............... Passed   10.69 sec
    Test #2: fbm.packaging.consumer . Passed    4.86 sec
    100% tests passed, 0 tests failed out of 2

Running `fbm_tests` directly reported:

    250 test(s) executed, 0 skipped, 84287 check(s), 0 failure(s)

### Debug configuration

    cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
    cmake --build build-debug
    ctest --test-dir build-debug --output-on-failure

Result: zero warnings under `/W4 /permissive- /WX`, and

    Test #1: fbm.unit ............... Passed   45.52 sec
    Test #2: fbm.packaging.consumer . Passed    4.53 sec
    100% tests passed, 0 tests failed out of 2

The Debug configuration is built with the toolchain's run-time checks
(`/RTC1`: stack frame checking and uninitialized-variable detection) and with
iterator debugging enabled. It is not a formality: the Debug configuration
caught a use-after-free in the command-line tool that the Release configuration
did not, and that defect is fixed (see below).

### Sanitizers

AddressSanitizer and UndefinedBehaviorSanitizer could **not** be run on this
host. The MSVC AddressSanitizer runtime libraries are not installed in this
Visual Studio instance, so linking an ASan binary fails with
`LNK1104: cannot open file 'clang_rt.asan_dynamic_runtime_thunk-x86_64.lib'`.
`FBM_ENABLE_SANITIZERS=ON` now probes for the runtime at configure time and
fails configuration with an actionable message rather than producing a broken
build, and this project reports no sanitizer results it did not observe.

The memory-safety evidence that does exist is therefore: the `/RTC1` Debug run
above over the whole suite, the adversarial suite's exhaustive single-byte
corruption and prefix-truncation sweeps over real durable records, and the
defect that the Debug run actually found and that was fixed.

### Real defects found during hardening

These were found by running, not by reading, and each was fixed at the root.

1. **Unpublished-slot detection was wrong.** With two slots, the inactive slot
   always holds the previous, perfectly valid generation, so "the other slot is
   present" is not evidence of an interrupted commit. Recovery now compares the
   other slot's commit sequence against the fence and only reports an
   unpublished slot when it is genuinely ahead. Without this, every recovery
   after the second commit would have claimed a discarded commit.

2. **Every `Digest` member was indeterminate.** `Digest` is a
   `std::array<std::uint8_t, 32>`, an aggregate of scalars, so a default-
   initialized `Digest` member holds whatever was on the stack. `create_cohort`
   produced a draft whose `baseline_digest` was garbage, which validation then
   rejected non-deterministically; verdicts and recovery reports could serialize
   indeterminate bytes. Fixed by value-initializing every `Digest` member and
   every enclosing aggregate at its declaration.

3. **Missing and stale evidence resolved to `Drifted`.** A component that had
   never been observed produced a `missing_observation` residual and therefore a
   `Drifted` verdict, which converts an absent measurement into a determinate
   answer. Missing, stale, and undetermined evidence now also raise an
   `Unknown` candidate, and only a determinate drift residual is waivable by an
   exception.

4. **Cohort promotion was not fenced.** `promote_cohort` checked the cohort's own
   revision but not the baseline generation, policy generation, or baseline
   content digest it was authorized against, so a cohort could be promoted on a
   voided authorization after the baseline moved. Promotion now performs the same
   fencing as minting.

5. **The control epoch advanced on every commit.** Because authorization tokens
   bind the epoch, a token was stale the instant it was minted and the documented
   `authorize rollout` then `token verify` sequence could never succeed. The store
   now preserves the caller's epoch across commits and the authority advances it
   once per incarnation, so the epoch fences what it is meant to fence: a
   superseded control plane, not unrelated evidence.

6. **A token's incarnation was treated as a fence.** An authorization exists to
   be executed by a different process, often after the authority has restarted,
   so requiring the minting incarnation to still be current made every
   cross-process verification fail. The incarnation is now provenance; the
   fences that still apply are scope, baseline identity, generation, revision and
   digest, policy generation, control epoch, plan, subject digest, and expiry.

7. **A running cohort's members could never count as conformant.** Every member
   of a running cohort was reported as `PendingRollout`, which outranks
   `Conformant`, so a promotion gate could never count the very members it gates.
   `PendingRollout` and `PendingRollback` are now reported only for an asset that
   still has outstanding work.

8. **The recovery report fabricated zeros.** A store with no committed generation
   reported commit sequence 0 and control epoch 0, and a fresh store's snapshot
   was written with those zeros. Both now stay unset and are omitted from the
   report, so "no generation" is never spelled "generation zero".

9. **Use-after-free in the command-line tool.** `cohort promote` passed the
   temporary vector returned by `cohorts()` into a lookup that returns a pointer,
   leaving the pointer aimed at freed memory. Release read stale-but-intact data;
   Debug read poisoned memory and threw `std::length_error("string too long")`.
   The cohort list is now materialized into a named local before the lookup.

10. **Two build-system defects.** `@PROJECT_VERSION@` is not expanded by
    `target_compile_definitions`, so `FBM_VERSION_STRING` was literally
    "`@PROJECT_VERSION@`"; and `$<SHELL_PATH:...>` keeps native separators on
    Windows, so the harness paths became invalid C++ escape sequences. Both are
    fixed by using a plain configure-time variable and the bare executable name.

11. **A gate could not be satisfied by any authorable policy.** The promotion
    gate rejected `minimum_conformant_assets = 0` while the engine could not
    count a running cohort's conformant members (defect 7). Relaxed so a gate may
    demand no conformant assets; `minimum_decided_assets` must still be at least
    one, and every unknown, unsupported, or blocked member is reported as an
    unmet condition rather than counted.

### Test coverage actually executed

| Area | What is proven |
| --- | --- |
| Foundations | SHA-256 against the FIPS 180-4 vectors and HMAC-SHA256 against RFC 4231, CRC-32C against known values, streaming equality at every split point, strict RFC 3339 parsing and formatting, firmware version total order and distance |
| Encoding | Strict JSON: canonical round trip, key-order independence, byte order mark, overlong and surrogate UTF-8, unescaped control bytes, malformed numbers and literals, duplicate keys, trailing content, every configured limit, and a deterministic sweep over truncations and single-byte mutations |
| Policy | Requirement evaluation for every kind and every unverifiable path, all five rule outcomes, self-contradiction detection, deterministic rule order, baseline authority selection, ambiguity reported rather than resolved, content-digest sensitivity |
| Evidence | All four ordering outcomes including idempotent lost-response replay, conflicting replay rejected, stale evidence never replacing newer evidence, undetermined version preserved as absent |
| Authority | All twelve verification checks each failing alone, the documented first-failure precedence, exclusive expiry, idempotent replay and replay rejection |
| Persistence | Frame decoding rejecting every malformed shape, every single-byte corruption at every offset, every prefix truncation, torn fences, corrupt active slots, absent fences, stale staging files, relocated stores |
| Crash consistency | Real process termination at all six commit points; exactly one authoritative generation recovered each time; the recovered content marker asserted for every point; three repeated cycles across all six points; the store usable afterwards |
| Multiprocess | A real peer process locked out by another; the kernel releasing the lock when the holder is killed; sequential commits from independent processes each advancing by one; cross-process visibility of a committed generation |
| Property | Canonical round trip and key-order independence, total order over a 96-version corpus, range containment against an independently written predicate, streaming digests, digest hex round trip, baseline digest stability, store round trip, identifier validation against an independent predicate |
| State machine | Four deterministic seeds, 120 randomized operations each, invariants checked after every operation, with the seed, step, and operation printed on failure |
| Adversarial | Absurd and boundary numerics, counter overflow reported not wrapped, duplicate identities at every level, stale generations and revisions, reordered evidence, hostile identities including traversal and alternate-data-stream forms, invalid encoding, long paths, repeated open and close, disk failures, resource limits, and repeated runs returning identical errors |
| Concurrency | Four readers against one writer with no torn read, reader completion, contiguous commit sequences with no gaps or duplicates, rejected mutations leaving the snapshot unchanged, and a commit observer proving the manager never invokes user code inside its critical section |
| Packaging | The installed library, headers, CMake package, and tool installed into a staging prefix; an independent out-of-tree consumer configured with `find_package(FirmwareBaselineManager)`, built, and run; and the installed command-line tool exercised as a real process |

### Fresh clone

The complete tree was copied into a separate directory with no version-control
metadata, no build cache, no generated files, and no prior configuration, and
built and tested there from scratch:

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ctest --test-dir build --output-on-failure

Result: configuration succeeded, the build produced zero warnings under
`/W4 /permissive- /WX`, and

    Test #1: fbm.unit ............... Passed    9.31 sec
    Test #2: fbm.packaging.consumer . Passed    3.08 sec
    100% tests passed, 0 tests failed out of 2

After the release commit and the annotated tag were published, a real
`git clone` of the published repository was configured, built, and tested the
same way, with the same result.


## Benchmarks

Methodology, stated so the numbers can be read correctly:

- Every throughput figure counts **completed** operations. Nothing measures
  submission or enqueue latency.
- The durable commit benchmark includes the whole durable cost a caller waits
  for: stage, flush, read-back verify, atomic publish, and fence.
- Latency figures are the median of the individual completed operations over the
  full sample, not a mean of means.
- Inputs are **SYNTHETIC**: generated in process. The storage medium and the
  operating system are **REAL**, so the durable numbers describe this host.
- Environment: MSVC 19.44, Release, Windows, `fbm_bench` at version 1.0.0.
- No before/after comparison is claimed; these are absolute figures from one
  configuration.

| Benchmark | Completed ops | Per second | Median | Payload |
| --- | --- | --- | --- | --- |
| Durable commit (full barrier cycle) | 200 | 96 | 9.95 ms | 47,876 bytes total |
| Conformance evaluation (32 assets) | 2,000 | 14,919 | 60.2 us | read-only, no durable cost |
| Policy document parse and canonicalize | 500 | 3,213 | 276.3 us | 7,670-byte document |

A repeat run of the same binary on the same host gave 103 commits/s, 16,422
evaluations/s, and 2,515 parses/s. The spread between the two runs is roughly
ten percent, which is the honest precision of a measurement taken on a general
purpose workstation with a warm page cache and no isolation; the figures above
should be read as order-of-magnitude characterizations, not as guarantees.

The durable commit figure is dominated by the two durable barriers per commit,
which is the intended trade: the store pays a full flush and a read-back
verification on every commit so that recovery never has to guess.


## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
