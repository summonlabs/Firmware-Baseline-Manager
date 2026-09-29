# Durable and policy document schema

This file is the normative description of every JSON document this repository reads or writes.
It is implemented by the strict reader in `src/json.cpp` plus the per-type validators. Anything
not described here is rejected as an unknown field; nothing is accepted by guessing.

## Common encodings

| Concept | Encoding |
| --- | --- |
| Identity (`AssetId`, `BaselineId`, ...) | JSON string matching the identifier rule in `identifier.hpp`: 1 to 128 ASCII bytes, first byte `[A-Za-z0-9]`, remaining `[A-Za-z0-9._-]` |
| Generation, counter, revision, epoch, sequence | JSON non-negative integer. An unset counter is **omitted**, never written as `0` |
| Timestamp | JSON string `YYYY-MM-DDTHH:MM:SS.fffffffffZ` (exactly nine fractional digits, UTC) |
| Digest | JSON string of exactly 64 lower-case hexadecimal characters |
| Firmware version | JSON string parsed by `FirmwareVersion::parse` |
| Expiry | Exactly one of `"expires_at": "<timestamp>"` or `"expires": "never"` |
| Freshness bound | Exactly one of `"max_age_nanos": <int>` or `"unbounded": true` |

### Version range

```json
{ "min": "1.2.0", "min_inclusive": true, "max": "2.0.0", "max_inclusive": false }
```

`min` and `max` are each optional; an absent bound is unbounded on that side. `min_inclusive` is
required exactly when `min` is present, and `max_inclusive` exactly when `max` is present.

### Hardware profile

```json
{
  "hardware_class": "gpu",
  "model": "h100",
  "revision": 4,
  "capabilities_observed": true,
  "capabilities": ["nvlink4", "sriov"]
}
```

`model` and `revision` are optional and mean *not observed* when absent. `capabilities_observed`
is required. `capabilities` is optional and defaults to the empty set; it is only meaningful when
`capabilities_observed` is true, and validation rejects a non-empty `capabilities` with
`capabilities_observed` false as an impossible combination.

### Requirement

```json
{ "kind": "component_version_in_range", "component": "bmc", "versions": { ... } }
{ "kind": "component_version_not_in_range", "component": "bmc", "versions": { ... } }
{ "kind": "hardware_revision_in_range", "minimum_revision": 1, "maximum_revision": 4 }
{ "kind": "capability_present", "capability": "sriov" }
{ "kind": "capability_absent", "capability": "sriov" }
```

Only the fields belonging to the stated kind may be present. Any other combination is
`SchemaInconsistentDocument`.

### Compatibility rule

```json
{
  "id": "r-bmc-bios",
  "when_component": "bmc",
  "when_versions": { "min": "2.4.0", "min_inclusive": true },
  "when_minimum_revision": 1,
  "when_maximum_revision": 3,
  "requirement": { "kind": "component_version_in_range", "component": "bios", "versions": { ... } },
  "reason": "BMC 2.4 requires BIOS 3.x"
}
```

`when_minimum_revision` and `when_maximum_revision` are optional. `reason` must be non-empty.

### Hardware selector

```json
{ "hardware_class": "gpu", "model": "h100", "minimum_revision": 1, "maximum_revision": 4 }
```

`model`, `minimum_revision`, and `maximum_revision` are optional.

### Component requirement

```json
{
  "component": "bmc",
  "approved": "2.4.1",
  "conformant": ["2.4.0", "2.4.1"],
  "rollback_targets": ["2.3.9", "2.3.8"],
  "freshness": { "max_age_nanos": 86400000000000 }
}
```

`conformant` must contain `approved`. `rollback_targets` is ordered most-preferred first and must
be disjoint from `conformant`. `freshness` is required.

### Promotion gate

```json
{
  "minimum_conformant_basis_points": 9900,
  "minimum_decided_assets": 2,
  "minimum_conformant_assets": 2,
  "soak_nanos": 0,
  "required_stages": 2
}
```

All five members are required. `minimum_conformant_basis_points` is at most 10000.

### Baseline

```json
{
  "id": "gpu-h100-train",
  "generation": 3,
  "revision": 5,
  "state": "published",
  "title": "H100 training baseline",
  "selectors": [ ... ],
  "components": [ ... ],
  "rules": [ ... ],
  "gate": { ... },
  "created_at": "...",
  "published_at": "..."
}
```

`state` is one of `draft`, `published`, `retired`. `selectors` and `components` must be non-empty,
sorted ascending by hardware class (then model) and by component identity respectively, with no
duplicates. `published_at` is required exactly when `state` is not `draft`; for a draft it must be
absent. This is the content digest input: the digest is SHA-256 over the canonical serialization of
exactly this object.

### Hardware observation

```json
{
  "id": "obs-1", "evidence": "ev-1", "asset": "node-01",
  "hardware": { ...profile... }, "hardware_generation": 7,
  "sequence": 12, "observed_at": "...", "reporter": 3
}
```

### Firmware observation

```json
{
  "id": "obs-2", "evidence": "ev-2", "asset": "node-01",
  "component": "bmc", "version": "2.4.0", "firmware_generation": 4,
  "sequence": 13, "observed_at": "...", "reporter": 3
}
```

`version` is **omitted** when the component was observed but its version was not determined. That
absence is meaningful and is never replaced by the approved version or by zero.

### Observation log

```json
{ "profiles": [ ... ], "components": [ ... ] }
```

`profiles` is ascending by asset identity; `components` is ascending by asset identity then
component identity.

### Exception scope

```json
{ "hardware_class": "gpu", "model": "h100", "asset": "node-01", "components": ["bmc"] }
```

`model`, `asset`, and `components` are optional. An empty `components` means every component in
scope, which is a deliberate widening and not a missing field.

### Baseline exception

```json
{
  "id": "exc-1", "scope": { ... }, "expires_at": "...",
  "reason": "...", "approval": "ap-1", "granted_under": 4,
  "revision": 1, "state": "active", "created_at": "..."
}
```

`state` is `active` or `revoked`. `revoked_at` is required exactly when `state` is `revoked` and
must be absent otherwise.

### Cohort

```json
{
  "id": "wave-1", "baseline": "gpu-h100-train", "baseline_generation": 3,
  "baseline_digest": "<hex>", "policy_generation": 4, "authorized_epoch": 9,
  "revision": 2, "stage": 1, "required_stages": 2, "state": "active",
  "members": ["node-01", "node-02"], "plan": "plan-1",
  "created_at": "...", "stage_entered_at": "...", "note": "..."
}
```

`state` is one of `draft`, `authorized`, `active`, `paused`, `completed`, `rolled_back`,
`cancelled`. `baseline_digest`, `policy_generation`, `authorized_epoch`, and `plan` are required
exactly when `state` is not `draft`, and must be absent for a draft. `members` is sorted, unique,
and non-empty. `last_promoted_at` is optional.

### Authority binding

```json
{
  "scope": "cohort/wave-1/rollout",
  "baseline": "gpu-h100-train", "baseline_generation": 3, "baseline_revision": 5,
  "baseline_digest": "<hex>", "policy_generation": 4, "control_epoch": 9,
  "commit_sequence": 11, "plan": "plan-1", "request": "req-1", "incarnation": 3,
  "subject_digest": "<hex>", "issued_at": "...", "expires_at": "...",
  "signature_mode": "none"
}
```

`signature_mode` is `none` or `hmac_sha256`.

### Authorization token

```json
{ "binding": { ... }, "mac": "<hex>" }
```

`mac` is required. It is the all-zero digest when `signature_mode` is `none`.

### Facility gates

```json
{
  "capacity": "open", "capacity_generation": 3,
  "dependency": "open", "dependency_generation": 3,
  "maintenance": "open", "maintenance_generation": 3,
  "topology": "open", "topology_generation": 3
}
```

Each gate is `open`, `closed`, or `unknown` and each has a required generation. `closed_reason` is
optional.

### Snapshot

```json
{
  "format": "summon.fbm.snapshot", "format_version": 1,
  "commit_sequence": 11, "control_epoch": 9, "policy_generation": 4, "revision": 12,
  "incarnation": 3, "created_at": "...", "updated_at": "...",
  "baselines": [ ... ],
  "observations": { "profiles": [ ... ], "components": [ ... ] },
  "exceptions": [ ... ], "cohorts": [ ... ], "authorizations": [ ... ]
}
```

Every array is ascending by identity. `format` and `format_version` are checked before anything
else; a snapshot written by a different schema version is rejected with
`FormatVersionUnsupported` rather than partially interpreted.

### Policy document

```json
{ "schema": "summon.fbm.policy", "schema_version": 1, "baselines": [ ... ] }
```

### Detached signature

```json
{ "schema": "summon.fbm.signature", "schema_version": 1, "mode": "hmac_sha256", "mac": "<hex>" }
```

## Validation precedence

Validation collects every defect and then selects exactly one primary error. The precedence is
the category order implemented by `error_precedence`: frame integrity, then text encoding, then
schema shape, then identity resolution, then authority, then policy semantics, then evidence,
then operational failures. Within a category the lower code wins, and remaining ties break on the
field path and then the message text. The result therefore never depends on map iteration order,
thread scheduling, or the order in which defects were discovered.
