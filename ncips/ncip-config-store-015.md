---
ncip: 15
title: Configuration Store — Schema, Layered Desired State, Config-as-Code
track: Standards Track
status: Review
authors: [hello@nexacoreos.com]
created: 2026-07-02
license: CC0-1.0
---

## Abstract

This NCIP specifies the NexaCore **configuration store**: a schema-validated,
declarative, layered settings system. It fixes the typed value model, the key
schema registry, the desired-state representation, the diff/apply/rollback
protocol against a pluggable backend, layer composition, profile import/export,
and the config-as-code text format. Settings are described as *desired state*
and reconciled, not mutated ad hoc, so configuration is reproducible and
auditable.

## Motivation

A system with per-user, per-machine, and administrator settings needs one
disciplined path for reading and writing them, or every subsystem invents its
own file format and validation. A schema-first, declarative store gives type
safety (a tunable cannot be set to an out-of-range or wrong-typed value),
reproducibility (a profile is a portable description of desired state), and safe
rollout (diff before apply, rollback after). It also lets configuration be
expressed as code and version-controlled.

## Specification

### Value model

`ConfigValue` is a typed value; `ValueType` classifies it. `KeySchema` describes
a key's `ValueType`, constraints, and default; `KeySchema::validate(value)`
rejects a value that is the wrong type or out of range fail-closed.

### Schema registry

`SchemaRegistry` maps a `Key` to its `KeySchema` (`register`/`get`). A curated
set of safe, user-exposed tunables is provided by `register_safe_tunables` from a
`catalog()` of `TunableSpec`s, so a settings UI enumerates exactly the keys a
user may change.

### Desired state and reconciliation

`DesiredConfig` is a set of `(Key, ConfigValue)` entries — the intended state.
Against a `ConfigStore<B: ConfigBackend>`:

- `diff(desired)` computes the `ConfigChange` set (what would change) **without**
  writing.
- `apply(desired)` validates every entry against the schema, then writes only the
  changed keys, returning the applied changes.
- `rollback(changes)` reverts a previously applied change set.

The backend is the `ConfigBackend` trait (default `MemoryBackend`); persistence
implementations plug in without changing the reconciliation logic.

### Layering and profiles

`compose(layers)` merges an ordered list of `DesiredConfig` layers (later layers
win) into one effective desired state — the mechanism for system < machine <
user precedence. `export_profile(store)` serializes the current effective state
to a `DesiredConfig`; `import_profile` applies a profile. `parse(text)` reads the
config-as-code text format into a `DesiredConfig`.

## Rationale

Desired-state reconciliation (diff → apply → rollback) is chosen over direct
mutation because it makes every change previewable, validated, and reversible —
the same discipline that makes infrastructure-as-code trustworthy, applied to OS
settings. Schema-first validation moves errors to write time instead of letting a
malformed value surface as a runtime failure in a consumer. A pluggable backend
keeps the policy (schema, diff, layering) independent of the storage medium.

## Backwards Compatibility

N/A — new subsystem defining the configuration contract. Consumers migrate to it
incrementally; there is no prior public config API to preserve.

## Test Cases

Host tests in `crates/nexacore-config/` cover: `KeySchema::validate` accepting valid
and rejecting mistyped/out-of-range values; `diff` reporting only real changes;
`apply` writing changed keys and rejecting schema-invalid input; `rollback`
restoring prior values; `compose` layer precedence; `export`/`import` profile
round-trips; and `parse` of the config-as-code text.

## Reference Implementation

`crates/nexacore-config/` (package `nexacore-config`): `value` (`ConfigValue`/
`ValueType`), `schema` (`KeySchema`/`SchemaRegistry`), `store`
(`ConfigBackend`/`ConfigStore`/`MemoryBackend`), `declarative` (`DesiredConfig`,
diff/apply/rollback/compose/import/export/parse), `tunable`
(`TunableSpec`/catalog). Plan task WS12 configuration workstream.

## Security Considerations

Schema validation is fail-closed: an out-of-range or wrong-typed value is
rejected before it is written, so a malformed config cannot drive a consumer into
undefined behaviour. The safe-tunable catalog bounds what a non-administrator may
change, so security-sensitive keys are not user-exposed by default. `apply`
validates the entire desired set before writing any key, so a partially-invalid
profile does not leave the store in a mixed state. Rollback provides a recovery
path after a bad change.

## Privacy Considerations

Configuration values may include user preferences; the store carries only the
keys and values a consumer defines and attaches no telemetry. Per-user values are
scoped by `UserId` at read time, so one user's settings are not exposed to
another. Exported profiles contain exactly the desired state the user chose to
export and no hidden identifiers.

## Copyright

This document is placed in the public domain under CC0-1.0.
