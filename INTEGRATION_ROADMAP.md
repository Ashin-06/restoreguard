# Future integrations and extended design

This document preserves the larger product design. **The capabilities below are not part of the local SQLite reference prototype.** They must not be described as completed integrations.

## Real identity and secrets services

Candidate integrations are Keycloak and Vault/OpenBao in disposable, version-pinned environments. Adding them requires an adapter that can create a fictional fixture, take a supported snapshot, restore it safely, verify health, probe actual protected effects, and clean up only resources belonging to the run.

```text
Future adapter contract:
  create_fixture(spec) -> instance
  snapshot(instance, checkpoint) -> manifest
  restore(instance, manifest) -> receipt
  health(instance) -> observation
  probe(actor, action, resource, credential_ref) -> effect
  cleanup(instance) -> receipt
```

These interfaces are proposed. No production credential should be supplied to the reference prototype, and no result from a synthetic fixture is evidence of a vulnerability in one of these products.

## Proposed future modules

```text
Future additions, not current files:
  adapters/base.py             # explicit lifecycle contract
  adapters/keycloak.py         # supported identity-server versions
  adapters/vault.py            # supported Vault/OpenBao versions
  scenario_loader.py          # validated declarative scenario input
  external_clock.py           # explicit real-time TTL experiments
  lab/compose.yaml            # isolated disposable integration lab
  tests/integration/          # adapter and restore interoperability tests
```

A local container engine and service images would be needed for this stage. They are not dependencies of the current standard-library prototype. Pin exact versions and measure actual hardware requirements when this work starts; do not carry forward an unverified fixed memory requirement.

## Declarative scenario files

The JSON files under `examples/` retain the proposed scenario-language design. The reference runner uses its built-in catalogue and does not execute those JSON descriptions. An implementation of file loading would need strict schemas, rejected unknown fields, typed operations, adapter allowlists, bounded resource use, and no arbitrary command or URL execution.

The larger design also envisages snapshot manifests with compatibility checks, restore receipts, and a policy journal outside the restoration set. The existence of a sample field does not mean the runtime currently exposes or validates it.

## Recovery dimensions outside the first prototype

- Restore order as a separate dimension from the selected checkpoint of each component.
- External caches, delayed replication, real token expiry, partitions, and asynchronous jobs.
- Product-native sessions, JWT validation, key rotation, and downstream secret leases.
- Larger search spaces using declared sampling or pairwise coverage.
- A maintained library of customer-written invariants for owned staging environments.
- Suggested recovery procedures validated through repeatable experiments.

Changing a clock inside a Python fixture does not establish behavior of a real external service. Repeated fixture runs measure repeatability within that fixture, not real-world concurrency coverage.

## Required isolation before real adapters

A restored secrets service can act on old lease records. Restored identity services may contain webhooks, scheduled jobs, and stale credentials. A future integration lab must prevent those components from contacting real consumers before any restored service starts. Network controls, service configuration, credentials, and background jobs all require explicit boundaries.

## Optional AI assistance

AI could explain an already classified trace or draft a new scenario for review. It must not decide whether an operation happened, rewrite the expected policy after seeing a result, or approve a production recovery. The reference prototype has no model dependency.

## Evidence required for a future integration claim

Publish the exact supported version, configuration, snapshot procedure, actual access probe, positive control, cleanup behavior, and replay record. Keep product-specific findings separate from deliberately seeded application defects. A clean integration run supports only the tested invariants and conditions.
