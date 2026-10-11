# Future integrations and extended design

This document preserves the remaining larger design. One bounded real adapter is delivered: **OpenBao 2.7.1, owned disposable single-node Raft, service-token revocation and two native restore checkpoints**, with strict executable inputs. See [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md). Additional capabilities below remain future work.

## Real identity and secrets services

Candidate additions are Keycloak and independently tested HashiCorp Vault compatibility. OpenBao could grow beyond service-token revocation to identities, key rotation and downstream leases. Each addition needs a supported snapshot procedure, real effect probes, legitimate-access controls and cleanup of only run-owned resources.

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
  adapters/vault.py            # independently tested Vault compatibility
  scenario_loader.py          # validated declarative scenario input
  external_clock.py           # explicit real-time TTL experiments
  lab/compose.yaml            # isolated disposable integration lab
  tests/integration/          # adapter and restore interoperability tests
```

A container-based extension needs its own engine and pinned images. The delivered native OpenBao adapter uses a verified executable and needs no Docker engine. Pin versions and measure hardware requirements for each further integration.

## Declarative scenario files

`examples/lab-config.json` and `examples/scenarios.json` retain the broader proposed language and are not executed. `examples/openbao-local.json` is implemented: bounded repetitions, two native checkpoint types and expected outcomes, with unknown fields and duplicate keys rejected. A general operation language remains future work and must preserve strict schemas, allowlists and bounded resource use without arbitrary commands or URLs.

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

A restored secrets service can act on old lease records. Restored identity services may contain webhooks and scheduled jobs. The delivered adapter creates a new service with only synthetic KV data and tokens, uses loopback listeners, and accepts no foreign snapshot or endpoint. It is not an OS sandbox. Extensions with real consumers require explicit network, credential and background-job boundaries before startup.

## Optional AI assistance

AI could explain an already classified trace or draft a new scenario for review. It must not decide whether an operation happened, rewrite the expected policy after seeing a result, or approve a production recovery. The reference prototype has no model dependency.

## Evidence required for a future integration claim

Publish the exact supported version, configuration, snapshot procedure, actual access probe, positive control, cleanup behavior, and replay record. Keep product-specific findings separate from deliberately seeded application defects. A clean integration run supports only the tested invariants and conditions.
