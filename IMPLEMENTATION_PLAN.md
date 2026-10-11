# Delivered scope and next milestones

The local reference prototype and one bounded real OpenBao integration are implemented. The larger product design remains a roadmap; production integrations are not claimed.

## Delivered reference layer

The core builds separate identity, permissions, and secrets SQLite stores, captures A/B/C snapshots, verifies a pre-recovery security baseline, and restores selected copies. The expected-policy journal and effect log remain outside the restoration set.

The built-in matrix, protected/vulnerable modes, repeated trials, six scenario checks, and finding-preserving reduction provide a small reproducible basis for demonstrating recovery-security failures. The command-line entry point, local interface, and evidence workflow make the experiments reviewable.

The SQLite runtime uses a fixed catalogue. Native OpenBao scenarios use the strict executable `restoreguard.openbao.v1` format. A general JSON operation interpreter, customer adapters and arbitrary backup import are not delivered.

## Delivered native integration

OpenBao 2.7.1 runs in an owned disposable Raft process. The adapter verifies restricted-token revocation and legitimate access, captures two native snapshots, verifies restore completion with a checkpoint barrier and probes actual KV reads against independent current intent. Repeated fresh instances, redacted evidence, verification, cleanup and a real integration test are delivered. See [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md).

## Reproduction gate

Before describing a local checkout as verified, run the checks in [EVALUATION.md](EVALUATION.md) and retain their actual outputs. Implementation existence is different from a measured test result. Claims about counts or speed must refer to a specific recorded run.

The gate should include a vulnerable matrix, protected matrix, all six scenario expectations, a reduced role failure, a deliberately limited reduction budget, and integrity verification of a generated bundle.

## Next milestone — stronger reference evidence

Possible additions include richer comparison between runs, an explicit export/replay format for fixture operations, longer-lived audit provenance, and measured resource use. These should preserve the current distinction between actual experiment evidence and a regenerated reference fixture.

A hash manifest alone is not a cryptographic attestation of execution. A future signed evidence design must define collector trust and key custody.

## Next milestone — external adapters

Add one pinned product or scenario family at a time. Keycloak and independently tested Vault compatibility remain candidates. Broader OpenBao identity, rotation, downstream lease and HA behavior remains uncovered. Each addition needs supported snapshots, health checks, real effects, cleanup and appropriate isolation.

Completion requires a reproducible integration test against the named version and configuration. Keep any product finding separate from seeded application mistakes.

## Next milestone — declarative scenario input

The older `lab-config.json` and `scenarios.json` preserve a broad proposal. The narrower `openbao-local.json` format is executable and strictly validated. A broader language still needs typed operations, bounds, allowlists and malformed-input tests without arbitrary code or shell execution.

## Next milestone — additional recovery dimensions

Restore order, cache convergence, real token expiry, replication, queues, downstream leases, and partitions are separate experiments. They are not covered by increasing repetitions of the current deterministic fixture.

Larger search spaces may require sampling. Reports must name the tested space and omitted dimensions rather than presenting sampled results as exhaustive.

## Optional AI layer

An AI explanation feature can summarize a classified finding and cite its observations. It must not determine whether access occurred or rewrite current policy to match a result. The reference prototype already works without a model.

## Portfolio and product claims

A portfolio can demonstrate SQLite snapshots, seeded failures, protected controls, evidence exports, bounded reduction and native OpenBao restore/token probes. A customer-facing product needs broader adapters, deployment controls, maintenance, privacy handling and actual operator validation.

See [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) for the preserved extended architecture and [SECURITY_SCOPE.md](SECURITY_SCOPE.md) for the current boundary.
