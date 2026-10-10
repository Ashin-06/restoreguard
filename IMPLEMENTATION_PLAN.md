# Delivered scope and next milestones

The local reference prototype is implemented. The original larger product design remains a roadmap, not a claim that production integrations have been completed.

## Delivered reference layer

The core builds separate identity, permissions, and secrets SQLite stores, captures A/B/C snapshots, verifies a pre-recovery security baseline, and restores selected copies. The expected-policy journal and effect log remain outside the restoration set.

The built-in matrix, protected/vulnerable modes, repeated trials, six scenario checks, and finding-preserving reduction provide a small reproducible basis for demonstrating recovery-security failures. The command-line entry point, local interface, and evidence workflow make the experiments reviewable.

The current runtime uses a fixed catalogue. A general JSON scenario interpreter, customer adapters, and arbitrary backup import are not delivered.

## Reproduction gate

Before describing a local checkout as verified, run the checks in [EVALUATION.md](EVALUATION.md) and retain their actual outputs. Implementation existence is different from a measured test result. Claims about counts or speed must refer to a specific recorded run.

The gate should include a vulnerable matrix, protected matrix, all six scenario expectations, a reduced role failure, a deliberately limited reduction budget, and integrity verification of a generated bundle.

## Next milestone — stronger reference evidence

Possible additions include richer comparison between runs, an explicit export/replay format for fixture operations, longer-lived audit provenance, and measured resource use. These should preserve the current distinction between actual experiment evidence and a regenerated reference fixture.

A hash manifest alone is not a cryptographic attestation of execution. A future signed evidence design must define collector trust and key custody.

## Next milestone — external adapters

Implement one version-pinned real product adapter at a time. Keycloak and Vault/OpenBao are candidate directions, not supported targets today. The required work includes safe fixture creation, supported snapshot procedures, health checks, real access effects, cleanup, and strict network isolation.

Completion requires a reproducible integration test against the named version and configuration. Keep any product finding separate from seeded application mistakes.

## Next milestone — declarative scenario input

The `examples/` files preserve a proposed schema. Supporting them requires a real loader, strict validation, typed operations, capability limits, adapter allowlists, and meaningful malformed-input tests. Do not add arbitrary code evaluation or shell execution to make sample descriptions runnable.

## Next milestone — additional recovery dimensions

Restore order, cache convergence, real token expiry, replication, queues, downstream leases, and partitions are separate experiments. They are not covered by increasing repetitions of the current deterministic fixture.

Larger search spaces may require sampling. Reports must name the tested space and omitted dimensions rather than presenting sampled results as exhaustive.

## Optional AI layer

An AI explanation feature can summarize a classified finding and cite its observations. It must not determine whether access occurred or rewrite current policy to match a result. The reference prototype already works without a model.

## Portfolio and product claims

A portfolio can demonstrate implemented SQLite snapshots, seeded failures, protected controls, evidence exports, and bounded reduction. A customer-facing product needs supported adapters, deployment controls, maintenance, privacy handling, and validation with actual operator workflows.

See [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) for the preserved extended architecture and [SECURITY_SCOPE.md](SECURITY_SCOPE.md) for the current boundary.
