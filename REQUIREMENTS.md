# Requirements and current capability boundary

## Runtime

- Python **3.10 or newer**.
- A writable project or output directory for generated runs.
- A browser for the optional local interface.
- An available loopback port, default **8766**.

The reference runtime uses Python's standard library, including SQLite. It does not require Docker, PostgreSQL, Keycloak, Vault, a cloud account, paid service, or model API. No fixed RAM minimum is claimed; the fixture is small and local, but actual resource use depends on the machine and selected work.

Run the module from the project directory. The Windows launcher looks for `py -3`, `python`, or `python3` with a compatible version. It does not install Python or change system settings.

## Implemented behavior

| Requirement | Current implementation |
|---|---|
| Create fictional component state | Three disposable SQLite stores |
| Keep current intent outside restored state | Independent policy journal |
| Verify security changes before recovery | Initial and post-change probes |
| Restore selected historical copies | Actual file snapshots A/B/C and digest receipts |
| Observe effects rather than messages alone | Authoritative effect records and explicit classifications |
| Preserve legitimate access checks | Direct positive control plus separate service read |
| Explore bounded checkpoint combinations | Up to 27 selections in fixed order |
| Check repeat consistency | Fresh fixtures per repeat; disagreement is inconclusive |
| Reduce a specific finding | Kind/actor-preserving replacement with C |
| Exercise named edge cases | Fixed six-scenario catalogue and built-in fixture faults |
| Expose local workflows | Command-line and local browser interface |
| Inspect saved evidence | Report and manifest verification workflow |

## Important input limits

Modes are `vulnerable` and `protected`. A selection contains exactly identity, permissions, and secrets with A/B/C checkpoint values. Matrix budgets are 1–27 and repeat counts 1–10. The core reducer accepts a bounded evaluation budget and counts actual fixture inspections; each oracle decision needs two inspections.

The current runner does not accept arbitrary scenario JSON, user-supplied SQLite databases, backup archives, commands, URLs, or external adapters. The example JSON files describe future integration work.

## Behavior not covered

The fixture does not model real cryptography, JWTs, distributed clocks, network partitions, service health or readiness of external systems, asynchronous work, or production backup compatibility. It uses fixed fixture time and opaque synthetic sessions.

Disposable SQLite stores use memory journals and disabled durability syncing for speed. This is not a crash-durability benchmark.

## Future integration requirements

External adapters would need supported version locks, container or process isolation, a network boundary, actual access probes, compatibility checks, and safe cleanup. These are described in [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md), not implied by the reference prototype's completion.
