# Architecture — local reference implementation

RestoreGuard has two separate paths: a disposable SQLite reference matrix and a native OpenBao Raft adapter. Both keep test-defined current intent outside restored data and observe legitimate access separately. The browser exposes the SQLite path; the native path uses CLI commands and standalone reports.

## Actual experiment stores

| Store | Contents | Restored by the matrix? |
|---|---|---|
| `identity.sqlite` | Enabled users and opaque fixture sessions | Yes |
| `permissions.sqlite` | Fictional document grants | Yes |
| `secrets.sqlite` | Synthetic client and verifier key fingerprints | Yes |
| `independent-policy.sqlite` | Expected policy, current revocations, and current key authority | No |
| `authoritative-effects.sqlite` | Effects actually produced by the fixture probes | No |

The expected-policy table supplies the oracle. Protected enforcement consults separate revocation/key tables, rather than consulting the expected result for a probe. These tables share an independent fixture database; their logical separation does not establish independent infrastructure or administration.

## Actual data flow

~~~text
fixed fictional fixture
       |
create identity / permissions / secrets stores
       |
A snapshot -> security changes -> verified B snapshot -> benign C snapshot
       |
choose one checkpoint per component
       |
copy snapshots into fresh active stores in a fixed order
       |
application authorization and secret probes
       |
authoritative effects + independent expected policy
       |
classification -> repeated matrix -> reduced reproduction -> saved report
~~~

Every inspected selection builds a fresh temporary fixture. All SQLite connections used for a snapshot are closed before file copying. Restore receipts contain source digests, and the copied active file is checked against its selected snapshot. Protected mode can then deliberately reconcile secret state.

## Code responsibilities

```text
restoreguard/
  core.py          SQLite fixtures, restore matrix, oracle, reducer, scenarios
  openbao.py       Owned native process, strict scenarios, Raft restores, probes, evidence
  evidence.py      Atomic run storage, manifests, verification, ZIP export
  reports.py       Escaped portable HTML report
  server.py        Loopback HTTP API, request limits, static interface
  cli.py           Command-line workflows and verdict exit codes
  __main__.py      python -m restoreguard entry point
  __init__.py      Version identifier
  static/
    index.html     Workbench, scenario checks and archive views
    styles.css     Responsive visual design
    app.js         API interactions, matrix exploration and evidence controls
tests/
  test_core.py         Fixture and security-oracle regression checks
  test_integration.py  CLI, HTTP and evidence lifecycle checks
  test_openbao.py      Native adapter errors, controls and optional real-service test
  browser_smoke.cjs    Optional Chrome/Playwright interface checks
examples/
  sample-run/              Generated run and deterministic SQLite inputs
  measured-validation.json Actual matrix, scenario and reduction results
  lab-config.json          Future declarative-input specification
  scenarios.json           Future declarative-input specification
  openbao-local.json       Executable bounded native OpenBao scenarios
  openbao-validation.json  Sanitized recorded native result
Start-RestoreGuard.ps1      Foreground Windows launcher
pyproject.toml             Optional package metadata; no runtime dependencies
runs/                      Generated local evidence, excluded from Git
service-runs/              Private native evidence and snapshots, excluded from Git
```

The core is in `restoreguard/core.py`:

| Interface | Responsibility |
|---|---|
| `inspect_selection(selection, mode, fault=...)` | One fresh physical restore experiment |
| `run_matrix(mode, max_experiments, repeats)` | Bounded checkpoint matrix and repeat consistency |
| `minimize_selection(selection, mode, target_kind, target_actor, max_evaluations)` | Reduce the selected restoration while preserving a finding |
| `run_scenarios()` | Six fixed seeded/control scenarios |
| `classify_observation(...)` | Compare expected access with actual effects |
| `default_restore_selection()` | Return a fresh all-A selection |

The entry point `restoreguard/__main__.py` dispatches to the command-line module. The local server and evidence modules expose the same experiment results rather than inventing a separate browser-only simulation. See the current repository tree for supporting server and static-interface files.

The earlier large adapter tree is retained in [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md). The implemented native adapter lives in `restoreguard/openbao.py`, without pretending that larger framework exists.

## Native OpenBao path

`load_config` rejects unknown fields and unbounded input. `run_openbao` verifies the executable version, owns a fresh process per repetition, and preserves native evidence. `OwnedOpenBao` manages initialization/unseal, direct HTTP calls, native Raft snapshots, checkpoint-marker restore barriers, and cleanup. `classify_read` requires the exact random fixture value for a successful read; `experiment_verdict` requires both revoked-client and allowed-client probes for a clean result. `verify_service` checks the separate native manifest.

The independent current-policy JSON is outside Raft storage and its hash is checked after each restore. Probes go directly to OpenBao; the policy is an oracle, not an enforcement proxy. The protected SQLite design is not claimed as native OpenBao protection. See [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md) for the exact lifecycle and contract.

## Snapshot meaning

- **A:** All fictional users/roles/sessions are initially usable; old secret fingerprints are current.
- **B:** A role is removed, an identity disabled, session S4 revoked, and the service key rotated. The fixture verifies both denial and legitimate access before recording B.
- **C:** Unrelated display labels, a benign extra grant, and secret labels change. Security intent remains the same as B.

If the pre/post-change baseline does not match its expected policy, the recovery experiment is rejected as `INCONCLUSIVE`.

## Independent probes

The removed-role, disabled-user, and revoked-session checks use direct document authorization. The allowed user's direct read is a positive control. Old-secret use and the allowed user's service-backed read are separate probes.

This prevents a stale service credential from hiding a restored role or session. Restoring old secrets can both revive an old verifier and break a current client's legitimate service read; those are separate findings.

## Vulnerable and protected modes

Vulnerable mode trusts restored local identity, permission, session, and secret state. Protected mode also checks current revocation records outside the restore set and reconciles client/verifier fingerprints with the current key.

This is a concrete reference pattern with an external-authority dependency. It is not a new revocation protocol, production key-management system, or proof that an independent authority cannot be rolled back.

## Oracle rules

An actual effect is authoritative over the transport status. A seeded endpoint that performs a tag operation and then returns 403 must fail the denied-action invariant.

- Effect occurred + expected allow: `PASS`.
- Effect occurred + expected deny: `FAIL`.
- No effect + an explicit fixture rejection status: pass a denied action; fail an allowed action.
- Unknown or insufficient effect evidence: `INCONCLUSIVE`.

At experiment level, an established failure takes precedence over an unknown probe. Missing evidence remains visible in the observations; it is not converted into proof that nothing happened.

## Matrix and reducer boundaries

The matrix enumerates A/B/C for each of three components: 27 selections. Its restore order is always identity, permissions, secrets. A smaller budget tests an initial subset of this enumeration, not a statistically representative sample.

Each repeated trial starts fresh. If outcome fingerprints differ, that selection becomes inconclusive. A full matrix with no failures and no inconclusive results can pass; partial coverage cannot establish a clean full-matrix result.

The reducer replaces a selected component checkpoint with C. It preserves the specified finding kind and actor plus the allowed user's direct-read control. It repeats each oracle decision twice. `one_minimal` means no remaining individual non-C component can be replaced by C under this tested reduction. It is not a globally shortest sequence and does not search restore order.

## Deliberate limits

SQLite fixture time is fixed and sessions are opaque references. Its path makes no network requests. The separate OpenBao path uses real local HTTP, service tokens and native storage; it does not test expiry, JWT validation, asynchronous consumers, HA, or distributed consistency. Temporary SQLite stores use memory journaling and disabled syncing for speed; neither path establishes crash durability.
