# Native OpenBao recovery integration

**Implemented and exercised against OpenBao 2.7.1.** This is a real, disposable single-node Raft service integration. RestoreGuard starts its own process, uses native initialization/token/KV/snapshot APIs, restores the snapshots, observes actual secret reads, and stops the process. It cannot attach to an existing service.

This integration tests one precise recovery question: after a restricted service token is revoked, does restoring an earlier complete Raft snapshot make that token usable again? A second snapshot, captured after verified revocation, is the safe recovery control. Historical-state restoration is expected behavior; the experiment does not claim a newly discovered OpenBao vulnerability.

## Requirements and launch

Use Python 3.10+ and the official OpenBao **2.7.1** executable for your platform. No Docker engine or Python package installation is needed. Obtain the binary from the [official release](https://github.com/openbao/openbao/releases/tag/v2.7.1) and verify the release checksum before supplying it. The executable is a separate local prerequisite, not a file shipped in this repository.

From the project folder, on this Windows checkout:

~~~powershell
python -m restoreguard openbao --config examples/openbao-local.json --executable "../.lab/runtimes/openbao-2.7.1/bin/bao.exe" --output-dir service-runs
~~~

On a different machine, replace the executable path with the path to your verified `bao.exe` or `bao`. The adapter checks the exact requested version before starting and records the executable SHA-256. A name/version check is not an authenticity check: obtain a trusted binary first.

The example runs two scenarios in each of two fresh service instances. A typical invocation prints the result and a saved `directory`. The run ends automatically. Open `report.html` in that directory for a readable report, or use:

~~~powershell
python -m restoreguard verify-service service-runs/<printed-native-run-id>
~~~

Replace the placeholder with the actual directory name. The existing browser on port 8766 remains the SQLite matrix workbench; native runs use this command and their standalone reports.

## Exact lifecycle

1. Validate the complete JSON input, exact product version, and executable path. Reject an external endpoint or arbitrary command field.
2. Create a new temporary Raft directory, choose API/cluster ports on `127.0.0.1`, and start only that OpenBao process. HTTP proxy forwarding and redirects are disabled for the adapter. Inherited `BAO_`/`VAULT_` configuration overrides are removed from the child's environment.
3. Require an uninitialized service, initialize it with one temporary Shamir share, unseal it, and verify its unique generated cluster name. TLS is disabled only for this disposable loopback listener.
4. Mount KV v2, write a random synthetic marker, and create two restricted one-hour service tokens. Both can read only `restoreguard/data/fixture`; neither receives the root/default policy. Verify both reads return the exact marker.
5. Download `before_revocation.snap` through the native Raft snapshot API. Revoke the first token, then verify that token is denied while the allowed token still returns the marker. Set the second checkpoint marker and download `after_revocation.snap`.
6. Before each restore, replace an administrator-only checkpoint value with a new barrier value. Post the chosen native snapshot and wait for readiness and for its expected checkpoint value to return. A successful HTTP restore response alone is insufficient.
7. Check that the independent current-policy file's hash is unchanged. Probe both tokens directly against OpenBao and compare the results with that policy: revoked client must be denied; allowed client must still read.
8. Save redacted observations and snapshot hashes. Stop only the process created by the run, clear in-memory credential references, and remove its temporary storage. Retain the selected evidence directory.

The independent policy is a test oracle. It does **not** intercept requests, repair OpenBao, or claim native protected-mode enforcement. The SQLite protected-mode demonstration remains a separate implementation.

## Executable input contract

`examples/openbao-local.json` is accepted by the runtime. Unlike the older `0.1-design` examples, it is not a proposal.

| Field | Accepted value |
|---|---|
| `schema_version` | Exactly `restoreguard.openbao.v1` |
| `adapter` | Exactly `openbao-raft` |
| `expected_version` | Exact three-part release version; measured support is 2.7.1 |
| `repeats` | Integer 1–3; a new native process per repetition |
| `startup_timeout_seconds` | Integer 5–60 for each readiness wait |
| `request_timeout_seconds` | Integer 1–30 for each HTTP request |
| `scenarios` | 1–8 objects, each containing exactly `id`, `restore_checkpoint`, `expected_outcome` |

Scenario IDs are unique, 2–40 characters, beginning with an uppercase letter and containing uppercase letters, digits, `_`, or `-`. Checkpoints are `before_revocation` and `after_revocation`. Expected outcomes are `PASS` or `FAIL`. The configuration is limited to 64 KiB; duplicate JSON keys, unknown fields, booleans used as integers, unsupported operations, and unbounded counts are rejected.

You can change the scenario order, select either checkpoint, and change the asserted expected outcome. The actor, resource, fixture creation, revocation operation, and safe native lifecycle remain fixed. This is a deliberately narrow executable scenario format, not a general scripting language or the earlier proposed Keycloak/Vault DSL.

## Interpret the results

| Field | Meaning |
|---|---|
| `status` | Did the complete run match every configured scenario expectation? |
| `security_status` | Aggregate actual recovery-security verdict: any demonstrated failure remains FAIL |
| `complete` | All requested scenario/repetition pairs finished without lifecycle errors |
| `results[].observed_outcome` | Actual verdict for one restored state |
| `positive_control_passed` | The allowed token returned the exact synthetic fixture value |
| `probes[].fixture_value_returned` | The actual response contained the expected marker |

The supplied catalogue intentionally expects **OB001=FAIL** and **OB002=PASS**. A correct run therefore has `status: PASS` and `security_status: FAIL`. CLI exit 0 means expectations matched, 1 means a completed expectation mismatch, and 2 means an incomplete run or invalid input. It is not a universal “safe to restore” approval code.

A read is allowed only when the exact marker appears in the response. An explicit native 401/403 error is denied; a malformed, unavailable, or inconclusive response is unknown. A marker returned alongside an error status still establishes disclosure. Empty or incomplete probe sets cannot pass. A valid forbidden read remains a finding even when another probe is unavailable; the missing control stays visible.

## Native evidence

~~~text
service-runs/<native-run-id>/
  service.json                 Config, runtime hash, outcomes, limitations
  trace.json                   Redacted native steps and baseline observations
  report.html                  Standalone readable results
  manifest.json                SHA-256 integrity manifest
  repeat-1/
    current-policy.json        Independent current security intent
    before_revocation.snap     Actual downloaded native Raft snapshot
    after_revocation.snap      Actual downloaded native Raft snapshot
  repeat-2/                    Present when a second repetition is configured
    ...
~~~

For the two-repeat example, the manifest covers nine files. These native snapshots are the actual snapshots restored during that run. They are separate from the regenerated SQLite reference exports.

**Keep raw native snapshots private.** They contain the disposable service's encrypted synthetic authentication state. JSON, HTML, and trace files omit tokens, root credentials, unseal shares, and the secret marker; integration tests check this redaction against the actual generated credentials. Unseal material is discarded, so the exported snapshot alone is not a ready-to-unseal service backup. Repeat the scenario to reproduce it. Python reference clearing does not guarantee secure memory erasure.

`service-runs/`, `.test-output/`, and all `*.snap` files are excluded from Git. The binary and its download archive are excluded too. The adapter does not provide a native ZIP command or serve these files through the workbench. Integrity checks detect missing, changed, unexpected, or unsafe-path files; unsigned manifests do not authenticate the collector.

## Test and scope

Run all checks, including the real native integration:

~~~powershell
$env:RESTOREGUARD_OPENBAO_EXE = (Resolve-Path "../.lab/runtimes/openbao-2.7.1/bin/bao.exe").Path
python -m unittest discover -s tests -v
~~~

Without that environment variable, the one real-service integration test is explicitly skipped; unit checks and the original SQLite tests still run. The native test creates two fresh instances and verifies both restores, positive controls, barrier checks, credential redaction, snapshot differences, cleanup events, and evidence integrity. See [VALIDATION.md](VALIDATION.md) for measured results.

There is no Keycloak integration, HashiCorp Vault compatibility certification, production endpoint support, HA cluster, cross-service mixed-snapshot matrix, real expiry test, external lease consumer, crash test, or operating-system sandbox. Loopback listeners and a generated service containing only synthetic data are the boundary; the child process still runs as the current operating-system user. No auto-download, installation, firewall changes, or background service registration occurs.

## Primary protocol references

- [OpenBao Raft snapshot API](https://openbao.org/docs/api/system/storage/raft/) — native snapshot download and restoration.
- [OpenBao initialization API](https://openbao.org/docs/api/system/init/) and [unseal API](https://openbao.org/docs/api/system/unseal/) — new disposable instance lifecycle.
- [OpenBao token API](https://openbao.org/docs/api/auth/token/) — restricted service token creation and revocation.
- [OpenBao Raft storage configuration](https://openbao.org/docs/configuration/storage/raft/) — persistent Raft configuration and cluster address.

These sources describe supported product mechanisms. The measured results and RestoreGuard's additional controls come from the implementation and tests in this repository.
