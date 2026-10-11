# RestoreGuard — Backup Recovery Security Tester

**Status: implemented local reference prototype with a real disposable OpenBao integration.** The browser workbench uses three SQLite fixture stores. A separate native adapter starts OpenBao 2.7.1, captures and restores real Raft snapshots, and checks revoked and allowed service tokens. This is not a production backup tool.

RestoreGuard answers a practical question: **can a backup restore bring back access that was deliberately removed?**

The prototype creates old and current snapshots, physically restores selected copies, and checks protected effects against a current policy journal that is kept outside the restore set. It compares a deliberately vulnerable application with a protected reference design.

## Start the application

From this project directory, with Python 3.10 or newer:

~~~powershell
python -m restoreguard serve --port 8766 --runs-dir runs
~~~

Open [http://127.0.0.1:8766](http://127.0.0.1:8766). Keep the terminal open; press Ctrl+C there to stop the server. On Windows, `./Start-RestoreGuard.ps1` finds a compatible Python interpreter and starts the same foreground server. If your machine uses the Python launcher, substitute `py -3` for `python` in the commands.

The reference workbench uses Python's standard library. No model API, Docker engine, database server, cloud account, or third-party Python package is required for it. The optional native adapter also needs the official local OpenBao executable. Run from this directory; installation as a system service is not part of the prototype.

## What is implemented

- Three separate SQLite component stores: **identity**, **permissions**, and **secrets**.
- Three actual snapshot points: A before security changes, B after verified changes, and C after unrelated benign updates.
- An independent current-policy journal and authoritative effect log, neither restored as a component.
- A checkpoint matrix of up to 27 combinations in one fixed restore order.
- Repeated fresh experiments and an explicit incomplete-coverage result.
- Independent probes for removed roles, disabled users, revoked sessions, old secrets, legitimate access, and legitimate service access.
- A protected mode that checks current external revocations and reconciles secret state.
- Failure reduction that preserves a specified finding and the allowed-user authorization control.
- Six built-in seeded/control scenarios, a local browser interface, saved reports, and evidence integrity checking.
- A native OpenBao Raft lifecycle with strict executable scenario JSON, repeated fresh processes, pre/post-revocation snapshots, independent current policy, verified restore completion, direct authorization controls, cleanup, and separate private evidence.

A successful allowed-user probe is checked separately. A fixture that denies everybody cannot qualify as a safe recovery.

## Try the main workflows

~~~powershell
python -m restoreguard matrix --mode vulnerable --budget 27 --repeats 2 --output-dir runs
python -m restoreguard matrix --mode protected --budget 27 --repeats 2 --output-dir runs
python -m restoreguard minimize --selection A,A,A --mode vulnerable --target-kind revived_role --target-actor removed-user --budget 100
python -m restoreguard scenarios
~~~

Selection order is **identity, permissions, secrets**. For example, `C,A,C` restores only permissions to the pre-revocation state while the other components use the latest fixture checkpoint.

A matrix command saves a run directory. Verify a particular directory using the path printed by that command:

~~~powershell
python -m restoreguard verify runs/<printed-run-id>
~~~

`<printed-run-id>` is a placeholder; replace it with the actual directory name.

Export a verified run with `python -m restoreguard bundle runs/<printed-run-id> --output evidence.zip`. Keep the ZIP outside the run directory. Each saved run contains `case.json`, `report.html`, `fixtures.json`, the SQLite fixture files, and `manifest.json`.

Verdict commands return exit code **0** for PASS, **1** for FAIL, and **2** for INCONCLUSIVE or invalid input. A vulnerable matrix intentionally returns 1 even when its evidence was saved successfully.

## Read results correctly

An experiment's `FAIL` means the tester found a seeded security or availability regression. It is a successful detection, not necessarily a program error.

For the scenario catalogue, `PASS` means the observed outcome matches the scenario's expectation. A deliberately unsafe scenario can therefore have `status: PASS` and `observed_outcome: FAIL`.

An incomplete matrix or unavailable evidence cannot establish a clean result. Integrity verification checks whether exported files still match their manifest; it does not prove the original experiment was truthful.

## What remains outside the implementation

The real-service workflow is described in [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md). From this checkout, with the separately verified binary available:

~~~powershell
python -m restoreguard openbao --config examples/openbao-local.json --executable "../.lab/runtimes/openbao-2.7.1/bin/bao.exe" --output-dir service-runs
~~~

Replace the executable path on another machine. The adapter creates its own disposable loopback service. The supplied catalogue expects an old snapshot to revive a revoked token and a post-revocation snapshot to keep it denied, with legitimate access checked in both states. For this command, `status: PASS` and exit 0 mean all configured expectations matched; `security_status` and each `observed_outcome` record actual security findings. Verify its separate private evidence with `python -m restoreguard verify-service <native-run-directory>`.

There are no production adapters, Keycloak integration, JWT tests, distributed-system timing tests, restore-order permutations, arbitrary uploaded backup support, or production remediation. SQLite sessions and key fingerprints are synthetic; the native integration uses actual OpenBao service tokens. SQLite durability syncing is disabled in disposable experiment stores, so crash recovery is not being measured. The native adapter covers only single-node Raft service-token revocation recovery, not the full SQLite matrix or protected-mode remediation.

`examples/openbao-local.json` is an executable, strictly validated native scenario configuration. `examples/lab-config.json` and `examples/scenarios.json` remain **design specifications** for a broader language and are not executed. `examples/measured-validation.json` and `examples/sample-run/` contain actual generated SQLite reference results; `examples/openbao-validation.json` records a sanitized native result. See [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) for the remaining Keycloak/Vault/Docker design.

## Project guide

| Document | What it explains |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Actual components, code structure, and trust boundaries |
| [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md) | Real OpenBao setup, strict input, native restore workflow and limits |
| [WORKFLOW.md](WORKFLOW.md) | A complete recovery experiment and interpretation |
| [DATA_CONTRACTS.md](DATA_CONTRACTS.md) | Runtime result fields and design-only example inputs |
| [EVALUATION.md](EVALUATION.md) | Reproducible checks, expected scenarios, and coverage limits |
| [VALIDATION.md](VALIDATION.md) | Recorded Python/browser checks and generated sample results |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Runtime requirements and current capability boundary |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Delivered reference scope and future milestones |
| [SECURITY_SCOPE.md](SECURITY_SCOPE.md) | Local fixture scope, sensitive artifacts, and limitations |
| [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md) | Unimplemented integrations and larger design |

## Contribution and prior art

The contribution is the concrete implementation: physical component snapshots, a bounded recovery matrix, independent security intent, repeatable effect checks, a reduced reference reproduction, and a versioned native OpenBao recovery experiment. Backup-related access resurrection itself is not a new discovery.

- [Microsoft Key Vault backup documentation](https://learn.microsoft.com/en-us/azure/key-vault/general/backup) describes independent restored key copies.
- [HashiCorp Vault snapshot restoration](https://developer.hashicorp.com/vault/docs/sysadmin/snapshots/restore) explains why restore tests must be isolated.
- [Pomerium recovery testing guidance](https://www.pomerium.com/learn/guides/test-backup-restore-and-clean-rebuild) includes verifying that old authority remains rejected.
- [Recovery Admission Lab author report](https://digitalthoughtdisruption.com/2026/09/19/restoring-state-must-not-restore-authority-independent-recovery-admission-for-ai-agents/) describes related authority-rollback experiments. Its complete lab was unavailable for download when reviewed, so its reported results were not independently reproduced here.

This project makes no “first ever” claim. The native experiment measures expected restoration of historical authorization state, not a new external-product vulnerability. The core does not use AI.
