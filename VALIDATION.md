# Recorded reference validation

Validated on 10 October 2026 with Python 3.12.3 on Windows. These results apply to this controlled fixture, not to a production backup system.

- **32 Python tests passed:** physical restore behavior, independent policy/effect checks, controls, repeat disagreement, bounded reduction, CLI, HTTP guards and evidence integrity.
- **9 browser checks passed:** live matrix runs, 19 vulnerable failures / 8 passes, protected 27 passes, reduction, filters, six scenarios, incomplete coverage, archive and 390px layout. No JavaScript errors were observed.
- **Vulnerable full matrix:** 27 attempted; 19 FAIL, 8 PASS, 0 INCONCLUSIVE.
- **Protected full matrix:** 27 attempted; 27 PASS, 0 FAIL, 0 INCONCLUSIVE.
- **Scenario catalogue:** all six expected outcomes matched, including the deliberately unavailable journal and HTTP/effect disagreement.
- **Role reduction:** three original restore operations reduced to one: permissions=A, with identity=C and secrets=C. Twelve fixture evaluations; 1-minimal under the declared removal operation.
- **Sample evidence:** all 17 manifest-covered files verified; all 81 restore receipt digests match the exported source snapshots.

Actual results are in `examples/measured-validation.json` and `examples/sample-run/`. The sample contains regenerated deterministic reference inputs, not the discarded active database of every matrix trial. Hash matching connects the exported snapshots to the trial receipts; an unsigned manifest is not proof of execution or authenticity.

Reproduce with `python -m unittest discover -s tests -v`. For optional browser checks, install Playwright in a development environment with Chrome, start the server on port8766, and run `node tests/browser_smoke.cjs`. Browser dependencies are not required to use RestoreGuard.

## Native OpenBao validated on 11 October 2026

The final release suite passed **49 tests**: all 32 reference tests, 16 native adapter configuration/error/evidence checks, and one actual OpenBao integration test. The real test used the verified official OpenBao 2.7.1 Windows binary, two fresh owned Raft instances, and four completed native restores. No real-service test was skipped in this run. The existing **9 browser workbench checks** also passed again.

The older checkpoint restored the revoked client's exact synthetic secret read (HTTP 200) in both repetitions. The checkpoint captured after revocation preserved denial (HTTP 403) in both repetitions. The allowed-client positive control succeeded in all four restored states. Fresh barrier/checkpoint observations established that each restore had completed. Tests also verified different native snapshots, credential redaction, unchanged independent policy, cleanup events, evidence integrity and unsafe-path rejection.

The separately retained release run has four matching expected outcomes and a nine-file verified manifest. Its compact measured record is `examples/openbao-validation.json`; raw snapshots and full reports remain in ignored `.test-output/release-runs/`. The run reports `status: PASS` for matching expectations and `security_status: FAIL` for the demonstrated rollback of revoked access. This is expected historical-state restoration, not a new product vulnerability claim.

Reproduce using the commands in [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md). Without `RESTOREGUARD_OPENBAO_EXE`, the unit suite explicitly skips its one real-service test. The native adapter covers this specific owned single-node OpenBao experiment, not arbitrary production backups or the remaining multi-product roadmap.
