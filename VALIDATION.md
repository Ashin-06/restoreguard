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
