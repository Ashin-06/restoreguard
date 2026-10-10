# Working through a recovery experiment

The commands below operate only on generated fictional SQLite fixtures. They do not read your account permissions or restore another application's database.

## 1. Start the local interface

~~~powershell
python -m restoreguard serve --port 8766 --runs-dir runs
~~~

Open [http://127.0.0.1:8766](http://127.0.0.1:8766), or use the command-line workflow below. The Windows launcher starts the same server and prints the address.

## 2. Understand the starting fixture

The fixture contains a fictional document, `budget-demo`, and users with different security transitions:

- `removed-user`: its document role is removed.
- `disabled-user`: its identity is disabled.
- `session-owner`: its session S4 is revoked.
- `allowed-user`: remains authorized and provides a positive control.
- `old-secret-client`: tries a synthetic old service credential.

The runner first verifies that the initial fixture behaves as expected. It copies actual closed SQLite files into checkpoint A.

## 3. Apply and verify security changes

The runner changes the local component stores and separately records current intent in the independent policy journal. It probes the changed state, checking that removed authority is rejected and legitimate access still works.

Only a verified baseline can proceed. It then records B and makes benign updates for C. The independent policy journal is never part of the selected restoration.

## 4. Run the vulnerable matrix

~~~powershell
python -m restoreguard matrix --mode vulnerable --budget 27 --repeats 2 --output-dir runs
~~~

For each selection, the runner builds a fresh fixture and physically copies the selected snapshots into the active stores. The checkpoint order in a selection is identity, permissions, secrets.

For example, `C,A,C` keeps current identity and secrets state but restores old permissions. The role probe is expected to reveal the deliberately seeded local-ACL failure. This is behavior of this reference fixture, not a finding against a named external product.

A budget of 27 covers the complete checkpoint-selection matrix in the one fixed restore order. A lower budget is useful for a quick demonstration but leaves coverage incomplete.

## 5. Inspect actual effects

Each probe records expected access, observed effect, transport status, and classification. A denial message is insufficient if a protected effect happened anyway. An allowed-user denial is an availability regression.

The direct allowed-user read is separated from the service-backed read. This makes it possible to distinguish restored permissions from a stale service credential that prevents a legitimate service request.

## 6. Find a smaller reproduction

~~~powershell
python -m restoreguard minimize --selection A,A,A --mode vulnerable --target-kind revived_role --target-actor removed-user --budget 100
~~~

The reducer starts from the requested selection and verifies the target finding. It checks a clean C/C/C baseline, then tries replacing individual restored components with C.

It preserves the same finding kind and actor and a working allowed-user direct read. Every decision uses two fresh inspections. The result reports the original and reduced selections, evaluation count, budget exhaustion, and whether the final selection is one-minimal under this replacement rule.

`status: FAIL` here means the selected security finding was reproduced. Check `one_minimal` and `budget_exhausted` before describing the reduction as complete.

## 7. Compare the protected design

~~~powershell
python -m restoreguard matrix --mode protected --budget 27 --repeats 2 --output-dir runs
~~~

Protected mode adds current external revocation checks and secret reconciliation. The clean-result claim, if observed in your run, applies to the exact synthetic fixture and 27 checkpoint selections. It does not extend to missing external authorities, production credentials, or untested distributed behavior.

## 8. Run the six scenario checks

~~~powershell
python -m restoreguard scenarios
~~~

The catalogue includes known unsafe cases, a safe control, and deliberately unavailable evidence. Its top-level result answers whether those observations matched the catalogue's expectations. Therefore RG-004 should be a successful catalogue check when its inspection is `INCONCLUSIVE`.

## 9. Save and verify a report

The matrix command prints a run directory containing the experiment data, readable report, and integrity manifest. Where fixture export is included, the bundle also contains synthetic component snapshots and the independent journal, identified as reference fixture material.

~~~powershell
python -m restoreguard verify runs/<printed-run-id>
~~~

Replace the placeholder with the actual run directory. Verification detects disagreement with the saved manifest. A hash manifest cannot prove the collector was honest or prevent someone who controls both data and manifest from rewriting both.

## 10. State the conclusion narrowly

A useful finding says which fixture selection, actor, action, and expected policy failed. A useful clean result states the mode, complete tested matrix, repeat count, and limitations.

Do not describe scenario expectation matches as six secure systems, or a complete checkpoint matrix as exhaustive coverage of recovery order, real token expiry, cloud services, and production outages.
