# Evaluation and reproducible checks

The reference implementation is intended to be inspected through its generated results. The commands below describe reproducible checks; they are not a substitute for retaining the actual output from your machine. No performance or external-product benchmark is claimed here.

## Run the reference checks

From this directory:

~~~powershell
python -m restoreguard scenarios
python -m restoreguard matrix --mode vulnerable --budget 27 --repeats 2 --output-dir runs
python -m restoreguard matrix --mode protected --budget 27 --repeats 2 --output-dir runs
python -m restoreguard minimize --selection A,A,A --mode vulnerable --target-kind revived_role --target-actor removed-user --budget 100
~~~

Inspect the output and verify saved run directories with `python -m restoreguard verify <directory>`. Keep vulnerable, protected, and reduced-case results distinct.

## Six built-in scenarios

| ID | Constructed condition | Expected experiment outcome |
|---|---|---|
| RG-001 | Restore old permissions while current identity/secrets remain | FAIL with revived-role finding |
| RG-002 | Apply current external controls to the old permission state | PASS |
| RG-003 | Restore old identity/session state | FAIL including revived-session finding |
| RG-004 | Current independent policy is unavailable | INCONCLUSIVE |
| RG-005 | Restore stale client secret state | FAIL including availability regression |
| RG-006 | A seeded mutation occurs before a denial response | FAIL with unauthorized-effect finding |

The catalogue's own PASS means the expected experiment outcome and required finding were observed. In particular, a correctly detected unsafe case is a passing catalogue check.

## Positive and negative controls

The fixture checks the original state before applying security changes and verifies the post-change baseline before recovery. The allowed user's direct read remains a positive control. Its service-backed read independently exposes stale credentials.

Additional built-in faults exercise an invalid pre-recovery baseline, deny-all behavior, and missing effect evidence. They are test-only controls; the user interface need not expose every fault as an ordinary operation.

## Matrix interpretation

There are 27 checkpoint selections, using A/B/C independently for three components. Every selection uses the same restore order. Repetitions create fresh fixtures and compare the outcome fingerprint; they do not add distributed timing coverage.

A budget below 27 leaves the declared matrix incomplete. The selected prefix is not random or statistically representative. Record both the number of attempted selections and the repeat count.

## Reduction checks

The reducer must preserve the requested kind/actor finding and the successful direct allowed-user probe. Replacement with C means removal of that component's historical restoration for this purpose.

Check both a sufficient budget and a deliberately limited one. If the budget is exhausted or an oracle decision is inconclusive, do not claim one-minimality. The reported evaluation count counts individual inspections, with two per normal oracle decision.

## Evidence checks

Verify an untouched generated bundle. On a disposable copy, change one covered file and verify that integrity checking rejects it. Do not modify the only copy of a result you want to retain.

A manifest is change-detection evidence relative to its own contents, not proof of trusted execution. Exported synthetic fixture snapshots support inspection of the model; distinguish regenerated reference snapshots from the transient databases of individual trials.

## Metrics to publish from actual runs

- Matched expectations out of the six built-in scenarios.
- Matrix pass/fail/inconclusive counts and complete/partial coverage.
- Repeat consistency.
- Original and reduced non-C component counts.
- Reduction evaluations and budget exhaustion.
- Manifest verification result.
- Elapsed time and resource use only when measured with environment details.

Broader recall and false-alarm claims require a separately defined set of independently seeded defects and safe cases. Counts from this small fixed catalogue are not a population-wide accuracy estimate.

## External validity

The tests cover synthetic local SQLite authorization and secret-state behavior. They do not test Keycloak, Vault, cloud services, real sessions or keys, asynchronous work, network failure, restore-order permutations, or crash durability. A clean protected matrix is conditional on an available current external authority and its implemented reconciliation behavior.
