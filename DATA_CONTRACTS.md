# Runtime data contracts

The reference runtime returns plain dictionaries from `restoreguard/core.py`. The native adapter has a separate strict executable format in `restoreguard/openbao.py`, documented in [OPENBAO_INTEGRATION.md](OPENBAO_INTEGRATION.md). `examples/lab-config.json` and `examples/scenarios.json` use a separate `0.1-design` specification and are **not executed**. `examples/measured-validation.json` and `examples/sample-run/` contain actual generated reference results.

## Selection

A selection maps exactly three names to checkpoint values:

~~~json
{"identity": "C", "permissions": "A", "secrets": "C"}
~~~

Valid checkpoint values are A, B, and C. Command-line comma order is identity, permissions, secrets.

## Inspection result

The main fields from `inspect_selection` are:

| Field | Meaning |
|---|---|
| `id` | Readable selection identifier |
| `selection`, `mode` | What was tested |
| `status` | PASS, FAIL, or INCONCLUSIVE for the experiment |
| `observations` | Individual access/effect probes |
| `findings` | Established failures or an explanation of unavailable baseline/policy |
| `baseline_verified`, `baseline` | Initial/post-change verification |
| `positive_control` | Whether the allowed-user direct read succeeded |
| `restore_order` | Fixed identity, permissions, secrets sequence |
| `policy_journal_restored` | False in this reference design |
| `restore_receipts` | Component, checkpoint, and selected snapshot digest |
| `scope` | Synthetic-fixture limitation |

A restore receipt describes the copied snapshot before any protected-mode reconciliation. It must not be interpreted as the hash of the final active secret store after reconciliation.

## Observation

Each observation includes `id`, `actor`, `action`, `resource`, `expected`, `observed`, `status`, `kind`, `transport_status`, and `effect_occurred`.

- `expected`: allow or deny, from the independent expected-policy table.
- `observed`: allowed, denied, or unknown.
- `effect_occurred`: true, false, or null when evidence is unavailable.
- `status`: the comparison result for that probe.

The implemented finding kinds include `revived_role`, `revived_identity`, `revived_session`, `revived_secret`, `availability_regression`, and `unauthorized_effect`. These are fixture categories, not external vulnerability identifiers.

## Matrix result

`run_matrix` returns `status`, `mode`, `summary`, `results`, `repeats`, `limitations`, and `scope`.

The summary contains `planned` (27), `attempted`, `passed`, `failed`, `inconclusive`, and `complete`. Each selection result also records `repeats` and `repeat_consistent`.

`attempted` counts checkpoint selections, not total repeated fixture inspections. An incomplete matrix without established failures has an inconclusive overall result; it cannot claim a full clean pass.

## Reduction result

`minimize_selection` returns:

- `original_selection` and `minimized_selection`.
- `original_steps` and `minimized_steps`, counting non-C components.
- `target_kind`, `target_actor`, and the reproduced `signature`.
- `evaluations`, `max_evaluations`, `budget_exhausted`, and `history`.
- `one_minimal`, `repeats`, `status`, `limitations`, and `scope`.

Each oracle decision performs two fresh inspections when budget permits. The history records candidate selections, phase, outcome, cumulative evaluation count, and whether a removal was accepted.

A reducer `FAIL` indicates reproduction of the requested security finding. Only `one_minimal: true` supports the claim that no remaining single non-C component can be set to C while preserving that finding and the direct positive control. It does not establish a global minimum.

## Scenario catalogue result

`run_scenarios` returns a suite `status`, `summary`, `results`, `scope`, and `interpretation`.

Each scenario has `expected_outcome`, `observed_outcome`, `expected_kind`, `observed_kinds`, an `inspection`, and its own expectation-match `status`. A scenario can pass by correctly producing FAIL or INCONCLUSIVE. The summary counts matched expectations, not secure recoveries.

## Saved bundle versus runtime result

The evidence layer wraps these results into a saved case, a readable report, and a hash manifest. Any exported fixture databases contain only synthetic reference state. A reconstructed reference fixture must not be described as the original transient database of every matrix trial.

Manifest verification can detect changed bytes relative to the manifest. It does not authenticate the person who generated the manifest, prove execution, or survive an attacker rewriting both data and manifest.

## Design-only input examples

`examples/lab-config.json` and `examples/scenarios.json` preserve the proposed future adapter/configuration language. Typed operations, scenario-file references, clock policies, and adapter IDs in those examples are specifications rather than accepted runtime inputs.

Supporting that broader language requires its own loader and tests. Current supported inputs are reference CLI options, the fixed SQLite catalogue and the separate `restoreguard.openbao.v1` JSON format.
