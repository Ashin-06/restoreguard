"""Recovery-oracle, matrix, minimization, and physical snapshot tests."""

import copy
import hashlib
import itertools
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from restoreguard import core


CURRENT = {"identity": "C", "permissions": "C", "secrets": "C"}


class OracleTests(unittest.TestCase):
    def test_403_cannot_hide_authoritative_unauthorized_effect(self):
        row = core.classify_observation(actor="removed-user", action="tag", resource="budget-demo", expected="deny", transport_status=403, effect_occurred=True, kind="unauthorized_effect")
        self.assertEqual(row["status"], "FAIL")
        self.assertEqual(row["observed"], "allowed")
        self.assertTrue(row["effect_occurred"])

    def test_200_without_matching_effect_is_not_success(self):
        row = core.classify_observation(actor="allowed-user", action="read", resource="budget-demo", expected="allow", transport_status=200, effect_occurred=False, kind="positive_control")
        self.assertEqual(row["status"], "INCONCLUSIVE")
        self.assertEqual(row["observed"], "unknown")

    def test_unavailable_effect_observer_is_inconclusive(self):
        for expected in ("allow", "deny"):
            for transport in (200, 403, None):
                row = core.classify_observation(actor="demo", action="read", resource="budget-demo", expected=expected, transport_status=transport, effect_occurred=None, kind="demo")
                self.assertEqual(row["status"], "INCONCLUSIVE")

    def test_known_denial_of_legitimate_user_is_availability_failure(self):
        row = core.classify_observation(actor="allowed-user", action="read", resource="budget-demo", expected="allow", transport_status=403, effect_occurred=False, kind="positive_control")
        self.assertEqual(row["status"], "FAIL")
        self.assertEqual(row["kind"], "availability_regression")


class FixtureTests(unittest.TestCase):
    def test_current_checkpoint_is_safe_and_positive_control_succeeds(self):
        result = core.inspect_selection(CURRENT)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["baseline_verified"])
        self.assertTrue(result["positive_control"])
        self.assertFalse(result["policy_journal_restored"])
        self.assertEqual(len(result["observations"]), 6)

    def test_old_snapshots_expose_independent_failures_without_masking(self):
        result = core.inspect_selection(core.default_restore_selection())
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(result["positive_control"])
        self.assertEqual({f["kind"] for f in result["findings"]}, {"revived_role", "revived_identity", "revived_session", "revived_secret", "availability_regression"})
        allowed = [row for row in result["observations"] if row["actor"] == "allowed-user"]
        self.assertEqual({row["action"]: row["status"] for row in allowed}, {"read": "PASS", "service_read": "FAIL"})

    def test_single_component_restore_role(self):
        result = core.inspect_selection({**CURRENT, "permissions": "A"})
        self.assertEqual([(f["kind"], f["actor"]) for f in result["findings"]], [("revived_role", "removed-user")])

    def test_external_revocation_and_secret_reconciliation_block_old_state(self):
        result = core.inspect_selection(core.default_restore_selection(), "protected")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["positive_control"])
        self.assertTrue(all(row["status"] == "PASS" for row in result["observations"]))

    def test_unverified_security_change_rejects_experiment(self):
        result = core.inspect_selection(core.default_restore_selection(), fault="baseline_not_revoked")
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertFalse(result["baseline_verified"])
        self.assertEqual(result["restore_receipts"], [])
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["findings"][0]["kind"], "baseline_invalid")

    def test_losing_independent_journal_is_inconclusive(self):
        for mode in core.MODES:
            result = core.inspect_selection(CURRENT, mode, fault="journal_unavailable")
            self.assertEqual(result["status"], "INCONCLUSIVE")
            self.assertEqual(result["observations"], [])
            self.assertEqual(result["findings"][0]["kind"], "policy_unavailable")

    def test_all_deny_does_not_vacuously_pass(self):
        result = core.inspect_selection(CURRENT, fault="deny_all")
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["positive_control"])
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(all(f["kind"] == "availability_regression" for f in result["findings"]))

    def test_real_effect_table_overrides_denial_response(self):
        result = core.inspect_selection(CURRENT, fault="status_effect_disagreement")
        target = next(row for row in result["observations"] if row["id"] == "tag")
        self.assertEqual(target["transport_status"], 403)
        self.assertTrue(target["effect_occurred"])
        self.assertEqual(target["status"], "FAIL")
        self.assertEqual(target["kind"], "unauthorized_effect")

    def test_export_contains_real_distinct_snapshots_and_independent_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "fixtures"
            metadata = core.export_fixtures(destination)
            snapshots = [a for a in metadata["artifacts"] if a["included_in_restore_matrix"]]
            self.assertEqual(len(snapshots), 9)
            for artifact in metadata["artifacts"]:
                path = destination / artifact["path"]
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), artifact["sha256"])
            with closing(sqlite3.connect(destination / "snapshots/A/permissions.sqlite")) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM grants WHERE actor='removed-user'").fetchone()[0], 1)
            with closing(sqlite3.connect(destination / "snapshots/B/permissions.sqlite")) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM grants WHERE actor='removed-user'").fetchone()[0], 0)
            with closing(sqlite3.connect(destination / "snapshots/C/permissions.sqlite")) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM grants WHERE resource='unrelated-demo'").fetchone()[0], 1)
            with closing(sqlite3.connect(destination / metadata["policy_journal"])) as db:
                self.assertEqual(db.execute("SELECT decision FROM expected_policy WHERE probe_id='role'").fetchone()[0], "deny")
            self.assertNotIn(metadata["policy_journal"], [r["path"] for r in snapshots])
            with self.assertRaises(ValueError):
                core.export_fixtures(destination)

    def test_immutable_input_and_serializable_output(self):
        selection = core.default_restore_selection()
        before = dict(selection)
        result = core.inspect_selection(selection)
        self.assertEqual(selection, before)
        selection["identity"] = "C"
        self.assertEqual(core.default_restore_selection()["identity"], "A")
        json.dumps(result)


class MatrixTests(unittest.TestCase):
    def test_exact_27_combinations_and_expected_vulnerable_counts(self):
        result = core.run_matrix(repeats=1)
        self.assertEqual(result["summary"], {"planned": 27, "attempted": 27, "passed": 8, "failed": 19, "inconclusive": 0, "complete": True})
        self.assertEqual(result["status"], "FAIL")
        combinations = {tuple(row["selection"][key] for key in core.COMPONENTS) for row in result["results"]}
        self.assertEqual(combinations, set(itertools.product(core.CHECKPOINTS, repeat=3)))
        self.assertEqual(len({row["id"] for row in result["results"]}), 27)

    def test_protected_complete_matrix_passes_with_allow_controls(self):
        result = core.run_matrix("protected", repeats=1)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["summary"]["passed"], 27)
        self.assertTrue(all(row["positive_control"] for row in result["results"]))

    def test_incomplete_clean_matrix_cannot_pass(self):
        result = core.run_matrix("protected", max_experiments=1, repeats=1)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertFalse(result["summary"]["complete"])
        self.assertEqual(result["summary"]["passed"], 1)

    def test_inconsistent_repeats_are_not_reported_as_stable_failure(self):
        fail = core.inspect_selection(core.default_restore_selection())
        clean = core.inspect_selection(core.default_restore_selection(), "protected")
        with patch.object(core, "inspect_selection", side_effect=[fail, clean]):
            result = core.run_matrix(max_experiments=1, repeats=2)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["results"][0]["findings"][0]["kind"], "unstable_probe")
        self.assertFalse(result["results"][0]["repeat_consistent"])


class ReducerTests(unittest.TestCase):
    def test_three_restore_recipe_reduces_to_permissions_only(self):
        selection = core.default_restore_selection()
        original = dict(selection)
        result = core.minimize_selection(selection)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["minimized_selection"], {"identity": "C", "permissions": "A", "secrets": "C"})
        self.assertEqual(result["original_steps"], 3)
        self.assertEqual(result["minimized_steps"], 1)
        self.assertTrue(result["one_minimal"])
        self.assertEqual(result["signature"], "revived_role:removed-user")
        self.assertEqual(selection, original)
        json.dumps(result)

    def test_session_target_cannot_hop_to_another_violation(self):
        result = core.minimize_selection(core.default_restore_selection(), target_kind="revived_session", target_actor="session-owner")
        self.assertEqual(result["minimized_selection"], {"identity": "A", "permissions": "C", "secrets": "C"})
        self.assertEqual(result["signature"], "revived_session:session-owner")
        self.assertTrue(result["one_minimal"])

    def test_budget_never_overruns_or_claims_unchecked_minimality(self):
        for budget in (1, 2, 4):
            result = core.minimize_selection(core.default_restore_selection(), max_evaluations=budget)
            self.assertLessEqual(result["evaluations"], budget)
            self.assertTrue(result["budget_exhausted"])
            self.assertFalse(result["one_minimal"])

    def test_target_requires_positive_control_and_clean_baseline(self):
        initial = core.inspect_selection(core.default_restore_selection())
        initial["positive_control"] = False
        with patch.object(core, "inspect_selection", return_value=initial):
            result = core.minimize_selection(core.default_restore_selection())
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertIsNone(result["signature"])
        self.assertFalse(result["one_minimal"])

    def test_safe_protection_does_not_produce_fake_witness(self):
        result = core.minimize_selection(core.default_restore_selection(), "protected")
        self.assertEqual(result["status"], "PASS")
        self.assertIsNone(result["signature"])
        self.assertEqual(result["original_selection"], result["minimized_selection"])
        self.assertFalse(result["one_minimal"])


class ScenarioAndValidationTests(unittest.TestCase):
    def test_all_six_documented_scenarios_match_expected_outcomes(self):
        result = core.run_scenarios()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["summary"], {"total": 6, "passed": 6, "failed": 0})
        self.assertEqual([row["id"] for row in result["results"]], [f"RG-{i:03}" for i in range(1, 7)])
        self.assertEqual(result["results"][3]["observed_outcome"], "INCONCLUSIVE")
        self.assertEqual(result["results"][0]["observed_outcome"], "FAIL")

    def test_rejects_malformed_or_unbounded_inputs(self):
        for selection in (None, {}, [], {**CURRENT, "journal": "A"}, {**CURRENT, "identity": "D"}):
            with self.assertRaises(ValueError):
                core.inspect_selection(selection)
        for kwargs in ({"mode": "real-product"}, {"max_experiments": 0}, {"max_experiments": 28}, {"repeats": True}, {"repeats": 0}):
            with self.assertRaises(ValueError):
                core.run_matrix(**kwargs)
        for budget in (0, 1001, False):
            with self.assertRaises(ValueError):
                core.minimize_selection(CURRENT, max_evaluations=budget)
        with self.assertRaises(ValueError):
            core.inspect_selection(CURRENT, fault="arbitrary-code")


if __name__ == "__main__":
    unittest.main()
