"""Controlled recovery-security experiments using disposable SQLite stores.

These are synthetic local fixtures, not Keycloak, Vault, JWT, or production
restore tests. Each trial builds fresh identity/permission/secret databases,
copies real closed-database snapshots, then restores the requested combination.
The expected-policy journal and authoritative effect log are never restored.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import shutil
import sqlite3
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path

COMPONENTS = ("identity", "permissions", "secrets")
CHECKPOINTS = ("A", "B", "C")
MODES = ("vulnerable", "protected")
SCOPE = "Synthetic local SQLite recovery-security fixture; no real product adapters"
LIMITATIONS = [
    "Only the controlled SQLite reference fixture is exercised; no Keycloak, Vault, cloud, or production system is tested.",
    "The 27 combinations cover checkpoint selection in one fixed identity/permissions/secrets restore order, not order permutations.",
    "Sessions are opaque fixture references under a fixed lab clock; no JWT, cryptography, network, expiry, or distributed consistency behavior is claimed.",
    "Authorization and secret probes run independently so a stale service credential cannot hide a restored role or session.",
    "Protection depends on an available external revocation authority and secret reconciliation; that authority is outside the restore set.",
    "Disposable fixture databases use memory journals and disabled durability syncing for speed; crash durability is not tested.",
]
FAULTS = (None, "journal_unavailable", "status_effect_disagreement", "baseline_not_revoked", "deny_all", "unknown_effect")
_OLD_KEY = hashlib.sha256(b"fictional-restoreguard-old-key").hexdigest()
_CURRENT_KEY = hashlib.sha256(b"fictional-restoreguard-current-key").hexdigest()
_DOCUMENT_HASH = hashlib.sha256(b"fictional budget document").hexdigest()
_PROBES = [
    {"id": "role", "actor": "removed-user", "action": "read", "resource": "budget-demo", "kind": "revived_role", "session": "S1"},
    {"id": "disabled", "actor": "disabled-user", "action": "read", "resource": "budget-demo", "kind": "revived_identity", "session": "S2"},
    {"id": "session", "actor": "session-owner", "action": "read", "resource": "budget-demo", "kind": "revived_session", "session": "S4"},
    {"id": "allowed", "actor": "allowed-user", "action": "read", "resource": "budget-demo", "kind": "positive_control", "session": "S3"},
    {"id": "old-secret", "actor": "old-secret-client", "action": "old_secret_use", "resource": "service-secret", "kind": "revived_secret"},
    {"id": "service", "actor": "allowed-user", "action": "service_read", "resource": "budget-demo", "kind": "availability_regression", "session": "S3"},
]
_TAG_PROBE = {"id": "tag", "actor": "removed-user", "action": "tag", "resource": "budget-demo", "kind": "unauthorized_effect", "session": "S1"}


def default_restore_selection() -> dict:
    return {component: "A" for component in COMPONENTS}


def _validate_selection(selection: dict) -> dict:
    if not isinstance(selection, dict) or set(selection) != set(COMPONENTS):
        raise ValueError("selection must contain exactly identity, permissions, and secrets")
    if any(value not in CHECKPOINTS for value in selection.values()):
        raise ValueError("each checkpoint must be A, B, or C")
    return {name: selection[name] for name in COMPONENTS}


def _validate_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError("mode must be 'vulnerable' or 'protected'")


def _bounded_int(value, label: str, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{label} must be an integer between 1 and {maximum}")


@contextmanager
def _connection(path: Path):
    # All files are disposable fixtures, never user-supplied evidence databases.
    with closing(sqlite3.connect(path)) as db:
        db.execute("PRAGMA journal_mode=MEMORY")
        db.execute("PRAGMA synchronous=OFF")
        with db:
            yield db


def classify_observation(*, actor: str, action: str, resource: str, expected: str,
                         transport_status: int | None, effect_occurred: bool | None,
                         kind: str) -> dict:
    """Classify independent policy and authoritative effect, not status alone."""
    if expected not in ("allow", "deny"):
        raise ValueError("expected policy must be allow or deny")
    if effect_occurred is not None and type(effect_occurred) is not bool:
        raise ValueError("effect_occurred must be True, False, or None")
    if effect_occurred is True:
        observed, status = "allowed", "PASS" if expected == "allow" else "FAIL"
    elif effect_occurred is False and transport_status in (401, 403, 503):
        observed, status = "denied", "PASS" if expected == "deny" else "FAIL"
    else:
        observed, status = "unknown", "INCONCLUSIVE"
    if status == "FAIL" and expected == "allow":
        kind = "availability_regression"
    return {"actor": actor, "action": action, "resource": resource, "expected": expected,
            "observed": observed, "status": status, "kind": kind,
            "transport_status": transport_status, "effect_occurred": effect_occurred}


class _Fixture:
    """Fresh physical stores and external policy/effect authorities per trial."""

    def __init__(self, root: Path):
        self.root = root
        self.active = root / "active"
        self.active.mkdir()
        self.snapshot_root = root / "snapshots"
        self.snapshot_root.mkdir()
        self.journal = root / "independent-policy.sqlite"
        self.effects = root / "authoritative-effects.sqlite"
        self.receipts = []
        self.baseline = {}

    def path(self, component: str) -> Path:
        return self.active / f"{component}.sqlite"

    def _snapshot(self, checkpoint: str) -> None:
        directory = self.snapshot_root / checkpoint
        directory.mkdir()
        for component in COMPONENTS:
            shutil.copyfile(self.path(component), directory / f"{component}.sqlite")

    def build(self, fault=None) -> bool:
        with _connection(self.path("identity")) as db:
            db.executescript("CREATE TABLE users(actor TEXT PRIMARY KEY, enabled INTEGER, display_name TEXT); CREATE TABLE sessions(sid TEXT PRIMARY KEY, actor TEXT, revoked INTEGER, expires INTEGER);")
            actors = [("removed-user", "S1"), ("disabled-user", "S2"), ("allowed-user", "S3"), ("session-owner", "S4")]
            db.executemany("INSERT INTO users VALUES (?,1,?)", [(actor, actor) for actor, _ in actors])
            db.executemany("INSERT INTO sessions VALUES (?,?,0,10000)", [(sid, actor) for actor, sid in actors])
        with _connection(self.path("permissions")) as db:
            db.execute("CREATE TABLE grants(actor TEXT, resource TEXT, role TEXT, PRIMARY KEY(actor,resource))")
            db.executemany("INSERT INTO grants VALUES (?,'budget-demo','viewer')", [(actor,) for actor, _ in actors])
        with _connection(self.path("secrets")) as db:
            db.execute("CREATE TABLE credential_slots(slot TEXT PRIMARY KEY, fingerprint TEXT, label TEXT)")
            db.executemany("INSERT INTO credential_slots VALUES (?,?,'initial')", [("client", _OLD_KEY), ("verifier", _OLD_KEY)])
        with _connection(self.journal) as db:
            db.executescript("CREATE TABLE expected_policy(probe_id TEXT PRIMARY KEY, decision TEXT); CREATE TABLE denied_grants(actor TEXT, resource TEXT); CREATE TABLE disabled_identities(actor TEXT PRIMARY KEY); CREATE TABLE revoked_sessions(sid TEXT PRIMARY KEY); CREATE TABLE current_key(fingerprint TEXT); CREATE TABLE events(event_id TEXT PRIMARY KEY, description TEXT);")
            db.executemany("INSERT INTO expected_policy VALUES (?,'allow')", [(probe["id"],) for probe in _PROBES])
            db.execute("INSERT INTO expected_policy VALUES ('tag','deny')")
            db.execute("INSERT INTO current_key VALUES (?)", (_OLD_KEY,))
        with _connection(self.effects) as db:
            db.execute("CREATE TABLE effects(probe_id TEXT PRIMARY KEY, actor TEXT, action TEXT, resource TEXT, result_hash TEXT)")
        before = self.probe_all("vulnerable")
        self._snapshot("A")
        # The expected-policy table is an oracle specification; protected
        # enforcement uses separate current revocation/key tables, not outcomes.
        with _connection(self.journal) as db:
            db.execute("UPDATE expected_policy SET decision='deny' WHERE probe_id IN ('role','disabled','session','old-secret')")
            db.execute("INSERT INTO denied_grants VALUES ('removed-user','budget-demo')")
            db.execute("INSERT INTO disabled_identities VALUES ('disabled-user')")
            db.execute("INSERT INTO revoked_sessions VALUES ('S4')")
            db.execute("UPDATE current_key SET fingerprint=?", (_CURRENT_KEY,))
            db.executemany("INSERT INTO events VALUES (?,?)", [("R1", "removed document role"), ("R2", "disabled identity"), ("R3", "revoked opaque session S4"), ("R4", "rotated synthetic service key")])
        with _connection(self.path("identity")) as db:
            db.execute("UPDATE users SET enabled=0 WHERE actor='disabled-user'")
            db.execute("UPDATE sessions SET revoked=1 WHERE sid='S4'")
        if fault != "baseline_not_revoked":
            with _connection(self.path("permissions")) as db:
                db.execute("DELETE FROM grants WHERE actor='removed-user' AND resource='budget-demo'")
        with _connection(self.path("secrets")) as db:
            db.execute("UPDATE credential_slots SET fingerprint=?,label='rotated'", (_CURRENT_KEY,))
        after = self.probe_all("vulnerable")
        self.baseline = {"before_change": [p["status"] for p in before], "after_change": [p["status"] for p in after],
                         "status": "PASS" if all(p["status"] == "PASS" for p in before + after) else "FAIL"}
        if self.baseline["status"] != "PASS":
            return False
        self._snapshot("B")
        with _connection(self.path("identity")) as db:
            db.execute("UPDATE users SET display_name=display_name || ' (updated)'")
        with _connection(self.path("permissions")) as db:
            db.execute("INSERT INTO grants VALUES ('allowed-user','unrelated-demo','viewer')")
        with _connection(self.path("secrets")) as db:
            db.execute("UPDATE credential_slots SET label='benign maintenance'")
        self._snapshot("C")
        return True

    def restore(self, selection: dict, mode: str) -> None:
        for component in COMPONENTS:
            source = self.snapshot_root / selection[component] / f"{component}.sqlite"
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            shutil.copyfile(source, self.path(component))
            if hashlib.sha256(self.path(component).read_bytes()).hexdigest() != digest:
                raise RuntimeError("restored fixture does not match its selected snapshot")
            self.receipts.append({"component": component, "checkpoint": selection[component], "sha256": digest})
        if mode == "protected":
            with _connection(self.journal) as db:
                current = db.execute("SELECT fingerprint FROM current_key").fetchone()[0]
            with _connection(self.path("secrets")) as db:
                db.execute("UPDATE credential_slots SET fingerprint=?,label='reconciled with external authority'", (current,))

    def _authorized(self, probe: dict, mode: str) -> bool:
        with _connection(self.path("identity")) as db:
            row = db.execute("SELECT u.enabled,s.revoked,s.expires FROM users u JOIN sessions s ON s.actor=u.actor WHERE u.actor=? AND s.sid=?", (probe["actor"], probe["session"])).fetchone()
        if row is None or row[0] != 1 or row[1] != 0 or row[2] <= 100:
            return False
        with _connection(self.path("permissions")) as db:
            grant = db.execute("SELECT 1 FROM grants WHERE actor=? AND resource=?", (probe["actor"], probe["resource"])).fetchone()
        if not grant:
            return False
        if mode == "protected":
            with _connection(self.journal) as db:
                blocked_role = db.execute("SELECT 1 FROM denied_grants WHERE actor=? AND resource=?", (probe["actor"], probe["resource"])).fetchone()
                blocked_identity = db.execute("SELECT 1 FROM disabled_identities WHERE actor=?", (probe["actor"],)).fetchone()
                blocked_session = db.execute("SELECT 1 FROM revoked_sessions WHERE sid=?", (probe["session"],)).fetchone()
            if blocked_role or blocked_identity or blocked_session:
                return False
        return True

    def probe_all(self, mode: str, fault=None) -> list[dict]:
        with _connection(self.effects) as db:
            db.execute("DELETE FROM effects")
        probes = _PROBES + ([_TAG_PROBE] if fault == "status_effect_disagreement" else [])
        observations = []
        for probe in probes:
            with _connection(self.journal) as db:
                expected = db.execute("SELECT decision FROM expected_policy WHERE probe_id=?", (probe["id"],)).fetchone()[0]
                backend_key = db.execute("SELECT fingerprint FROM current_key").fetchone()[0]
            if probe["action"] == "old_secret_use":
                with _connection(self.path("secrets")) as db:
                    verifier = db.execute("SELECT fingerprint FROM credential_slots WHERE slot='verifier'").fetchone()[0]
                allowed = verifier == _OLD_KEY
                if mode == "protected":
                    allowed = allowed and backend_key == _OLD_KEY
                transport = 200 if allowed else 403
            else:
                allowed = self._authorized(probe, mode)
                transport = 200 if allowed else 403
                if probe["action"] == "service_read" and allowed:
                    with _connection(self.path("secrets")) as db:
                        client = db.execute("SELECT fingerprint FROM credential_slots WHERE slot='client'").fetchone()[0]
                    if client != backend_key:
                        allowed, transport = False, 503
            if fault == "deny_all":
                allowed, transport = False, 403
            if probe["action"] == "tag":
                # Deliberately seeded bad application behavior: mutate, then
                # return denial. The effect observer must override the response.
                allowed, transport = True, 403
            if allowed:
                with _connection(self.effects) as db:
                    db.execute("INSERT INTO effects VALUES (?,?,?,?,?)", (probe["id"], probe["actor"], probe["action"], probe["resource"], _DOCUMENT_HASH))
            with _connection(self.effects) as db:
                effect = db.execute("SELECT 1 FROM effects WHERE probe_id=? AND actor=? AND action=? AND resource=? AND result_hash=?", (probe["id"], probe["actor"], probe["action"], probe["resource"], _DOCUMENT_HASH)).fetchone() is not None
            if fault == "unknown_effect":
                effect = None
            observation = classify_observation(actor=probe["actor"], action=probe["action"], resource=probe["resource"], expected=expected,
                                               transport_status=transport, effect_occurred=effect, kind=probe["kind"])
            observation["id"] = probe["id"]
            observations.append(observation)
        return observations


def _aggregate(observations: list[dict]) -> str:
    if any(item["status"] == "FAIL" for item in observations):
        return "FAIL"
    if not observations or any(item["status"] == "INCONCLUSIVE" for item in observations):
        return "INCONCLUSIVE"
    return "PASS"


def inspect_selection(selection: dict, mode: str = "vulnerable", *, fault=None) -> dict:
    """Run one fresh, verified, physically restored fixture experiment."""
    selection = _validate_selection(selection)
    _validate_mode(mode)
    if fault not in FAULTS:
        raise ValueError("unsupported built-in fixture fault")
    result = {"id": "_".join(f"{name[0].upper()}-{selection[name]}" for name in COMPONENTS),
              "selection": selection, "mode": mode, "status": "INCONCLUSIVE", "observations": [], "findings": [],
              "scope": SCOPE, "restore_order": list(COMPONENTS), "policy_journal_restored": False,
              "baseline_verified": False, "positive_control": False, "restore_receipts": []}
    with tempfile.TemporaryDirectory(prefix="restoreguard-") as directory:
        fixture = _Fixture(Path(directory))
        if not fixture.build(fault):
            result.update(baseline=fixture.baseline, findings=[{"kind": "baseline_invalid", "actor": "fixture", "message": "Security changes were not verified before restore; experiment rejected"}])
            return result
        result.update(baseline_verified=True, baseline=fixture.baseline)
        if fault == "journal_unavailable":
            fixture.journal.unlink()
            result["findings"] = [{"kind": "policy_unavailable", "actor": "policy-authority", "message": "Independent current policy unavailable; no access conclusion is justified"}]
            return result
        fixture.restore(selection, mode)
        observations = fixture.probe_all(mode, fault)
        findings = [{"kind": item["kind"], "actor": item["actor"], "action": item["action"], "resource": item["resource"],
                     "expected": item["expected"], "observed": item["observed"], "transport_status": item["transport_status"],
                     "effect_occurred": item["effect_occurred"]} for item in observations if item["status"] == "FAIL"]
        result.update(status=_aggregate(observations), observations=observations, findings=findings,
                      positive_control=any(item["id"] == "allowed" and item["status"] == "PASS" and item["effect_occurred"] is True for item in observations),
                      restore_receipts=fixture.receipts)
    return result


def export_fixtures(directory: Path) -> dict:
    """Persist reproducible reference inputs to a new or empty output directory.

    No existing files are replaced. Metadata paths are relative to this output
    directory. The external policy journal is explicitly excluded from restores.
    Stored credentials are fictional one-way fingerprints, never usable tokens.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError("fixture export directory must be empty; existing artifacts are never replaced")
    fixture = _Fixture(directory)
    if not fixture.build():
        raise RuntimeError("reference fixture failed baseline verification")
    artifacts = []
    for path in sorted(directory.rglob("*.sqlite")):
        artifacts.append({"path": path.relative_to(directory).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size,
                          "included_in_restore_matrix": path.is_relative_to(fixture.snapshot_root)})
    return {"scope": SCOPE, "baseline": fixture.baseline, "artifacts": artifacts,
            "checkpoint_meanings": {"A": "before security changes", "B": "after verified security changes", "C": "after subsequent benign changes"},
            "policy_journal": "independent-policy.sqlite", "policy_journal_restored": False,
            "restore_order": list(COMPONENTS), "limitations": list(LIMITATIONS)}


def _fingerprint(result: dict) -> str:
    return json.dumps({field: result.get(field) for field in ("status", "observations", "findings", "positive_control", "baseline_verified")}, sort_keys=True)


def run_matrix(mode: str = "vulnerable", max_experiments: int = 27, repeats: int = 2) -> dict:
    _validate_mode(mode)
    _bounded_int(max_experiments, "max_experiments", 27)
    _bounded_int(repeats, "repeats", 10)
    results = []
    for points in list(itertools.product(CHECKPOINTS, repeat=3))[:max_experiments]:
        selection = dict(zip(COMPONENTS, points))
        trials = [inspect_selection(selection, mode) for _ in range(repeats)]
        result = copy.deepcopy(trials[0])
        result["repeats"] = repeats
        result["repeat_consistent"] = len({_fingerprint(trial) for trial in trials}) == 1
        if not result["repeat_consistent"]:
            result.update(status="INCONCLUSIVE", observations=[], findings=[{"kind": "unstable_probe", "actor": "fixture", "message": "Independent repeated trials disagreed; their access observations cannot establish a stable result"}], positive_control=False)
        results.append(result)
    summary = {"planned": 27, "attempted": len(results), "passed": sum(r["status"] == "PASS" for r in results),
               "failed": sum(r["status"] == "FAIL" for r in results), "inconclusive": sum(r["status"] == "INCONCLUSIVE" for r in results),
               "complete": len(results) == 27}
    status = "FAIL" if summary["failed"] else "INCONCLUSIVE" if summary["inconclusive"] or not summary["complete"] else "PASS"
    return {"status": status, "mode": mode, "summary": summary, "results": results, "repeats": repeats,
            "limitations": list(LIMITATIONS), "scope": SCOPE}


def minimize_selection(selection: dict, mode: str = "vulnerable", target_kind: str = "revived_role",
                       target_actor: str = "removed-user", max_evaluations: int = 100) -> dict:
    """Remove restore steps by selecting C, preserving kind+actor and control.

    Each oracle decision repeats two fresh experiments. 1-minimality means no
    remaining individual non-C component can be set to C while preserving this
    finding and the allowed-user authorization control. It is not global or an
    optimization over restore order, other checkpoints, or arbitrary steps.
    """
    original = _validate_selection(selection)
    _validate_mode(mode)
    _bounded_int(max_evaluations, "max_evaluations", 1000)
    if not isinstance(target_kind, str) or not target_kind or not isinstance(target_actor, str) or not target_actor:
        raise ValueError("target_kind and target_actor must be nonempty strings")
    current, history, evaluations, budget_exhausted = dict(original), [], 0, False
    signature = f"{target_kind}:{target_actor}"

    def oracle(choice: dict, phase: str) -> tuple[dict, bool]:
        nonlocal evaluations, budget_exhausted
        if evaluations + 2 > max_evaluations:
            budget_exhausted = True
            result = {"status": "INCONCLUSIVE", "positive_control": False, "findings": []}
        else:
            trials = [inspect_selection(choice, mode) for _ in range(2)]
            evaluations += 2
            result = trials[0]
            if _fingerprint(trials[0]) != _fingerprint(trials[1]):
                result = {"status": "INCONCLUSIVE", "positive_control": False, "findings": []}
        reproduces = result["status"] == "FAIL" and result["positive_control"] and any(f.get("kind") == target_kind and f.get("actor") == target_actor for f in result["findings"])
        history.append({"phase": phase, "selection": dict(choice), "status": result["status"], "signature": signature if reproduces else None, "evaluations": evaluations})
        return result, reproduces

    initial, reproduced = oracle(current, "baseline target")
    one_minimal = False
    if reproduced:
        stable, _ = oracle({component: "C" for component in COMPONENTS}, "clean baseline")
        if stable["status"] == "PASS":
            while not budget_exhausted:
                reduced, inconclusive = False, False
                for component in COMPONENTS:
                    if current[component] == "C":
                        continue
                    candidate = dict(current)
                    candidate[component] = "C"
                    observation, accepted = oracle(candidate, "single restore removal")
                    history[-1]["accepted"] = accepted
                    if accepted:
                        current, reduced = candidate, True
                        break
                    inconclusive |= observation["status"] == "INCONCLUSIVE"
                    if budget_exhausted:
                        break
                if reduced:
                    continue
                one_minimal = not inconclusive and not budget_exhausted
                break
    status = "FAIL" if reproduced else "PASS" if initial["status"] == "PASS" else "INCONCLUSIVE"
    return {"status": status, "mode": mode, "original_selection": original, "minimized_selection": current,
            "original_steps": sum(v != "C" for v in original.values()), "minimized_steps": sum(v != "C" for v in current.values()),
            "one_minimal": one_minimal, "evaluations": evaluations, "max_evaluations": max_evaluations, "budget_exhausted": budget_exhausted,
            "history": history, "signature": signature if reproduced else None,
            "target_kind": target_kind, "target_actor": target_actor, "repeats": 2,
            "limitations": list(LIMITATIONS) + ["1-minimal only under replacing a remaining restore checkpoint with C; not a globally shortest recipe."], "scope": SCOPE}


def run_scenarios() -> dict:
    """Validate the six documented seeded/control scenarios, RG-001..RG-006."""
    specs = [
        ("RG-001", "Removed role returns", {"identity": "C", "permissions": "A", "secrets": "C"}, "vulnerable", None, "FAIL", "revived_role"),
        ("RG-002", "External current policy blocks old ACL", {"identity": "C", "permissions": "A", "secrets": "C"}, "protected", None, "PASS", None),
        ("RG-003", "Revoked session returns", {"identity": "A", "permissions": "C", "secrets": "C"}, "vulnerable", None, "FAIL", "revived_session"),
        ("RG-004", "Independent policy unavailable", {"identity": "C", "permissions": "C", "secrets": "C"}, "vulnerable", "journal_unavailable", "INCONCLUSIVE", "policy_unavailable"),
        ("RG-005", "Stale client credential blocks legitimate service read", {"identity": "C", "permissions": "C", "secrets": "A"}, "vulnerable", None, "FAIL", "availability_regression"),
        ("RG-006", "Denial response conceals completed mutation", {"identity": "C", "permissions": "C", "secrets": "C"}, "vulnerable", "status_effect_disagreement", "FAIL", "unauthorized_effect"),
    ]
    results = []
    for sid, title, selection, mode, fault, outcome, kind in specs:
        observed = inspect_selection(selection, mode, fault=fault)
        kinds = sorted({finding["kind"] for finding in observed["findings"]})
        passed = observed["status"] == outcome and (kind is None or kind in kinds)
        results.append({"id": sid, "title": title, "expected_outcome": outcome, "observed_outcome": observed["status"],
                        "status": "PASS" if passed else "FAIL", "expected_kind": kind, "observed_kinds": kinds, "inspection": observed})
    summary = {"total": len(results), "passed": sum(r["status"] == "PASS" for r in results), "failed": sum(r["status"] == "FAIL" for r in results)}
    return {"status": "PASS" if summary["failed"] == 0 else "FAIL", "summary": summary, "results": results, "scope": SCOPE,
            "interpretation": "PASS means the observed experiment outcome matched the documented expectation, including intentionally unsafe and inconclusive scenarios."}
