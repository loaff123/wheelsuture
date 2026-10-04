"""Independent ownership reconstruction and causal evidence expansion."""

from __future__ import annotations

from ..canonical import digest
from ..errors import InvalidInput


class Replay:
    def __init__(self, plan, inventories, case_id, budget):
        self.plan = plan
        self.wheels = {w["wheel_id"]: w for w in inventories}
        self.case = case_id
        self.profile = plan["profile"]
        self.budget = budget
        self.active = {}
        self.actual = {}
        self.last_event = {}
        self.tombstones = {}
        self.operations = []
        self.events = []
        self.findings = []

    def _finding(
        self,
        phase,
        boundary,
        kind,
        wheels,
        claims=(),
        path=None,
        expected=None,
        actual=None,
        cause=None,
        retained=False,
    ):
        wheels, claims = sorted(wheels), sorted(claims)
        self.budget.charge("findings", 1)
        fid = digest(
            "wheelsuture/finding/1",
            [
                self.case,
                phase,
                boundary,
                kind,
                retained,
                wheels,
                claims,
                path,
                expected,
                actual,
                cause,
            ],
        )
        return dict(
            finding_id=fid,
            boundary_operation_id=boundary,
            phase=phase,
            kind=kind,
            retained=retained,
            wheel_ids=wheels,
            claim_ids=claims,
            path_id=digest("wheelsuture/path/1", [self.profile, path])
            if path is not None
            else None,
            destination=path,
            expected=expected,
            actual=actual,
            cause_event_id=cause,
        )

    @staticmethod
    def _order(f):
        path = f["destination"]
        return (
            f["kind"],
            (0, b"") if path is None else (1, path.encode("utf-8")),
            f["wheel_ids"],
            f["claim_ids"],
        )

    def _claim_failures(self, wheel_ids, phase, boundary, retained_names):
        result = []
        for wheel_id in wheel_ids:
            wheel = self.wheels[wheel_id]
            for claim in wheel["claims"]:
                if not claim["checked"]:
                    continue
                path = claim["destination"]
                observed = self.actual.get(path)
                actual = observed["signature"] if observed else None
                if actual == claim["signature"]:
                    continue
                cause = (
                    observed["last_event_id"] if observed else self.tombstones.get(path)
                )
                result.append(
                    self._finding(
                        phase,
                        boundary,
                        "displaced" if observed else "missing",
                        [wheel_id],
                        [claim["claim_id"]],
                        path,
                        claim["signature"],
                        actual,
                        cause,
                        wheel["canonical_name"] in retained_names,
                    )
                )
        return result

    def _change_path(self, operation_id, wheel_id, claim, writing, ordinal):
        path = claim["destination"]
        observed = self.actual.get(path)
        before = observed["signature"] if observed else None
        after = claim["signature"] if writing else None
        if writing:
            action = "control_write" if claim["kind"] == "control" else "write"
        else:
            action = "control_delete" if claim["kind"] == "control" else "delete"
            if observed is None:
                action += "_absent"
        self.budget.charge("expanded_events", 1)
        eid = digest(
            "wheelsuture/event/1", [operation_id, ordinal, path, action, before, after]
        )
        event = dict(
            event_id=eid,
            operation_id=operation_id,
            ordinal=ordinal,
            action=action,
            path_id=claim["path_id"],
            destination=path,
            wheel_id=wheel_id,
            claim_id=claim["claim_id"],
            before=before,
            after=after,
            prior_event_id=self.last_event.get(path),
        )
        if writing:
            if path not in self.actual:
                self.budget.maximum("state_slots", len(self.actual) + 1)
            self.actual[path] = dict(
                path_id=claim["path_id"],
                destination=path,
                signature=after,
                last_event_id=eid,
            )
            self.tombstones.pop(path, None)
        elif observed is not None:
            del self.actual[path]
            self.tombstones[path] = eid
        self.last_event[path] = eid
        self.events.append(event)

    def apply(self, source, phase, index):
        previous_names = set(self.active)
        operation_id = digest(
            "wheelsuture/operation/1", [self.case, phase, index, source]
        )
        op = source["op"]
        remove_id = (
            source.get("from")
            if op == "replace"
            else source.get("wheel")
            if op in ("remove", "reinstall")
            else None
        )
        install_id = (
            source.get("to")
            if op == "replace"
            else source.get("wheel")
            if op in ("install", "reinstall")
            else None
        )
        if remove_id is not None:
            name = self.wheels[remove_id]["canonical_name"]
            if self.active.get(name) != remove_id:
                raise InvalidInput(
                    "Removal, reinstall or replacement requires exact active wheel"
                )
        if op == "replace":
            old, new = self.wheels[remove_id], self.wheels[install_id]
            if (
                old["canonical_name"] != new["canonical_name"]
                or old["source_sha256"] == new["source_sha256"]
            ):
                raise InvalidInput(
                    "Replace requires different artifacts of the same normalized name"
                )
        if install_id is not None:
            name = self.wheels[install_id]["canonical_name"]
            if name in self.active and remove_id is None:
                raise InvalidInput(
                    "Install requires absent normalized distribution name"
                )
        self.operations.append(
            dict(operation_id=operation_id, phase=phase, index=index, source=source)
        )
        ordinal = 0
        if remove_id is not None:
            wheel = self.wheels[remove_id]
            for claim in wheel["claims"]:
                self._change_path(operation_id, remove_id, claim, False, ordinal)
                ordinal += 1
            del self.active[wheel["canonical_name"]]
        if install_id is not None:
            wheel = self.wheels[install_id]
            for claim in wheel["claims"]:
                self._change_path(operation_id, install_id, claim, True, ordinal)
                ordinal += 1
            self.active[wheel["canonical_name"]] = install_id
        failures = self._claim_failures(
            self.active.values(), phase, operation_id, previous_names & set(self.active)
        )
        self.findings.extend(sorted(failures, key=self._order))

    def finish(self, phase="final"):
        desired = {
            self.wheels[wid]["canonical_name"]: wid for wid in self.plan["desired"]
        }
        if len(desired) != len(self.plan["desired"]):
            raise InvalidInput(
                "Desired artifacts repeat a normalized distribution name"
            )
        failures = []
        for name in sorted(self.active.keys() | desired.keys()):
            wanted, active = desired.get(name), self.active.get(name)
            if wanted == active:
                continue
            if active is None:
                kind, ids = "identity_missing", [wanted]
            elif wanted is None:
                kind, ids = "identity_extra", [active]
            else:
                kind, ids = "identity_mismatch", [wanted, active]
            failures.append(self._finding(phase, None, kind, ids))
        failures += self._claim_failures(self.plan["desired"], phase, None, set())
        failures.sort(key=self._order)
        self.findings.extend(failures)
        return failures

    def state(self):
        identities = [
            dict(
                canonical_name=name,
                wheel_id=wid,
                sha256=self.wheels[wid]["source_sha256"],
            )
            for name, wid in sorted(self.active.items())
        ]
        slots = [
            self.actual[p] for p in sorted(self.actual, key=lambda p: p.encode("utf-8"))
        ]
        state = dict(identities=identities, slots=slots)
        return dict(state, state_sha256=digest("wheelsuture/state/1", state))
