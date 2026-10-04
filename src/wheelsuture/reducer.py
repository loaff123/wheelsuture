"""Lifecycle state: immutable claims and actual contents are deliberately separate."""

from collections import defaultdict
from .canonical import canonical_bytes, digest, finalize_document
from .constants import PROFILE_ID, MODEL_REVISION, COVERAGE
from .model import AnalysisReport, WheelInventory, Plan
from .errors import InvalidInput, UnsupportedInput

MAXIMA = {
    "member_bytes",
    "record_member_bytes",
    "metadata_member_bytes",
    "json_depth",
    "state_slots",
    "report_bytes",
}


def _seed_budget(plan, inventories, budget):
    totals = {k: 0 for k in budget.usage}
    for source in plan.sources:
        inv = inventories.get(source.id)
        if not isinstance(inv, WheelInventory) or not inv.validated():
            raise InvalidInput("Inventory was not validated by inventory_wheel.")
        if (
            inv.profile_id != PROFILE_ID
            or inv.source_sha256 != source.sha256
            or inv.to_dict()["wheel_id"] != source.id
        ):
            raise InvalidInput("Inventory provenance differs from plan.")
        for k, v in inv.resource_usage.items():
            totals[k] = max(totals[k], v) if k in MAXIMA else totals[k] + v
    totals.update(
        plan_bytes=plan.plan_bytes,
        json_depth=plan.json_depth,
        user_operations=len(plan.to_dict()["initial"])
        + len(plan.to_dict()["transition"]),
    )
    for k, value in totals.items():
        old = budget.usage[k]
        if old not in (0, value):
            raise InvalidInput("Budget contains unrelated work: " + k)
        budget.maximum(k, value)


def _global_preflight(wheels):
    paths = set()
    by_path = {}
    for wheel in wheels.values():
        for c in wheel["claims"]:
            p = c["destination"]
            paths.add(p)
            sig = c["signature"]
            old = by_path.get(p)
            if old is not None:
                if old["kind"] != sig["kind"] or (
                    sig["kind"] == "entry_point" and old != sig
                ):
                    raise UnsupportedInput(
                        "Supplied claims have unequal provider signatures or different signature kinds.",
                        code="unsupported_overlap",
                    )
            else:
                by_path[p] = sig
    for p in paths:
        parts = p.split("/")
        if any("/".join(parts[:i]) in paths for i in range(1, len(parts))):
            raise UnsupportedInput(
                "Historical artifact destinations have a file/ancestor collision.",
                code="historical_prefix",
            )


def _finding_key(f):
    return (
        f["kind"],
        b"" if f["destination"] is None else f["destination"].encode("utf8"),
        f["wheel_ids"],
        f["claim_ids"],
    )


class Replay:
    def __init__(self, plan, inventories, budget):
        if not isinstance(plan, Plan) or not plan.validated():
            raise InvalidInput("Plan was not validated by load_plan.")
        self.plan = plan
        self.data = plan.to_dict()
        self.budget = budget
        if set(inventories) != set(w["id"] for w in self.data["wheels"]):
            raise InvalidInput("Inventory set differs from plan.")
        _seed_budget(plan, inventories, budget)
        self.wheels = {k: v.to_dict() for k, v in inventories.items()}
        _global_preflight(self.wheels)
        desired_names = [self.wheels[w]["canonical_name"] for w in self.data["desired"]]
        if len(set(desired_names)) != len(desired_names):
            raise InvalidInput("Desired set repeats a canonical distribution name.")
        self.identities = {}
        self.slots = {}
        self.latest = {}
        self.tombstones = {}
        self.active_claims = {}
        self.reverse = defaultdict(set)
        self.bad = set()
        self.operations = []
        self.events = []
        self.findings = []

    def _refresh(self, path):
        actual = self.slots.get(path)
        for cid in self.reverse.get(path, ()):
            claim = self.active_claims[cid]
            if actual is None or actual["signature"] != claim["signature"]:
                self.bad.add(cid)
            else:
                self.bad.discard(cid)

    def _event(self, operation, claim, write, ordinal):
        p = claim["destination"]
        before = self.slots.get(p)
        before_sig = before["signature"] if before else None
        after = claim["signature"] if write else None
        action = ("control_" if claim["kind"] == "control" else "") + (
            "write" if write else "delete" if before else "delete_absent"
        )
        self.budget.charge("expanded_events", 1)
        eid = digest(
            "wheelsuture/event/1",
            [operation["operation_id"], ordinal, p, action, before_sig, after],
        )
        event = dict(
            event_id=eid,
            operation_id=operation["operation_id"],
            ordinal=ordinal,
            action=action,
            path_id=claim["path_id"],
            destination=p,
            wheel_id=claim["wheel_id"],
            claim_id=claim["claim_id"],
            before=before_sig,
            after=after,
            prior_event_id=self.latest.get(p),
        )
        if write:
            self.budget.maximum("state_slots", len(self.slots) + (p not in self.slots))
            self.slots[p] = dict(
                path_id=claim["path_id"],
                destination=p,
                signature=after,
                last_event_id=eid,
            )
            self.tombstones.pop(p, None)
        elif before:
            del self.slots[p]
            self.tombstones[p] = eid
        self.latest[p] = eid
        self.events.append(event)
        self._refresh(p)

    def _add(self, wid, operation, ordinal):
        wheel = self.wheels[wid]
        name = wheel["canonical_name"]
        if name in self.identities:
            raise InvalidInput(
                "Install requires an absent canonical name.",
                operation_id=operation["source"]["id"],
            )
        self.identities[name] = wid
        for c in wheel["claims"]:
            if c["checked"]:
                self.active_claims[c["claim_id"]] = c
                self.reverse[c["destination"]].add(c["claim_id"])
            self._event(operation, c, True, ordinal)
            ordinal += 1
        return ordinal

    def _remove(self, wid, operation, ordinal):
        wheel = self.wheels[wid]
        name = wheel["canonical_name"]
        if self.identities.get(name) != wid:
            raise InvalidInput(
                "Remove requires the exact active artifact.",
                operation_id=operation["source"]["id"],
            )
        del self.identities[name]
        for c in wheel["claims"]:
            if c["checked"]:
                self.active_claims.pop(c["claim_id"], None)
                self.reverse[c["destination"]].discard(c["claim_id"])
                self.bad.discard(c["claim_id"])
        for c in wheel["claims"]:
            self._event(operation, c, False, ordinal)
            ordinal += 1
        return ordinal

    def _finding(
        self,
        phase,
        boundary,
        kind,
        retained,
        wids,
        cids,
        path=None,
        expected=None,
        actual=None,
        cause=None,
    ):
        wids = sorted(wids)
        cids = sorted(cids)
        fid = digest(
            "wheelsuture/finding/1",
            [
                self.plan.case_id,
                phase,
                boundary,
                kind,
                retained,
                wids,
                cids,
                path,
                expected,
                actual,
                cause,
            ],
        )
        self.budget.charge("findings", 1)
        return dict(
            finding_id=fid,
            boundary_operation_id=boundary,
            phase=phase,
            kind=kind,
            retained=retained,
            wheel_ids=wids,
            claim_ids=cids,
            path_id=digest("wheelsuture/path/1", [PROFILE_ID, path]) if path else None,
            destination=path,
            expected=expected,
            actual=actual,
            cause_event_id=cause,
        )

    def _claim_finding(self, c, phase, boundary, retained):
        slot = self.slots.get(c["destination"])
        if slot and slot["signature"] == c["signature"]:
            return None
        return self._finding(
            phase,
            boundary,
            "displaced" if slot else "missing",
            retained,
            [c["wheel_id"]],
            [c["claim_id"]],
            c["destination"],
            c["signature"],
            slot["signature"] if slot else None,
            slot["last_event_id"] if slot else self.tombstones.get(c["destination"]),
        )

    def apply(self, source, phase, index):
        before_names = set(self.identities)
        oid = digest(
            "wheelsuture/operation/1", [self.plan.case_id, phase, index, source]
        )
        operation = dict(operation_id=oid, phase=phase, index=index, source=source)
        verb = source["op"]
        ordinal = 0
        if verb == "replace":
            a, b = source["from"], source["to"]
            if (
                self.wheels[a]["canonical_name"] != self.wheels[b]["canonical_name"]
                or self.wheels[a]["source_sha256"] == self.wheels[b]["source_sha256"]
            ):
                raise InvalidInput(
                    "Replace requires different artifacts of the same canonical name."
                )
            ordinal = self._remove(a, operation, ordinal)
            self._add(b, operation, ordinal)
        elif verb == "reinstall":
            ordinal = self._remove(source["wheel"], operation, ordinal)
            self._add(source["wheel"], operation, ordinal)
        elif verb == "remove":
            self._remove(source["wheel"], operation, ordinal)
        elif verb == "install":
            self._add(source["wheel"], operation, ordinal)
        else:
            raise InvalidInput("Unsupported operation.")
        self.operations.append(operation)
        findings = []
        for cid in self.bad:
            c = self.active_claims[cid]
            name = self.wheels[c["wheel_id"]]["canonical_name"]
            findings.append(
                self._claim_finding(
                    c, phase, oid, name in before_names and name in self.identities
                )
            )
        self.findings.extend(sorted(findings, key=_finding_key))

    def desired_findings(self, phase="final"):
        findings = []
        desired = {self.wheels[w]["canonical_name"]: w for w in self.data["desired"]}
        for name in sorted(set(desired) | set(self.identities)):
            expected = desired.get(name)
            actual = self.identities.get(name)
            if expected != actual:
                kind = (
                    "identity_missing"
                    if actual is None
                    else "identity_extra"
                    if expected is None
                    else "identity_mismatch"
                )
                findings.append(
                    self._finding(
                        phase,
                        None,
                        kind,
                        False,
                        [w for w in [actual, expected] if w is not None],
                        [],
                    )
                )
        for wid in self.data["desired"]:
            for c in self.wheels[wid]["claims"]:
                if c["checked"]:
                    finding = self._claim_finding(c, phase, None, False)
                    if finding:
                        findings.append(finding)
        return sorted(findings, key=_finding_key)

    def state(self):
        identities = [
            dict(
                canonical_name=name,
                wheel_id=wid,
                sha256=self.wheels[wid]["source_sha256"],
            )
            for name, wid in sorted(self.identities.items())
        ]
        slots = [
            self.slots[p] for p in sorted(self.slots, key=lambda x: x.encode("utf8"))
        ]
        state = dict(identities=identities, slots=slots)
        state["state_sha256"] = digest("wheelsuture/state/1", state)
        return state

    def original(self, declared_limits=None):
        for phase in ("initial", "transition"):
            for i, source in enumerate(self.data[phase]):
                self.apply(source, phase, i)
        final = self.desired_findings()
        self.findings.extend(final)
        d = dict(
            schema_version=1,
            document_type="analysis_report",
            model_revision=MODEL_REVISION,
            profile=PROFILE_ID,
            case_id=self.plan.case_id,
            input_sha256=self.plan.input_sha256,
            status="broken" if final else "preserved",
            complete=True,
            coverage=COVERAGE,
            wheels=[self.wheels[w["id"]] for w in self.data["wheels"]],
            operations=self.operations.copy(),
            events=self.events.copy(),
            findings=self.findings.copy(),
            final_state=self.state(),
            desired=self.data["desired"],
            diagnostics=[],
            resource_usage=self.budget.usage,
            effective_limits=(declared_limits or self.budget.limits).to_dict(),
            evidence_sha256="0" * 64,
        )
        return finalize_document(d, self.budget, "report")


def _simulate_snapshot(plan, inventories, *, budget):
    """Private pure-state entry point used by finite synthetic unit tests."""
    return AnalysisReport(canonical_bytes(Replay(plan, inventories, budget).original()))


def simulate(plan, inventories, *, budget):
    result = _simulate_snapshot(plan, inventories, budget=budget)
    from .plan import rehash_sources

    rehash_sources(plan)
    return result
