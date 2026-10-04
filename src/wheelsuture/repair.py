"""Conservative, verified proposals. This module never executes a repair."""

from .canonical import canonical_bytes, finalize_document
from .constants import PROFILE_ID, VERIFIER_REVISION
from .model import RepairProposal, Limits
from .reducer import Replay
from .errors import UnsupportedInput, VerificationError, LimitExceeded, InvalidInput


def _independent_check(plan, report, proposal):
    from .verify import verify_candidate

    result = verify_candidate(plan, report, proposal)
    if not result.valid or not result.complete:
        raise VerificationError(
            "Independent verification did not establish this proposal."
        )


def _conflict(wheels, desired):
    claims = sorted(
        (c for wid in desired for c in wheels[wid]["claims"] if c["checked"]),
        key=lambda c: (c["destination"].encode("utf8"), c["claim_id"]),
    )
    previous = {}
    for c in claims:
        p = c["destination"]
        s = c["signature"]
        old = previous.get(p)
        if old and old["signature"] != s:
            kind = s["kind"]
            if kind == "bytes":
                return [
                    dict(
                        kind="different_bytes",
                        claim_ids=sorted([old["claim_id"], c["claim_id"]]),
                        destinations=[p],
                        explanation="Desired claims require different copied bytes.",
                    )
                ]
            if kind == "rewritten_script":
                return [
                    dict(
                        kind="different_rewritten_tail",
                        claim_ids=sorted([old["claim_id"], c["claim_id"]]),
                        destinations=[p],
                        explanation="Desired claims require different rewritten script tails.",
                    )
                ]
            raise UnsupportedInput(
                "Supplied claims have unequal provider signatures or different signature kinds.",
                code="unsupported_overlap",
            )
        previous.setdefault(p, c)
    return []


def propose_repair(plan, report, inventories, *, budget):
    original = report.to_dict()
    try:
        declared = Limits(**original["effective_limits"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationError("Invalid original report limits.") from exc
    if any(
        value > getattr(declared, key) for key, value in budget.limits.to_dict().items()
    ):
        raise InvalidInput("Repair limits may not exceed original analysis limits.")
    r = Replay(plan, inventories, budget)
    reconstructed = r.original(declared_limits=declared)
    if canonical_bytes(reconstructed) != canonical_bytes(original):
        raise VerificationError("Report does not match original plan reconstruction.")
    d = dict(
        schema_version=1,
        document_type="repair_proposal",
        profile=PROFILE_ID,
        case_id=plan.case_id,
        input_sha256=plan.input_sha256,
        analysis_evidence_sha256=original["evidence_sha256"],
        strategy="remove_all_then_install_desired",
        status="unknown",
        actions=[],
        witnesses=[],
        diagnostics=[],
        verification=None,
        effective_limits=budget.limits.to_dict(),
    )
    witnesses = _conflict(r.wheels, r.data["desired"])
    if witnesses:
        d.update(status="conflict", witnesses=witnesses)
    else:
        operations_start = len(r.operations)
        events_start = len(r.events)
        findings_start = len(r.findings)
        actions = []
        if original["status"] != "preserved":
            actions.extend(
                dict(id="repair_remove_" + str(i), op="remove", wheel=wid)
                for i, (name, wid) in enumerate(sorted(r.identities.items()))
            )
            desired = sorted(
                r.data["desired"], key=lambda wid: r.wheels[wid]["canonical_name"]
            )
            actions.extend(
                dict(id="repair_install_" + str(i), op="install", wheel=wid)
                for i, wid in enumerate(desired)
            )
        try:
            budget.charge("user_operations", len(actions))
            for i, action in enumerate(actions):
                r.apply(action, "repair", i)
            final = r.desired_findings("repair") if actions else []
            r.findings.extend(final)
            if final:
                raise UnsupportedInput(
                    "Proposed replay does not satisfy final desired claims.",
                    code="unproved_repair",
                )
            usage = budget.usage
            usage["report_bytes"] = 0
            d.update(
                status="verified" if actions else "already_satisfied",
                actions=actions,
                verification=dict(
                    verifier_revision=VERIFIER_REVISION,
                    source_sha256s=[
                        dict(wheel_id=k, sha256=v["source_sha256"])
                        for k, v in sorted(r.wheels.items())
                    ],
                    final_state=r.state(),
                    evidence_sha256="0" * 64,
                    resource_usage=usage,
                    operations=r.operations[operations_start:],
                    events=r.events[events_start:],
                    findings=r.findings[findings_start:],
                ),
            )
            d = finalize_document(d, budget, "repair")
        except UnsupportedInput as e:
            d.update(
                status="unknown",
                actions=[],
                verification=None,
                diagnostics=[e.diagnostic()],
            )
    if len(canonical_bytes(d)) + 1 > budget.limits.report_bytes:
        raise LimitExceeded("Resource limit exceeded: report_bytes")
    _independent_check(plan, original, d)
    return RepairProposal(canonical_bytes(d))
