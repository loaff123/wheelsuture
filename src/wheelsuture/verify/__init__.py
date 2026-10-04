"""Complete evidence verification by independently authored parsing and replay.

Only immutable model values, generic canonical hashing and fixed constants are
shared with the producer. This package never imports the production archive,
inventory, profile mapping, reducer or repair implementation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from ..canonical import canonical_bytes, digest, finalize_document
from ..constants import COVERAGE, MODEL_REVISION, PROFILE_ID, VERIFIER_REVISION
from ..errors import (
    InputChanged,
    InvalidInput,
    LimitExceeded,
    UnsupportedInput,
    VerificationError,
)
from ..model import Budget, DEFAULT_LIMITS, Limits, Plan
from ._replay import Replay
from ._source import check_union, inventory, path_parts, read_regular, read_source


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    complete: bool
    status: str
    diagnostics: tuple[str, ...] = ()

    @property
    def exit_code(self):
        return 0 if self.valid and self.complete else 3 if not self.complete else 5

    def to_dict(self):
        return asdict(self)


def _strict_read(path, cap, depth_cap):
    raw = read_regular(path, cap)
    if len(raw) > cap:
        raise LimitExceeded("JSON byte budget exceeded")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InvalidInput("JSON byte-order marks are forbidden")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise InvalidInput("JSON must be strict UTF-8") from exc
    depth, maximum, quoted, escape = 0, 0, False, False
    for c in text:
        if quoted:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c in "[{":
            depth += 1
            maximum = max(maximum, depth)
            if depth > depth_cap:
                raise LimitExceeded("JSON nesting depth exceeded")
        elif c in "]}":
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidInput("Duplicate JSON object key")
            result[key] = value
        return result

    def no_float(value):
        raise InvalidInput("JSON floats and nonfinite values are forbidden")

    try:
        value = json.loads(
            text, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float
        )
    except (ValueError, RecursionError) as exc:
        raise InvalidInput("Malformed strict JSON") from exc

    def scalars(v):
        if isinstance(v, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
                raise InvalidInput("Unpaired Unicode surrogate in JSON")
        elif isinstance(v, dict):
            for key, val in v.items():
                scalars(key)
                scalars(val)
        elif isinstance(v, list):
            for val in v:
                scalars(val)

    scalars(value)
    return value, raw, maximum


def _shape(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise InvalidInput("Unexpected or missing plan object fields")


def _id(value):
    if (
        type(value) is not str
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value) is None
    ):
        raise InvalidInput("Invalid plan identifier")


def _read_plan(path, budget):
    value, raw, depth = _strict_read(
        path, budget.limits.plan_bytes, budget.limits.json_depth
    )
    _shape(
        value,
        ("schema_version", "profile", "wheels", "initial", "transition", "desired"),
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise InvalidInput("Unsupported plan schema")
    profile = value["profile"]
    if (
        type(profile) is not str
        or len(profile) > 128
        or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", profile)
    ):
        raise InvalidInput("Malformed profile identifier")
    for key in ("wheels", "initial", "transition", "desired"):
        if type(value[key]) is not list:
            raise InvalidInput("Plan array field is not an array")
    if (
        len(value["wheels"]) > budget.limits.wheels
        or len(value["desired"]) > budget.limits.wheels
    ):
        raise LimitExceeded("Resource limit exceeded: wheels")
    budget.charge("plan_bytes", len(raw))
    budget.maximum("json_depth", depth)
    budget.charge("user_operations", len(value["initial"]) + len(value["transition"]))
    wheel_ids, paths, hashes = set(), set(), set()
    for source in value["wheels"]:
        _shape(source, ("id", "path", "sha256"))
        _id(source["id"])
        path_, h = source["path"], source["sha256"]
        if type(path_) is not str or not path_.endswith(".whl"):
            raise InvalidInput("Wheel source path must end in .whl")
        try:
            path_parts(path_)
        except UnsupportedInput as exc:
            raise InvalidInput("Invalid source relative path") from exc
        if type(h) is not str or re.fullmatch(r"[0-9a-f]{64}", h) is None:
            raise InvalidInput("Invalid pinned wheel digest")
        if source["id"] in wheel_ids or path_ in paths or h in hashes:
            raise InvalidInput("Repeated wheel identifier, path or digest")
        wheel_ids.add(source["id"])
        paths.add(path_)
        hashes.add(h)
    operation_ids = set()
    for phase in ("initial", "transition"):
        for source in value[phase]:
            if type(source) is not dict or source.get("op") not in (
                "install",
                "remove",
                "reinstall",
                "replace",
            ):
                raise InvalidInput("Unknown or malformed plan operation")
            op = source["op"]
            _shape(
                source,
                ("id", "op", "from", "to")
                if op == "replace"
                else ("id", "op", "wheel"),
            )
            _id(source["id"])
            if source["id"] in operation_ids or phase == "initial" and op != "install":
                raise InvalidInput(
                    "Repeated operation identifier or invalid initial operation"
                )
            operation_ids.add(source["id"])
            for key in ("from", "to") if op == "replace" else ("wheel",):
                _id(source[key])
                if source[key] not in wheel_ids:
                    raise InvalidInput("Unresolved operation wheel reference")
    desired = set()
    for wid in value["desired"]:
        _id(wid)
        if wid in desired or wid not in wheel_ids:
            raise InvalidInput("Duplicate or unresolved desired wheel")
        desired.add(wid)
    if profile != PROFILE_ID:
        raise UnsupportedInput("Unknown installer profile")
    return value, raw


def _cloned_budget(budget):
    result = Budget(budget.limits)
    for name, number in budget.usage.items():
        result.charge(name, number)
    return result


def _context(path, limits, declared_limits=None):
    path = Path(path)
    budget = Budget(limits)
    plan, original = _read_plan(path, budget)
    wheels = [inventory(source, path.parent, budget) for source in plan["wheels"]]
    check_union(wheels)
    desired_names = [
        next(w["canonical_name"] for w in wheels if w["wheel_id"] == wid)
        for wid in plan["desired"]
    ]
    if len(set(desired_names)) != len(desired_names):
        raise InvalidInput("Desired set repeats a normalized distribution name")
    input_hash = digest("wheelsuture/plan/1", plan)
    case = digest(
        "wheelsuture/case/1",
        [
            plan["profile"],
            MODEL_REVISION,
            input_hash,
            [[w["id"], w["sha256"]] for w in plan["wheels"]],
        ],
    )
    replay = Replay(plan, wheels, case, budget)
    for phase in ("initial", "transition"):
        for index, operation in enumerate(plan[phase]):
            replay.apply(operation, phase, index)
    final_findings = replay.finish()
    report = dict(
        schema_version=1,
        document_type="analysis_report",
        model_revision=MODEL_REVISION,
        profile=plan["profile"],
        case_id=case,
        input_sha256=input_hash,
        status="broken" if final_findings else "preserved",
        complete=True,
        coverage=copy.deepcopy(COVERAGE),
        wheels=wheels,
        operations=list(replay.operations),
        events=list(replay.events),
        findings=list(replay.findings),
        final_state=replay.state(),
        desired=list(plan["desired"]),
        diagnostics=[],
        resource_usage=budget.usage,
        evidence_sha256="0" * 64,
        effective_limits=(declared_limits or limits).to_dict(),
    )
    report = finalize_document(report, _cloned_budget(budget), "report")
    return path, plan, original, report, replay, budget


def _unchanged(path, plan, original, limits):
    _, final, _ = _strict_read(path, limits.plan_bytes, limits.json_depth)
    if final != original:
        raise InputChanged("Trusted plan changed during reconstruction")
    for source in plan["wheels"]:
        try:
            read_source(path.parent, source, limits.archive_bytes)
        except InvalidInput as exc:
            raise InputChanged("Pinned source changed during reconstruction") from exc


def reconstruct(plan_path, limits=DEFAULT_LIMITS):
    """Reconstruct the complete original report from independently read sources."""
    path, plan, original, report, replay, budget = _context(plan_path, limits)
    _unchanged(path, plan, original, limits)
    return report


def _conflict(wheels, desired):
    mandatory = [
        claim
        for wheel in wheels
        if wheel["wheel_id"] in desired
        for claim in wheel["claims"]
        if claim["checked"]
    ]
    mandatory.sort(key=lambda c: (c["destination"].encode("utf-8"), c["claim_id"]))
    for index, left in enumerate(mandatory):
        for right in mandatory[index + 1 :]:
            if right["destination"] != left["destination"]:
                break
            a, b = left["signature"], right["signature"]
            if a == b:
                continue
            if a["kind"] == b["kind"] == "bytes":
                kind, explanation = (
                    "different_bytes",
                    "Desired claims require different copied bytes.",
                )
            elif a["kind"] == b["kind"] == "rewritten_script":
                kind, explanation = (
                    "different_rewritten_tail",
                    "Desired claims require different rewritten script tails.",
                )
            else:
                raise UnsupportedInput(
                    "Supplied claims have unequal provider signatures or different signature kinds."
                )
            return dict(
                kind=kind,
                claim_ids=sorted([left["claim_id"], right["claim_id"]]),
                destinations=[left["destination"]],
                explanation=explanation,
            )
    return None


def _repair_attempt(context, declared_limits=None):
    path, plan, original, report, replay, budget = context
    result = dict(
        schema_version=1,
        document_type="repair_proposal",
        profile=plan["profile"],
        case_id=report["case_id"],
        input_sha256=report["input_sha256"],
        analysis_evidence_sha256=report["evidence_sha256"],
        strategy="remove_all_then_install_desired",
        status="verified",
        actions=[],
        witnesses=[],
        diagnostics=[],
        verification=None,
        effective_limits=(declared_limits or budget.limits).to_dict(),
    )
    witness = _conflict(report["wheels"], plan["desired"])
    if witness:
        result.update(status="conflict", witnesses=[witness])
        if len(canonical_bytes(result)) + 1 > budget.limits.report_bytes:
            raise LimitExceeded("Resource limit exceeded: report_bytes")
        return result
    if report["status"] == "preserved":
        result["status"] = "already_satisfied"
    else:
        result["actions"] = [
            dict(id="repair_remove_" + str(i), op="remove", wheel=wid)
            for i, (name, wid) in enumerate(sorted(replay.active.items()))
        ]
        desired = sorted(
            plan["desired"], key=lambda wid: replay.wheels[wid]["canonical_name"]
        )
        result["actions"] += [
            dict(id="repair_install_" + str(i), op="install", wheel=wid)
            for i, wid in enumerate(desired)
        ]
    start_operations, start_events, start_findings = (
        len(replay.operations),
        len(replay.events),
        len(replay.findings),
    )
    budget.charge("user_operations", len(result["actions"]))
    for index, source in enumerate(result["actions"]):
        replay.apply(source, "repair", index)
    if replay.finish("repair"):
        raise UnsupportedInput(
            "Proposed replay does not satisfy final desired claims.",
            code="unproved_repair",
        )
    result["verification"] = dict(
        verifier_revision=VERIFIER_REVISION,
        source_sha256s=[
            dict(wheel_id=w["id"], sha256=w["sha256"])
            for w in sorted(plan["wheels"], key=lambda w: w["id"])
        ],
        final_state=replay.state(),
        evidence_sha256="0" * 64,
        resource_usage=budget.usage,
        operations=replay.operations[start_operations:],
        events=replay.events[start_events:],
        findings=replay.findings[start_findings:],
    )
    return finalize_document(result, budget, "repair")


def _caller_exhausted(exc, actual_limits, declared_limits):
    """A caller-imposed lower cap cannot disprove previously bounded evidence."""
    if isinstance(exc, LimitExceeded):
        prefix = "Resource limit exceeded: "
        key = str(exc)[len(prefix) :] if str(exc).startswith(prefix) else None
        if key in actual_limits.to_dict() and getattr(actual_limits, key) < getattr(
            declared_limits, key
        ):
            raise exc
        if key is None and actual_limits != declared_limits:
            # Input/JSON byte caps have contextual messages rather than a
            # Budget key. Fail incomplete conservatively if the caller lowered
            # any cap; do not label the certificate false on that basis.
            raise exc


def _unknown_repair(report, declared_limits, actual_limits, exc):
    result = dict(
        schema_version=1,
        document_type="repair_proposal",
        profile=report["profile"],
        case_id=report["case_id"],
        input_sha256=report["input_sha256"],
        analysis_evidence_sha256=report["evidence_sha256"],
        strategy="remove_all_then_install_desired",
        status="unknown",
        actions=[],
        witnesses=[],
        diagnostics=[exc.diagnostic()],
        verification=None,
        effective_limits=declared_limits.to_dict(),
    )
    if len(canonical_bytes(result)) + 1 > actual_limits.report_bytes:
        raise LimitExceeded("Resource limit exceeded: report_bytes")
    return result


def _repair(context, declared_limits=None):
    declared_limits = declared_limits or context[5].limits
    try:
        return _repair_attempt(context, declared_limits)
    except UnsupportedInput as exc:
        _caller_exhausted(exc, context[5].limits, declared_limits)
        return _unknown_repair(context[3], declared_limits, context[5].limits, exc)


def reconstruct_repair(plan_path, limits=DEFAULT_LIMITS):
    """Independent complete expected proposal; useful for agreement tests."""
    context = _context(plan_path, limits)
    result = _repair(context)
    _unchanged(context[0], context[1], context[2], limits)
    return result


def _limits(report, caller):
    try:
        declared = Limits(**report["effective_limits"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationError("Evidence has invalid effective limits") from exc
    actual = Limits(
        **{k: min(v, getattr(caller, k)) for k, v in declared.to_dict().items()}
    )
    return declared, actual


def _compare(expected, actual, label):
    if canonical_bytes(expected) != canonical_bytes(actual):
        raise VerificationError(label + " differs from independent full reconstruction")


def _expected_repair(context, candidate, caller_limits):
    report = context[3]
    original_limits = Limits(**report["effective_limits"])
    declared, actual = _limits(candidate, caller_limits)
    if any(
        value > getattr(original_limits, key)
        for key, value in declared.to_dict().items()
    ):
        raise VerificationError("Repair effective limits increase original limits")
    if declared == original_limits and actual == context[5].limits:
        repair_context = context
    else:
        try:
            repair_context = _context(context[0], actual, original_limits)
        except UnsupportedInput as exc:
            _caller_exhausted(exc, actual, declared)
            return _unknown_repair(report, declared, actual, exc)
        _compare(
            repair_context[3],
            report,
            "Original evidence under repair-stage reconstruction",
        )
    return _repair(repair_context, declared)


def verify_candidate(plan, report_dict, repair_dict=None):
    """Verify an in-memory proposal before a producer can claim verified status."""
    if isinstance(plan, Plan) and not getattr(plan, "validated", lambda: False)():
        raise InvalidInput("Verifier candidate requires a validated immutable Plan")
    limits = plan.limits if isinstance(plan, Plan) else DEFAULT_LIMITS
    path = plan.path if isinstance(plan, Plan) else Path(plan)
    declared, actual = _limits(report_dict, limits)
    context = _context(path, actual, declared)
    if isinstance(plan, Plan) and (
        canonical_bytes(context[1]) != plan.canonical
        or hashlib.sha256(context[2]).hexdigest() != plan.source_file_sha256
    ):
        raise InputChanged("Trusted Plan value differs from current source")
    _compare(context[3], report_dict, "Original analysis evidence")
    if repair_dict is not None:
        _compare(
            _expected_repair(context, repair_dict, limits),
            repair_dict,
            "Repair evidence",
        )
    _unchanged(context[0], context[1], context[2], actual)
    return VerificationResult(True, True, "consistent")


def verify_report(plan_path, report_path, *, repair_path=None, limits=DEFAULT_LIMITS):
    """Verify full canonical reports, returning a bounded verdict for bad evidence.

    Malformed trusted plans and invalid pinned source inputs remain typed input
    errors; evidence mismatches return exit 5, and bounded/unsupported reconstruction
    returns incomplete (exit 3), never a false preservation assertion.
    """
    try:
        try:
            report, _, _ = _strict_read(
                report_path, limits.report_bytes, limits.json_depth
            )
        except InvalidInput as exc:
            raise VerificationError("Malformed analysis evidence: " + str(exc)) from exc
        if type(report) is not dict:
            raise VerificationError("Analysis evidence must be an object")
        declared, actual = _limits(report, limits)
        context = _context(plan_path, actual, declared)
        _compare(context[3], report, "Original analysis evidence")
        if repair_path is not None:
            try:
                repair, _, _ = _strict_read(
                    repair_path, limits.report_bytes, limits.json_depth
                )
            except InvalidInput as exc:
                raise VerificationError(
                    "Malformed repair evidence: " + str(exc)
                ) from exc
            if type(repair) is not dict:
                raise VerificationError("Repair evidence must be an object")
            _compare(
                _expected_repair(context, repair, limits), repair, "Repair evidence"
            )
        _unchanged(context[0], context[1], context[2], actual)
        return VerificationResult(True, True, "consistent")
    except VerificationError as exc:
        return VerificationResult(False, True, "mismatch", (str(exc),))
    except UnsupportedInput as exc:
        return VerificationResult(False, False, "incomplete", (str(exc),))


__all__ = [
    "VerificationResult",
    "verify_report",
    "verify_candidate",
    "reconstruct",
    "reconstruct_repair",
]
