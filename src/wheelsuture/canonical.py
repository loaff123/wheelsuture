"""Canonical wire encoding and domain-separated consistency hashes."""

import hashlib
import json
from .errors import LimitExceeded


def canonical_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(domain, value):
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + canonical_bytes(value)
    ).hexdigest()


def _json_clone(value):
    """Detach supported JSON values without an unbounded encoded intermediary."""
    if isinstance(value, dict):
        return {key: _json_clone(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_clone(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise TypeError("Unsupported canonical JSON value")


def _bounded_size(value, cap):
    """Count encoded chunks before ever allocating a complete wire document."""
    encoder = json.JSONEncoder(
        ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    size = 1  # final LF
    for chunk in encoder.iterencode(value):
        size += len(chunk.encode("utf-8"))
        if size > cap:
            raise LimitExceeded("Resource limit exceeded: report_bytes")
    return size


def finalize_document(document, budget, kind="report"):
    """Finalize detached JSON, byte-length fixed point, then evidence digest."""
    d = _json_clone(document)
    usage = (
        d["verification"]["resource_usage"] if kind == "repair" else d["resource_usage"]
    )
    holder = d["verification"] if kind == "repair" else d
    has_digest = kind in ("report", "repair")
    if has_digest:
        holder["evidence_sha256"] = "0" * 64
    for _ in range(10):
        size = _bounded_size(d, budget.limits.report_bytes)
        if usage["report_bytes"] == size:
            break
        usage["report_bytes"] = size
    else:
        raise LimitExceeded("Report length did not converge.")
    budget.maximum("report_bytes", size)
    if has_digest:
        del holder["evidence_sha256"]
        h = digest("wheelsuture/" + kind + "/1", d)
        holder["evidence_sha256"] = h
    return d
