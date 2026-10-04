"""Deterministic JSON and an inert, self-contained HTML evidence view."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from html import escape
import json
import re
import unicodedata

from .canonical import canonical_bytes
from .errors import LimitExceeded
from .model import DEFAULT_LIMITS


def _document(value):
    return value.to_dict() if hasattr(value, "to_dict") else value


def json_bytes(value) -> bytes:
    """The shared canonical encoding with its one required terminating LF."""
    return canonical_bytes(_document(value)) + b"\n"


def terminal_text(value) -> str:
    """Prevent terminal line, ANSI and bidi spoofing without shortening IDs."""
    parts = []
    for char in str(value):
        point = ord(char)
        if char == "\n":
            parts.append("\\n")
        elif char == "\r":
            parts.append("\\r")
        elif char == "\t":
            parts.append("\\t")
        elif unicodedata.category(char) in {"Cc", "Cf", "Cs"}:
            parts.append(("\\u%04x" if point <= 0xFFFF else "\\U%08x") % point)
        else:
            parts.append(char)
    return "".join(parts)


def _text(value) -> str:
    return escape(str(value), quote=True)


def _json(value) -> str:
    return _text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _anchor(kind, value) -> str:
    return (
        kind
        + "-"
        + hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()
    )


class _HtmlParts(list):
    """Account UTF-8 output chunks before building the complete HTML string."""

    def __init__(self, values, maximum):
        super().__init__()
        self.maximum = maximum
        self.byte_count = 0
        for value in values:
            self.append(value)

    def append(self, value):
        size = len(value.encode("utf-8"))
        if size > self.maximum - self.byte_count:
            raise LimitExceeded("HTML report exceeds the report byte limit")
        self.byte_count += size
        super().append(value)


def render_html(
    report,
    *,
    json_name="report.json",
    repair=None,
    max_events: int = 200,
    max_bytes: int = DEFAULT_LIMITS.report_bytes,
) -> bytes:
    """Render evidence as escaped text only; no active content or remote assets."""
    if type(max_events) is not int or max_events < 0:
        raise ValueError("max_events must be a non-negative integer")
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    data = _document(report)
    proposal = _document(repair) if repair is not None else None
    status = str(data.get("status", "unknown"))
    status_class = (
        status if status in {"preserved", "broken", "incomplete"} else "unknown"
    )
    parts = _HtmlParts(
        [
            '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta http-equiv="Content-Security-Policy" content="default-src &#x27;none&#x27;; style-src &#x27;unsafe-inline&#x27;; base-uri &#x27;none&#x27;; form-action &#x27;none&#x27;">',
            "<title>WheelSuture declared wheel-transition report</title>",
            "<style>body{font:16px/1.55 system-ui,sans-serif;max-width:76rem;margin:auto;padding:2rem;color:#16212b;background:#fafbfc}h1,h2,h3{line-height:1.2}section{border-top:1px solid #c9d1d9;margin-top:2rem;padding-top:1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef1f4;padding:1rem}li{overflow-wrap:anywhere}.status{font-size:1.4rem;font-weight:700;padding:1rem;border:2px solid}.preserved{color:#176035}.broken{color:#9d2020}.incomplete,.unknown{color:#784b00}a{color:#064da3}code{overflow-wrap:anywhere}*{unicode-bidi:plaintext}</style>",
            "</head><body><h1>WheelSuture</h1>",
            "<p>Declared wheel-transition rehearsal. This report does not establish import correctness, dependency compatibility, or runtime safety.</p>",
            '<p class="status ' + status_class + '">Status: ' + _text(status) + "</p>",
            "<p>Canonical JSON reference: " + _text(json_name) + "</p>",
            "<section><h2>Profile</h2><p>"
            + _text(data.get("profile", "unknown"))
            + "</p>",
            "<p>Case: " + _text(data.get("case_id", "unknown")) + "</p></section>",
            "<section><h2>Effective limits</h2><pre>"
            + _json(data.get("effective_limits", {}))
            + "</pre></section>",
            "<section><h2>Excluded claims</h2><pre>"
            + _json(data.get("coverage", {}).get("excluded", []))
            + "</pre></section>",
            "<section><h2>Source wheels</h2><ul>",
        ],
        max_bytes,
    )
    for wheel in data.get("wheels", []):
        summary = {
            key: value
            for key, value in wheel.items()
            if key not in {"claims", "deletion_paths"}
        }
        parts.append("<li><pre>" + _json(summary) + "</pre></li>")
    parts.append("</ul></section><section><h2>Transitions</h2><ol>")
    for operation in data.get("operations", []):
        anchor = _anchor("operation", operation.get("operation_id", ""))
        parts.append('<li id="' + anchor + '"><pre>' + _json(operation) + "</pre></li>")
    parts.append("</ol></section><section><h2>Findings and Causes</h2>")
    findings = data.get("findings", [])
    if not findings:
        parts.append("<p>No recorded findings.</p>")
    events = data.get("events", [])
    displayed_events = {str(e.get("event_id", "")) for e in events[:max_events]}
    for finding in findings:
        parts.append(
            '<article id="' + _anchor("finding", finding.get("finding_id", "")) + '">'
        )
        parts.append(
            "<h3>"
            + _text(finding.get("kind", "unknown"))
            + "</h3><pre>"
            + _json(finding)
            + "</pre>"
        )
        cause = finding.get("cause_event_id")
        if cause is not None and str(cause) in displayed_events:
            parts.append(
                '<p>Cause: <a href="#'
                + _anchor("event", cause)
                + '">'
                + _text(cause)
                + "</a></p>"
            )
        elif cause is not None:
            parts.append("<p>Cause event in canonical JSON: " + _text(cause) + "</p>")
        else:
            parts.append("<p>No causal event is recorded for this finding.</p>")
        parts.append("</article>")
    parts.append(
        "</section><section><h2>Events</h2><p>Total events: "
        + str(len(events))
        + "</p>"
    )
    for event in events[:max_events]:
        parts.append(
            '<pre id="'
            + _anchor("event", event.get("event_id", ""))
            + '">'
            + _json(event)
            + "</pre>"
        )
    if len(events) > max_events:
        parts.append(
            "<p>"
            + str(len(events) - max_events)
            + " additional events omitted from this HTML view; all events remain in the canonical JSON.</p>"
        )
    parts.append("</section><section><h2>Repair</h2>")
    if proposal is None:
        parts.append(
            "<p>No repair proposal is included. WheelSuture never executes repairs.</p>"
        )
    else:
        parts.append(
            "<p>Proposal status: " + _text(proposal.get("status", "unknown")) + "</p>"
        )
        parts.append("<pre>" + _json(proposal.get("actions", [])) + "</pre>")
        parts.append("<p>The original analysis findings above remain unchanged.</p>")
    parts.append(
        "</section><section><h2>Diagnostics</h2><pre>"
        + _json(data.get("diagnostics", []))
        + "</pre></section>"
    )
    parts.append("</body></html>\n")
    return "".join(parts).encode("utf-8")


def error_document(
    error: BaseException, *, exit_code: int, partial_outputs=(), byte_limit: int = 65536
):
    """Return a closed, bounded error envelope without internal traceback text."""
    states = {
        2: "invalid",
        3: "incomplete",
        4: "io_error",
        5: "verification_failed",
        70: "internal_error",
        130: "incomplete",
    }
    message = str(getattr(error, "message", str(error))) or "Operation did not complete"
    code = str(getattr(error, "code", "internal_error"))
    if exit_code == 70:
        message = "Unexpected internal error; no complete result was produced"
        code = "internal_error"
    elif exit_code == 130:
        message = "Interrupted; no complete result was produced"
        code = "interrupted"
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
        code = "operation_error"
    # Exception text may contain filesystem surrogate escapes. Error envelopes
    # remain valid Unicode, even when the input filename was not valid Unicode.
    message = message.encode("utf-8", errors="replace").decode("utf-8")[:4096]
    diagnostic = dict(
        code=code, message=message, wheel_id=None, operation_id=None, path=None
    )
    for key in ("wheel_id", "operation_id"):
        value = getattr(error, key, None)
        if isinstance(value, str) and re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_-]{0,63}", value
        ):
            diagnostic[key] = value
    path = getattr(error, "path", None)
    if path is not None:
        diagnostic["path"] = (
            str(path).encode("utf-8", errors="replace").decode("utf-8")[:1024] or None
        )
    result = dict(
        schema_version=1,
        document_type="error",
        status=states[exit_code],
        exit_code=exit_code,
        diagnostics=[diagnostic],
        case_id=None,
        partial_outputs=[
            str(p).encode("utf-8", errors="replace").decode("utf-8")[:1024]
            for p in partial_outputs
        ][:3],
    )
    if len(json_bytes(result)) > byte_limit:
        diagnostic["message"] = "Error details exceeded the bounded error-report limit"
        diagnostic["path"] = None
        if len(json_bytes(result)) > byte_limit:
            raise ValueError("error byte limit cannot contain the error envelope")
    return result
