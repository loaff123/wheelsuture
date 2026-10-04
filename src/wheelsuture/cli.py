"""Offline command orchestration. No command can install or execute a payload."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
import sys
import os

from .errors import InvalidInput, LimitExceeded, OutputError, WheelSutureError
from .model import DEFAULT_LIMITS, Profile, WheelSource
from .output import publish_outputs
from .plan import load_plan
from .report import error_document, json_bytes, render_html, terminal_text


# Small lazy adapters keep --help/--version offline and decouple CLI tests from
# the parser/reducer implementation; all real operations use the public APIs.
def analyze(*args, **kwargs):
    from .api import analyze as implementation

    return implementation(*args, **kwargs)


def create_repair(*args, **kwargs):
    from .api import create_repair as implementation

    return implementation(*args, **kwargs)


def inspect_wheel(*args, **kwargs):
    from .api import inspect_wheel as implementation

    return implementation(*args, **kwargs)


def verify_report(*args, **kwargs):
    from .verify import verify_report as implementation

    return implementation(*args, **kwargs)


def profile_catalog():
    from .profiles import profile_catalog as implementation

    return implementation()


def _version():
    try:
        return version("wheelsuture")
    except PackageNotFoundError:
        from . import __version__

        return __version__


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wheelsuture",
        description=(
            "Rehearse declared local wheel transitions and independently verify evidence. "
            "Never installs, executes, downloads, or discovers a live environment."
        ),
    )
    parser.add_argument(
        "--version", action="version", version="wheelsuture " + _version()
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="analyze a declared transition plan")
    check.add_argument("plan", type=Path)
    check.add_argument("--json", type=Path, required=True, metavar="REPORT")
    check.add_argument("--html", type=Path, metavar="HTML")
    repair = commands.add_parser(
        "repair-plan", help="propose and verify a replay; never execute it"
    )
    repair.add_argument("plan", type=Path)
    repair.add_argument("--output", type=Path, required=True, metavar="REPAIR")
    repair.add_argument("--json", type=Path, metavar="REPORT")
    verify = commands.add_parser(
        "verify", help="independently reconstruct and check evidence"
    )
    verify.add_argument("plan", type=Path)
    verify.add_argument("--report", type=Path, required=True)
    verify.add_argument("--repair", type=Path)
    inspect = commands.add_parser("inspect", help="inventory one pinned local wheel")
    inspect.add_argument("wheel", type=Path)
    inspect.add_argument("--sha256", required=True)
    inspect.add_argument("--profile", required=True)
    inspect.add_argument("--json", type=Path, required=True, metavar="INVENTORY")
    profiles = commands.add_parser("profiles", help="list exact modeled profiles")
    profiles.add_argument("--json", action="store_true", required=True)
    for command in (check, repair, inspect):
        command.add_argument(
            "--overwrite",
            action="store_true",
            help="explicitly allow atomic replacement of existing outputs",
        )
    return parser


def _dict(document):
    return document.to_dict() if hasattr(document, "to_dict") else document


def _bounded_json(document):
    content = json_bytes(document)
    if len(content) > DEFAULT_LIMITS.report_bytes:
        raise LimitExceeded("Serialized report exceeds the report byte limit")
    return content


def _write(stream, text):
    try:
        stream.write(text)
        stream.flush()
    except (OSError, UnicodeError) as exc:
        if isinstance(exc, BrokenPipeError):
            # CPython otherwise retries a buffered flush at interpreter shutdown
            # and substitutes exit 120 for the promised output-failure status.
            try:
                fd = stream.fileno()
                null = os.open(os.devnull, os.O_WRONLY)
                try:
                    os.dup2(null, fd)
                finally:
                    os.close(null)
            except (OSError, ValueError, AttributeError):
                pass
        raise OutputError("Unable to write terminal output") from exc


def _publish(entries, *, inputs, overwrite, authoritative):
    outputs = dict(entries)
    if len(outputs) != len(entries):
        raise OutputError("Requested output paths alias each other")
    return publish_outputs(
        outputs, inputs=inputs, overwrite=overwrite, authoritative=authoritative
    )


def _plan_inputs(path):
    plan = load_plan(path, limits=DEFAULT_LIMITS)
    return (path, *(source.base / source.path for source in plan.sources))


def main(argv=None, *, stdout=None, stderr=None) -> int:
    """Return the documented exit status; no exception traceback reaches stdout."""
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    args = None
    inputs = ()
    published = ()
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                args = _parser().parse_args(argv)
            except SystemExit as exc:
                _write(stdout, "")
                _write(stderr, "")
                return int(exc.code)
        if args.command == "profiles":
            _write(stdout, _bounded_json(profile_catalog()).decode("utf-8"))
            return 0
        if args.command == "verify":
            result = verify_report(
                args.plan, args.report, repair_path=args.repair, limits=DEFAULT_LIMITS
            )
            _write(stdout, "Evidence: " + terminal_text(result.status) + "\n")
            for diagnostic in result.diagnostics:
                _write(stderr, terminal_text(diagnostic) + "\n")
            return result.exit_code
        if args.command == "inspect":
            inputs = (args.wheel,)
            if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
                raise InvalidInput(
                    "SHA-256 must be 64 lowercase hexadecimal characters"
                )
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args.profile):
                raise InvalidInput("Malformed profile identifier")
            source = WheelSource(
                "inspected", args.wheel.name, args.sha256, args.wheel.absolute().parent
            )
            inventory = inspect_wheel(
                source, Profile(args.profile), limits=DEFAULT_LIMITS
            )
            published = _publish(
                [(args.json, _bounded_json(inventory))],
                inputs=inputs,
                overwrite=args.overwrite,
                authoritative=args.json,
            )
            _write(stdout, "Inventoried: " + terminal_text(args.wheel.name) + "\n")
            return 0
        inputs = (args.plan,)
        inputs = _plan_inputs(args.plan)
        if args.command == "check":
            result = analyze(args.plan, limits=DEFAULT_LIMITS)
            data = _dict(result)
            entries = [(args.json, _bounded_json(data))]
            if args.html is not None:
                html = render_html(data, json_name=args.json.name)
                if len(html) > DEFAULT_LIMITS.report_bytes:
                    raise LimitExceeded("HTML report exceeds the report byte limit")
                entries.append((args.html, html))
            published = _publish(
                entries,
                inputs=inputs,
                overwrite=args.overwrite,
                authoritative=args.json,
            )
            status = data["status"]
            code = {"preserved": 0, "broken": 1, "incomplete": 3}[status]
            if not data.get("complete", False):
                code = 3
            _write(
                stdout,
                "Analysis: "
                + terminal_text(status)
                + "; "
                + str(len(data.get("findings", [])))
                + " recorded findings\n",
            )
            return code
        original, proposal = create_repair(args.plan, limits=DEFAULT_LIMITS)
        proposal_data = _dict(proposal)
        entries = [(args.output, _bounded_json(proposal_data))]
        authoritative = args.output
        if args.json is not None:
            entries.append((args.json, _bounded_json(original)))
            authoritative = args.json
        published = _publish(
            entries,
            inputs=inputs,
            overwrite=args.overwrite,
            authoritative=authoritative,
        )
        status = proposal_data["status"]
        _write(
            stdout, "Repair proposal: " + terminal_text(status) + "; nothing executed\n"
        )
        return {"already_satisfied": 0, "verified": 0, "conflict": 1, "unknown": 3}[
            status
        ]
    except KeyboardInterrupt as exc:
        return _handle_failure(exc, 130, args, inputs, published, stderr)
    except WheelSutureError as exc:
        return _handle_failure(exc, exc.exit_code, args, inputs, published, stderr)
    except (OSError, UnicodeError) as exc:
        return _handle_failure(exc, 4, args, inputs, published, stderr)
    except Exception as exc:
        return _handle_failure(exc, 70, args, inputs, published, stderr)


def _handle_failure(error, code, args, inputs, published, stderr):
    partial = tuple(getattr(error, "partial_outputs", ())) or tuple(map(str, published))
    envelope = error_document(
        error,
        exit_code=code,
        partial_outputs=partial,
        byte_limit=DEFAULT_LIMITS.error_bytes,
    )
    # An honest already-published report is never replaced with an error result.
    # Publication failures are not retried at a destination that might now exist.
    target = None
    if args is not None and not partial and not isinstance(error, OutputError):
        candidate = getattr(args, "json", None)
        if isinstance(candidate, Path):
            target = candidate
        elif isinstance(getattr(args, "output", None), Path):
            target = args.output
    if target is not None:
        try:
            publish_outputs(
                {target: json_bytes(envelope)},
                inputs=inputs,
                overwrite=False,
                authoritative=target,
            )
        except OutputError as output_error:
            code = 4
            partial = tuple(output_error.partial_outputs)
            envelope = error_document(
                output_error, exit_code=4, partial_outputs=partial
            )
    message = "wheelsuture: " + terminal_text(envelope["diagnostics"][0]["message"])
    if partial:
        message += "\nPartial outputs: " + ", ".join(
            terminal_text(path) for path in partial
        )
    try:
        _write(stderr, message + "\n")
    except OutputError:
        return 4
    return code
