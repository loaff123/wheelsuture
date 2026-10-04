#!/usr/bin/env python3
"""Reproducible original/inert capacity fixtures in bounded fresh subprocesses.

No payload is installed, imported or executed. Measurements include fixture
construction, analysis, independent verification, repair generation and checking.
The parent records watchdog termination even if the child cannot write a receipt.
"""

from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import random
import resource
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1"
SITE = "lib/python3.12/site-packages"
MiB = 1024 * 1024
SEEDS = {"development": (11, 23), "held_out": (101, 103)}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def path_of_length(index, length):
    tail = f"p{index:05d}.dat"
    remaining = length - len(tail) - 1
    pieces = []
    while remaining > 255:
        pieces.append("x" * 255)
        remaining -= 256
    if remaining > 0:
        pieces.append("x" * remaining)
    elif remaining < 0:
        raise ValueError("requested path is too short")
    return "/".join(pieces + [tail])


def make_wheel(root, name, payload, *, directories=(), stored=False, comment=b""):
    """Original ZIP + strict RECORD writer; deterministic data-only members."""
    dist = name + "-1.0.dist-info"
    files = dict(payload)
    files[dist + "/METADATA"] = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n\n".encode()
    )
    files[dist + "/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: original-capacity-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
    )
    rows = [
        [
            p,
            "sha256="
            + base64.urlsafe_b64encode(hashlib.sha256(b).digest())
            .rstrip(b"=")
            .decode(),
            str(len(b)),
        ]
        for p, b in files.items()
    ]
    rows.append([dist + "/RECORD", "", ""])
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    files[dist + "/RECORD"] = output.getvalue().encode()
    path = root / (name + "-1.0-py3-none-any.whl")
    with zipfile.ZipFile(path, "w") as archive:
        for p, b in files.items():
            info = zipfile.ZipInfo(p, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, b)
        for directory in directories:
            info = zipfile.ZipInfo(directory, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = (0o40755 << 16) | 0x10
            archive.writestr(info, b"")
        archive.comment = comment
    raw = path.read_bytes()
    return (
        {"id": name, "path": path.name, "sha256": hashlib.sha256(raw).hexdigest()},
        {
            "archive_bytes": len(raw),
            "decoded_bytes": sum(map(len, files.values())),
            "entries": len(files) + len(directories),
            "mapped_claims": len(files) + 3,
            "path_text_bytes": sum(len(x.encode()) for x in [*files, *directories])
            + sum(
                len((SITE + "/" + x).encode())
                for x in files
                if not x.endswith("/RECORD")
            )
            + sum(
                len((SITE + "/" + dist + "/" + c).encode())
                for c in ("RECORD", "INSTALLER", "REQUESTED", "direct_url.json")
            ),
        },
    )


def case_specs():
    specs = [
        dict(name="baseline", shape="tiny", seed=11, n=1, expected="complete"),
        dict(name="wheels_32", shape="wheels", n=32, expected="complete"),
        dict(name="wheels_33", shape="wheels", n=33, expected="wheels"),
        dict(name="claims_4096", shape="tiny", n=4090, expected="complete"),
        dict(name="claims_4097", shape="tiny", n=4091, expected="mapped_claims"),
        dict(name="entries_4096", shape="directories", n=4092, expected="complete"),
        dict(name="entries_4097", shape="directories", n=4093, expected="entries"),
        dict(name="deflate_buffer_65537", shape="member", n=65537, expected="complete"),
        dict(name="member_4m", shape="member", n=4 * MiB, expected="complete"),
        dict(
            name="member_4m_plus1",
            shape="member",
            n=4 * MiB + 1,
            expected="member_bytes",
        ),
        dict(
            name="decoded_32m",
            shape="bytes",
            counter="decoded_bytes",
            n=32 * MiB,
            expected="complete",
        ),
        dict(
            name="decoded_32m_plus1",
            shape="bytes",
            counter="decoded_bytes",
            n=32 * MiB + 1,
            expected="decoded_bytes",
        ),
        dict(
            name="archive_32m",
            shape="bytes",
            counter="archive_bytes",
            n=32 * MiB,
            expected="complete",
        ),
        dict(
            name="archive_32m_plus1",
            shape="bytes",
            counter="archive_bytes",
            n=32 * MiB + 1,
            expected="archive_bytes",
        ),
        dict(
            name="events_20000", shape="events", extra=7, length=30, expected="complete"
        ),
        dict(
            name="events_20001",
            shape="events",
            extra=8,
            length=30,
            expected="expanded_events",
        ),
        dict(name="findings_4096", shape="findings", drop=False, expected="complete"),
        dict(name="findings_4097", shape="findings", drop=True, expected="findings"),
        dict(name="operations_256", shape="operations", n=256, expected="complete"),
        dict(
            name="operations_257", shape="operations", n=257, expected="user_operations"
        ),
        dict(name="path_text_1m", shape="path_text", n=MiB, expected="complete"),
        dict(
            name="path_text_1m_plus1",
            shape="path_text",
            n=MiB + 1,
            expected="path_text_bytes",
        ),
        dict(
            name="path_mapped_1024",
            shape="long",
            n=1,
            length=1024 - len(SITE) - 1,
            expected="complete",
        ),
        dict(
            name="path_mapped_1025",
            shape="long",
            n=1,
            length=1025 - len(SITE) - 1,
            expected="unsupported",
        ),
        dict(
            name="report_dense_long",
            shape="events",
            extra=7,
            length=970,
            expected="complete",
        ),
        dict(
            name="report_combined_over",
            shape="report",
            length=970,
            expected="report_bytes",
        ),
        dict(
            name="report_32m",
            shape="report",
            length=939,
            path_extra=56,
            operation_padding=5300,
            expected="complete",
        ),
        dict(
            name="report_32m_plus1",
            shape="report",
            length=939,
            path_extra=56,
            operation_padding=5301,
            expected="report_bytes",
        ),
        dict(
            name="repair_dense_damage",
            shape="findings",
            drop=True,
            repetitions=29,
            expected="complete",
            repair_status="unknown",
        ),
        dict(
            name="repair_damage_verified",
            shape="findings",
            drop=True,
            repetitions=0,
            expected="complete",
            repair_status="verified",
        ),
    ]
    # Held-out seeds plus alias/Unicode/tiny-size layouts are not boundary-tuning inputs.
    specs += [
        dict(
            name="development_seed_23",
            shape="tiny",
            seed=23,
            n=100,
            expected="complete",
        )
    ]
    for seed in SEEDS["held_out"]:
        specs += [
            dict(
                name=f"held_dense_{seed}",
                shape="dense",
                seed=seed,
                n=32,
                expected="complete",
                held_out=True,
            ),
            dict(
                name=f"held_long_{seed}",
                shape="long",
                seed=seed,
                n=500,
                length=950,
                expected="complete",
                held_out=True,
            ),
            dict(
                name=f"held_tiny_{seed}",
                shape="tiny",
                seed=seed,
                n=4090,
                expected="complete",
                held_out=True,
            ),
        ]
    return specs


def build_case(root, spec):
    rng = random.Random(spec.get("seed", 11))
    sources, facts = [], []

    def wheel(name, payload, **kwargs):
        source, sizes = make_wheel(root, name, payload, **kwargs)
        sources.append(source)
        facts.append(dict(wheel_id=name, **sizes))

    shape = spec["shape"]
    initial, transition, desired = [], [], []
    if shape in ("tiny", "long"):
        paths = [
            path_of_length(i, spec["length"])
            if shape == "long"
            else f"payload/p{i:05d}.dat"
            for i in range(spec["n"])
        ]
        if spec.get("held_out") and shape == "long":
            paths = [p.replace("xx", "é") if i % 2 else p for i, p in enumerate(paths)]
        if spec.get("held_out") and shape == "tiny":
            paths = [f"tiny/{i % 17:02d}/p{i:05d}.dat" for i in range(spec["n"])]
        wheel(
            "capdemo",
            {
                p: rng.randbytes(
                    (i % 8) if spec.get("held_out") and shape == "tiny" else 1
                )
                for i, p in enumerate(paths)
            },
        )
    elif shape == "directories":
        wheel(
            "capdemo",
            {"payload/a.dat": b"x"},
            directories=[f"dir{i:05d}/" for i in range(spec["n"])],
        )
    elif shape == "member":
        wheel("capdemo", {"payload/a.dat": b"x" * spec["n"]})
    elif shape == "bytes":
        stored = spec["counter"] == "archive_bytes"
        sizes = [4 * MiB] * 7 + [3 * MiB]
        # RECORD digit widths are stable here. Adjust exact size using the independent writer's counters.
        for attempt in range(3):
            payload = {
                f"payload/p{i}.dat": (
                    random.Random(11 + i).randbytes(n) if stored else b"x" * n
                )
                for i, n in enumerate(sizes)
            }
            source, sizes_fact = make_wheel(root, "capdemo", payload, stored=stored)
            delta = spec["n"] - sizes_fact[spec["counter"]]
            if delta == 0:
                sources.append(source)
                facts.append(dict(wheel_id="capdemo", **sizes_fact))
                break
            sizes[-1] += delta
        else:
            raise AssertionError("byte fixture fixed point did not converge")
    elif shape in ("wheels", "dense"):
        shared = {f"shared/p{i:04d}.dat": rng.randbytes(1) for i in range(121)}
        for i in range(spec["n"]):
            name = f"capw{i:02d}"
            payload = shared if shape == "dense" else {f"own{i:02d}/a.dat": bytes([i])}
            if shape == "dense" and spec.get("held_out"):
                prefix = (
                    "",
                    name + "-1.0.data/purelib/",
                    name + "-1.0.data/data/" + SITE + "/",
                )[i % 3]
                payload = {prefix + p: b for p, b in shared.items()}
            wheel(name, payload)
    elif shape == "events":
        wheel("capdemo", {path_of_length(i, spec["length"]): b"x" for i in range(73)})
        wheel("capextra", {f"extra/p{i:04d}.dat": b"x" for i in range(spec["extra"])})
        initial = [dict(id="i0", op="install", wheel="capdemo")]
        transition = [
            dict(id=f"t{i}", op="remove" if i % 2 == 0 else "install", wheel="capdemo")
            for i in range(252)
        ]
        transition.append(dict(id="extra", op="install", wheel="capextra"))
        desired = ["capdemo", "capextra"]
    elif shape == "report":
        wheel(
            "capdemo",
            {
                path_of_length(
                    i, spec["length"] + (spec.get("path_extra", 0) if i == 72 else 0)
                ): b"x"
                for i in range(73)
            },
        )
        wheel("capextra", {path_of_length(i, spec["length"]): b"y" for i in range(16)})
        initial = [
            dict(id="i0", op="install", wheel="capdemo"),
            dict(id="i1", op="install", wheel="capextra"),
        ]
        transition = [
            dict(id=f"t{i}", op="reinstall", wheel="capdemo") for i in range(125)
        ]
        remaining = spec.get("operation_padding", 0)
        for operation in transition:
            extra = min(64 - len(operation["id"]), remaining)
            operation["id"] += "x" * extra
            remaining -= extra
        if remaining:
            raise ValueError("Operation padding exceeds supported IDs")
        desired = ["capdemo", "capextra"]
    elif shape == "operations":
        wheel("capdemo", {"payload/a.dat": b"x"})
        initial = [dict(id="i0", op="install", wheel="capdemo")]
        transition = [
            dict(id=f"t{i}", op="remove" if i % 2 == 0 else "install", wheel="capdemo")
            for i in range(spec["n"] - 1)
        ]
        desired = ["capdemo"] if spec["n"] % 2 else []
    elif shape == "findings":
        for name, value in [("capdemo", b"a"), ("capextra", b"b")]:
            wheel(name, {f"shared/p{i:04d}.dat": value for i in range(128)})
        initial = [
            dict(id="i0", op="install", wheel="capdemo"),
            dict(id="i1", op="install", wheel="capextra"),
        ]
        transition = [
            dict(id=f"t{i}", op="reinstall", wheel="capextra")
            for i in range(spec.get("repetitions", 30))
        ]
        desired = ["capdemo"] if spec["drop"] else ["capdemo", "capextra"]
    elif shape == "path_text":
        payload = {path_of_length(i, 850): b"x" for i in range(600)}
        _, sizes_fact = make_wheel(root, "capdemo", payload)
        remaining = spec["n"] - sizes_fact["path_text_bytes"]
        directories = []
        while remaining:
            length = min(1000, remaining)
            if length < 10:
                directories[-1] = directories[-1][:-1] + "x" * length + "/"
                remaining = 0
                break
            directories.append(path_of_length(len(directories), length - 1) + "/")
            remaining -= length
        wheel("capdemo", payload, directories=directories)
    else:
        raise ValueError(shape)
    if not initial:
        initial = [
            dict(id=f"i{i}", op="install", wheel=s["id"]) for i, s in enumerate(sources)
        ]
        desired = [s["id"] for s in sources]
    plan = dict(
        schema_version=1,
        profile=PROFILE,
        wheels=sources,
        initial=initial,
        transition=transition,
        desired=desired,
    )
    path = root / "plan.json"
    path.write_bytes(canonical(plan) + b"\n")
    return path, dict(
        plan_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        sources=sources,
        fixture_sizes=facts,
    )


def hardware():
    def read(path):
        try:
            return Path(path).read_text().strip()
        except OSError:
            return None

    cpu = read("/proc/cpuinfo") or ""
    return dict(
        python=sys.version,
        platform=platform.platform(),
        cpu_model=next(
            (
                x.split(":", 1)[1].strip()
                for x in cpu.splitlines()
                if x.startswith("model name")
            ),
            None,
        ),
        visible_cpu_count=os.cpu_count(),
        affinity_before=sorted(os.sched_getaffinity(0))
        if hasattr(os, "sched_getaffinity")
        else None,
        memory_total_kib=next(
            (
                x.split(":", 1)[1].strip()
                for x in (read("/proc/meminfo") or "").splitlines()
                if x.startswith("MemTotal:")
            ),
            None,
        ),
        cgroup_memory_max=read("/sys/fs/cgroup/memory.max"),
        cgroup_cpu_max=read("/sys/fs/cgroup/cpu.max"),
    )


def constrain():
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        affinity = sorted(os.sched_getaffinity(0))[:2]
        os.sched_setaffinity(0, affinity)
    return dict(
        rlimit_as_bytes=resource.getrlimit(resource.RLIMIT_AS),
        rlimit_cpu_seconds=resource.getrlimit(resource.RLIMIT_CPU),
        affinity=affinity,
        wall_timeout_seconds=120,
    )


def timed(label, call):
    wall, cpu = time.perf_counter(), time.process_time()
    try:
        value = call()
        result = dict(stage=label, outcome="complete")
        if hasattr(value, "valid"):
            result.update(
                valid=value.valid,
                complete=value.complete,
                status=value.status,
                exit_code=value.exit_code,
                diagnostics=list(value.diagnostics),
            )
        return value, result
    except Exception as exc:
        failure = dict(
            stage=label,
            outcome="error",
            error_type=type(exc).__name__,
            message=str(exc),
            exit_code=getattr(exc, "exit_code", 70),
            traceback=traceback.format_exc(),
        )
        tb = exc.__traceback__
        while tb:
            frame = tb.tb_frame
            if frame.f_code.co_name == "_bounded_size":
                failure["bound_trigger"] = dict(
                    counter="report_bytes",
                    attempted=frame.f_locals["size"],
                    limit=frame.f_locals["cap"],
                    function="_bounded_size",
                    file=Path(frame.f_code.co_filename).name,
                    line=tb.tb_lineno,
                )
            if (
                frame.f_code.co_name in ("maximum", "charge")
                and "key" in frame.f_locals
                and "self" in frame.f_locals
            ):
                obj = frame.f_locals["self"]
                key = frame.f_locals["key"]
                if hasattr(obj, "usage"):
                    failure["bound_trigger"] = dict(
                        counter=key,
                        previous=obj.usage[key],
                        requested=frame.f_locals.get("n"),
                        attempted=frame.f_locals.get("value", frame.f_locals.get("n")),
                        limit=getattr(obj.limits, key),
                        function=frame.f_code.co_name,
                        file=Path(frame.f_code.co_filename).name,
                        line=tb.tb_lineno,
                    )
            tb = tb.tb_next
        return None, failure
    finally:
        # Results are populated by the caller wrapper, which can include failures.
        pass


def run_stage(label, call):
    wall, cpu = time.perf_counter(), time.process_time()
    value, result = timed(label, call)
    result.update(
        wall_seconds=round(time.perf_counter() - wall, 6),
        cpu_seconds=round(time.process_time() - cpu, 6),
        process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    )
    return value, result


def worker(spec):
    enforcement = constrain()
    sys.path.insert(0, str(ROOT / "src"))
    from wheelsuture.api import analyze, create_repair
    from wheelsuture.model import DEFAULT_LIMITS
    from wheelsuture.verify import verify_report

    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="wheelsuture-capacity-") as directory:
        root = Path(directory)
        path, fixture = build_case(root, spec)
        hashes_before = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()
        }
        report, analysis = run_stage("analyze", lambda: analyze(path))
        stages = [analysis]
        report_path = root / "report.json"
        if report is not None:
            data = report.to_dict()
            analysis.update(
                status=data["status"],
                usage=data["resource_usage"],
                report_sha256=hashlib.sha256(report.canonical + b"\n").hexdigest(),
                measured_report_bytes=len(report.canonical) + 1,
            )
            report_path.write_bytes(report.canonical + b"\n")
        else:
            # Minimal declared-limits evidence causes independent reconstruction;
            # a consistent result is never expected from this placeholder.
            report_path.write_bytes(
                canonical({"effective_limits": DEFAULT_LIMITS.to_dict()})
            )
        _, verification = run_stage(
            "verify_report", lambda: verify_report(path, report_path)
        )
        stages.append(verification)
        if report is not None:
            pair, repair = run_stage("create_repair", lambda: create_repair(path))
            stages.append(repair)
            if pair:
                proposal = pair[1]
                pd = proposal.to_dict()
                repair.update(
                    status=pd["status"],
                    diagnostics=pd["diagnostics"],
                    usage=(pd.get("verification") or {}).get("resource_usage"),
                    proposal_bytes=len(proposal.canonical) + 1,
                )
                repair_path = root / "repair.json"
                repair_path.write_bytes(proposal.canonical + b"\n")
                _, rv = run_stage(
                    "verify_repair",
                    lambda: verify_report(path, report_path, repair_path=repair_path),
                )
                stages.append(rv)
        unchanged = all(
            hashlib.sha256((root / name).read_bytes()).hexdigest() == h
            for name, h in hashes_before.items()
        )
        return dict(
            spec=spec,
            enforcement=enforcement,
            fixture=fixture,
            stages=stages,
            inputs_preserved=unchanged,
            total_wall_seconds=round(time.perf_counter() - start, 6),
            peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        )


def validate_receipt(receipt):
    errors = []
    if "stages" not in receipt:
        return ["Worker did not complete within its resource/watchdog envelope"]
    spec = receipt["spec"]
    stages = receipt["stages"]
    analysis = stages[0]
    if not receipt["inputs_preserved"]:
        errors.append("Input source hash changed")
    if spec["expected"] == "complete":
        if analysis["outcome"] != "complete":
            errors.append("Expected complete analysis")
        for stage in stages:
            if stage["outcome"] != "complete":
                errors.append(stage["stage"] + " failed")
            if stage["stage"].startswith("verify") and not (
                stage.get("valid")
                and stage.get("complete")
                and stage.get("exit_code") == 0
            ):
                errors.append(stage["stage"] + " did not establish consistency")
        if (
            analysis["outcome"] == "complete"
            and analysis["usage"]["report_bytes"] != analysis["measured_report_bytes"]
        ):
            errors.append("Report length counter mismatch")
        expected_repair = spec.get("repair_status")
        if expected_repair and not any(
            s["stage"] == "create_repair" and s.get("status") == expected_repair
            for s in stages
        ):
            errors.append("Unexpected repair status")
    else:
        if analysis["outcome"] != "error" or analysis.get("exit_code") != 3:
            errors.append("Expected fail-closed incomplete/resource analysis")
        if spec["expected"] != "unsupported" and spec["expected"] not in analysis.get(
            "message", ""
        ):
            errors.append("Wrong first resource bound")
        verification = stages[1]
        if (
            verification["outcome"] != "complete"
            or verification.get("valid")
            or verification.get("exit_code") != 3
        ):
            errors.append("Verifier failed to classify incomplete/resource input")
    exact = {
        "wheels_32": ("wheels", 32),
        "claims_4096": ("mapped_claims", 4096),
        "entries_4096": ("entries", 4096),
        "member_4m": ("member_bytes", 4 * MiB),
        "decoded_32m": ("decoded_bytes", 32 * MiB),
        "archive_32m": ("archive_bytes", 32 * MiB),
        "events_20000": ("expanded_events", 20000),
        "findings_4096": ("findings", 4096),
        "operations_256": ("user_operations", 256),
        "path_text_1m": ("path_text_bytes", MiB),
        "report_32m": ("report_bytes", 32 * MiB),
    }
    if spec["name"] in exact and analysis["outcome"] == "complete":
        counter, value = exact[spec["name"]]
        if analysis["usage"][counter] != value:
            errors.append("Fixture did not reach its exact stated counter")
    if (
        spec["name"] == "report_32m_plus1"
        and analysis.get("bound_trigger", {}).get("attempted") != 32 * MiB + 1
    ):
        errors.append("Report over-limit fixture is not exact +1")
    return errors


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--output", type=Path, default=ROOT / "qualification/evidence/capacity"
    )
    p.add_argument("--case", action="append")
    p.add_argument("--worker")
    args = p.parse_args()
    if args.worker:
        print(json.dumps(worker(json.loads(args.worker)), sort_keys=True))
        return
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = dict(
        schema_version=1,
        purpose="Original inert fixtures; all child stages constrained, no installation or payload imports",
        hardware=hardware(),
        seeds=SEEDS,
        sources={
            str(f.relative_to(ROOT)): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in sorted((ROOT / "src").rglob("*.py"))
        },
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        receipts=[],
    )
    for spec in case_specs():
        if args.case and spec["name"] not in args.case:
            continue
        wall = time.perf_counter()
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    json.dumps(spec),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=ROOT,
            )
            receipt = (
                json.loads(proc.stdout)
                if proc.returncode == 0
                else dict(
                    spec=spec,
                    subprocess_returncode=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                )
            )
        except subprocess.TimeoutExpired as exc:
            receipt = dict(
                spec=spec,
                watchdog="wall_timeout_120_seconds",
                stdout=str(exc.stdout),
                stderr=str(exc.stderr),
            )
        receipt["controller_wall_seconds"] = round(time.perf_counter() - wall, 6)
        receipt["qualification_errors"] = validate_receipt(receipt)
        receipt["qualified"] = not receipt["qualification_errors"]
        file = args.output / (spec["name"] + ".json")
        file.write_bytes(canonical(receipt) + b"\n")
        manifest["receipts"].append(
            dict(
                name=spec["name"],
                path=file.name,
                sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                qualified=receipt["qualified"],
            )
        )
        print(
            spec["name"],
            [
                (s["stage"], s.get("status", s.get("message", s["outcome"])))
                for s in receipt.get("stages", [])
            ],
            receipt.get("peak_rss_kib", "terminated"),
            flush=True,
        )
    manifest["source_files_after"] = {
        str(f.relative_to(ROOT)): hashlib.sha256(f.read_bytes()).hexdigest()
        for f in sorted((ROOT / "src").rglob("*.py"))
    }
    manifest["source_unchanged_during_run"] = (
        manifest["sources"] == manifest["source_files_after"]
    )
    manifest["qualified"] = (
        all(r["qualified"] for r in manifest["receipts"])
        and manifest["source_unchanged_during_run"]
    )
    (args.output / "manifest.json").write_bytes(canonical(manifest) + b"\n")
    if not manifest["qualified"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
