"""Strict, bounded manifests and no-follow read-only source access."""

import contextlib, hashlib, json, os, re, stat
from pathlib import Path
from .canonical import canonical_bytes
from .constants import PROFILE_ID
from .model import Plan, DEFAULT_LIMITS, _validated_plan
from .errors import (
    InvalidInput,
    UnsupportedInput,
    LimitExceeded,
    InputChanged,
    InputIOError,
)

ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")


def _depth(raw, limit):
    depth = high = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            high = max(high, depth)
            if high > limit:
                raise LimitExceeded("Resource limit exceeded: json_depth")
        elif byte in (93, 125):
            depth -= 1
    return high


def strict_json(raw, limits=DEFAULT_LIMITS, *, byte_limit=None):
    cap = limits.plan_bytes if byte_limit is None else byte_limit
    if len(raw) > cap:
        raise LimitExceeded("Resource limit exceeded: JSON bytes")
    _depth(raw, limits.json_depth)

    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise InvalidInput("Duplicate JSON object key.")
            result[k] = v
        return result

    def bad(value):
        raise InvalidInput("Only finite integer JSON numbers are supported.")

    try:
        text = raw.decode("utf-8")
        obj = json.loads(
            text, object_pairs_hook=pairs, parse_float=bad, parse_constant=bad
        )

        def check(v):
            if isinstance(v, str):
                v.encode("utf-8")
            elif isinstance(v, dict):
                for k, x in v.items():
                    check(k)
                    check(x)
            elif isinstance(v, list):
                for x in v:
                    check(x)

        check(obj)
        return obj
    except (UnicodeError, ValueError, RecursionError) as e:
        raise InvalidInput("Invalid strict UTF-8 JSON.") from e


def validate_relative(path):
    if (
        not isinstance(path, str)
        or not path
        or len(path.encode("utf8")) > 1024
        or "\\" in path
        or ":" in path
        or path.startswith("/")
    ):
        raise InvalidInput("Invalid relative wheel path.")
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise InvalidInput("Control character in wheel path.")
    if any(
        p in ("", ".", "..") or len(p.encode("utf8")) > 255 for p in path.split("/")
    ):
        raise InvalidInput("Invalid wheel path component.")
    return path


@contextlib.contextmanager
def _open_regular(path):
    path = Path(os.path.abspath(path))
    fd = None
    directory = None
    try:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for component in path.parts[1:-1]:
            nxt = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = nxt
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InvalidInput("Input must be a regular file.")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            yield stream
    except OSError as e:
        if e.errno in (40, 20):
            raise InvalidInput(
                "Symlinks and non-directory input components are prohibited."
            ) from e
        raise InputIOError("Cannot read input: " + path.name) from e
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)


@contextlib.contextmanager
def open_source(source):
    validate_relative(source.path)
    with _open_regular(Path(source.base) / source.path) as stream:
        yield stream


def _shape(d, keys):
    if type(d) is not dict or set(d) != set(keys):
        raise InvalidInput("Invalid object fields.")


def _id(s):
    if type(s) is not str or not ID.fullmatch(s):
        raise InvalidInput("Invalid identifier.")


def load_plan(path, *, limits=DEFAULT_LIMITS):
    path = Path(os.path.abspath(path))
    with _open_regular(path) as f:
        raw = f.read(limits.plan_bytes + 1)
    d = strict_json(raw, limits)
    _shape(
        d, ["schema_version", "profile", "wheels", "initial", "transition", "desired"]
    )
    if type(d["schema_version"]) is not int or d["schema_version"] != 1:
        raise InvalidInput("Unsupported schema version.")
    if type(d["profile"]) is not str or not re.fullmatch(
        "[a-z0-9][a-z0-9._-]{0,127}", d["profile"]
    ):
        raise InvalidInput("Invalid profile identifier.")
    for field, cap in [
        ("wheels", limits.wheels),
        ("initial", limits.user_operations),
        ("transition", limits.user_operations),
        ("desired", limits.wheels),
    ]:
        if type(d[field]) is not list:
            raise InvalidInput("Expected array: " + field)
        if len(d[field]) > cap:
            raise LimitExceeded("Resource limit exceeded: " + field)
    if len(d["initial"]) + len(d["transition"]) > limits.user_operations:
        raise LimitExceeded("Resource limit exceeded: user_operations")
    ids = set()
    paths = set()
    hashes = set()
    for w in d["wheels"]:
        _shape(w, ["id", "path", "sha256"])
        _id(w["id"])
        validate_relative(w["path"])
        if not w["path"].endswith(".whl"):
            raise InvalidInput("Expected a .whl path.")
        if type(w["sha256"]) is not str or not re.fullmatch(
            "[0-9a-f]{64}", w["sha256"]
        ):
            raise InvalidInput("Invalid pinned wheel digest.")
        if w["id"] in ids or w["path"] in paths or w["sha256"] in hashes:
            raise InvalidInput("Duplicate wheel ID, path or digest.")
        ids.add(w["id"])
        paths.add(w["path"])
        hashes.add(w["sha256"])
    opids = set()
    for phase in ("initial", "transition"):
        for op in d[phase]:
            if type(op) is not dict or op.get("op") not in (
                "install",
                "remove",
                "replace",
                "reinstall",
            ):
                raise InvalidInput("Unknown operation.")
            if phase == "initial" and op["op"] != "install":
                raise InvalidInput("Initial operations must install.")
            refs = ["from", "to"] if op["op"] == "replace" else ["wheel"]
            _shape(op, ["id", "op"] + refs)
            _id(op["id"])
            if op["id"] in opids:
                raise InvalidInput("Duplicate operation ID.")
            opids.add(op["id"])
            for ref in refs:
                _id(op[ref])
                if op[ref] not in ids:
                    raise InvalidInput("Unknown wheel reference.")
    for w in d["desired"]:
        _id(w)
        if w not in ids:
            raise InvalidInput("Unknown desired wheel.")
    if len(set(d["desired"])) != len(d["desired"]):
        raise InvalidInput("Duplicate desired wheel.")
    if d["profile"] != PROFILE_ID:
        raise UnsupportedInput("Unknown installer profile.", code="unsupported_profile")
    return _validated_plan(
        path,
        canonical_bytes(d),
        limits,
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        _depth(raw, limits.json_depth),
    )


def rehash_sources(plan):
    with _open_regular(plan.path) as f:
        raw = f.read(plan.limits.plan_bytes + 1)
    if hashlib.sha256(raw).hexdigest() != plan.source_file_sha256:
        raise InputChanged("Plan changed during analysis.")
    for source in plan.sources:
        h = hashlib.sha256()
        with open_source(source) as f:
            before = os.fstat(f.fileno())
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
            after = os.fstat(f.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ino,
        ) or h.hexdigest() != source.sha256:
            raise InputChanged("Wheel changed during analysis.", wheel_id=source.id)
