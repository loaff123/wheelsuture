"""Immutable public values and explicit per-run resource accounting."""

from dataclasses import dataclass, asdict, fields
from pathlib import Path
import json
from .canonical import canonical_bytes, digest
from .constants import MODEL_REVISION
from .errors import LimitExceeded, InvalidInput


@dataclass(frozen=True)
class Limits:
    wheels: int = 32
    entries: int = 4096
    archive_bytes: int = 33554432
    decoded_bytes: int = 33554432
    member_bytes: int = 4194304
    expanded_events: int = 20000
    mapped_claims: int = 4096
    deletion_paths: int = 4096
    findings: int = 4096
    state_slots: int = 4096
    central_directory_bytes: int = 1048576
    path_text_bytes: int = 1048576
    plan_bytes: int = 1048576
    record_member_bytes: int = 1048576
    metadata_member_bytes: int = 262144
    user_operations: int = 256
    report_bytes: int = 33554432
    json_depth: int = 32
    error_bytes: int = 65536

    def __post_init__(self):
        for f in fields(self):
            v = getattr(self, f.name)
            if type(v) is not int or not 0 <= v <= f.default:
                raise ValueError("Limits can only lower hard caps: " + f.name)

    def to_dict(self):
        return asdict(self)


DEFAULT_LIMITS = Limits()


class Budget:
    def __init__(self, limits=DEFAULT_LIMITS):
        if not isinstance(limits, Limits):
            raise TypeError("limits must be Limits")
        self.limits = limits
        self._usage = {k: 0 for k in limits.to_dict() if k != "error_bytes"}

    @property
    def usage(self):
        return dict(self._usage)

    def charge(self, key, n):
        if type(n) is not int or n < 0:
            raise ValueError("Invalid resource charge")
        value = self._usage[key] + n
        if value > getattr(self.limits, key):
            raise LimitExceeded("Resource limit exceeded: " + key, path=None)
        self._usage[key] = value

    def maximum(self, key, n):
        if type(n) is not int or n < 0:
            raise ValueError("Invalid resource maximum")
        if n > getattr(self.limits, key):
            raise LimitExceeded("Resource limit exceeded: " + key)
        self._usage[key] = max(self._usage[key], n)


@dataclass(frozen=True)
class WheelSource:
    id: str
    path: str
    sha256: str
    base: Path


@dataclass(frozen=True)
class Profile:
    id: str


_PLAN_TOKEN = object()


@dataclass(frozen=True)
class Plan:
    path: Path
    canonical: bytes
    limits: Limits = DEFAULT_LIMITS
    source_file_sha256: str = ""
    plan_bytes: int = 0
    json_depth: int = 0
    _seal: object = None

    def validated(self):
        binding = (
            self.path,
            self.canonical,
            self.limits,
            self.source_file_sha256,
            self.plan_bytes,
            self.json_depth,
        )
        return (
            isinstance(self._seal, tuple)
            and len(self._seal) == 2
            and self._seal[0] is _PLAN_TOKEN
            and self._seal[1] == binding
        )

    def to_dict(self):
        return json.loads(self.canonical)

    @property
    def input_sha256(self):
        return digest("wheelsuture/plan/1", self.to_dict())

    @property
    def sources(self):
        return tuple(
            WheelSource(w["id"], w["path"], w["sha256"], self.path.parent)
            for w in self.to_dict()["wheels"]
        )

    @property
    def case_id(self):
        d = self.to_dict()
        return digest(
            "wheelsuture/case/1",
            [
                d["profile"],
                MODEL_REVISION,
                self.input_sha256,
                [[w["id"], w["sha256"]] for w in d["wheels"]],
            ],
        )


def _validated_plan(
    path,
    canonical,
    limits=DEFAULT_LIMITS,
    source_file_sha256="",
    plan_bytes=0,
    json_depth=0,
):
    binding = (path, canonical, limits, source_file_sha256, plan_bytes, json_depth)
    return Plan(*binding, _seal=(_PLAN_TOKEN, binding))


@dataclass(frozen=True)
class Document:
    canonical: bytes

    def to_dict(self):
        return json.loads(self.canonical)


@dataclass(frozen=True)
class AnalysisReport(Document):
    pass


@dataclass(frozen=True)
class RepairProposal(Document):
    pass


_INVENTORY_TOKEN = object()


@dataclass(frozen=True)
class WheelInventory(Document):
    profile_id: str
    source_sha256: str
    limits: Limits
    usage_canonical: bytes
    _token: object = None

    @property
    def resource_usage(self):
        return json.loads(self.usage_canonical)

    def validated(self):
        binding = (
            self.canonical,
            self.profile_id,
            self.source_sha256,
            self.limits,
            self.usage_canonical,
        )
        return (
            isinstance(self._token, tuple)
            and len(self._token) == 2
            and self._token[0] is _INVENTORY_TOKEN
            and self._token[1] == binding
        )


def _validated_inventory(wheel, profile_id, source_sha256, limits, usage):
    binding = (
        canonical_bytes(wheel),
        profile_id,
        source_sha256,
        limits,
        canonical_bytes(usage),
    )
    return WheelInventory(*binding, _token=(_INVENTORY_TOKEN, binding))
