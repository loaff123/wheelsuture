"""Validate immutable wheel declarations and map claims without extraction."""

import base64
import csv
from email import policy
from email.parser import Parser
from email.errors import MessageError
import io
import keyword
from pathlib import PurePosixPath
import re

from packaging.tags import parse_tag
from packaging.utils import (
    canonicalize_name,
    parse_wheel_filename,
    InvalidName,
    InvalidWheelFilename,
)
from packaging.version import Version, InvalidVersion

from .canonical import digest
from .constants import PROFILE_ID
from .errors import InvalidInput, UnsupportedInput
from .model import Budget, _validated_inventory
from .profiles import SITE, map_member, require_profile, validate_destination
from .zipscan import scan_wheel


class _InventoryBudget:
    """Charge global budget first while recording immutable per-source usage."""

    def __init__(self, global_budget):
        self.global_budget = global_budget
        self.local = Budget(global_budget.limits)
        self.limits = global_budget.limits

    @property
    def usage(self):
        return self.global_budget.usage

    def charge(self, key, n):
        self.global_budget.charge(key, n)
        self.local.charge(key, n)

    def maximum(self, key, n):
        self.global_budget.maximum(key, n)
        self.local.maximum(key, n)


def _text(member):
    if member.text is None:
        raise InvalidInput(
            "Missing structural metadata content", code="invalid_metadata"
        )
    try:
        return member.text.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidInput(
            "Structural metadata must be strict UTF-8", code="invalid_metadata"
        ) from exc


def _headers(member, required):
    text = _text(member)
    if "\0" in text or "\r" in text.replace("\r\n", ""):
        raise InvalidInput("Malformed metadata text", code="invalid_metadata")
    try:
        message = Parser(policy=policy.default.clone(raise_on_defect=True)).parsestr(
            text
        )
    except (MessageError, ValueError) as exc:
        raise InvalidInput(
            "Malformed metadata headers", code="invalid_metadata"
        ) from exc
    if message.defects:
        raise InvalidInput("Defective metadata headers", code="invalid_metadata")
    for field in required:
        values = message.get_all(field, [])
        if (
            len(values) != 1
            or not str(values[0]).strip()
            or "\n" in str(values[0])
            or "\r" in str(values[0])
        ):
            raise InvalidInput(
                "Missing, duplicated, or folded metadata field: " + field,
                code="invalid_metadata",
            )
        # email's header object unfolds lines, so inspect raw_items as well.
        if any(
            "\n" in value or "\r" in value
            for key, value in message.raw_items()
            if key.lower() == field.lower()
        ):
            raise UnsupportedInput(
                "Folded structural metadata field", code="unsupported_metadata"
            )
    return message


def _record(members, record_name):
    raw = _text(members[record_name])
    rows = {}
    try:
        for row in csv.reader(io.StringIO(raw, newline=""), strict=True):
            if len(row) != 3 or not row[0] or row[0] in rows:
                raise InvalidInput(
                    "RECORD rows must be unique triples", code="invalid_record"
                )
            rows[row[0]] = row[1:]
    except csv.Error as exc:
        raise InvalidInput("Malformed RECORD CSV", code="invalid_record") from exc
    regular = {p for p, m in members.items() if not m.is_dir}
    if set(rows) != regular or rows.get(record_name) != ["", ""]:
        raise InvalidInput(
            "RECORD must cover each regular member and contain its empty self row",
            code="invalid_record",
        )
    for name, (value, size) in rows.items():
        if name == record_name:
            continue
        if not re.fullmatch(r"[0-9]+", size):
            raise InvalidInput(
                "RECORD size must be nonnegative decimal", code="invalid_record"
            )
        if len(size) > 20 or int(size) != members[name].size:
            raise InvalidInput("RECORD member size mismatch", code="invalid_record")
        if "=" not in value:
            raise InvalidInput("Missing RECORD digest", code="invalid_record")
        algorithm, encoded = value.split("=", 1)
        if algorithm not in ("sha256", "sha384", "sha512"):
            raise UnsupportedInput(
                "Unsupported RECORD digest algorithm", code="unsupported_hash"
            )
        actual = bytes.fromhex(getattr(members[name], algorithm))
        expected = base64.urlsafe_b64encode(actual).rstrip(b"=").decode("ascii")
        if encoded != expected:
            raise InvalidInput(
                "RECORD digest mismatch or noncanonical encoding", code="invalid_record"
            )


def _entry_points(member):
    """Parse a deliberately small unambiguous INI declaration grammar."""
    current = None
    groups = {}
    providers = []
    for line in _text(member).splitlines():
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        if line != line.lstrip():
            raise UnsupportedInput(
                "Entry-point continuations or indentation are unsupported",
                code="unsupported_entry_point",
            )
        if line.startswith("["):
            match = re.fullmatch(r"\[([A-Za-z0-9_.-]+)\]\s*", line)
            if not match or match[1] in groups:
                raise InvalidInput(
                    "Duplicate or malformed entry-point group",
                    code="invalid_entry_point",
                )
            current = match[1]
            groups[current] = set()
            continue
        if current is None or "=" not in line:
            raise InvalidInput(
                "Malformed entry-point declaration", code="invalid_entry_point"
            )
        name, target = (s.strip() for s in line.split("=", 1))
        if not name or name in groups[current]:
            raise InvalidInput("Duplicate entry-point key", code="invalid_entry_point")
        groups[current].add(name)
        if current not in ("console_scripts", "gui_scripts"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", name):
            raise UnsupportedInput(
                "Unsupported entry-point basename", code="unsupported_entry_point"
            )
        identifier = r"[A-Za-z_][A-Za-z0-9_]*"
        dotted = identifier + r"(?:\." + identifier + r")*"
        match = re.fullmatch("(" + dotted + "):(" + dotted + ")", target)
        if not match or any(
            len(part) > 1024
            or any(keyword.iskeyword(piece) for piece in part.split("."))
            for part in match.groups()
        ):
            raise UnsupportedInput(
                "Unsupported entry-point target", code="unsupported_entry_point"
            )
        if any(p["name"] == name for p in providers):
            raise UnsupportedInput(
                "Console/gui provider basename overlap", code="unsupported_entry_point"
            )
        providers.append(
            {
                "kind": "entry_point",
                "group": current,
                "name": name,
                "module": match[1],
                "attribute": match[2],
                "profile": PROFILE_ID,
            }
        )
    return providers


def _bounded_tag(value):
    parts = value.split("-")
    if len(parts) != 3 or any(
        not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*", p) for p in parts
    ):
        raise InvalidInput("Malformed wheel compatibility tag", code="invalid_metadata")
    product = 1
    for part in parts:
        product *= part.count(".") + 1
        if product > 128:
            raise UnsupportedInput(
                "Compressed compatibility tag expansion exceeds supported bound",
                code="unsupported_tags",
            )
    return value


def inventory_wheel(source, profile, budget):
    require_profile(profile)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", source.id) or not re.fullmatch(
        r"[0-9a-f]{64}", source.sha256
    ):
        raise InvalidInput(
            "Invalid wheel source identity or pin", code="invalid_source"
        )
    from .plan import validate_relative

    validate_relative(source.path)
    filename = PurePosixPath(source.path).name
    if filename.endswith(".whl") and len(filename[:-4].split("-")) in (5, 6):
        _bounded_tag("-".join(filename[:-4].split("-")[-3:]))
    try:
        fname, fversion, build, ftags = parse_wheel_filename(filename)
    except InvalidWheelFilename as exc:
        raise InvalidInput("Malformed wheel filename", code="invalid_filename") from exc
    measured = _InventoryBudget(budget)
    sequence = scan_wheel(source, measured)
    members = {m.name: m for m in sequence}
    directories = {
        m.name.split("/")[0]
        for m in sequence
        if m.name.split("/")[0].endswith(".dist-info")
    }
    if len(directories) != 1:
        raise InvalidInput(
            "Wheel must have one top-level dist-info directory", code="invalid_metadata"
        )
    dist_info = next(iter(directories))
    expected = "-".join(PurePosixPath(source.path).name.split("-")[:2]) + ".dist-info"
    if dist_info != expected:
        raise UnsupportedInput(
            "Unnormalized or foreign dist-info stem is unsupported",
            code="unsupported_layout",
        )
    required = {k: dist_info + "/" + k for k in ("METADATA", "WHEEL", "RECORD")}
    if any(n not in members or members[n].is_dir for n in required.values()):
        raise InvalidInput(
            "Missing required wheel metadata member", code="invalid_metadata"
        )
    metadata = _headers(
        members[required["METADATA"]], ("Metadata-Version", "Name", "Version")
    )
    if not re.fullmatch(r"[0-9]+\.[0-9]+", str(metadata["Metadata-Version"])):
        raise InvalidInput("Invalid Metadata-Version", code="invalid_metadata")
    name = str(metadata["Name"])
    original_version = str(metadata["Version"])
    if len(name) > 255 or len(original_version) > 255:
        raise UnsupportedInput(
            "Metadata identity exceeds profile bounds", code="unsupported_metadata"
        )
    try:
        normalized = canonicalize_name(name, validate=True)
        version = Version(original_version)
    except (InvalidName, InvalidVersion) as exc:
        raise InvalidInput(
            "Invalid wheel metadata identity", code="invalid_metadata"
        ) from exc
    if normalized != fname or version != fversion:
        raise InvalidInput(
            "Filename and metadata identities disagree", code="identity_mismatch"
        )
    dist_name, dist_version = dist_info[:-10].rsplit("-", 1)
    try:
        stem_name = canonicalize_name(dist_name, validate=True)
        stem_version = Version(dist_version)
    except (InvalidName, InvalidVersion) as exc:
        raise InvalidInput(
            "Invalid dist-info identity", code="invalid_metadata"
        ) from exc
    if stem_name != normalized or stem_version != version:
        raise InvalidInput(
            "Dist-info and metadata identities disagree", code="identity_mismatch"
        )
    wheel = _headers(members[required["WHEEL"]], ("Wheel-Version", "Root-Is-Purelib"))
    if str(wheel["Wheel-Version"]) != "1.0":
        raise UnsupportedInput(
            "Only Wheel-Version 1.0 is supported", code="unsupported_wheel_version"
        )
    pure = str(wheel["Root-Is-Purelib"])
    if pure not in ("true", "false"):
        raise InvalidInput("Invalid Root-Is-Purelib boolean", code="invalid_metadata")
    tag_values = wheel.get_all("Tag", [])
    if not tag_values or len(tag_values) > 128:
        raise InvalidInput("Missing or too many wheel tags", code="invalid_metadata")
    tags = set()
    try:
        for value in tag_values:
            tags.update(parse_tag(_bounded_tag(str(value))))
            if len(tags) > 128:
                raise UnsupportedInput(
                    "Too many expanded wheel tags", code="unsupported_tags"
                )
    except (ValueError, TypeError) as exc:
        raise InvalidInput(
            "Malformed wheel compatibility tags", code="invalid_metadata"
        ) from exc
    if tags != set(ftags):
        raise InvalidInput("Filename and WHEEL tags disagree", code="tag_mismatch")
    if {str(t) for t in tags} != {"py3-none-any"}:
        raise UnsupportedInput(
            "Only exact py3-none-any wheels are currently supported",
            code="unsupported_tags",
        )
    _record(members, required["RECORD"])
    claims = []
    destinations = set()

    def add(destination, member, kind, signature):
        if destination in destinations:
            raise UnsupportedInput("Duplicate mapped destination", code="mapped_alias")
        measured.charge("mapped_claims", 1)
        measured.charge("deletion_paths", 1)
        measured.charge("path_text_bytes", len(destination.encode()))
        destinations.add(destination)
        claims.append(
            {
                "claim_id": digest(
                    "wheelsuture/claim/1",
                    [PROFILE_ID, source.sha256, member, kind, destination, signature],
                ),
                "path_id": digest("wheelsuture/path/1", [PROFILE_ID, destination]),
                "wheel_id": source.id,
                "destination": destination,
                "member": member,
                "kind": kind,
                "signature": signature,
                "checked": kind != "control",
            }
        )

    ep_name = dist_info + "/entry_points.txt"
    providers = _entry_points(members[ep_name]) if ep_name in members else []
    aliases = {
        shape
        for p in providers
        for shape in (
            p["name"],
            p["name"] + ".exe",
            p["name"] + "-script.py",
            p["name"] + ".pya",
        )
    }
    for member in sequence:
        if member.is_dir:
            continue
        destination, script = map_member(
            member.name, dist_info=dist_info, canonical_name=normalized
        )
        if member.name == required["RECORD"]:
            continue
        if script and member.name.rsplit("/", 1)[-1] in aliases:
            raise UnsupportedInput(
                "Bundled script aliases a generated entry point",
                code="unsupported_script_alias",
            )
        if script and member.rewritten:
            kind = "rewritten_script"
            signature = {
                "kind": kind,
                "tail_sha256": member.tail_sha256,
                "tail_size": member.tail_size,
                "interpreter_token": "profile-interpreter",
                "profile": PROFILE_ID,
            }
        else:
            kind = "copied"
            signature = {"kind": "bytes", "sha256": member.sha256, "size": member.size}
        add(destination, member.name, kind, signature)
    for signature in providers:
        destination = "bin/" + signature["name"]
        validate_destination(destination)
        add(destination, ep_name, "entry_point", signature)
    for control in ("RECORD", "INSTALLER", "REQUESTED", "direct_url.json"):
        destination = SITE + "/" + dist_info + "/" + control
        validate_destination(destination, dist_info=dist_info, own_metadata=True)
        add(
            destination,
            None,
            "control",
            {"kind": "control", "control": control, "wheel_sha256": source.sha256},
        )
    for destination in destinations:
        parts = destination.split("/")
        if any("/".join(parts[:i]) in destinations for i in range(1, len(parts))):
            raise UnsupportedInput(
                "Mapped file/directory prefix collision", code="prefix_collision"
            )
    claims.sort(key=lambda c: (c["destination"].encode(), c["claim_id"]))
    result = {
        "wheel_id": source.id,
        "source_sha256": source.sha256,
        "name": name,
        "canonical_name": normalized,
        "version": str(version),
        "dist_info": dist_info,
        "root_is_purelib": pure == "true",
        "tags": sorted(str(t) for t in tags),
        "member_count": len(sequence),
        "decoded_bytes": sum(m.size for m in sequence),
        "claims": claims,
        "deletion_paths": sorted(destinations, key=lambda p: p.encode()),
    }
    return _validated_inventory(
        result, PROFILE_ID, source.sha256, budget.limits, measured.local.usage
    )
