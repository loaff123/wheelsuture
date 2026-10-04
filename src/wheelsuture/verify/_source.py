"""Independent source reader. No production archive, inventory or mapping imports.

Each source is bounded before allocation; member decompression is metered using the
actual output. Nothing is extracted, imported, or evaluated.
"""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import keyword
import os
import re
import stat
import struct
import unicodedata
import zlib
from email import policy
from email.parser import Parser
from pathlib import Path

from packaging.tags import parse_tag
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from ..canonical import digest
from ..errors import InputChanged, InvalidInput, LimitExceeded, UnsupportedInput

PROFILE = "pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1"
SITE = "lib/python3.12/site-packages"


def _bad(message):
    raise InvalidInput(message)


def path_parts(value, *, directory=False):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise UnsupportedInput("Unsupported member path")
    if any(unicodedata.category(c) in ("Cc", "Cs", "Cf") for c in value):
        raise UnsupportedInput("Control character in path")
    if len(value.encode("utf-8")) > 1024:
        raise UnsupportedInput("Path exceeds supported byte length")
    plain = value[:-1] if directory and value.endswith("/") else value
    parts = plain.split("/")
    if any(p in ("", ".", "..") or len(p.encode("utf-8")) > 255 for p in parts):
        raise UnsupportedInput("Unsupported path component")
    return parts


def read_regular(path, cap):
    """Bounded read with no-follow traversal of every path component."""
    absolute = Path(path).absolute()
    parts = absolute.parts
    descriptors = []
    try:
        directory = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        for part in parts[1:-1]:
            directory = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            descriptors.append(directory)
        fd = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        descriptors.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            _bad("Input is not a regular file")
        if before.st_size > cap:
            raise LimitExceeded("Input byte budget exceeded")
        chunks, length = [], 0
        while True:
            part = os.read(fd, min(65536, cap - length + 1))
            if not part:
                break
            length += len(part)
            if length > cap:
                raise LimitExceeded("Input byte budget exceeded")
            chunks.append(part)
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise InputChanged("Input changed during read")
        return b"".join(chunks)
    except OSError as exc:
        if exc.errno in (40, 20):
            raise InvalidInput("Symlink or non-directory in input path") from exc
        raise
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def read_source(base, source, cap):
    try:
        path_parts(source["path"])
    except UnsupportedInput as exc:
        raise InvalidInput("Invalid wheel source path") from exc
    raw = read_regular(Path(base) / source["path"], cap)
    if hashlib.sha256(raw).hexdigest() != source["sha256"]:
        _bad("Wheel source digest does not match trusted plan")
    return raw


def _extras(raw, *, central=False):
    cursor, seen = 0, set()
    while cursor < len(raw):
        if len(raw) - cursor < 4:
            _bad("Truncated ZIP extra header")
        code, size = struct.unpack_from("<HH", raw, cursor)
        cursor += 4
        if code in seen or size > len(raw) - cursor:
            _bad("Duplicate or truncated ZIP extra field")
        seen.add(code)
        data = raw[cursor : cursor + size]
        cursor += size
        if code == 1:
            raise UnsupportedInput(
                "ZIP64 archives are outside the current verifier profile"
            )
        if code == 0x5455:
            if (
                not data
                or data[0] & ~7
                or len(data)
                != 1 + 4 * (int(bool(data[0] & 1)) if central else data[0].bit_count())
            ):
                _bad("Malformed extended timestamp ZIP extra")
        elif code == 0x000A:
            if len(data) < 4 or data[:4] != b"\0\0\0\0":
                _bad("Malformed NTFS timestamp ZIP extra")
            offset, attribute_tags = 4, set()
            while offset < len(data):
                if len(data) - offset < 4:
                    _bad("Malformed NTFS timestamp tag")
                tag, n = struct.unpack_from("<HH", data, offset)
                if tag in attribute_tags:
                    raise UnsupportedInput("Duplicate NTFS attribute in ZIP extra")
                attribute_tags.add(tag)
                offset += 4
                if tag != 1 or n != 24 or n > len(data) - offset:
                    _bad("Unsupported NTFS timestamp structure")
                offset += n
        elif code == 0x7875:
            if len(data) < 3 or data[0] != 1:
                _bad("Malformed Unix UID/GID ZIP extra")
            n = data[1]
            if not n or len(data) < n + 3:
                _bad("Malformed Unix UID ZIP extra")
            m = data[n + 2]
            if not m or len(data) != n + m + 3:
                _bad("Malformed Unix GID ZIP extra")
        else:
            raise UnsupportedInput("Unknown or path-reinterpreting ZIP extra field")


def decode_archive(raw, budget):
    """Validate central and local records before independently decoding streams."""
    if len(raw) < 22:
        _bad("Truncated ZIP archive")
    lower = max(0, len(raw) - 65557)
    search_before = len(raw)
    end, zip64_fallback = -1, -1
    while search_before > lower:
        candidate = raw.rfind(b"PK\x05\x06", lower, search_before)
        if candidate < 0:
            break
        if candidate + 22 <= len(raw):
            declared_comment = struct.unpack_from("<H", raw, candidate + 20)[0]
            if candidate + 22 + declared_comment == len(raw):
                candidate_count = struct.unpack_from("<H", raw, candidate + 10)[0]
                candidate_size, candidate_offset = struct.unpack_from(
                    "<II", raw, candidate + 12
                )
                # Magic within a legitimate comment is not its outer EOCD.
                # Ordinary candidates must bound a directory ending here;
                # real ZIP64 declarations remain explicitly unsupported.
                zip64 = (
                    candidate_count == 65535
                    or candidate_size == 0xFFFFFFFF
                    or candidate_offset == 0xFFFFFFFF
                )
                if zip64:
                    if zip64_fallback < 0:
                        zip64_fallback = candidate
                elif candidate_offset + candidate_size == candidate:
                    end = candidate
                    break
        search_before = candidate
    if end < 0:
        end = zip64_fallback
    if end < 0:
        _bad("Missing or unterminated ZIP end directory")
    sig, disk, central_disk, disk_n, total, central_size, central_at, comment = (
        struct.unpack_from("<4s4H2IH", raw, end)
    )
    if end + 22 + comment != len(raw):
        _bad("Unexplained trailing archive bytes")
    if disk or central_disk or disk_n != total:
        _bad("Multi-disk archive")
    if (
        total == 65535
        or central_size == 0xFFFFFFFF
        or central_at == 0xFFFFFFFF
        or (end >= 20 and raw[end - 20 : end - 16] == b"PK\x06\x07")
    ):
        raise UnsupportedInput(
            "ZIP64 archives are outside the current verifier profile"
        )
    if central_at + central_size != end:
        _bad("Contradictory central directory extent")
    budget.charge("entries", total)
    budget.charge("central_directory_bytes", central_size)
    cursor, entries, names, raw_names = central_at, [], set(), set()
    for _ in range(total):
        if cursor + 46 > end or raw[cursor : cursor + 4] != b"PK\x01\x02":
            _bad("Invalid central ZIP record")
        fields = struct.unpack_from("<4s6H3I5H2I", raw, cursor)
        (
            _,
            made,
            needed,
            flags,
            method,
            time,
            date,
            crc,
            compressed,
            decoded,
            nn,
            ne,
            nc,
            disk_start,
            internal,
            external,
            offset,
        ) = fields
        if needed > 20:
            raise UnsupportedInput("Unsupported ZIP extraction version")
        if (
            compressed == 0xFFFFFFFF
            or decoded == 0xFFFFFFFF
            or offset == 0xFFFFFFFF
            or disk_start == 65535
        ):
            raise UnsupportedInput(
                "ZIP64 member is outside the current verifier profile"
            )
        if disk_start:
            _bad("Multi-disk member")
        if flags & 8:
            raise UnsupportedInput(
                "Data-descriptor ZIP members are outside the current verifier profile"
            )
        if flags & ~0x806:
            raise UnsupportedInput("Encrypted or unsupported ZIP flags")
        if method not in (0, 8) or (method == 0 and flags & 6):
            raise UnsupportedInput("Unsupported ZIP compression")
        next_cursor = cursor + 46 + nn + ne + nc
        if next_cursor > end:
            _bad("Truncated central member name or extra")
        name_raw = raw[cursor + 46 : cursor + 46 + nn]
        if b"\0" in name_raw:
            _bad("NUL in raw ZIP member name")
        if name_raw in raw_names:
            _bad("Duplicate raw ZIP member name")
        raw_names.add(name_raw)
        try:
            name = name_raw.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeError as exc:
            raise InvalidInput("Invalid member-name encoding") from exc
        if name in names:
            _bad("Duplicate ZIP member name")
        names.add(name)
        directory = name.endswith("/")
        path_parts(name, directory=directory)
        if external & 0x10 and not directory:
            raise UnsupportedInput("DOS directory attribute on a regular member")
        mode = external >> 16
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise UnsupportedInput("Non-regular ZIP member")
        if kind == stat.S_IFDIR and not directory or directory and kind == stat.S_IFREG:
            _bad("Contradictory ZIP file kind")
        if directory and decoded:
            _bad("Directory member has payload")
        _extras(raw[cursor + 46 + nn : cursor + 46 + nn + ne], central=True)
        budget.charge("path_text_bytes", len(name.encode("utf-8")))
        entries.append(
            (offset, name, name_raw, flags, method, crc, compressed, decoded, directory)
        )
        cursor = next_cursor
    if cursor != end:
        _bad("Central ZIP count does not match directory size")
    # The supported profile has no prepended stub, unexplained gap or stream alias.
    by_position = sorted(entries)
    cursor, files = 0, {}
    for (
        offset,
        name,
        name_raw,
        flags,
        method,
        crc,
        compressed,
        decoded,
        directory,
    ) in by_position:
        if (
            offset != cursor
            or offset + 30 > central_at
            or raw[offset : offset + 4] != b"PK\x03\x04"
        ):
            _bad("Overlapping, repeated, gapped or prepended ZIP stream")
        (
            _,
            needed,
            local_flags,
            local_method,
            time,
            date,
            local_crc,
            local_compressed,
            local_decoded,
            nn,
            ne,
        ) = struct.unpack_from("<4s5H3I2H", raw, offset)
        if needed > 20:
            raise UnsupportedInput("Unsupported local ZIP extraction version")
        begin = offset + 30 + nn + ne
        finish = begin + compressed
        if begin > central_at or finish > central_at:
            _bad("Member stream crosses archive directory")
        if (local_flags, local_method, local_crc, local_compressed, local_decoded) != (
            flags,
            method,
            crc,
            compressed,
            decoded,
        ):
            _bad("Local and central member declarations disagree")
        if raw[offset + 30 : offset + 30 + nn] != name_raw:
            _bad("Local and central member names disagree")
        _extras(raw[offset + 30 + nn : begin])
        pieces, actual, checksum = [], 0, 0
        basename = name.rsplit("/", 1)[-1]
        text_counter = (
            "record_member_bytes"
            if basename == "RECORD"
            else "metadata_member_bytes"
            if basename in ("METADATA", "WHEEL", "entry_points.txt")
            else None
        )
        inflater = zlib.decompressobj(-15) if method == 8 else None
        pos = begin
        pending = b""
        while True:
            if inflater is None and not pending and pos == finish:
                break
            if not pending:
                amount = 65536
                if inflater is None:
                    amount = min(
                        amount,
                        budget.limits.member_bytes - actual + 1,
                        budget.limits.decoded_bytes - budget.usage["decoded_bytes"] + 1,
                    )
                    if text_counter:
                        amount = min(
                            amount, getattr(budget.limits, text_counter) - actual + 1
                        )
                next_pos = min(pos + amount, finish)
                pending = raw[pos:next_pos]
                pos = next_pos
            supplied = pending
            if inflater is None:
                part, pending = pending, b""
            else:
                try:
                    ceiling = min(
                        65536,
                        budget.limits.member_bytes - actual + 1,
                        budget.limits.decoded_bytes - budget.usage["decoded_bytes"] + 1,
                    )
                    if text_counter:
                        ceiling = min(
                            ceiling, getattr(budget.limits, text_counter) - actual + 1
                        )
                    part = inflater.decompress(pending, ceiling)
                except zlib.error as exc:
                    raise InvalidInput("Invalid raw deflate member") from exc
                pending = inflater.unconsumed_tail
                if inflater.unused_data:
                    _bad("Trailing or concatenated deflate stream")
            actual += len(part)
            budget.maximum("member_bytes", actual)
            budget.charge("decoded_bytes", len(part))
            if text_counter:
                budget.maximum(text_counter, actual)
            checksum = binascii.crc32(part, checksum)
            pieces.append(part)
            if inflater is not None and inflater.eof:
                if pos != finish or pending:
                    _bad("Deflate stream ended before its extent")
                break
            if inflater is not None and not supplied and not part and not pending:
                _bad("Truncated deflate stream")
        if inflater is not None and not inflater.eof:
            _bad("Truncated deflate stream")
        if actual != decoded or checksum & 0xFFFFFFFF != crc:
            _bad("Decoded member size or CRC mismatch")
        if method == 0 and compressed != decoded:
            _bad("Stored stream sizes disagree")
        if not directory:
            files[name] = b"".join(pieces)
        cursor = finish
    if cursor != central_at:
        _bad("Unexplained bytes before central directory")
    all_names = {n.rstrip("/") for n in names}
    for name in files:
        parts = name.split("/")
        if name + "/" in names or any(
            "/".join(parts[:i]) in files for i in range(1, len(parts))
        ):
            _bad("File/directory-prefix conflict inside archive")
    return files, len(entries), names


def _text_headers(payload, budget):
    budget.maximum("metadata_member_bytes", len(payload))
    try:
        text = payload.decode("utf-8")
        if "\0" in text or "\r" in text.replace("\r\n", ""):
            _bad("NUL or bare CR in metadata")
    except UnicodeError as exc:
        raise InvalidInput("Invalid UTF-8 metadata") from exc
    message = Parser(policy=policy.default).parsestr(text)
    if message.defects or any(
        getattr(value, "defects", ()) for value in message.values()
    ):
        _bad("Malformed metadata headers")
    return message


def _one(message, name):
    values = message.get_all(name, [])
    raw_values = [v for k, v in message.raw_items() if k.lower() == name.lower()]
    if (
        len(values) != 1
        or not str(values[0]).strip()
        or any("\n" in v or "\r" in v for v in raw_values)
    ):
        _bad("Missing or repeated required metadata header")
    return str(values[0]).strip()


def _record(files, dist, budget):
    path = dist + "/RECORD"
    payload = files.get(path)
    if payload is None:
        _bad("Wheel RECORD is missing")
    budget.maximum("record_member_bytes", len(payload))
    try:
        rows = csv.reader(io.StringIO(payload.decode("utf-8"), newline=""), strict=True)
        seen = set()
        for row in rows:
            if len(row) != 3:
                _bad("RECORD row must have exactly three fields")
            name, h, size = row
            if name in seen or name not in files or name.endswith("/"):
                _bad("Duplicate, phantom or directory RECORD row")
            seen.add(name)
            if name == path:
                if h or size:
                    _bad("RECORD self row must have empty digest and size")
                continue
            if (
                len(size) > 20
                or not re.fullmatch(r"[0-9]+", size)
                or (size.lstrip("0") or "0") != str(len(files[name]))
            ):
                _bad("RECORD size mismatch")
            algorithm, sep, encoded = h.partition("=")
            if algorithm not in ("sha256", "sha384", "sha512"):
                raise UnsupportedInput("Unsupported RECORD digest algorithm")
            expected = (
                base64.urlsafe_b64encode(hashlib.new(algorithm, files[name]).digest())
                .rstrip(b"=")
                .decode()
            )
            if not sep or encoded != expected:
                _bad("RECORD digest mismatch")
    except (UnicodeError, csv.Error) as exc:
        raise InvalidInput("Malformed UTF-8 RECORD CSV") from exc
    if seen != set(files):
        _bad("RECORD does not cover exactly all regular members")


def _screen(destination, *, own_dist=None):
    parts = path_parts(destination)
    if any(
        p.lower() == "__pycache__"
        or p.lower().endswith(
            (".pth", ".egg-link", ".pyc", ".pyo", ".egg-info", ".egg")
        )
        for p in parts
    ):
        raise UnsupportedInput(
            "Unsupported bytecode, editable or discovery destination"
        )
    for i, part in enumerate(parts):
        if part.lower().endswith(".dist-info"):
            if own_dist is None or "/".join(parts[: i + 1]) != SITE + "/" + own_dist:
                raise UnsupportedInput("Foreign or aliased metadata destination")
    if destination in (
        "bin",
        "lib",
        "lib/python3.12",
        SITE,
        "include",
        "include/site",
        "include/site/python3.12",
        "include/python3.12",
    ):
        raise UnsupportedInput("Payload replaces interpreter scaffold directory")
    if (
        parts[0] == "lib64"
        or parts[0] == "bin"
        and len(parts) > 1
        and parts[1] in ("activate", "activate.csh", "activate.fish", "Activate.ps1")
    ):
        raise UnsupportedInput("Payload overlaps venv scaffold or alias")
    if parts[0] in ("pyvenv.cfg", "pip.conf"):
        raise UnsupportedInput("Payload overlaps interpreter scaffold")
    if (
        len(parts) >= 2
        and parts[0] == "bin"
        and (
            re.fullmatch(r"(?:python|pip)(?:[0-9]+(?:\.[0-9]+)?)?", parts[1])
            or parts[1] == "easy_install"
            or parts[1].startswith("easy_install-")
        )
    ):
        raise UnsupportedInput("Payload overlaps interpreter executable")
    if destination.startswith(SITE + "/"):
        first = destination[len(SITE) + 1 :].split("/")[0]
        if first == "pip" or first.startswith("pip-") and first.endswith(".dist-info"):
            raise UnsupportedInput("Payload overlaps pip scaffold")
        if any(
            first == x or first.startswith(x + ".")
            for x in ("sitecustomize", "usercustomize")
        ):
            raise UnsupportedInput("Payload provides interpreter startup hook")


def _entrypoints(payload, budget):
    budget.maximum("metadata_member_bytes", len(payload))
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise InvalidInput("Invalid UTF-8 entry-point metadata") from exc
    group, sections, keys, entries, basenames = None, set(), set(), [], set()
    dotted = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    for rawline in text.splitlines():
        stripped = rawline.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if rawline[:1].isspace():
            raise UnsupportedInput("Entry-point continuation ambiguity")
        if stripped.startswith("[") and stripped.endswith("]"):
            group = stripped[1:-1]
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", group) or group in sections:
                _bad("Duplicate or empty entry-point group")
            sections.add(group)
            continue
        key, sep, value = stripped.partition("=")
        key, value = key.strip(), value.strip()
        if group is None or not sep or not key or (group, key) in keys:
            _bad("Malformed or repeated entry-point key")
        keys.add((group, key))
        if group not in ("console_scripts", "gui_scripts"):
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", key):
            raise UnsupportedInput("Unsupported entry-point basename")
        target = re.fullmatch(
            r"(" + dotted + r"):(" + dotted + r")", value, flags=re.ASCII
        )
        if (
            target is None
            or len(target[1]) > 1024
            or len(target[2]) > 1024
            or any(
                keyword.iskeyword(p)
                for side in target.groups()
                for p in side.split(".")
            )
        ):
            raise UnsupportedInput("Unsupported entry-point target")
        if key in basenames or re.fullmatch(r"(?:pip|easy_install)(?:[0-9.-].*)?", key):
            raise UnsupportedInput("Ambiguous or special generated script name")
        basenames.add(key)
        entries.append(
            dict(
                kind="entry_point",
                group=group,
                name=key,
                module=target[1],
                attribute=target[2],
                profile=PROFILE,
            )
        )
    return entries


def _bounded_tag(value):
    if not isinstance(value, str):
        _bad("Invalid wheel tag")
    components = value.split("-")
    if len(components) != 3:
        _bad("Invalid wheel tag")
    count = 1
    for part in components:
        if re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*", part, re.ASCII) is None:
            _bad("Invalid compressed wheel tag")
        count *= part.count(".") + 1
        if count > 128:
            raise UnsupportedInput("Wheel tag expansion exceeds supported bound")
    return value


def inventory(source, base, budget):
    budget.charge("wheels", 1)
    raw = read_source(
        base, source, budget.limits.archive_bytes - budget.usage["archive_bytes"]
    )
    budget.charge("archive_bytes", len(raw))
    start_decoded = budget.usage["decoded_bytes"]
    files, count, archive_names = decode_archive(raw, budget)
    dirs = {
        path.split("/")[0]
        for path in archive_names
        if path.split("/")[0].lower().endswith(".dist-info")
    }
    if len(dirs) != 1:
        _bad("Wheel requires one unambiguous top-level dist-info directory")
    dist = next(iter(dirs))
    expected_dist = "-".join(Path(source["path"]).name.split("-")[:2]) + ".dist-info"
    if dist != expected_dist:
        raise UnsupportedInput(
            "Unnormalized dist-info spelling is outside the supported layout"
        )
    try:
        meta = _text_headers(files[dist + "/METADATA"], budget)
        whe = _text_headers(files[dist + "/WHEEL"], budget)
    except KeyError as exc:
        raise InvalidInput("Wheel METADATA or WHEEL is missing") from exc
    if re.fullmatch(r"[0-9]+\.[0-9]+", _one(meta, "Metadata-Version")) is None:
        _bad("Invalid Metadata-Version")
    name, version_text = _one(meta, "Name"), _one(meta, "Version")
    try:
        canonical_name = canonicalize_name(name, validate=True)
        version = Version(version_text)
        filename = Path(source["path"]).name
        _bounded_tag("-".join(filename[:-4].split("-")[-3:]))
        filename_name, filename_version, build, filename_tags = parse_wheel_filename(
            filename
        )
        di_name, di_version = dist[:-10].rsplit("-", 1)
        if (
            canonicalize_name(di_name, validate=True) != canonical_name
            or Version(di_version) != version
        ):
            _bad("dist-info identity disagrees with metadata")
        if canonical_name != filename_name or version != filename_version:
            _bad("Filename identity disagrees with metadata")
    except (ValueError, InvalidVersion) as exc:
        raise InvalidInput("Invalid wheel distribution identity") from exc
    if len(name) > 255 or len(str(version)) > 255:
        _bad("Wheel identity exceeds supported length")
    if _one(whe, "Wheel-Version") != "1.0":
        raise UnsupportedInput("Unsupported Wheel-Version")
    pure = _one(whe, "Root-Is-Purelib")
    if pure not in ("true", "false"):
        _bad("Invalid Root-Is-Purelib value")
    try:
        tags = set()
        for tag in whe.get_all("Tag", []):
            tags.update(parse_tag(_bounded_tag(str(tag))))
            if len(tags) > 128:
                raise UnsupportedInput(
                    "Aggregate wheel tag expansion exceeds supported bound"
                )
    except ValueError as exc:
        raise InvalidInput("Invalid wheel tag") from exc
    if tags != set(filename_tags) or not tags:
        _bad("WHEEL and filename tag sets disagree")
    if {str(t) for t in tags} != {"py3-none-any"}:
        raise UnsupportedInput("Only py3-none-any wheels are currently supported")
    _record(files, dist, budget)
    entry_member = dist + "/entry_points.txt"
    providers = (
        _entrypoints(files[entry_member], budget) if entry_member in files else []
    )
    alias_names = {
        name
        for p in providers
        for name in (
            p["name"],
            p["name"] + ".exe",
            p["name"] + "-script.py",
            p["name"] + ".pya",
        )
    }
    data_dir = dist[:-10] + ".data"
    claims, destinations = [], set()

    def add(destination, member, kind, signature, own_dist=None):
        _screen(destination, own_dist=own_dist)
        if destination in destinations:
            raise UnsupportedInput("Duplicate mapped wheel destination")
        destinations.add(destination)
        budget.charge("mapped_claims", 1)
        budget.charge("deletion_paths", 1)
        budget.charge("path_text_bytes", len(destination.encode("utf-8")))
        claim = dict(
            claim_id=digest(
                "wheelsuture/claim/1",
                [PROFILE, source["sha256"], member, kind, destination, signature],
            ),
            path_id=digest("wheelsuture/path/1", [PROFILE, destination]),
            wheel_id=source["id"],
            destination=destination,
            member=member,
            kind=kind,
            signature=signature,
            checked=kind != "control",
        )
        claims.append(claim)

    for member, payload in files.items():
        parts = member.split("/")
        if any(
            p.lower() == "__pycache__"
            or p.lower().endswith((".pth", ".egg-link", ".pyc", ".pyo"))
            for p in parts
        ):
            raise UnsupportedInput("Unsupported bytecode or editable wheel member")
        if parts[0] == dist and any("editable" in p.lower() for p in parts[1:]):
            raise UnsupportedInput("Editable metadata or payload layout is unsupported")
        if member in {
            dist + "/" + c
            for c in (
                "INSTALLER",
                "REQUESTED",
                "direct_url.json",
                "RECORD.jws",
                "RECORD.p7s",
            )
        } or member.startswith(dist + "/scripts/"):
            raise UnsupportedInput("Unsupported bundled control or legacy metadata")
        if member == dist + "/RECORD":
            continue
        script = False
        own = dist if member.startswith(dist + "/") else None
        if parts[0].endswith(".data"):
            if parts[0] != data_dir or len(parts) < 3:
                raise UnsupportedInput("Foreign or malformed wheel data layout")
            scheme, tail = parts[1], "/".join(parts[2:])
            if scheme in ("purelib", "platlib"):
                destination = SITE + "/" + tail
            elif scheme == "headers":
                destination = "include/site/python3.12/" + canonical_name + "/" + tail
            elif scheme == "data":
                destination = tail
            elif scheme == "scripts":
                if len(parts) != 3 or tail in alias_names:
                    raise UnsupportedInput(
                        "Unsupported nested or filtered wheel script"
                    )
                destination, script = "bin/" + tail, True
            else:
                raise UnsupportedInput("Unknown wheel data scheme")
        else:
            destination = SITE + "/" + member
        if script and payload.startswith(b"#!python"):
            tail = payload.partition(b"\n")[2]
            sig = dict(
                kind="rewritten_script",
                tail_sha256=hashlib.sha256(tail).hexdigest(),
                tail_size=len(tail),
                interpreter_token="profile-interpreter",
                profile=PROFILE,
            )
            add(destination, member, "rewritten_script", sig, own)
        else:
            sig = dict(
                kind="bytes",
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
            )
            add(destination, member, "copied", sig, own)
    for provider in providers:
        add("bin/" + provider["name"], entry_member, "entry_point", provider)
    for control in ("RECORD", "INSTALLER", "REQUESTED", "direct_url.json"):
        signature = dict(kind="control", control=control, wheel_sha256=source["sha256"])
        add(SITE + "/" + dist + "/" + control, None, "control", signature, dist)
    claims.sort(key=lambda c: (c["destination"].encode("utf-8"), c["claim_id"]))
    # Intra-wheel mapped aliases may create a prefix conflict even when raw paths do not.
    check_union([dict(claims=claims)])
    return dict(
        wheel_id=source["id"],
        source_sha256=source["sha256"],
        name=name,
        canonical_name=canonical_name,
        version=str(version),
        dist_info=dist,
        root_is_purelib=pure == "true",
        tags=sorted(map(str, tags)),
        member_count=count,
        decoded_bytes=budget.usage["decoded_bytes"] - start_decoded,
        claims=claims,
        deletion_paths=[c["destination"] for c in claims],
    )


def check_union(wheels):
    paths = {}
    for wheel in wheels:
        for claim in wheel["claims"]:
            path = claim["destination"]
            for prior in paths.get(path, ()):
                a, b = prior["signature"], claim["signature"]
                if a != b and (a["kind"] != b["kind"] or a["kind"] == "entry_point"):
                    raise UnsupportedInput(
                        "Supplied claims have unequal provider signatures or different signature kinds."
                    )
                if a["kind"] == "control" and prior["wheel_id"] != claim["wheel_id"]:
                    # Distinct versions of the same owner need not be simultaneously active.
                    pass
            paths.setdefault(path, []).append(claim)
    for path in paths:
        components = path.split("/")
        if any("/".join(components[:i]) in paths for i in range(1, len(components))):
            raise UnsupportedInput("Historical file/ancestor destination conflict")
