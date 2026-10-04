"""Bounded, non-extracting ZIP scanner.

Supported ZIP subset: single disk, stored/raw-deflate, ordinary 32-bit headers,
without data descriptors. ZIP64 and descriptors fail closed as unsupported.
No ZipFile parser or declared decoded length controls decompressor output.
"""

from dataclasses import dataclass
import hashlib
import os
import stat
import struct
import zlib

from .errors import InvalidInput, UnsupportedInput, InputChanged

_CHUNK = 65536


@dataclass(frozen=True)
class Member:
    name: str
    is_dir: bool
    size: int
    sha256: str
    sha384: str
    sha512: str
    text: bytes | None
    rewritten: bool
    tail_sha256: str
    tail_size: int


@dataclass(frozen=True)
class _Entry:
    name: str
    raw_name: bytes
    is_dir: bool
    flags: int
    method: int
    crc: int
    compressed: int
    decoded: int
    offset: int
    data_offset: int = 0


def validate_path(name, *, directory=False):
    """Validate exact Unicode POSIX spelling without normalizing it."""
    from unicodedata import category

    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise UnsupportedInput("Unsupported member path", code="unsupported_path")
    if any(category(c) in ("Cc", "Cs", "Cf") for c in name):
        raise UnsupportedInput(
            "Control characters in member path", code="unsupported_path"
        )
    parts = (name[:-1] if directory and name.endswith("/") else name).split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise UnsupportedInput(
            "Non-relative or ambiguous member path", code="unsupported_path"
        )
    if len(name.encode("utf-8")) > 1024 or any(
        len(p.encode("utf-8")) > 255 for p in parts
    ):
        raise UnsupportedInput(
            "Member path exceeds fixed profile length", code="unsupported_path"
        )
    return parts


def _exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise InvalidInput("Truncated ZIP structure", code="invalid_archive")
    return b


def _extras(data, *, central):
    seen = set()
    pos = 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise InvalidInput("Truncated ZIP extra field", code="invalid_archive")
        kind, size = struct.unpack_from("<HH", data, pos)
        pos += 4
        if kind in seen or size > len(data) - pos:
            raise InvalidInput(
                "Duplicate or truncated ZIP extra field", code="invalid_archive"
            )
        seen.add(kind)
        b = data[pos : pos + size]
        pos += size
        if kind == 1:
            raise UnsupportedInput(
                "ZIP64 is outside the supported archive subset",
                code="unsupported_zip64",
            )
        if kind == 0x5455:
            if not b or b[0] & ~7:
                raise InvalidInput(
                    "Malformed extended timestamp", code="invalid_archive"
                )
            expected = 1 + 4 * ((b[0] & 1) if central else b[0].bit_count())
            if len(b) != expected:
                raise InvalidInput(
                    "Malformed extended timestamp length", code="invalid_archive"
                )
        elif kind == 0x000A:
            if len(b) < 4 or b[:4] != b"\0" * 4:
                raise InvalidInput("Malformed NTFS extra field", code="invalid_archive")
            j = 4
            tags = set()
            while j < len(b):
                if len(b) - j < 4:
                    raise InvalidInput(
                        "Truncated NTFS attribute", code="invalid_archive"
                    )
                tag, n = struct.unpack_from("<HH", b, j)
                j += 4
                if tag in tags or tag != 1 or n != 24 or n > len(b) - j:
                    raise UnsupportedInput(
                        "Unsupported NTFS extra attribute", code="unsupported_extra"
                    )
                tags.add(tag)
                j += n
        elif kind == 0x7875:
            if len(b) < 3 or b[0] != 1:
                raise InvalidInput(
                    "Malformed Unix UID/GID extra field", code="invalid_archive"
                )
            j = 2 + b[1]
            if not b[1] or j >= len(b) or not b[j] or j + 1 + b[j] != len(b):
                raise InvalidInput(
                    "Malformed Unix UID/GID lengths", code="invalid_archive"
                )
        else:
            raise UnsupportedInput(
                "Unknown or path-reinterpreting ZIP extra field",
                code="unsupported_extra",
            )


def _hash_file(f):
    f.seek(0)
    h = hashlib.sha256()
    while b := f.read(_CHUNK):
        h.update(b)
    return h.hexdigest()


def _fingerprint(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def scan_wheel(source, budget):
    """Return immutable summaries, buffering only bounded structural text."""
    from .plan import open_source

    with open_source(source) as f:
        before = os.fstat(f.fileno())
        budget.charge("wheels", 1)
        budget.charge("archive_bytes", before.st_size)
        if _hash_file(f) != source.sha256:
            raise InvalidInput(
                "Wheel does not match its pinned SHA-256",
                code="digest_mismatch",
                wheel_id=source.id,
            )
        entries = _preflight(f, before.st_size, budget)
        result = tuple(_decode(f, e, budget) for e in entries)
        if (
            _fingerprint(os.fstat(f.fileno())) != _fingerprint(before)
            or _hash_file(f) != source.sha256
        ):
            raise InputChanged(
                "Wheel changed during inventory",
                code="input_changed",
                wheel_id=source.id,
            )
        return result


def _preflight(f, size, budget):
    if size < 22:
        raise InvalidInput("Missing ZIP end record", code="invalid_archive")
    tail_size = min(size, 65557)
    f.seek(size - tail_size)
    tail = _exact(f, tail_size)
    # A signature in the comment is data. Consider only complete candidates
    # whose exact comment reaches EOF, preferring coherent directory bounds.
    p = tail.rfind(b"PK\x05\x06")
    fallback = None
    while p >= 0:
        if len(tail) - p >= 22:
            fields = struct.unpack_from("<4s4H2IH", tail, p)
            if p + 22 + fields[-1] == len(tail):
                if fallback is None:
                    fallback = p
                if fields[5] + fields[6] == size - tail_size + p:
                    break
        p = tail.rfind(b"PK\x05\x06", 0, p)
    if p < 0:
        p = fallback
    if p is None:
        raise InvalidInput("Missing ZIP end record", code="invalid_archive")
    sig, disk, cd_disk, n_disk, n, cd_size, cd_offset, comment = struct.unpack_from(
        "<4s4H2IH", tail, p
    )
    eocd = size - tail_size + p
    if p + 22 + comment != len(tail):
        raise InvalidInput(
            "Unexplained bytes after ZIP end record", code="invalid_archive"
        )
    if (
        n == 65535
        or n_disk == 65535
        or cd_size == 0xFFFFFFFF
        or cd_offset == 0xFFFFFFFF
        or tail[max(0, p - 20) : p].startswith(b"PK\x06\x07")
    ):
        raise UnsupportedInput(
            "ZIP64 is outside the supported archive subset", code="unsupported_zip64"
        )
    if disk or cd_disk or n_disk != n:
        raise UnsupportedInput(
            "Multi-disk ZIP is unsupported", code="unsupported_multidisk"
        )
    if cd_offset + cd_size != eocd:
        raise InvalidInput(
            "Central directory bounds or unexplained ZIP bytes", code="invalid_archive"
        )
    budget.charge("entries", n)
    budget.charge("central_directory_bytes", cd_size)
    if cd_size < n * 46:
        raise InvalidInput("Impossible central directory count", code="invalid_archive")
    f.seek(cd_offset)
    entries = []
    names = set()
    raw_names = set()
    for _ in range(n):
        if f.tell() + 46 > eocd:
            raise InvalidInput("Truncated central directory", code="invalid_archive")
        v = struct.unpack("<4s6H3I5H2I", _exact(f, 46))
        (
            sig,
            made,
            needed,
            flags,
            method,
            mtime,
            mdate,
            crc,
            compressed,
            decoded,
            nlen,
            xlen,
            clen,
            start_disk,
            internal,
            external,
            offset,
        ) = v
        if sig != b"PK\x01\x02" or f.tell() + nlen + xlen + clen > eocd:
            raise InvalidInput(
                "Malformed central directory entry", code="invalid_archive"
            )
        if (
            compressed == 0xFFFFFFFF
            or decoded == 0xFFFFFFFF
            or offset == 0xFFFFFFFF
            or start_disk == 65535
        ):
            raise UnsupportedInput(
                "ZIP64 is outside the supported archive subset",
                code="unsupported_zip64",
            )
        if start_disk:
            raise UnsupportedInput(
                "Multi-disk ZIP is unsupported", code="unsupported_multidisk"
            )
        if flags & 1:
            raise UnsupportedInput(
                "Encrypted ZIP members are unsupported", code="unsupported_encryption"
            )
        if flags & 8:
            raise UnsupportedInput(
                "Data descriptors are outside the supported archive subset",
                code="unsupported_descriptor",
            )
        if flags & ~0x806 or (method == 0 and flags & 6):
            raise UnsupportedInput("Unsupported ZIP flags", code="unsupported_flags")
        if method not in (0, 8):
            raise UnsupportedInput(
                "Unsupported ZIP compression", code="unsupported_compression"
            )
        if needed > 20:
            raise UnsupportedInput(
                "Unsupported ZIP extraction version", code="unsupported_zip_version"
            )
        raw = _exact(f, nlen)
        extra = _exact(f, xlen)
        _exact(f, clen)
        if b"\0" in raw:
            raise InvalidInput("NUL in raw ZIP member name", code="invalid_archive")
        try:
            name = raw.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeDecodeError as exc:
            raise InvalidInput(
                "Invalid ZIP filename encoding", code="invalid_archive"
            ) from exc
        directory = name.endswith("/")
        validate_path(name, directory=directory)
        budget.charge("path_text_bytes", len(name.encode()))
        if name in names or raw in raw_names:
            raise InvalidInput("Duplicate ZIP member name", code="duplicate_member")
        names.add(name)
        raw_names.add(raw)
        mode = external >> 16
        kind = stat.S_IFMT(mode)
        if (directory and kind not in (0, stat.S_IFDIR)) or (
            not directory and (kind not in (0, stat.S_IFREG) or external & 0x10)
        ):
            raise UnsupportedInput(
                "Non-regular archive member", code="unsupported_file_kind"
            )
        if directory and (decoded or crc):
            raise UnsupportedInput(
                "Nonempty directory entry", code="unsupported_directory"
            )
        _extras(extra, central=True)
        entries.append(
            _Entry(
                name, raw, directory, flags, method, crc, compressed, decoded, offset
            )
        )
    if f.tell() != eocd:
        raise InvalidInput("Unused central directory bytes", code="invalid_archive")
    files = {e.name for e in entries if not e.is_dir}
    for e in entries:
        p = e.name.rstrip("/").split("/")
        if (
            e.is_dir
            and e.name[:-1] in files
            or any("/".join(p[:i]) in files for i in range(1, len(p)))
        ):
            raise UnsupportedInput(
                "File/directory prefix collision", code="prefix_collision"
            )
    result = []
    expected = 0
    for e in sorted(entries, key=lambda x: x.offset):
        if e.offset != expected or e.offset + 30 > cd_offset:
            raise InvalidInput(
                "Overlapping, prefixed or noncontiguous member extents",
                code="invalid_archive",
            )
        f.seek(e.offset)
        v = struct.unpack("<4s5H3I2H", _exact(f, 30))
        (
            sig,
            needed,
            flags,
            method,
            mtime,
            mdate,
            crc,
            compressed,
            decoded,
            nlen,
            xlen,
        ) = v
        if sig != b"PK\x03\x04" or (flags, method, crc, compressed, decoded) != (
            e.flags,
            e.method,
            e.crc,
            e.compressed,
            e.decoded,
        ):
            raise InvalidInput(
                "Contradictory local and central headers", code="invalid_archive"
            )
        if needed > 20:
            raise UnsupportedInput(
                "Unsupported local extraction version", code="unsupported_zip_version"
            )
        if f.tell() + nlen + xlen > cd_offset:
            raise InvalidInput(
                "Local header outside payload area", code="invalid_archive"
            )
        raw = _exact(f, nlen)
        extra = _exact(f, xlen)
        if raw != e.raw_name or b"\0" in raw:
            raise InvalidInput("Contradictory raw member names", code="invalid_archive")
        _extras(extra, central=False)
        start = f.tell()
        expected = start + compressed
        if expected > cd_offset:
            raise InvalidInput(
                "Compressed extent overlaps central directory", code="invalid_archive"
            )
        result.append(
            _Entry(
                e.name,
                e.raw_name,
                e.is_dir,
                e.flags,
                e.method,
                e.crc,
                e.compressed,
                e.decoded,
                e.offset,
                start,
            )
        )
    if expected != cd_offset:
        raise InvalidInput(
            "Unexplained bytes before central directory", code="invalid_archive"
        )
    # Decode in central order so resource-limit stop boundaries are deterministic.
    offsets = {e.offset: e for e in result}
    return tuple(offsets[e.offset] for e in entries)


def _decode(f, e, budget):
    f.seek(e.data_offset)
    count = 0
    crc = 0
    h256 = hashlib.sha256()
    h384 = hashlib.sha384()
    h512 = hashlib.sha512()
    tail = hashlib.sha256()
    tail_size = 0
    prefix = bytearray()
    line_finished = False
    basename = e.name.rsplit("/", 1)[-1]
    text_kind = (
        "record_member_bytes"
        if basename == "RECORD"
        else "metadata_member_bytes"
        if basename in ("METADATA", "WHEEL", "entry_points.txt")
        else None
    )
    text = bytearray() if text_kind else None

    def accept(b):
        nonlocal count, crc, tail_size, line_finished
        count += len(b)
        budget.maximum("member_bytes", count)
        budget.charge("decoded_bytes", len(b))
        if text_kind:
            budget.maximum(text_kind, count)
        h256.update(b)
        h384.update(b)
        h512.update(b)
        crc = zlib.crc32(b, crc)
        if len(prefix) < 8:
            prefix.extend(b[: 8 - len(prefix)])
        if line_finished:
            tail.update(b)
            tail_size += len(b)
        else:
            split = b.find(b"\n")
            if split >= 0:
                line_finished = True
                tail.update(b[split + 1 :])
                tail_size += len(b) - split - 1
        if text is not None:
            text.extend(b)

    def output_bound():
        allowed = min(
            _CHUNK,
            budget.limits.member_bytes - count + 1,
            budget.limits.decoded_bytes - budget.usage["decoded_bytes"] + 1,
        )
        if text_kind:
            allowed = min(allowed, getattr(budget.limits, text_kind) - count + 1)
        return max(1, allowed)

    if e.method == 0:
        if e.compressed != e.decoded:
            raise InvalidInput(
                "Stored member size contradiction", code="invalid_archive"
            )
        left = e.compressed
        while left:
            b = _exact(f, min(left, output_bound()))
            left -= len(b)
            accept(b)
    else:
        dec = zlib.decompressobj(-15)
        left = e.compressed
        try:
            while left:
                b = _exact(f, min(left, _CHUNK))
                left -= len(b)
                while b:
                    out = dec.decompress(b, output_bound())
                    accept(out)
                    if dec.unused_data:
                        raise InvalidInput(
                            "Trailing or concatenated deflate streams",
                            code="invalid_archive",
                        )
                    b = dec.unconsumed_tail
                    if dec.eof and (b or left):
                        raise InvalidInput(
                            "Early deflate end marker", code="invalid_archive"
                        )
            while not dec.eof:
                out = dec.decompress(b"", output_bound())
                if not out:
                    break
                accept(out)
        except zlib.error as exc:
            raise InvalidInput(
                "Invalid raw deflate stream", code="invalid_archive"
            ) from exc
        if not dec.eof or dec.unused_data or dec.unconsumed_tail:
            raise InvalidInput(
                "Truncated or incompletely consumed deflate stream",
                code="invalid_archive",
            )
    if count != e.decoded or (crc & 0xFFFFFFFF) != e.crc:
        raise InvalidInput(
            "Decoded member size or CRC differs from headers", code="invalid_archive"
        )
    return Member(
        e.name,
        e.is_dir,
        count,
        h256.hexdigest(),
        h384.hexdigest(),
        h512.hexdigest(),
        bytes(text) if text is not None else None,
        bytes(prefix).startswith(b"#!python"),
        tail.hexdigest(),
        tail_size,
    )
