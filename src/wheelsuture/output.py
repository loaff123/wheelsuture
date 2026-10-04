"""Per-file atomic publication with create-only commits unless explicitly replaced.

A collection of outputs is deliberately not advertised as a transaction. All
files are staged before the first commit; the authoritative JSON is committed
last. Directory descriptors prevent following symlink parents during writes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import uuid

from .errors import OutputError


@dataclass
class _Target:
    original: Path
    path: Path
    directory_fd: int
    basename: str
    temporary: str | None = None


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _open_directory(path: Path) -> int:
    """Open each directory component without following a symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            new_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = new_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stat_target(target: _Target) -> os.stat_result | None:
    try:
        return os.stat(
            target.basename, dir_fd=target.directory_fd, follow_symlinks=False
        )
    except FileNotFoundError:
        return None


def _check_parent(target: _Target) -> tuple[int, int]:
    # Detect replaced or symlink parents while retaining the originally opened
    # descriptor for the actual atomic directory-entry operation.
    current = _open_directory(target.path.parent)
    try:
        identity = _identity(os.fstat(current))
        if identity != _identity(os.fstat(target.directory_fd)):
            raise OSError("output directory changed during publication")
        return identity
    finally:
        os.close(current)


def _check_targets(
    targets: list[_Target],
    input_paths: set[Path],
    input_inodes: set[tuple[int, int]],
    *,
    overwrite: bool,
) -> None:
    paths: set[tuple[tuple[int, int], str]] = set()
    inodes: set[tuple[int, int]] = set()
    for target in targets:
        parent_identity = _check_parent(target)
        key = (parent_identity, target.basename)
        if key in paths or target.path in input_paths:
            raise OSError("output aliases an input or another output")
        paths.add(key)
        info = _stat_target(target)
        if info is None:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise OSError("output must not be a symlink or non-regular file")
        identity = _identity(info)
        if identity in input_inodes or identity in inodes:
            raise OSError("output aliases an input or another output")
        inodes.add(identity)
        if not overwrite:
            raise FileExistsError("output already exists; use --overwrite")


def publish_outputs(
    outputs: Mapping[Path, bytes],
    *,
    inputs: Iterable[Path] = (),
    overwrite: bool = False,
    authoritative: Path | None = None,
) -> tuple[Path, ...]:
    """Stage and atomically publish bytes; raise OutputError with partial paths.

    No-overwrite publication uses an atomic hard-link create operation, never a
    check followed by a replacing rename. Explicit overwrite uses os.replace.
    Both operations are local to the held directory descriptor. As with normal
    file APIs this is not a hostile-filesystem sandbox or a multi-file commit.
    """
    targets: list[_Target] = []
    published: list[Path] = []
    try:
        entries = [(Path(path), data) for path, data in outputs.items()]
        if any(not isinstance(data, bytes) for _, data in entries):
            raise TypeError("output content must already be serialized bytes")
        if authoritative is not None:
            authoritative = Path(authoritative)
            if authoritative not in [path for path, _ in entries]:
                raise ValueError("authoritative output is not requested")
            entries.sort(key=lambda item: item[0] == authoritative)
        input_paths = {Path(os.path.abspath(path)) for path in inputs}
        # Follow input aliases solely to protect their actual file identities;
        # this never opens an input for writing.
        input_paths |= {path.resolve() for path in tuple(input_paths)}
        input_inodes: set[tuple[int, int]] = set()
        for path in input_paths:
            try:
                input_inodes.add(_identity(path.stat()))
            except FileNotFoundError:
                pass
        for original, _ in entries:
            path = Path(os.path.abspath(original))
            fd = _open_directory(path.parent)
            targets.append(_Target(original, path, fd, path.name))
        _check_targets(targets, input_paths, input_inodes, overwrite=overwrite)
        for target, (_, data) in zip(targets, entries):
            target.temporary = ".wheelsuture-" + uuid.uuid4().hex + ".tmp"
            fd = os.open(
                target.temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=target.directory_fd,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        # Recheck aliases after staging. Create-only correctness does not rely
        # on this check: os.link itself refuses a concurrently created target.
        _check_targets(targets, input_paths, input_inodes, overwrite=overwrite)
        for target in targets:
            _check_parent(target)
            if overwrite:
                info = _stat_target(target)
                if info is not None and (
                    not stat.S_ISREG(info.st_mode) or _identity(info) in input_inodes
                ):
                    raise OSError("output became an unsafe alias during publication")
                os.replace(
                    target.temporary,
                    target.basename,
                    src_dir_fd=target.directory_fd,
                    dst_dir_fd=target.directory_fd,
                )
                target.temporary = None
            else:
                os.link(
                    target.temporary,
                    target.basename,
                    src_dir_fd=target.directory_fd,
                    dst_dir_fd=target.directory_fd,
                    follow_symlinks=False,
                )
            published.append(target.original)
            if target.temporary is not None:
                os.unlink(target.temporary, dir_fd=target.directory_fd)
                target.temporary = None
            os.fsync(target.directory_fd)
        return tuple(published)
    except KeyboardInterrupt as exc:
        exc.partial_outputs = tuple(map(str, published))
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise OutputError(str(exc), partial_outputs=tuple(map(str, published))) from exc
    finally:
        for target in targets:
            try:
                if target.temporary is not None:
                    try:
                        os.unlink(target.temporary, dir_fd=target.directory_fd)
                    except OSError:
                        pass
            finally:
                os.close(target.directory_fd)
