"""Artifact storage.

The code talks to ``ArtifactStore`` only, so an S3-compatible store (requirements section
3) can replace the filesystem one without touching callers. Quarantined files (downloads
captured during a session) live under a separate root and are written without execute
permission (NFR-5).
"""

import hashlib
import os
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from sandbox.config import Settings

QUARANTINE_PREFIX = "quarantine/"
_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class StoredObject:
    key: str
    size: int
    sha256: str
    md5: str


class ArtifactStore(Protocol):
    def put_file(self, key: str, source: Path) -> StoredObject: ...

    def put_bytes(self, key: str, data: bytes) -> StoredObject: ...

    def open(self, key: str): ...

    def path(self, key: str) -> Path:
        """Local path for streaming responses; S3 stores would return a temp copy."""
        ...

    def delete(self, key: str) -> None: ...

    def exists(self, key: str) -> bool: ...


def hash_file(path: Path) -> tuple[str, str, int]:
    sha, md5, size = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            sha.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), md5.hexdigest(), size


class LocalStore:
    def __init__(self, root: str | Path, quarantine_root: str | Path):
        self.root = Path(root).resolve()
        self.quarantine_root = Path(quarantine_root).resolve()

    def _resolve(self, key: str) -> Path:
        parts = PurePosixPath(key).parts
        if not parts or key.startswith("/") or any(p in ("..", "") for p in parts):
            raise ValueError(f"Invalid object key {key!r}")
        if key.startswith(QUARANTINE_PREFIX):
            return self.quarantine_root.joinpath(*parts[1:])
        return self.root.joinpath(*parts)

    def path(self, key: str) -> Path:
        return self._resolve(key)

    def _finish(self, key: str, target: Path) -> StoredObject:
        # Nothing in the store is ever executable; quarantined files are also read-only.
        os.chmod(target, 0o444 if key.startswith(QUARANTINE_PREFIX) else 0o644)
        sha, md5, size = hash_file(target)
        return StoredObject(key=key, size=size, sha256=sha, md5=md5)

    def put_file(self, key: str, source: Path) -> StoredObject:
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".part")
        shutil.copyfile(source, tmp)
        self._replace(tmp, target)
        return self._finish(key, target)

    @staticmethod
    def _replace(tmp: Path, target: Path) -> None:
        if target.exists():
            os.chmod(target, 0o644)  # read-only quarantine files block replacement on Windows
        os.replace(tmp, target)

    def put_bytes(self, key: str, data: bytes) -> StoredObject:
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".part")
        tmp.write_bytes(data)
        self._replace(tmp, target)
        return self._finish(key, target)

    def open(self, key: str):
        return self._resolve(key).open("rb")

    def read_bytes(self, key: str) -> bytes:
        return self._resolve(key).read_bytes()

    def delete(self, key: str) -> None:
        target = self._resolve(key)
        if target.exists():
            os.chmod(target, 0o644)
            target.unlink()

    def exists(self, key: str) -> bool:
        return self._resolve(key).is_file()

    def iter_keys(self, prefix: str = "") -> Iterator[str]:
        base = self.root
        for path in base.rglob("*"):
            if path.is_file() and not path.name.endswith(".part"):
                key = path.relative_to(base).as_posix()
                if key.startswith(prefix):
                    yield key


def make_store(settings: Settings) -> LocalStore:
    return LocalStore(settings.artifact_root, settings.quarantine_root)
