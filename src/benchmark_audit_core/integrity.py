"""Content-addressing and detached artifact-seal primitives."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

DEFAULT_HASH_CHUNK_SIZE = 8 * 1024 * 1024


class IntegrityError(ValueError):
    """Raised when evidence cannot be hashed or an artifact seal is invalid."""


class StrictIntegrityModel(BaseModel):
    """Reject unknown fields in integrity records."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, populate_by_name=True)


class SealedFile(StrictIntegrityModel):
    """Digest and byte count for one file in a detached artifact seal."""

    byte_size: int = Field(alias="bytes", ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ArtifactSeal(StrictIntegrityModel):
    """Detached digest manifest for every file in a flat artifact directory."""

    schema_version: Literal[1] = 1
    algorithm: Literal["sha256"] = "sha256"
    created_at: datetime
    files: dict[str, SealedFile]

    @model_validator(mode="after")
    def validate_seal(self) -> Self:
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        for name in self.files:
            _validate_member_name(name)
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json", by_alias=True))

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


class ArtifactSealVerification(StrictIntegrityModel):
    """Summary returned after every sealed file and the detached seal are verified."""

    artifact: str
    files_verified: int = Field(ge=0)
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize JSON-compatible data deterministically for hashing and storage."""

    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_bytes(content: bytes) -> str:
    """Return the lowercase SHA-256 digest of an in-memory byte string."""

    return hashlib.sha256(content).hexdigest()


def sha256_file(
    path: str | Path,
    *,
    chunk_size: int = DEFAULT_HASH_CHUNK_SIZE,
) -> str:
    """Hash a file incrementally without loading model-sized evidence into memory."""

    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def create_artifact_seal(
    directory: str | Path,
    *,
    seal_name: str = "seal.json",
    created_at: datetime | None = None,
) -> ArtifactSeal:
    """Digest every finalized file except the detached seal itself.

    Artifact directories are intentionally flat. Symlinks, subdirectories, sockets, and other
    entries are rejected because they would otherwise sit outside the detached file map.
    """

    _validate_member_name(seal_name)
    resolved = _resolve_directory(directory)
    files = {
        path.name: SealedFile(bytes=path.stat().st_size, sha256=sha256_file(path))
        for path in _artifact_files(resolved, seal_name=seal_name)
    }
    return ArtifactSeal(
        created_at=created_at or datetime.now(UTC),
        files=files,
    )


def verify_artifact_seal(
    directory: str | Path,
    *,
    seal_name: str = "seal.json",
) -> ArtifactSealVerification:
    """Reject added, removed, unsupported, resized, or mutated artifact entries."""

    _validate_member_name(seal_name)
    resolved = _resolve_directory(directory)
    seal_path = resolved / seal_name
    if seal_path.is_symlink():
        raise IntegrityError(f"artifact seal cannot be a symlink: {seal_path}")
    try:
        payload = seal_path.read_text(encoding="utf-8")
        seal = ArtifactSeal.model_validate_json(payload)
    except (OSError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise IntegrityError(f"could not read artifact seal {seal_path}: {exc}") from exc

    actual_files = _artifact_files(resolved, seal_name=seal_name)
    actual_names = {path.name for path in actual_files}
    sealed_names = set(seal.files)
    if actual_names != sealed_names:
        added = sorted(actual_names - sealed_names)
        missing = sorted(sealed_names - actual_names)
        raise IntegrityError(f"artifact file set changed: added={added}, missing={missing}")

    for path in actual_files:
        evidence = seal.files[path.name]
        observed_size = path.stat().st_size
        observed_digest = sha256_file(path)
        if evidence.byte_size != observed_size or evidence.sha256 != observed_digest:
            raise IntegrityError(f"artifact seal mismatch: {path.name}")
    return ArtifactSealVerification(
        artifact=str(resolved),
        files_verified=len(sealed_names),
        seal_sha256=sha256_file(seal_path),
    )


def _artifact_files(directory: Path, *, seal_name: str) -> list[Path]:
    files: list[Path] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.name == seal_name:
            continue
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"unsupported unsealed artifact entry: {path}")
        files.append(path)
    return files


def _resolve_directory(directory: str | Path) -> Path:
    candidate = Path(directory).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise IntegrityError(f"artifact directory is unavailable: {candidate}: {exc}") from exc
    if not resolved.is_dir():
        raise IntegrityError(f"artifact path is not a directory: {resolved}")
    return resolved


def _validate_member_name(name: str) -> None:
    if not name or name in {".", ".."} or Path(name).name != name or "/" in name or "\\" in name:
        raise ValueError(f"artifact member must be one safe file name: {name!r}")
