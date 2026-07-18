"""Helpers for describing evidence without copying or printing its contents."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from benchmark_audit_core.integrity import sha256_file
from benchmark_audit_core.models import EvidenceRef


def evidence_ref_from_file(
    path: str | Path,
    *,
    uri: str | None = None,
    media_type: str | None = None,
) -> EvidenceRef:
    """Build a content-addressed reference for one local regular file."""

    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"evidence path is unavailable: {candidate}: {exc}") from exc
    if not resolved.is_file():
        raise ValueError(f"evidence path is not a file: {resolved}")
    detected_type = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
    return EvidenceRef(
        uri=uri or resolved.as_uri(),
        sha256=sha256_file(resolved),
        media_type=media_type or detected_type,
        byte_size=resolved.stat().st_size,
    )
