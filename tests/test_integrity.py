from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from benchmark_audit_core import (
    IntegrityError,
    create_artifact_seal,
    evidence_ref_from_file,
    sha256_bytes,
    sha256_file,
    verify_artifact_seal,
)


def _write_seal(directory: Path) -> Path:
    seal = create_artifact_seal(
        directory,
        created_at=datetime(2026, 7, 18, tzinfo=UTC),
    )
    path = directory / "seal.json"
    path.write_text(
        json.dumps(seal.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def test_evidence_reference_hashes_without_copying_content(tmp_path: Path) -> None:
    artifact = tmp_path / "samples.json"
    content = b'{"latency_us":[12.0,13.0]}\n'
    artifact.write_bytes(content)

    evidence = evidence_ref_from_file(artifact, uri="object://audit/samples.json")

    assert evidence.uri == "object://audit/samples.json"
    assert evidence.sha256 == sha256_bytes(content) == sha256_file(artifact, chunk_size=3)
    assert evidence.byte_size == len(content)
    assert evidence.media_type == "application/json"

    with pytest.raises(ValueError, match="not a file"):
        evidence_ref_from_file(tmp_path)
    with pytest.raises(ValueError, match="unavailable"):
        evidence_ref_from_file(tmp_path / "missing.json")


def test_detached_seal_round_trip_and_mutation_detection(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text('{"status":"passed"}\n', encoding="utf-8")
    (tmp_path / "trace.jsonl").write_text('{"event":"finished"}\n', encoding="utf-8")
    seal_path = _write_seal(tmp_path)
    seal = create_artifact_seal(
        tmp_path,
        created_at=datetime(2026, 7, 18, tzinfo=UTC),
    )

    verification = verify_artifact_seal(tmp_path)

    assert verification.files_verified == 2
    assert verification.seal_sha256 == sha256_file(seal_path)
    assert seal.digest() == sha256_bytes(seal.canonical_bytes())
    (tmp_path / "trace.jsonl").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="seal mismatch: trace.jsonl"):
        verify_artifact_seal(tmp_path)


def test_verifier_accepts_probe_legacy_v1_seal_shape(tmp_path: Path) -> None:
    artifact = tmp_path / "manifest.json"
    artifact.write_text('{"status":"passed"}\n', encoding="utf-8")
    legacy = {
        "schema_version": 1,
        "algorithm": "sha256",
        "created_at": "2026-07-17T08:00:00+00:00",
        "files": {
            artifact.name: {
                "bytes": artifact.stat().st_size,
                "sha256": sha256_file(artifact),
            }
        },
    }
    (tmp_path / "seal.json").write_text(
        json.dumps(legacy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    verification = verify_artifact_seal(tmp_path)

    assert verification.files_verified == 1


def test_detached_seal_rejects_added_and_unsupported_entries(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text("{}\n", encoding="utf-8")
    _write_seal(tmp_path)
    (tmp_path / "extra.txt").write_text("extra\n", encoding="utf-8")

    with pytest.raises(IntegrityError, match="file set changed"):
        verify_artifact_seal(tmp_path)

    (tmp_path / "extra.txt").unlink()
    (tmp_path / "nested").mkdir()
    with pytest.raises(IntegrityError, match="unsupported unsealed artifact entry"):
        verify_artifact_seal(tmp_path)


def test_invalid_paths_and_seals_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(IntegrityError, match="not a directory"):
        create_artifact_seal(__file__)
    with pytest.raises(ValueError, match="chunk_size"):
        sha256_file(__file__, chunk_size=0)
    with pytest.raises(ValueError, match="safe file name"):
        create_artifact_seal(tmp_path, seal_name="../seal.json")

    (tmp_path / "seal.json").write_text("not-json\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="could not read artifact seal"):
        verify_artifact_seal(tmp_path)
