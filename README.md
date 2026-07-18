# Benchmark Audit Core

`benchmark-audit-core` is the portable evidence and decision layer shared by benchmark runners and
trace platforms in this workspace. It provides strict, versioned Pydantic contracts for autonomous
benchmark sessions; a deterministic headline-publication gate and report renderer; content-addressed
file references; streaming SHA-256 helpers; and detached seals for flat artifact directories.

It deliberately does not provide object storage, telemetry collection, benchmark execution, or a
domain-specific promotion workflow. AgentTrace owns immutable bundle persistence. Probe owns its
Apple-Silicon inference correctness, environment, replication, and reviewer rules.

> Status: `0.1.0` is a local release candidate and has not been published to a Python package index.

## Install and verify

```bash
uv sync --all-extras
make check
```

`make check` also rebuilds the wheel and source archive. Both distributions include the MIT license
and the PEP 561 `py.typed` marker so their contents cannot silently lag behind the checked source.

Sibling repositories use a normal `benchmark-audit-core>=0.1,<0.2` dependency and a local
`[tool.uv.sources]` override while the package is developed in this multi-repository checkout. That
override is not a standalone release mechanism: publish the core first, remove the override from
each consumer, regenerate its `uv.lock` from the selected registry, and verify a frozen install in a
checkout that does not contain `../benchmark-audit-core`.

## Audit a session

```python
from benchmark_audit_core import AuditableSession, build_audit_bundle, render_audit_report

session = AuditableSession.model_validate_json(manifest_json)
bundle = build_audit_bundle(session)
report = render_audit_report(bundle)
```

`bundle.canonical_bytes()` and `bundle.digest()` are stable inputs to a consumer-owned immutable
store. A headline passes only when every declared execution and independent-audit check passes.
Under audit schema `1.0.0`, that includes `manual_review_completed=true` from a human or hybrid
auditor; an agent-only auditor cannot claim manual review.

## Describe and seal evidence

```python
from pathlib import Path

from benchmark_audit_core import (
    create_artifact_seal,
    evidence_ref_from_file,
    verify_artifact_seal,
)

evidence = evidence_ref_from_file("outputs/samples.json")
artifact = Path("outputs/run")
seal = create_artifact_seal(artifact)
(artifact / "seal.json").write_bytes(seal.canonical_bytes())

# Verify immediately before trusting or consuming the artifact.
verification = verify_artifact_seal(artifact)
print(verification.files_verified, verification.seal_sha256)
```

`create_artifact_seal` covers every regular file immediately inside the directory except the
detached `seal.json`. Symlinks, nested directories, and other unsupported entries are rejected so an
artifact cannot contain unsealed additions. The caller writes the returned JSON; storage remains a
consumer concern.

## Trust boundaries

- The deterministic gate evaluates the supplied manifest and attestations. It does not prove that a
  claim, reviewer identity, manual-review flag, resolved route, or re-test statement is truthful.
- An `EvidenceRef` validates URI/digest/media-type/size metadata; it does not retrieve bytes, verify
  availability, establish authorship, or prove that the referenced evidence supports the claim.
- A detached seal detects changed flat-directory members when `verify_artifact_seal()` observes
  them. It is not a signature, timestamp, access-control system, or immutable store. Someone able to
  replace both files and seal can create a new self-consistent artifact.
- Verification does not reserve the files after it returns. Consumers own trusted custody,
  concurrency/access controls, and any verify-then-use race protection; verify as close as possible
  to the actual read.

## Compatibility policy

- Audit schema `1.0.0` preserves its canonical JSON, check identifiers, and report shape throughout
  the `0.1.x` package series. The distribution remains pre-stable; any intentional schema
  or gate-semantic change must introduce a new audit schema version and migration notes.
- Consumers may add stricter policy gates after the core gate; they must not reinterpret a blocked
  core result as eligible.
- `AuditPolicy` intentionally requires manual review by a human or hybrid auditor. Agent-only
  protocols such as Probe's current independent review use the shared integrity primitives but
  retain a separate domain-specific promotion decision with additional Probe checks until a
  versioned policy profile is designed; they do not treat `evaluate_headline_gate()` as their
  promotion verdict.
