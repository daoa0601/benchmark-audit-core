# Benchmark Audit Core project context

This package owns portable benchmark-audit contracts, deterministic publication gating, evidence
references, file hashing, and detached directory seals. It must not depend on trace platforms,
benchmark harnesses, object stores, telemetry collectors, or domain-specific promotion policies.

The JSON schema version and canonical serialization are compatibility boundaries. Breaking changes
require a schema-version change and migration notes. Storage and CLI integrations belong in the
projects that use this package. Run `make check` before committing.
