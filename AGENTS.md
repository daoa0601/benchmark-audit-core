# Benchmark Audit Core project context

This package owns portable benchmark-audit contracts, deterministic publication gating, evidence
references, file hashing, and detached directory seals. It must remain independent of AgentTrace,
Probe, benchmark harnesses, object stores, telemetry collectors, and domain-specific promotion
policies.

The JSON schema version and canonical serialization are compatibility boundaries. Breaking changes
require a schema-version change and migration notes. Storage and CLI integrations belong in consumer
projects. Run `make check` before publishing.
