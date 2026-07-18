"""Versioned contracts for auditable autonomous benchmark sessions."""

from __future__ import annotations

import math
from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from benchmark_audit_core.integrity import canonical_json_bytes, sha256_bytes

AUDIT_SCHEMA_VERSION = "1.0.0"


class StrictAuditModel(BaseModel):
    """Reject unknown fields so audit attestations cannot silently drift."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class BenchmarkStage(StrEnum):
    COMPILE = "compile"
    CHECK = "check"
    BENCHMARK = "benchmark"


class OptimizationScope(StrEnum):
    CPU_ONLY = "cpu_only"
    SINGLE_DEVICE = "single_device"
    MULTI_DEVICE = "multi_device"


class TerminationPolicy(StrEnum):
    AGENT_DECIDES = "agent_decides"
    FIXED_BUDGET = "fixed_budget"


class TerminationReason(StrEnum):
    AGENT_FINISHED = "agent_finished"
    WATCHDOG = "watchdog"
    MAX_TURNS = "max_turns"
    ERROR = "error"
    CANCELLED = "cancelled"


class RetestCategory(StrEnum):
    FRESH_PROCESS = "fresh_process"
    COLD_CACHE = "cold_cache"
    INPUT_PERTURBATION = "input_perturbation"
    EXECUTION_ORDER = "execution_order"
    HIDDEN_CHECKS = "hidden_checks"
    REPEATED_MEASUREMENT = "repeated_measurement"
    OUTPUT_VALIDATION = "output_validation"
    TIMING_SANITY = "timing_sanity"
    RESOURCE_ISOLATION = "resource_isolation"


class RetestOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"


class FindingCategory(StrEnum):
    CACHE_CONTAMINATION = "cache_contamination"
    GRADER_GAMING = "grader_gaming"
    HARDCODED_INPUT = "hardcoded_input"
    TEST_OVERFITTING = "test_overfitting"
    INVALID_TIMING = "invalid_timing"
    MEASUREMENT_SCOPE = "measurement_scope"
    CORRECTNESS = "correctness"
    PROVENANCE = "provenance"
    OTHER = "other"


class AuditorKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    HYBRID = "hybrid"


class AuditVerdict(StrEnum):
    PASS = "pass"
    PASS_WITH_FINDINGS = "pass_with_findings"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class GateStatus(StrEnum):
    PASSED = "passed"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"


class EvidenceRef(StrictAuditModel):
    """Content-addressed evidence that can be independently retrieved."""

    uri: str = Field(min_length=1, max_length=2048)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: str = Field(default="application/octet-stream", min_length=1, max_length=128)
    byte_size: int | None = Field(default=None, ge=0)


class HardwareProfile(StrictAuditModel):
    """Declared hardware scope plus observed, content-addressed evidence."""

    accelerator_vendor: str | None = Field(default=None, min_length=1, max_length=128)
    accelerator_models: list[str] = Field(default_factory=list)
    accelerator_count: int = Field(default=0, ge=0)
    optimization_scope: OptimizationScope
    host_architecture: str = Field(min_length=1, max_length=128)
    machine_class: str | None = Field(default=None, max_length=256)
    driver_version: str | None = Field(default=None, max_length=128)
    runtime_versions: dict[str, str] = Field(default_factory=dict)
    observed_evidence: EvidenceRef

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        object.__setattr__(
            self,
            "accelerator_models",
            list(dict.fromkeys(self.accelerator_models)),
        )
        if self.optimization_scope == OptimizationScope.CPU_ONLY:
            if self.accelerator_count != 0 or self.accelerator_models:
                raise ValueError("cpu_only scope cannot declare accelerators")
        elif self.optimization_scope == OptimizationScope.SINGLE_DEVICE:
            if self.accelerator_count != 1 or len(self.accelerator_models) != 1:
                raise ValueError("single_device scope requires exactly one accelerator")
        elif self.accelerator_count < 2 or not self.accelerator_models:
            raise ValueError("multi_device scope requires at least two accelerators")
        if self.accelerator_count and not self.accelerator_vendor:
            raise ValueError("accelerator hardware requires accelerator_vendor")
        return self


class SessionPolicy(StrictAuditModel):
    """Execution policy for one autonomous benchmark session."""

    one_task_per_session: Literal[True] = True
    termination_policy: TerminationPolicy = TerminationPolicy.AGENT_DECIDES
    watchdog_seconds: int = Field(default=86_400, ge=1)
    max_turns: int | None = Field(default=None, ge=1)
    live_hardware: Literal[True] = True
    required_stages: list[BenchmarkStage] = Field(
        default_factory=lambda: [
            BenchmarkStage.COMPILE,
            BenchmarkStage.CHECK,
            BenchmarkStage.BENCHMARK,
        ]
    )
    minimum_benchmark_repetitions: int = Field(default=3, ge=1)

    @model_validator(mode="after")
    def validate_stage_policy(self) -> Self:
        object.__setattr__(
            self,
            "required_stages",
            list(dict.fromkeys(self.required_stages)),
        )
        if self.termination_policy == TerminationPolicy.FIXED_BUDGET and self.max_turns is None:
            raise ValueError("fixed_budget termination requires max_turns")
        return self


class AuditPolicy(StrictAuditModel):
    """Requirements that a result must satisfy before headline publication."""

    require_clean_source: Literal[True] = True
    require_agent_decided_stop: Literal[True] = True
    require_independent_reviewer: Literal[True] = True
    require_manual_review: Literal[True] = True
    require_final_artifact_review: Literal[True] = True
    require_full_trace_review: Literal[True] = True
    require_task_definition_review: Literal[True] = True
    require_benchmark_protocol_review: Literal[True] = True
    required_retests: list[RetestCategory] = Field(
        default_factory=lambda: [
            RetestCategory.FRESH_PROCESS,
            RetestCategory.COLD_CACHE,
            RetestCategory.INPUT_PERTURBATION,
            RetestCategory.OUTPUT_VALIDATION,
        ]
    )
    blocking_severities: list[FindingSeverity] = Field(
        default_factory=lambda: [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
    )

    @model_validator(mode="after")
    def validate_unique_requirements(self) -> Self:
        object.__setattr__(
            self,
            "required_retests",
            list(dict.fromkeys(self.required_retests)),
        )
        object.__setattr__(
            self,
            "blocking_severities",
            list(dict.fromkeys(self.blocking_severities)),
        )
        baseline_retests = {
            RetestCategory.FRESH_PROCESS,
            RetestCategory.COLD_CACHE,
            RetestCategory.INPUT_PERTURBATION,
            RetestCategory.OUTPUT_VALIDATION,
        }
        if not baseline_retests.issubset(self.required_retests):
            raise ValueError("audit policy cannot remove baseline anti-gaming re-tests")
        baseline_blockers = {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
        if not baseline_blockers.issubset(self.blocking_severities):
            raise ValueError("critical and high findings must remain blocking")
        return self


class BenchmarkClaim(StrictAuditModel):
    """One reported metric with the evidence needed to reproduce it."""

    claim_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$")
    metric_name: str = Field(min_length=1, max_length=256)
    value: float
    unit: str = Field(min_length=1, max_length=64)
    aggregation: str = Field(default="median", min_length=1, max_length=128)
    headline: bool = False
    baseline_value: float | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_finite_values(self) -> Self:
        values = [self.value]
        if self.baseline_value is not None:
            values.append(self.baseline_value)
        if not all(math.isfinite(value) for value in values):
            raise ValueError("claim values must be finite")
        return self


class EmpiricalRetest(StrictAuditModel):
    retest_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$")
    category: RetestCategory
    outcome: RetestOutcome
    isolated_from_original_session: bool
    evidence: list[EvidenceRef] = Field(min_length=1)
    notes: str = Field(default="", max_length=4000)


class AuditFinding(StrictAuditModel):
    finding_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$")
    category: FindingCategory
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.OPEN
    observation: str = Field(min_length=1, max_length=8000)
    recommendation: str = Field(default="", max_length=8000)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class IndependentAudit(StrictAuditModel):
    """Attestation made outside the session that generated the result."""

    audit_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$")
    auditor_id: str = Field(min_length=1, max_length=256)
    auditor_kind: AuditorKind
    independent: bool
    manual_review_completed: bool
    reviewed_final_artifact: bool
    reviewed_full_trace: bool
    reviewed_task_definition: bool
    reviewed_benchmark_protocol: bool
    retests: list[EmpiricalRetest] = Field(default_factory=list)
    findings: list[AuditFinding] = Field(default_factory=list)
    verdict: AuditVerdict
    completed_at: datetime

    @model_validator(mode="after")
    def validate_audit(self) -> Self:
        if self.completed_at.tzinfo is None:
            raise ValueError("completed_at must be timezone-aware")
        if self.manual_review_completed and self.auditor_kind == AuditorKind.AGENT:
            raise ValueError("manual review requires a human or hybrid auditor_kind")
        retest_ids = [item.retest_id for item in self.retests]
        finding_ids = [item.finding_id for item in self.findings]
        if len(retest_ids) != len(set(retest_ids)):
            raise ValueError("retest_id values must be unique")
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_id values must be unique")
        return self


class AuditableSession(StrictAuditModel):
    """Portable manifest connecting execution, evidence, claims, and audit."""

    schema_version: Literal["1.0.0"] = AUDIT_SCHEMA_VERSION
    session_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$")
    experiment_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    episode_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    task_id: str = Field(min_length=1, max_length=128)
    task_version: str = Field(min_length=1, max_length=128)
    generator_id: str = Field(min_length=1, max_length=256)
    source_commit: str = Field(min_length=7, max_length=128)
    source_dirty: bool
    benchmark_protocol_version: str = Field(min_length=1, max_length=128)
    task_definition: EvidenceRef
    benchmark_protocol: EvidenceRef
    started_at: datetime
    ended_at: datetime
    termination_reason: TerminationReason
    hardware: HardwareProfile
    session_policy: SessionPolicy = Field(default_factory=SessionPolicy)
    audit_policy: AuditPolicy = Field(default_factory=AuditPolicy)
    stage_counts: dict[BenchmarkStage, int] = Field(default_factory=dict)
    benchmark_repetitions: int = Field(default=1, ge=1)
    full_trace: EvidenceRef
    final_artifact: EvidenceRef
    claims: list[BenchmarkClaim] = Field(min_length=1)
    audit: IndependentAudit | None = None
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_session(self) -> Self:
        if self.started_at.tzinfo is None or self.ended_at.tzinfo is None:
            raise ValueError("session timestamps must be timezone-aware")
        if self.ended_at < self.started_at:
            raise ValueError("ended_at cannot precede started_at")
        if any(count < 0 for count in self.stage_counts.values()):
            raise ValueError("stage counts cannot be negative")
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("claim_id values must be unique")
        if self.audit is not None and self.audit.independent:
            if self.audit.auditor_id == self.generator_id:
                raise ValueError("independent auditor must differ from generator")
            if self.audit.completed_at < self.ended_at:
                raise ValueError("audit cannot complete before the session ends")
        return self

    def canonical_bytes(self) -> bytes:
        """Return deterministic JSON suitable for hashing and immutable storage."""

        return canonical_json_bytes(self.model_dump(mode="json"))

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


class GateCheck(StrictAuditModel):
    check_id: str
    passed: bool
    reason: str


class HeadlineGateResult(StrictAuditModel):
    schema_version: Literal["1.0.0"] = AUDIT_SCHEMA_VERSION
    session_id: str
    session_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    headline_claim_ids: list[str]
    status: GateStatus
    eligible_for_headline: bool
    checks: list[GateCheck]
    evaluated_at: datetime

    @model_validator(mode="after")
    def validate_evaluated_at(self) -> Self:
        if self.evaluated_at.tzinfo is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return self


class AuditBundle(StrictAuditModel):
    """Immutable session and the deterministic gate decision derived from it."""

    schema_version: Literal["1.0.0"] = AUDIT_SCHEMA_VERSION
    session: AuditableSession
    headline_gate: HeadlineGateResult

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.headline_gate.session_id != self.session.session_id:
            raise ValueError("headline gate session_id does not match session")
        if self.headline_gate.session_digest != self.session.digest():
            raise ValueError("headline gate digest does not match session")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())
