"""Deterministic publication gate and human-readable audit report."""

from __future__ import annotations

from benchmark_audit_core.models import (
    AuditableSession,
    AuditBundle,
    AuditVerdict,
    FindingStatus,
    GateCheck,
    GateStatus,
    HeadlineGateResult,
    RetestOutcome,
    TerminationPolicy,
    TerminationReason,
)


def evaluate_headline_gate(session: AuditableSession) -> HeadlineGateResult:
    """Evaluate whether all headline claims meet the session's declared audit policy."""

    headline_ids = [claim.claim_id for claim in session.claims if claim.headline]
    evaluated_at = session.audit.completed_at if session.audit is not None else session.ended_at
    if not headline_ids:
        return HeadlineGateResult(
            session_id=session.session_id,
            session_digest=session.digest(),
            headline_claim_ids=[],
            status=GateStatus.NOT_APPLICABLE,
            eligible_for_headline=False,
            checks=[],
            evaluated_at=evaluated_at,
        )

    checks: list[GateCheck] = []

    def add(check_id: str, passed: bool, reason: str) -> None:
        checks.append(GateCheck(check_id=check_id, passed=passed, reason=reason))

    policy = session.audit_policy
    execution = session.session_policy
    add(
        "source.clean",
        not policy.require_clean_source or not session.source_dirty,
        "source tree is clean" if not session.source_dirty else "source tree was dirty",
    )
    add(
        "session.one_task",
        execution.one_task_per_session,
        "one task was isolated in this session"
        if execution.one_task_per_session
        else "session policy allows multiple tasks",
    )
    add(
        "hardware.live",
        execution.live_hardware,
        "benchmark used live hardware" if execution.live_hardware else "live hardware not attested",
    )
    agent_stop = (
        execution.termination_policy == TerminationPolicy.AGENT_DECIDES
        and session.termination_reason == TerminationReason.AGENT_FINISHED
    )
    add(
        "termination.agent_decided",
        not policy.require_agent_decided_stop or agent_stop,
        "agent chose to finish; watchdog remained a safety cap"
        if agent_stop
        else "session ended before an agent-declared finish",
    )
    for stage in execution.required_stages:
        count = session.stage_counts.get(stage, 0)
        add(
            f"stage.{stage.value}",
            count > 0,
            f"trace contains {count} {stage.value} stage(s)",
        )
    add(
        "benchmark.repetitions",
        session.benchmark_repetitions >= execution.minimum_benchmark_repetitions,
        (
            f"recorded {session.benchmark_repetitions} repetition(s); "
            f"minimum is {execution.minimum_benchmark_repetitions}"
        ),
    )
    headline_evidence = all(claim.evidence for claim in session.claims if claim.headline)
    add(
        "claims.evidence",
        headline_evidence,
        "every headline claim has content-addressed evidence"
        if headline_evidence
        else "one or more headline claims lack evidence",
    )

    audit = session.audit
    add(
        "audit.present",
        audit is not None,
        "independent audit is attached" if audit else "audit missing",
    )
    if audit is not None:
        independent = audit.independent and audit.auditor_id != session.generator_id
        add(
            "audit.independent",
            not policy.require_independent_reviewer or independent,
            "auditor is independent from the generating agent"
            if independent
            else "auditor independence not established",
        )
        add(
            "audit.manual_review",
            not policy.require_manual_review or audit.manual_review_completed,
            "manual review completed"
            if audit.manual_review_completed
            else "manual review not completed",
        )
        add(
            "audit.final_artifact_review",
            not policy.require_final_artifact_review or audit.reviewed_final_artifact,
            "final artifact was reviewed end to end"
            if audit.reviewed_final_artifact
            else "final artifact was not reviewed end to end",
        )
        add(
            "audit.full_trace_review",
            not policy.require_full_trace_review or audit.reviewed_full_trace,
            "full session trace was reviewed"
            if audit.reviewed_full_trace
            else "full session trace was not reviewed",
        )
        add(
            "audit.task_definition_review",
            not policy.require_task_definition_review or audit.reviewed_task_definition,
            "versioned task definition was reviewed"
            if audit.reviewed_task_definition
            else "versioned task definition was not reviewed",
        )
        add(
            "audit.benchmark_protocol_review",
            not policy.require_benchmark_protocol_review or audit.reviewed_benchmark_protocol,
            "benchmark protocol was reviewed"
            if audit.reviewed_benchmark_protocol
            else "benchmark protocol was not reviewed",
        )
        for category in policy.required_retests:
            matching = [retest for retest in audit.retests if retest.category == category]
            passed = any(
                retest.outcome == RetestOutcome.PASSED and retest.isolated_from_original_session
                for retest in matching
            )
            add(
                f"retest.{category.value}",
                passed,
                (
                    "isolated empirical re-test passed"
                    if passed
                    else "missing, failed, inconclusive, or non-isolated empirical re-test"
                ),
            )
        all_retests_passed = all(
            retest.outcome == RetestOutcome.PASSED and retest.isolated_from_original_session
            for retest in audit.retests
        )
        add(
            "audit.retest_outcomes",
            all_retests_passed,
            "all recorded empirical re-tests passed in isolation"
            if all_retests_passed
            else (
                "one or more empirical re-tests failed, were inconclusive, or reused session state"
            ),
        )
        blockers = [
            finding.finding_id
            for finding in audit.findings
            if finding.severity in policy.blocking_severities
            and finding.status != FindingStatus.RESOLVED
        ]
        add(
            "audit.blocking_findings",
            not blockers,
            "no unresolved blocking findings"
            if not blockers
            else f"unresolved blocking findings: {', '.join(blockers)}",
        )
        accepted_verdict = audit.verdict in {
            AuditVerdict.PASS,
            AuditVerdict.PASS_WITH_FINDINGS,
        }
        add(
            "audit.verdict",
            accepted_verdict,
            f"audit verdict is {audit.verdict.value}",
        )

    eligible = all(check.passed for check in checks)
    return HeadlineGateResult(
        session_id=session.session_id,
        session_digest=session.digest(),
        headline_claim_ids=headline_ids,
        status=GateStatus.PASSED if eligible else GateStatus.BLOCKED,
        eligible_for_headline=eligible,
        checks=checks,
        evaluated_at=evaluated_at,
    )


def build_audit_bundle(session: AuditableSession) -> AuditBundle:
    """Bind a session to the deterministic publication-gate result derived from it."""

    return AuditBundle(session=session, headline_gate=evaluate_headline_gate(session))


def render_audit_report(bundle: AuditBundle) -> str:
    """Render a stable report with audit findings kept in a dedicated section."""

    session = bundle.session
    gate = bundle.headline_gate
    lines = [
        f"# Benchmark audit: {session.session_id}",
        "",
        "## Session",
        "",
        f"- Task: `{session.task_id}@{session.task_version}`",
        f"- Run: `{session.run_id}`",
        f"- Trace: `{session.trace_id}`",
        (
            f"- Source commit: `{session.source_commit}` "
            f"(dirty: `{str(session.source_dirty).lower()}`)"
        ),
        f"- Hardware scope: `{session.hardware.optimization_scope.value}`",
        f"- Termination: `{session.termination_reason.value}`",
        "",
        "## Headline gate",
        "",
        f"Status: **{gate.status.value}**",
        "",
    ]
    for check in gate.checks:
        marker = "PASS" if check.passed else "BLOCK"
        lines.append(f"- [{marker}] `{check.check_id}` — {check.reason}")
    lines.extend(["", "## Claims", ""])
    for claim in session.claims:
        label = "headline" if claim.headline else "supporting"
        lines.append(
            f"- `{claim.claim_id}` ({label}): {claim.metric_name} = "
            f"{claim.value:g} {claim.unit} ({claim.aggregation})"
        )

    lines.extend(["", "## Empirical re-tests", ""])
    if session.audit is None or not session.audit.retests:
        lines.append("No empirical re-tests were attached.")
    else:
        for retest in session.audit.retests:
            isolated = "isolated" if retest.isolated_from_original_session else "not isolated"
            lines.append(
                f"- `{retest.retest_id}`: {retest.category.value} — "
                f"**{retest.outcome.value}** ({isolated})"
            )

    lines.extend(["", "## Audit findings", ""])
    if session.audit is None or not session.audit.findings:
        lines.append("No findings were recorded.")
    else:
        for finding in session.audit.findings:
            lines.append(
                f"### {finding.finding_id}: {finding.category.value} "
                f"[{finding.severity.value}/{finding.status.value}]"
            )
            lines.extend(["", finding.observation, ""])
            if finding.recommendation:
                lines.extend([f"Recommendation: {finding.recommendation}", ""])
    return "\n".join(lines).rstrip() + "\n"
