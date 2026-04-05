from __future__ import annotations

from dataclasses import dataclass

from ._interfaces import EngineContext, StageResult
from ._store import ArtifactRecord, SessionState
from ._types import (
    ActionEnvelope,
    ChainRiskSummary,
    DecisionEnvelope,
    ProvenanceSummary,
    ReasonCode,
    RiskLevel,
    TaintSummary,
)


@dataclass
class TaintContext:
    session_tainted: bool
    taint_sources: list[str]
    tainted_artifacts: list[str]
    agent_authored_paths: list[str]
    lineage_depth: int
    origin_sources: list[str]


@dataclass
class TaintAnalysisResult:
    decision: str
    reason_code: str | None
    summary: str
    taint_summary: TaintSummary
    provenance_summary: ProvenanceSummary


@dataclass
class ChainRiskContext:
    risk_level: RiskLevel
    review_count: int
    block_count: int
    sensitive_read_count: int


CLASSIFICATION_PRECEDENCE: dict[str, int] = {
    "CLEAN": 0,
    "AGENT_GENERATED": 1,
    "SENSITIVE": 2,
    "TAINTED": 3,
    "FORBIDDEN": 4,
}


def _build_base_session(session_id: str, timestamp: str, existing: SessionState | None) -> SessionState:
    return SessionState(
        session_id=session_id,
        created_at=existing.created_at if existing is not None else timestamp,
        updated_at=timestamp,
        message_count=existing.message_count if existing is not None else 0,
        taint_sources=list(existing.taint_sources) if existing is not None else [],
        whitelisted_scripts=dict(existing.whitelisted_scripts) if existing is not None else {},
        suspect_until=existing.suspect_until if existing is not None else None,
        risk_level=existing.risk_level if existing is not None else None,
        review_count=existing.review_count if existing is not None else None,
        block_count=existing.block_count if existing is not None else None,
        sensitive_read_count=existing.sensitive_read_count if existing is not None else None,
    )


def _read_touched_path(envelope: ActionEnvelope) -> str | None:
    path = envelope.arguments.path
    if isinstance(path, str) and path.strip():
        return path
    return None


async def _put_artifact_if_escalation(
    ctx: EngineContext,
    path: str,
    next_record: ArtifactRecord,
) -> None:
    existing = await ctx.artifact_store.get_artifact(path)
    if (
        existing is not None
        and CLASSIFICATION_PRECEDENCE[existing.classification]
        > CLASSIFICATION_PRECEDENCE[next_record.classification]
    ):
        return
    await ctx.artifact_store.put_artifact(
        path,
        ArtifactRecord(
            path=path,
            classification=next_record.classification,
            source=next_record.source,
            reason=next_record.reason,
            first_seen=existing.first_seen if existing is not None else next_record.first_seen,
            last_seen=next_record.last_seen,
            provenance_chain=(
                list(next_record.provenance_chain)
                if next_record.provenance_chain is not None
                else list(existing.provenance_chain)
                if existing is not None and existing.provenance_chain is not None
                else None
            ),
        ),
    )


def build_taint_context(ctx: EngineContext, _envelope: ActionEnvelope) -> TaintContext:
    tainted_artifacts: list[str] = []
    agent_authored_paths: list[str] = []
    lineage_depth = 0
    origin_source_set: set[str] = set()

    for path, record in (ctx.related_artifacts or {}).items():
        if record is None:
            continue
        if record.classification == "TAINTED":
            tainted_artifacts.append(path)
            chain = record.provenance_chain or []
            lineage_depth = max(lineage_depth, len(chain))
            for entry in chain:
                entry_record = (ctx.related_artifacts or {}).get(entry)
                if entry_record is None or entry_record.classification in {"CLEAN", "SENSITIVE"}:
                    origin_source_set.add(entry)
        if record.classification == "AGENT_GENERATED":
            agent_authored_paths.append(path)

    session_taint_sources = list(ctx.session.taint_sources) if ctx.session is not None else []
    return TaintContext(
        session_tainted=len(session_taint_sources) > 0,
        taint_sources=session_taint_sources,
        tainted_artifacts=tainted_artifacts,
        agent_authored_paths=agent_authored_paths,
        lineage_depth=lineage_depth,
        origin_sources=list(origin_source_set),
    )


def analyze_taint(envelope: ActionEnvelope, taint_ctx: TaintContext) -> TaintAnalysisResult:
    path = envelope.arguments.path
    provenance_summary = ProvenanceSummary(
        agent_authored=(
            [value for value in [path or envelope.tool_name] if value.strip()]
            if envelope.arguments.agent_authored is True
            else list(taint_ctx.agent_authored_paths)
        ),
        propagated_from=list(taint_ctx.tainted_artifacts),
        lineage_depth=taint_ctx.lineage_depth if taint_ctx.lineage_depth > 0 else None,
        origin_sources=list(taint_ctx.origin_sources) if taint_ctx.origin_sources else None,
    )
    taint_summary = TaintSummary(
        session_tainted=taint_ctx.session_tainted,
        taint_sources=list(taint_ctx.taint_sources),
        artifacts_tainted=list(taint_ctx.tainted_artifacts),
    )

    if taint_ctx.tainted_artifacts:
        return TaintAnalysisResult(
            decision="REVIEW",
            reason_code=ReasonCode.TAINTED_ARTIFACT_ACCESS,
            summary="Action touches an artifact previously tagged as tainted.",
            taint_summary=taint_summary,
            provenance_summary=provenance_summary,
        )
    if taint_ctx.session_tainted and envelope.action_type in {"command_exec", "tool_call"}:
        return TaintAnalysisResult(
            decision="REVIEW",
            reason_code=ReasonCode.TAINTED_SESSION_COMMAND,
            summary="Tainted session is attempting to execute a command or tool.",
            taint_summary=taint_summary,
            provenance_summary=provenance_summary,
        )
    if taint_ctx.agent_authored_paths and envelope.action_type in {"command_exec", "file_read"}:
        return TaintAnalysisResult(
            decision="REVIEW",
            reason_code=ReasonCode.AGENT_AUTHORED_EXECUTION,
            summary="Action is reading or executing agent-authored content.",
            taint_summary=taint_summary,
            provenance_summary=provenance_summary,
        )
    return TaintAnalysisResult(
        decision="ALLOW",
        reason_code=None,
        summary="No taint or provenance signals detected.",
        taint_summary=taint_summary,
        provenance_summary=provenance_summary,
    )


def build_taint_stage_result(analysis: TaintAnalysisResult) -> StageResult:
    enrichments = {
        "taint_summary": analysis.taint_summary,
        "provenance_summary": analysis.provenance_summary,
    }
    if analysis.decision == "ALLOW":
        return StageResult(
            stage="taint",
            passed=True,
            decision="ALLOW",
            reason_codes=[],
            enrichments=enrichments,
        )
    enrichments["summary"] = analysis.summary
    return StageResult(
        stage="taint",
        passed=False,
        decision=analysis.decision,  # type: ignore[arg-type]
        reason_codes=[analysis.reason_code] if analysis.reason_code is not None else [],
        enrichments=enrichments,
    )


async def update_taint_state(envelope: ActionEnvelope, decision: DecisionEnvelope, ctx: EngineContext) -> None:
    timestamp = envelope.timestamp
    path = _read_touched_path(envelope)
    taint_ctx = build_taint_context(ctx, envelope)

    if envelope.action_type == "file_write" and envelope.arguments.agent_authored is True and path:
        await _put_artifact_if_escalation(
            ctx,
            path,
            ArtifactRecord(
                path=path,
                classification="AGENT_GENERATED",
                source="agent_write",
                reason="agent_authored flag set",
                first_seen=timestamp,
                last_seen=timestamp,
                provenance_chain=[],
            ),
        )

    if envelope.action_type == "file_write" and path:
        source_chains: list[str] = []
        max_ref_classification = "CLEAN"
        for ref_path in envelope.referenced_paths or []:
            if ref_path == path:
                continue
            ref_artifact = (ctx.related_artifacts or {}).get(ref_path)
            if ref_artifact and ref_artifact.classification in {"TAINTED", "AGENT_GENERATED"}:
                source_chains.extend([*(ref_artifact.provenance_chain or []), ref_path])
                if CLASSIFICATION_PRECEDENCE[ref_artifact.classification] > CLASSIFICATION_PRECEDENCE[max_ref_classification]:
                    max_ref_classification = ref_artifact.classification
        if source_chains:
            await _put_artifact_if_escalation(
                ctx,
                path,
                ArtifactRecord(
                    path=path,
                    classification=max_ref_classification,
                    source="artifact_write_propagation",
                    reason="file written from action that referenced tainted or agent-generated artifacts",
                    first_seen=timestamp,
                    last_seen=timestamp,
                    provenance_chain=list(dict.fromkeys(source_chains)),
                ),
            )

    if ctx.session is not None and ctx.session.taint_sources and envelope.action_type == "file_write" and path:
        await _put_artifact_if_escalation(
            ctx,
            path,
            ArtifactRecord(
                path=path,
                classification="TAINTED",
                source="tainted_session_write",
                reason="file written from tainted session context",
                first_seen=timestamp,
                last_seen=timestamp,
                provenance_chain=list(ctx.session.taint_sources),
            ),
        )

    if envelope.action_type == "file_read" and path and path in taint_ctx.tainted_artifacts:
        existing = ctx.session if ctx.session is not None else await ctx.session_store.get_session(ctx.session_id)
        current = _build_base_session(ctx.session_id, timestamp, existing)
        current.taint_sources = list(dict.fromkeys([*current.taint_sources, path]))
        await ctx.session_store.put_session(ctx.session_id, current)

    if ReasonCode.SENSITIVE_FILE_ACCESS in decision.reason_codes and path:
        await _put_artifact_if_escalation(
            ctx,
            path,
            ArtifactRecord(
                path=path,
                classification="SENSITIVE",
                source="policy_sensitive_file",
                reason="matched sensitive_files policy",
                first_seen=timestamp,
                last_seen=timestamp,
                provenance_chain=[],
            ),
        )


def build_chain_risk_context(ctx: EngineContext, _envelope: ActionEnvelope) -> ChainRiskContext:
    session = ctx.session
    return ChainRiskContext(
        risk_level=session.risk_level if session and session.risk_level else "NORMAL",
        review_count=session.review_count if session and session.review_count is not None else 0,
        block_count=session.block_count if session and session.block_count is not None else 0,
        sensitive_read_count=(
            session.sensitive_read_count if session and session.sensitive_read_count is not None else 0
        ),
    )


def analyze_chain_risk(envelope: ActionEnvelope, chain_ctx: ChainRiskContext) -> StageResult:
    chain_summary = ChainRiskSummary(
        risk_level=chain_ctx.risk_level,
        review_count=chain_ctx.review_count,
        block_count=chain_ctx.block_count,
        sensitive_read_count=chain_ctx.sensitive_read_count,
    )
    high_risk_action = envelope.action_type in {"command_exec", "tool_call", "outbound_request"}
    if chain_ctx.risk_level == "HIGH" and high_risk_action:
        return StageResult(
            stage="chain_risk",
            passed=False,
            decision="REVIEW",
            reason_codes=[ReasonCode.CHAIN_RISK_HIGH],
            enrichments={
                "summary": "Session has accumulated high risk; action requires review.",
                "chain_risk_summary": chain_summary,
            },
        )
    if chain_ctx.sensitive_read_count > 0 and envelope.action_type == "outbound_request":
        return StageResult(
            stage="chain_risk",
            passed=False,
            decision="REVIEW",
            reason_codes=[ReasonCode.EXFIL_CHAIN_PRECURSOR],
            enrichments={
                "summary": "Outbound request follows sensitive file access in this session.",
                "chain_risk_summary": chain_summary,
            },
        )
    if chain_ctx.risk_level == "ELEVATED" and envelope.action_type == "outbound_request":
        return StageResult(
            stage="chain_risk",
            passed=False,
            decision="REVIEW",
            reason_codes=[ReasonCode.CHAIN_RISK_ELEVATED],
            enrichments={
                "summary": "Outbound request from elevated-risk session requires review.",
                "chain_risk_summary": chain_summary,
            },
        )
    return StageResult(
        stage="chain_risk",
        passed=True,
        decision="ALLOW",
        reason_codes=[],
        enrichments={"chain_risk_summary": chain_summary},
    )


async def update_chain_risk_state(envelope: ActionEnvelope, decision: DecisionEnvelope, ctx: EngineContext) -> None:
    existing = await ctx.session_store.get_session(envelope.session_id)
    if existing is None:
        existing = ctx.session

    prev_review_count = existing.review_count if existing and existing.review_count is not None else 0
    prev_block_count = existing.block_count if existing and existing.block_count is not None else 0
    prev_sensitive_read_count = (
        existing.sensitive_read_count if existing and existing.sensitive_read_count is not None else 0
    )

    review_count = prev_review_count + (1 if decision.decision == "REVIEW" else 0)
    block_count = prev_block_count + (1 if decision.decision == "BLOCK" else 0)
    sensitive_read_count = prev_sensitive_read_count + (
        1
        if envelope.action_type == "file_read" and ReasonCode.SENSITIVE_FILE_ACCESS in decision.reason_codes
        else 0
    )

    if (
        review_count == prev_review_count
        and block_count == prev_block_count
        and sensitive_read_count == prev_sensitive_read_count
    ):
        return

    if block_count >= 1 or review_count >= 3:
        risk_level: RiskLevel = "HIGH"
    elif review_count >= 2:
        risk_level = "ELEVATED"
    else:
        risk_level = "NORMAL"

    next_state = _build_base_session(envelope.session_id, envelope.timestamp, existing)
    next_state.risk_level = risk_level
    next_state.review_count = review_count
    next_state.block_count = block_count
    next_state.sensitive_read_count = sensitive_read_count
    await ctx.session_store.put_session(envelope.session_id, next_state)
