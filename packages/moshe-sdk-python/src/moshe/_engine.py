from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from ._interfaces import Analyzer, ApprovalProvider, DecisionProvider, EngineContext, PolicyProvider, StageResult, TelemetrySink
from ._policy import collect_matched_rules, decision_from_results, evaluate_static_policy
from ._approval import ApprovalBlockedError
from ._taint import (
    analyze_chain_risk,
    analyze_taint,
    build_chain_risk_context,
    build_taint_context,
    build_taint_stage_result,
    update_chain_risk_state,
    update_taint_state,
)
from ._types import ActionEnvelope, DecisionEnvelope, ReasonCode, TelemetryEvent


@dataclass
class EngineConfig:
    policy: PolicyProvider
    session_store: Any
    artifact_store: Any
    analyzers: list[Analyzer] | None = None
    decision_provider: DecisionProvider | None = None
    approval_provider: ApprovalProvider | None = None
    telemetry_sinks: list[TelemetrySink] | None = None
    on_error: str = "BLOCK"
    on_unhandled_review: str = "BLOCK"


def _fallback_action_id(envelope: Any) -> str:
    if isinstance(envelope, dict):
        value = envelope.get("action_id")
        if isinstance(value, str) and value.strip():
            return value
    return str(uuid.uuid4())


def _fallback_session_id(envelope: Any) -> str:
    if isinstance(envelope, dict):
        value = envelope.get("session_id")
        if isinstance(value, str) and value.strip():
            return value
    return "unknown-session"


def _merge_reason_codes(results: list[StageResult]) -> list[str]:
    return list(dict.fromkeys(code for result in results for code in result.reason_codes or []))


def _summary_for_decision(decision: str, reason_codes: list[str]) -> str:
    if decision == "BLOCK":
        return f"Blocked action due to {', '.join(reason_codes)}." if reason_codes else "Blocked action."
    if decision == "REVIEW":
        return f"Action requires review due to {', '.join(reason_codes)}." if reason_codes else "Action requires review."
    return "Action allowed."


def _build_telemetry_event(
    *,
    event_type: str,
    action_id: str,
    session_id: str,
    elapsed_ms: float | None = None,
    stage: str | None = None,
    decision: str | None = None,
    reason_codes: list[str] | None = None,
    debug: dict[str, Any] | None = None,
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=str(uuid.uuid4()),
        event_type=event_type,  # type: ignore[arg-type]
        action_id=action_id,
        session_id=session_id,
        elapsed_ms=elapsed_ms,
        stage=stage,
        decision=decision,  # type: ignore[arg-type]
        reason_codes=reason_codes,
        debug=debug,
    )


class MosheEngine:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    async def evaluate(self, envelope: ActionEnvelope) -> DecisionEnvelope:
        started_at = time.perf_counter()
        current_envelope: ActionEnvelope | None = None
        current_context: EngineContext | None = None
        try:
            current_envelope = await self.normalize(envelope)
            await self.emit_single_telemetry(
                _build_telemetry_event(
                    event_type="ACTION_RECEIVED",
                    action_id=current_envelope.action_id,
                    session_id=current_envelope.session_id,
                    elapsed_ms=0,
                )
            )
            current_context = await self.enrich(current_envelope, started_at)
            await self.emit_stage_event(current_envelope, current_context, "enrich")

            policy_result = await self.evaluate_policy(current_envelope, current_context)
            await self.emit_stage_event(current_envelope, current_context, "static_policy", policy_result)

            if policy_result.decision == "BLOCK":
                decision = self.compose(current_envelope, current_context, [policy_result])
                await self.emit_decision_telemetry(current_envelope, current_context, decision)
                await self.emit_telemetry(current_envelope, current_context, decision)
                await update_taint_state(current_envelope, decision, current_context)
                await update_chain_risk_state(current_envelope, decision, current_context)
                return decision

            analysis_results = await self.run_analyzers(current_envelope, current_context)
            await self.emit_stage_event(
                current_envelope,
                current_context,
                "analysis",
                StageResult(
                    stage="analysis",
                    passed=all(result.passed for result in analysis_results),
                    decision=decision_from_results(analysis_results),  # type: ignore[arg-type]
                    reason_codes=_merge_reason_codes(analysis_results),
                    matched_rules=collect_matched_rules(analysis_results),
                ),
            )

            approval_result = await self.check_approval(current_envelope, current_context, [policy_result, *analysis_results])
            await self.emit_stage_event(current_envelope, current_context, "approval", approval_result)

            decision = self.compose(current_envelope, current_context, [policy_result, *analysis_results, approval_result])
            await self.emit_decision_telemetry(current_envelope, current_context, decision)
            await self.emit_telemetry(current_envelope, current_context, decision)
            await update_taint_state(current_envelope, decision, current_context)
            await update_chain_risk_state(current_envelope, decision, current_context)
            return decision
        except Exception as error:
            action_id = current_envelope.action_id if current_envelope else _fallback_action_id(envelope.__dict__)
            session_id = current_envelope.session_id if current_envelope else _fallback_session_id(envelope.__dict__)
            elapsed_ms = (time.perf_counter() - started_at) * 1000
            decision = DecisionEnvelope(
                decision=self.config.on_error,  # type: ignore[arg-type]
                reason_codes=[ReasonCode.ENGINE_ERROR],
                summary=f"Engine failed and returned configured {self.config.on_error}.",
                debug={"error": str(error)},
            )
            try:
                await self.emit_single_telemetry(
                    _build_telemetry_event(
                        event_type="DECISION_MADE",
                        action_id=action_id,
                        session_id=session_id,
                        decision=decision.decision,
                        reason_codes=decision.reason_codes,
                        elapsed_ms=elapsed_ms,
                        debug=decision.debug,
                    )
                )
            except Exception:
                pass
            return decision

    async def normalize(self, envelope: ActionEnvelope) -> ActionEnvelope:
        if envelope.action_id.strip() == "" or envelope.session_id.strip() == "":
            raise ValueError("ActionEnvelope validation failed: action_id and session_id are required")
        if envelope.framework.strip() == "" or envelope.tool_name.strip() == "":
            raise ValueError("ActionEnvelope validation failed: framework and tool_name are required")
        valid_action_types = {
            "tool_call",
            "command_exec",
            "file_read",
            "file_write",
            "outbound_request",
            "message_send",
            "unknown",
        }
        if envelope.action_type not in valid_action_types:
            raise ValueError(
                f"ActionEnvelope validation failed: invalid action_type '{envelope.action_type}'"
            )
        if not envelope.operation.strip():
            raise ValueError("ActionEnvelope validation failed: operation is required")
        return envelope

    async def enrich(self, envelope: ActionEnvelope, started_at: float) -> EngineContext:
        effective_policy = await self.config.policy.get_effective()
        await self.config.policy.validate(effective_policy)

        path_candidates: set[str] = set()
        if envelope.arguments.path and envelope.arguments.path.strip():
            path_candidates.add(envelope.arguments.path)
        for path in envelope.referenced_paths or []:
            if path.strip():
                path_candidates.add(path)

        related_artifacts: dict[str, Any | None] = {}
        for path in path_candidates:
            related_artifacts[path] = await self.config.artifact_store.get_artifact(path)

        return EngineContext(
            session_id=envelope.session_id,
            policy=effective_policy,
            session_store=self.config.session_store,
            artifact_store=self.config.artifact_store,
            started_at=started_at,
            session=await self.config.session_store.get_session(envelope.session_id),
            related_artifacts=related_artifacts,
        )

    async def evaluate_policy(self, envelope: ActionEnvelope, ctx: EngineContext) -> StageResult:
        return await evaluate_static_policy(envelope, ctx)

    async def run_analyzers(self, envelope: ActionEnvelope, ctx: EngineContext) -> list[StageResult]:
        results: list[StageResult] = []
        for analyzer in self.config.analyzers or []:
            results.append(await analyzer.analyze(envelope, ctx))
        if self.config.decision_provider is not None:
            provider_result = await self.config.decision_provider.evaluate(envelope, ctx)
            if provider_result is not None:
                results.append(provider_result)
        taint_ctx = build_taint_context(ctx, envelope)
        taint_analysis = analyze_taint(envelope, taint_ctx)
        results.append(build_taint_stage_result(taint_analysis))
        chain_ctx = build_chain_risk_context(ctx, envelope)
        results.append(analyze_chain_risk(envelope, chain_ctx))
        return results

    async def check_approval(
        self, envelope: ActionEnvelope, ctx: EngineContext, analysis_results: list[StageResult]
    ) -> StageResult:
        review_result = next((result for result in analysis_results if result.decision == "REVIEW"), None)
        if review_result is None:
            return StageResult(
                stage="approval",
                passed=True,
                decision="ALLOW",
                reason_codes=[ReasonCode.NO_APPROVAL_REQUIRED],
                enrichments={"summary": "No approval required."},
            )

        if self.config.approval_provider is None:
            return StageResult(
                stage="approval",
                passed=self.config.on_unhandled_review == "ALLOW",
                decision=self.config.on_unhandled_review,  # type: ignore[arg-type]
                reason_codes=[ReasonCode.UNHANDLED_REVIEW],
                matched_rules=review_result.matched_rules,
                enrichments={
                    "summary": f"Review requested without approval provider; fell back to {self.config.on_unhandled_review}.",
                },
            )

        try:
            approval_request = await self.config.approval_provider.create(envelope, ctx)
        except ApprovalBlockedError:
            return StageResult(
                stage="approval",
                passed=False,
                decision="BLOCK",
                reason_codes=[ReasonCode.APPROVAL_REPLAY_BLOCKED],
                enrichments={
                    "summary": "Action blocked: previously BLOCK-resolved within cooldown period.",
                },
            )
        if approval_request is None:
            return StageResult(
                stage="approval",
                passed=True,
                decision="ALLOW",
                reason_codes=[ReasonCode.APPROVAL_REPLAY_ALLOWED],
                enrichments={"summary": "Action allowed via prior approval."},
            )

        return StageResult(
            stage="approval",
            passed=False,
            decision="REVIEW",
            reason_codes=[ReasonCode.APPROVAL_REQUIRED],
            matched_rules=review_result.matched_rules,
            enrichments={
                "summary": "Approval required before this action can proceed.",
                "approval_request": approval_request,
            },
        )

    def compose(self, envelope: ActionEnvelope, ctx: EngineContext, results: list[StageResult]) -> DecisionEnvelope:
        decision = decision_from_results(results)
        reason_codes = _merge_reason_codes(results)
        enrichments = [result.enrichments for result in results if result.enrichments is not None]
        summary = next(
            (value["summary"] for value in enrichments if isinstance(value.get("summary"), str)),
            _summary_for_decision(decision, reason_codes),
        )
        composed: dict[str, Any] = {
            "decision": decision,
            "reason_codes": reason_codes,
            "summary": summary,
            "debug": {
                "stage_count": len(results),
                "session_id": ctx.session_id,
                "action_id": envelope.action_id,
            },
        }
        matched_rules = collect_matched_rules(results)
        if matched_rules is not None:
            composed["matched_rules"] = matched_rules
        for enrichment in enrichments:
            composed.update(enrichment)
        return DecisionEnvelope(**composed)

    async def emit_telemetry(self, envelope: ActionEnvelope, ctx: EngineContext, decision: DecisionEnvelope) -> None:
        await self.emit_single_telemetry(
            _build_telemetry_event(
                event_type="STAGE_COMPLETE",
                action_id=envelope.action_id,
                session_id=envelope.session_id,
                stage="compose",
                decision=decision.decision,
                reason_codes=decision.reason_codes,
                elapsed_ms=(time.perf_counter() - ctx.started_at) * 1000,
            )
        )

    async def emit_stage_event(
        self, envelope: ActionEnvelope, ctx: EngineContext, stage: str, result: StageResult | None = None
    ) -> None:
        await self.emit_single_telemetry(
            _build_telemetry_event(
                event_type="STAGE_COMPLETE",
                action_id=envelope.action_id,
                session_id=envelope.session_id,
                stage=stage,
                elapsed_ms=(time.perf_counter() - ctx.started_at) * 1000,
                decision=result.decision if result else None,
                reason_codes=result.reason_codes if result else None,
            )
        )

    async def emit_decision_telemetry(
        self, envelope: ActionEnvelope, ctx: EngineContext, decision: DecisionEnvelope
    ) -> None:
        await self.emit_single_telemetry(
            _build_telemetry_event(
                event_type="DECISION_MADE",
                action_id=envelope.action_id,
                session_id=envelope.session_id,
                decision=decision.decision,
                reason_codes=decision.reason_codes,
                elapsed_ms=(time.perf_counter() - ctx.started_at) * 1000,
            )
        )

    async def emit_single_telemetry(self, event: TelemetryEvent) -> None:
        for sink in self.config.telemetry_sinks or []:
            await sink.emit(event)
