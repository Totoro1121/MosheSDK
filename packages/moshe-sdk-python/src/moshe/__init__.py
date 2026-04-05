from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from ._adapter import (
    AdapterResult,
    AllowResult,
    BlockResult,
    BlockedActionError,
    GenericAdapter,
    MosheAdapterError,
    ReviewRequiredError,
    ReviewResult,
)
from ._analyzers import CommandIntentAnalyzer, FileAccessIntentAnalyzer, OutboundClassificationAnalyzer
from ._anthropic_adapter import AnthropicAdapter, AnthropicToolUseBlock
from ._approval import ApprovalContext, ApprovalResolution, InProcessApprovalProvider
from ._engine import EngineConfig, MosheEngine
from ._interfaces import Analyzer, ApprovalProvider, ArtifactStore, DecisionProvider, PolicyProvider, SessionStore, TelemetrySink
from ._lineage import LineageNode, LineageReport, resolve_lineage
from ._openai_adapter import OpenAIAdapter, OpenAIFunction, OpenAIToolCall
from ._policy import (
    ASSISTANT_WITH_TOOLS_PRESET,
    BROWSING_AGENT_PRESET,
    CODING_AGENT_PRESET,
    PRESETS,
    PRESET_NAMES,
    FilePolicyProvider,
    StaticPolicyProvider,
    apply_preset_overlays,
    policy_config_from_mapping,
    validate_policy_rules,
)
from ._providers import CallbackDecisionProvider, DecisionCallback, HttpDecisionProvider, NoopDecisionProvider
from ._store import ApprovalReplayEntry, ArtifactRecord, MemoryStore, SessionState
from ._telemetry import FeedbackEmitter, FeedbackSubmission, MemoryTelemetrySink
from ._types import *


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _tool_arguments_from_value(value: ToolArguments | dict[str, Any] | None) -> ToolArguments:
    if value is None:
        return ToolArguments()
    if isinstance(value, ToolArguments):
        return value
    return ToolArguments(**value)


class Moshe:
    def __init__(
        self,
        *,
        policy: PolicyConfig | PolicyProvider | dict[str, Any],
        store: Any = None,
        analyzers: list[Analyzer] | None = None,
        decision_provider: DecisionProvider | None = None,
        approval_provider: ApprovalProvider | None = None,
        telemetry_sinks: list[TelemetrySink] | None = None,
        on_error: str = "BLOCK",
        on_unhandled_review: str = "BLOCK",
    ) -> None:
        if isinstance(policy, dict):
            policy_provider: PolicyProvider = StaticPolicyProvider(policy_config_from_mapping(policy))
        elif isinstance(policy, PolicyConfig):
            policy_provider = StaticPolicyProvider(policy)
        else:
            policy_provider = policy

        self._store = store or MemoryStore()
        self._engine = MosheEngine(
            EngineConfig(
                policy=policy_provider,
                session_store=self._store,
                artifact_store=self._store,
                analyzers=analyzers,
                decision_provider=decision_provider,
                approval_provider=approval_provider,
                telemetry_sinks=telemetry_sinks,
                on_error=on_error,
                on_unhandled_review=on_unhandled_review,
            )
        )
        self._feedback = FeedbackEmitter(telemetry_sinks or [])

    async def evaluate(
        self,
        *,
        session_id: str,
        framework: str,
        action_type: ActionType,
        operation: str,
        tool_name: str,
        arguments: ToolArguments | dict[str, Any] | None = None,
        action_id: str | None = None,
        timestamp: str | None = None,
        agent_id: str | None = None,
        cwd: str | None = None,
        referenced_paths: list[str] | None = None,
        outbound_targets: list[str] | None = None,
        content_refs: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DecisionEnvelope:
        envelope = ActionEnvelope(
            action_id=action_id or str(uuid.uuid4()),
            session_id=session_id,
            timestamp=timestamp or _iso_now(),
            framework=framework,
            action_type=action_type,
            operation=operation,
            tool_name=tool_name,
            arguments=_tool_arguments_from_value(arguments),
            agent_id=agent_id,
            cwd=cwd,
            referenced_paths=referenced_paths,
            outbound_targets=outbound_targets,
            content_refs=content_refs,
            metadata=metadata,
        )
        return await self._engine.evaluate(envelope)

    def with_session(self, session_id: str) -> "MosheSession":
        return MosheSession(self, session_id)

    @property
    def feedback(self) -> FeedbackEmitter:
        return self._feedback

    async def close(self) -> None:
        close_method = getattr(self._store, "close", None)
        if callable(close_method):
            await close_method()


class MosheSession:
    def __init__(self, moshe: Moshe, session_id: str) -> None:
        self._moshe = moshe
        self._session_id = session_id

    async def evaluate(
        self, *, framework: str, action_type: ActionType, operation: str, tool_name: str, **kwargs: Any
    ) -> DecisionEnvelope:
        return await self._moshe.evaluate(
            session_id=self._session_id,
            framework=framework,
            action_type=action_type,
            operation=operation,
            tool_name=tool_name,
            **kwargs,
        )


__all__ = [
    "Moshe",
    "MosheSession",
    "MemoryStore",
    "SessionState",
    "ArtifactRecord",
    "ApprovalReplayEntry",
    "StaticPolicyProvider",
    "FilePolicyProvider",
    "CODING_AGENT_PRESET",
    "ASSISTANT_WITH_TOOLS_PRESET",
    "BROWSING_AGENT_PRESET",
    "PRESETS",
    "PRESET_NAMES",
    "apply_preset_overlays",
    "validate_policy_rules",
    "CommandIntentAnalyzer",
    "FileAccessIntentAnalyzer",
    "OutboundClassificationAnalyzer",
    "InProcessApprovalProvider",
    "ApprovalContext",
    "ApprovalResolution",
    "MemoryTelemetrySink",
    "FeedbackEmitter",
    "FeedbackSubmission",
    "NoopDecisionProvider",
    "CallbackDecisionProvider",
    "DecisionCallback",
    "HttpDecisionProvider",
    "OpenAIAdapter",
    "OpenAIFunction",
    "OpenAIToolCall",
    "AnthropicAdapter",
    "AnthropicToolUseBlock",
    "GenericAdapter",
    "MosheAdapterError",
    "BlockedActionError",
    "ReviewRequiredError",
    "AdapterResult",
    "AllowResult",
    "BlockResult",
    "ReviewResult",
    "LineageNode",
    "LineageReport",
    "resolve_lineage",
    "ActionEnvelope",
    "ActionType",
    "ApprovalRequest",
    "ChainRiskSummary",
    "Decision",
    "DecisionEnvelope",
    "FeedbackVerdict",
    "MatchedRule",
    "OutboundRule",
    "PolicyConfig",
    "ProvenanceSummary",
    "ReasonCode",
    "RecipientThreshold",
    "RiskLevel",
    "Severity",
    "TaintSummary",
    "TelemetryEvent",
    "TelemetryEventType",
    "TelemetryRef",
    "ToolArguments",
]
