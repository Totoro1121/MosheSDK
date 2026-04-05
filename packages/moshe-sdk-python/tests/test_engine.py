from __future__ import annotations

import pytest

from moshe import (
    CallbackDecisionProvider,
    FeedbackSubmission,
    InProcessApprovalProvider,
    MemoryStore,
    MemoryTelemetrySink,
    Moshe,
    PolicyConfig,
    ReasonCode,
    ToolArguments,
)
from moshe._interfaces import StageResult


@pytest.mark.asyncio
async def test_engine_allows_action_with_no_policy_rules() -> None:
    sdk = Moshe(policy=PolicyConfig())
    decision = await sdk.evaluate(session_id="s1", framework="test", action_type="tool_call", operation="call", tool_name="search")
    assert decision.decision == "ALLOW"


@pytest.mark.asyncio
async def test_engine_blocks_forbidden_tool() -> None:
    sdk = Moshe(policy=PolicyConfig(forbidden_tools=["danger"]))
    decision = await sdk.evaluate(session_id="s1", framework="test", action_type="tool_call", operation="call", tool_name="danger")
    assert decision.decision == "BLOCK"


@pytest.mark.asyncio
async def test_engine_reviews_sensitive_file_with_approval_provider() -> None:
    store = MemoryStore()
    sdk = Moshe(
        policy=PolicyConfig(sensitive_files=[".env"]),
        store=store,
        approval_provider=InProcessApprovalProvider(store),
    )
    decision = await sdk.evaluate(
        session_id="s1",
        framework="test",
        action_type="file_read",
        operation="read",
        tool_name="read_file",
        arguments=ToolArguments(path=".env"),
    )
    assert decision.decision == "REVIEW"
    assert decision.approval_request is not None


@pytest.mark.asyncio
async def test_engine_exfil_chain() -> None:
    store = MemoryStore()
    sdk = Moshe(policy=PolicyConfig(sensitive_files=[".env"]), store=store, on_unhandled_review="ALLOW")
    await sdk.evaluate(
        session_id="s1",
        framework="test",
        action_type="file_read",
        operation="read",
        tool_name="read_file",
        arguments=ToolArguments(path=".env"),
    )
    decision = await sdk.evaluate(
        session_id="s1",
        framework="test",
        action_type="outbound_request",
        operation="fetch",
        tool_name="http_get",
        arguments=ToolArguments(url="https://collector.example.com"),
        outbound_targets=["https://collector.example.com"],
    )
    assert ReasonCode.EXFIL_CHAIN_PRECURSOR in decision.reason_codes


@pytest.mark.asyncio
async def test_memory_telemetry_sink_receives_decision_event() -> None:
    sink = MemoryTelemetrySink()
    sdk = Moshe(policy=PolicyConfig(), telemetry_sinks=[sink])
    decision = await sdk.evaluate(session_id="s1", framework="test", action_type="tool_call", operation="call", tool_name="search")
    event = sink.get_decision_event(next(iter(sink.get_events())).action_id)
    assert event is not None
    assert event.decision == decision.decision


@pytest.mark.asyncio
async def test_feedback_emitter_emits_feedback_event() -> None:
    sink = MemoryTelemetrySink()
    sdk = Moshe(policy=PolicyConfig(), telemetry_sinks=[sink])
    decision = await sdk.evaluate(session_id="s1", framework="test", action_type="tool_call", operation="call", tool_name="search")
    action_id = next(iter(sink.get_events())).action_id
    await sdk.feedback.submit(FeedbackSubmission(action_id=action_id, session_id="s1", verdict="CORRECT"))
    assert sink.get_events()[-1].event_type == "FEEDBACK"


@pytest.mark.asyncio
async def test_callback_decision_provider_review_contributes_to_final_decision() -> None:
    store = MemoryStore()
    provider = CallbackDecisionProvider(
        lambda _env, _ctx: StageResult(
            stage="decision_provider",
            passed=False,
            decision="REVIEW",
            reason_codes=[ReasonCode.COMMAND_INTENT_SUSPICIOUS],
        )
    )
    sdk = Moshe(
        policy=PolicyConfig(),
        store=store,
        decision_provider=provider,
        approval_provider=InProcessApprovalProvider(store),
    )
    decision = await sdk.evaluate(session_id="s1", framework="test", action_type="tool_call", operation="call", tool_name="search")
    assert decision.decision == "REVIEW"


@pytest.mark.asyncio
async def test_with_session_binds_session_id() -> None:
    sdk = Moshe(policy=PolicyConfig())
    session = sdk.with_session("bound-session")
    decision = await session.evaluate(framework="test", action_type="tool_call", operation="call", tool_name="search")
    assert decision.debug is not None
    assert decision.debug["session_id"] == "bound-session"


@pytest.mark.asyncio
async def test_moshe_defaults_to_memory_store() -> None:
    sdk = Moshe(policy=PolicyConfig())
    decision = await sdk.evaluate(session_id="s1", framework="test", action_type="tool_call", operation="call", tool_name="search")
    assert decision.decision == "ALLOW"


@pytest.mark.asyncio
async def test_engine_error_path_returns_engine_error_reason_code() -> None:
    sdk = Moshe(policy=PolicyConfig())
    decision = await sdk.evaluate(session_id="", framework="test", action_type="tool_call", operation="call", tool_name="search")
    assert decision.reason_codes == [ReasonCode.ENGINE_ERROR]
