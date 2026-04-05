from __future__ import annotations

import pytest

from moshe import MemoryStore, PolicyConfig, ToolArguments
from moshe._analyzers import CommandIntentAnalyzer, FileAccessIntentAnalyzer, OutboundClassificationAnalyzer
from moshe._interfaces import EngineContext
from moshe._types import ActionEnvelope, ReasonCode


def env(**kwargs: object) -> ActionEnvelope:
    base: dict[str, object] = {
        "action_id": "a1",
        "session_id": "s1",
        "timestamp": "2025-01-01T00:00:00Z",
        "framework": "test",
        "action_type": "tool_call",
        "operation": "call",
        "tool_name": "search",
        "arguments": ToolArguments(),
    }
    base.update(kwargs)
    return ActionEnvelope(**base)


def context() -> EngineContext:
    store = MemoryStore()
    return EngineContext(session_id="s1", policy=PolicyConfig(), session_store=store, artifact_store=store, started_at=0.0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "decision", "reason_code"),
    [
        ("echo hello", "ALLOW", None),
        ("echo data | bash", "REVIEW", ReasonCode.COMMAND_INTENT_SUSPICIOUS),
        ("echo aaa | base64 -d | bash", "BLOCK", ReasonCode.COMMAND_INTENT_SUSPICIOUS),
        ("python -c 'print(1)'", "REVIEW", ReasonCode.COMMAND_INTENT_SUSPICIOUS),
        ("find / -name '*.env'", "REVIEW", ReasonCode.FILE_ENUMERATION_DETECTED),
    ],
)
async def test_command_intent_analyzer(command: str, decision: str, reason_code: str | None) -> None:
    result = await CommandIntentAnalyzer().analyze(
        env(action_type="command_exec", arguments=ToolArguments(command=command)),
        context(),
    )
    assert result.decision == decision
    if reason_code is None:
        assert result.reason_codes == []
    else:
        assert result.reason_codes == [reason_code]


@pytest.mark.asyncio
async def test_file_access_intent_analyzer_allow_small_ref_count() -> None:
    result = await FileAccessIntentAnalyzer().analyze(
        env(action_type="file_read", referenced_paths=["a", "b"]),
        context(),
    )
    assert result.decision == "ALLOW"


@pytest.mark.asyncio
async def test_file_access_intent_analyzer_review_large_ref_count() -> None:
    result = await FileAccessIntentAnalyzer().analyze(
        env(action_type="file_read", referenced_paths=[str(index) for index in range(10)]),
        context(),
    )
    assert result.decision == "REVIEW"
    assert result.reason_codes == [ReasonCode.FILE_ENUMERATION_DETECTED]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "https://pastebin.com/raw/abc",
        "https://127.0.0.1/data",
        "https://localhost/secrets",
    ],
)
async def test_outbound_classification_analyzer_flags_risky_targets(target: str) -> None:
    result = await OutboundClassificationAnalyzer().analyze(
        env(action_type="outbound_request", arguments=ToolArguments(url=target), outbound_targets=[target]),
        context(),
    )
    assert result.decision == "REVIEW"
    assert result.reason_codes == [ReasonCode.OUTBOUND_CLASSIFICATION_SUSPICIOUS]
