from __future__ import annotations

from typing import Any

import pytest

from moshe import (
    AllowResult,
    AnthropicAdapter,
    AnthropicToolUseBlock,
    BlockResult,
    BlockedActionError,
    MemoryStore,
    Moshe,
    PolicyConfig,
    ReviewRequiredError,
    ReviewResult,
)
from moshe._types import ApprovalRequest, DecisionEnvelope, ToolArguments


def _make_tool_use(name: str, input_dict: dict[str, Any]) -> AnthropicToolUseBlock:
    return AnthropicToolUseBlock(id=f"toolu_{name}", name=name, input=input_dict)


async def _async_value(value: str) -> str:
    return value


class SessionEvaluator:
    def __init__(self, decision: DecisionEnvelope) -> None:
        self.decision = decision
        self.calls: list[dict[str, Any]] = []

    async def evaluate(self, **kwargs: Any) -> DecisionEnvelope:
        self.calls.append(kwargs)
        return self.decision


class RootEvaluator:
    def __init__(self, decision: DecisionEnvelope) -> None:
        self.decision = decision
        self.with_session_calls: list[str] = []

    def with_session(self, session_id: str) -> SessionEvaluator:
        self.with_session_calls.append(session_id)
        return SessionEvaluator(self.decision)


def _decision(decision: str) -> DecisionEnvelope:
    kwargs: dict[str, Any] = {
        "decision": decision,
        "reason_codes": [],
        "summary": "ok",
    }
    if decision == "REVIEW":
        kwargs["approval_request"] = ApprovalRequest(approval_id="approval-1", expires_at="2025-01-01T01:00:00Z")
    return DecisionEnvelope(**kwargs)


@pytest.mark.asyncio
async def test_session_mode_allow() -> None:
    evaluator = SessionEvaluator(_decision("ALLOW"))
    adapter = AnthropicAdapter(evaluator)
    result = await adapter.wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("ok"))
    assert result == "ok"
    assert evaluator.calls[0]["tool_name"] == "search"


@pytest.mark.asyncio
async def test_session_mode_block() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("BLOCK")))
    with pytest.raises(BlockedActionError):
        await adapter.wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("nope"))


@pytest.mark.asyncio
async def test_session_mode_review() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("REVIEW")))
    with pytest.raises(ReviewRequiredError):
        await adapter.wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("nope"))


@pytest.mark.asyncio
async def test_try_wrap_allow() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("ALLOW")))
    result = await adapter.try_wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("ok"))
    assert isinstance(result, AllowResult)


@pytest.mark.asyncio
async def test_try_wrap_block() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("BLOCK")))
    result = await adapter.try_wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("ok"))
    assert isinstance(result, BlockResult)


@pytest.mark.asyncio
async def test_try_wrap_review() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("REVIEW")))
    result = await adapter.try_wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("ok"))
    assert isinstance(result, ReviewResult)


def test_to_tool_arguments_string_fields() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("ALLOW")))
    arguments = adapter._to_tool_arguments(  # type: ignore[attr-defined]
        {
            "command": "echo hi",
            "shell": "bash",
            "path": "/tmp/file",
            "content": "hello",
            "url": "https://example.com",
            "method": "POST",
            "subject": "subj",
            "body": "body",
            "agentAuthored": True,
        }
    )
    assert arguments == ToolArguments(
        command="echo hi",
        shell="bash",
        path="/tmp/file",
        content="hello",
        url="https://example.com",
        method="POST",
        subject="subj",
        body="body",
        agent_authored=True,
    )


def test_input_is_dict_no_json_parse() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("ALLOW")))
    arguments = adapter._to_tool_arguments({"path": "/tmp/file"})  # type: ignore[attr-defined]
    assert arguments.path == "/tmp/file"


def test_to_tool_arguments_headers_valid() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("ALLOW")))
    arguments = adapter._to_tool_arguments({"headers": {"x-key": "v"}})  # type: ignore[attr-defined]
    assert arguments.headers == {"x-key": "v"}


def test_to_tool_arguments_invalid_params_omitted() -> None:
    adapter = AnthropicAdapter(SessionEvaluator(_decision("ALLOW")))
    arguments = adapter._to_tool_arguments({"params": {"ok": ["bad"]}})  # type: ignore[attr-defined]
    assert arguments.params is None


@pytest.mark.asyncio
async def test_root_mode_allow() -> None:
    root = RootEvaluator(_decision("ALLOW"))
    adapter = AnthropicAdapter(root)
    result = await adapter.wrap_tool_use(
        tool_use=_make_tool_use("search", {}),
        execute=lambda: _async_value("ok"),
        session_id="session-1",
    )
    assert result == "ok"
    assert root.with_session_calls == ["session-1"]


@pytest.mark.asyncio
async def test_root_mode_missing_session_id_raises() -> None:
    adapter = AnthropicAdapter(RootEvaluator(_decision("ALLOW")))
    with pytest.raises(ValueError, match="session_id is required"):
        await adapter.wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("ok"))


@pytest.mark.asyncio
async def test_session_mode_real_moshe_end_to_end() -> None:
    store = MemoryStore()
    sdk = Moshe(policy=PolicyConfig(), store=store)
    adapter = AnthropicAdapter(sdk.with_session("session-real"))
    result = await adapter.wrap_tool_use(tool_use=_make_tool_use("search", {}), execute=lambda: _async_value("ok"))
    assert result == "ok"


@pytest.mark.asyncio
async def test_root_mode_real_moshe_end_to_end() -> None:
    store = MemoryStore()
    sdk = Moshe(policy=PolicyConfig(), store=store)
    adapter = AnthropicAdapter(sdk)
    result = await adapter.wrap_tool_use(
        tool_use=_make_tool_use("search", {}),
        execute=lambda: _async_value("ok"),
        session_id="session-root-real",
    )
    assert result == "ok"
