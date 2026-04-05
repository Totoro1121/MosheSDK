from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from moshe import (
    AllowResult,
    BlockResult,
    BlockedActionError,
    InProcessApprovalProvider,
    MemoryStore,
    Moshe,
    OpenAIAdapter,
    OpenAIFunction,
    OpenAIToolCall,
    PolicyConfig,
    ReviewRequiredError,
    ReviewResult,
)
from moshe._types import ApprovalRequest, DecisionEnvelope, ToolArguments


def _make_tool_call(name: str, args_json: str) -> OpenAIToolCall:
    return OpenAIToolCall(id=f"call_{name}", function=OpenAIFunction(name=name, arguments=args_json))


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
        self.session_evaluators: list[SessionEvaluator] = []

    def with_session(self, session_id: str) -> SessionEvaluator:
        self.with_session_calls.append(session_id)
        evaluator = SessionEvaluator(self.decision)
        self.session_evaluators.append(evaluator)
        return evaluator


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
    adapter = OpenAIAdapter(evaluator)
    result = await adapter.wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("ok"))
    assert result == "ok"
    assert evaluator.calls[0]["tool_name"] == "search"


@pytest.mark.asyncio
async def test_session_mode_block() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("BLOCK")))
    with pytest.raises(BlockedActionError):
        await adapter.wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("nope"))


@pytest.mark.asyncio
async def test_session_mode_review() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("REVIEW")))
    with pytest.raises(ReviewRequiredError):
        await adapter.wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("nope"))


@pytest.mark.asyncio
async def test_try_wrap_allow() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
    result = await adapter.try_wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("ok"))
    assert isinstance(result, AllowResult)
    assert result.value == "ok"


@pytest.mark.asyncio
async def test_try_wrap_block() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("BLOCK")))
    result = await adapter.try_wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("ok"))
    assert isinstance(result, BlockResult)


@pytest.mark.asyncio
async def test_try_wrap_review() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("REVIEW")))
    result = await adapter.try_wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("ok"))
    assert isinstance(result, ReviewResult)


def test_parse_arguments_valid() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
    parsed = adapter._parse_arguments('{"path":"/tmp/file","command":"ls"}')  # type: ignore[attr-defined]
    assert parsed == {"path": "/tmp/file", "command": "ls"}


def test_parse_arguments_invalid_json() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
    assert adapter._parse_arguments("not-json") == {}  # type: ignore[attr-defined]


def test_parse_arguments_array_json() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
    assert adapter._parse_arguments('["a"]') == {}  # type: ignore[attr-defined]


def test_to_tool_arguments_string_fields() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
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


def test_to_tool_arguments_headers_valid() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
    arguments = adapter._to_tool_arguments({"headers": {"x-key": "v"}})  # type: ignore[attr-defined]
    assert arguments.headers == {"x-key": "v"}


def test_to_tool_arguments_headers_nonstr_value_omitted() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
    arguments = adapter._to_tool_arguments({"headers": {"x-key": 123}})  # type: ignore[attr-defined]
    assert arguments.headers is None


def test_to_tool_arguments_recipients_valid() -> None:
    adapter = OpenAIAdapter(SessionEvaluator(_decision("ALLOW")))
    arguments = adapter._to_tool_arguments({"recipients": ["a@b.com"]})  # type: ignore[attr-defined]
    assert arguments.recipients == ["a@b.com"]


@pytest.mark.asyncio
async def test_root_mode_allow() -> None:
    root = RootEvaluator(_decision("ALLOW"))
    adapter = OpenAIAdapter(root)
    result = await adapter.wrap_tool_call(
        tool_call=_make_tool_call("search", "{}"),
        execute=lambda: _async_value("ok"),
        session_id="session-1",
    )
    assert result == "ok"
    assert root.with_session_calls == ["session-1"]


@pytest.mark.asyncio
async def test_root_mode_missing_session_id_raises() -> None:
    adapter = OpenAIAdapter(RootEvaluator(_decision("ALLOW")))
    with pytest.raises(ValueError, match="session_id is required"):
        await adapter.wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("ok"))


@pytest.mark.asyncio
async def test_parsed_arguments_override() -> None:
    evaluator = SessionEvaluator(_decision("ALLOW"))
    adapter = OpenAIAdapter(evaluator)
    await adapter.wrap_tool_call(
        tool_call=_make_tool_call("read_file", '{"path":"ignored"}'),
        parsed_arguments={"path": "/tmp/real"},
        execute=lambda: _async_value("ok"),
    )
    assert evaluator.calls[0]["arguments"].path == "/tmp/real"


@pytest.mark.asyncio
async def test_session_mode_real_moshe_end_to_end() -> None:
    store = MemoryStore()
    sdk = Moshe(policy=PolicyConfig(), store=store)
    adapter = OpenAIAdapter(sdk.with_session("session-real"))
    result = await adapter.wrap_tool_call(tool_call=_make_tool_call("search", "{}"), execute=lambda: _async_value("ok"))
    assert result == "ok"


@pytest.mark.asyncio
async def test_root_mode_real_moshe_end_to_end() -> None:
    store = MemoryStore()
    sdk = Moshe(policy=PolicyConfig(), store=store)
    adapter = OpenAIAdapter(sdk)
    result = await adapter.wrap_tool_call(
        tool_call=_make_tool_call("search", "{}"),
        execute=lambda: _async_value("ok"),
        session_id="session-root-real",
    )
    assert result == "ok"
