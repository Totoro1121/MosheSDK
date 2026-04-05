from __future__ import annotations

import pytest

from moshe import (
    BlockResult,
    BlockedActionError,
    GenericAdapter,
    InProcessApprovalProvider,
    MemoryStore,
    Moshe,
    PolicyConfig,
    ReviewRequiredError,
    ReviewResult,
    ToolArguments,
)


@pytest.mark.asyncio
async def test_wrap_tool_call_calls_execute_on_allow() -> None:
    moshe = Moshe(policy=PolicyConfig())
    adapter = GenericAdapter(moshe.with_session("s1"))
    result = await adapter.wrap_tool_call(tool_name="search", execute=lambda: _async_value("ok"))
    assert result == "ok"


@pytest.mark.asyncio
async def test_wrap_tool_call_raises_blocked_action_error() -> None:
    moshe = Moshe(policy=PolicyConfig(forbidden_tools=["danger"]))
    adapter = GenericAdapter(moshe.with_session("s1"))
    with pytest.raises(BlockedActionError):
        await adapter.wrap_tool_call(tool_name="danger", execute=lambda: _async_value("never"))


@pytest.mark.asyncio
async def test_wrap_tool_call_raises_review_required_error() -> None:
    store = MemoryStore()
    moshe = Moshe(
        policy=PolicyConfig(sensitive_files=[".env"]),
        store=store,
        approval_provider=InProcessApprovalProvider(store),
    )
    adapter = GenericAdapter(moshe.with_session("s1"))
    with pytest.raises(ReviewRequiredError):
        await adapter.wrap_tool_call(
            tool_name="read_file",
            arguments=ToolArguments(path=".env"),
            execute=lambda: _async_value("never"),
        )


@pytest.mark.asyncio
async def test_try_wrap_tool_call_returns_allow_result() -> None:
    moshe = Moshe(policy=PolicyConfig())
    adapter = GenericAdapter(moshe.with_session("s1"))
    result = await adapter.try_wrap_tool_call(tool_name="search", execute=lambda: _async_value("ok"))
    assert result.outcome == "ALLOW"


@pytest.mark.asyncio
async def test_try_wrap_tool_call_returns_block_result() -> None:
    moshe = Moshe(policy=PolicyConfig(forbidden_tools=["danger"]))
    adapter = GenericAdapter(moshe.with_session("s1"))
    result = await adapter.try_wrap_tool_call(tool_name="danger", execute=lambda: _async_value("never"))
    assert isinstance(result, BlockResult)


@pytest.mark.asyncio
async def test_try_wrap_command_builds_command_exec() -> None:
    moshe = Moshe(policy=PolicyConfig())
    adapter = GenericAdapter(moshe.with_session("s1"))
    result = await adapter.try_wrap_command(command="echo hi", execute=lambda: _async_value("ok"))
    assert result.decision.debug is not None
    assert result.outcome == "ALLOW"


@pytest.mark.asyncio
async def test_wrap_outbound_always_includes_url() -> None:
    moshe = Moshe(policy=PolicyConfig(outbound_rules=[]))
    adapter = GenericAdapter(moshe.with_session("s1"))
    result = await adapter.try_wrap_outbound(url="https://example.com", execute=lambda: _async_value("ok"))
    assert result.outcome == "ALLOW"


@pytest.mark.asyncio
async def test_on_block_callback_awaited_before_raise() -> None:
    order: list[str] = []
    moshe = Moshe(policy=PolicyConfig(forbidden_tools=["danger"]))

    async def on_block(_decision: object) -> None:
        order.append("callback")

    adapter = GenericAdapter(moshe.with_session("s1"), on_block=on_block)
    with pytest.raises(BlockedActionError):
        await adapter.wrap_tool_call(tool_name="danger", execute=lambda: _async_value("never"))
    assert order == ["callback"]


async def _async_value(value: str) -> str:
    return value
