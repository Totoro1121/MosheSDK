from __future__ import annotations

import asyncio

import pytest

from moshe import InProcessApprovalProvider, MemoryStore, PolicyConfig, ToolArguments
from moshe._approval import ApprovalBlockedError
from moshe._interfaces import EngineContext
from moshe._types import ActionEnvelope


def envelope() -> ActionEnvelope:
    return ActionEnvelope(
        action_id="a1",
        session_id="s1",
        timestamp="2025-01-01T00:00:00Z",
        framework="test",
        action_type="file_read",
        operation="read",
        tool_name="read_file",
        arguments=ToolArguments(path=".env"),
    )


def context(store: MemoryStore) -> EngineContext:
    return EngineContext(session_id="s1", policy=PolicyConfig(), session_store=store, artifact_store=store, started_at=0.0)


@pytest.mark.asyncio
async def test_create_returns_request_for_new_action() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store)
    request = await provider.create(envelope(), context(store))
    assert request is not None


@pytest.mark.asyncio
async def test_check_returns_pending_before_resolve() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    assert await provider.check(request.approval_id) == "PENDING"


@pytest.mark.asyncio
async def test_check_returns_allow_once_after_resolve() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    await provider.resolve(request.approval_id, "ALLOW_ONCE")
    assert await provider.check(request.approval_id) == "ALLOW_ONCE"


@pytest.mark.asyncio
async def test_resolve_allow_session_stores_replay() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    await provider.resolve(request.approval_id, "ALLOW_SESSION")
    replay_entries = await store.get_approval_replay(next(iter(provider._pending_by_fingerprint)))  # type: ignore[attr-defined]
    assert replay_entries is not None


@pytest.mark.asyncio
async def test_create_returns_none_for_allow_session_replay() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    await provider.resolve(request.approval_id, "ALLOW_SESSION")
    second = await provider.create(envelope(), context(store))
    assert second is None


@pytest.mark.asyncio
async def test_allow_once_replay_consumed_on_second_call() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    await provider.resolve(request.approval_id, "ALLOW_ONCE")
    second = await provider.create(envelope(), context(store))
    assert second is None
    third = await provider.create(envelope(), context(store))
    assert third is not None


@pytest.mark.asyncio
async def test_block_resolution_suppresses_create_during_cooldown_then_allows_again() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store, ttl_ms=20)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    await provider.resolve(request.approval_id, "BLOCK")

    with pytest.raises(ApprovalBlockedError):
        await provider.create(envelope(), context(store))

    await asyncio.sleep(0.03)
    second = await provider.create(envelope(), context(store))
    assert second is not None


@pytest.mark.asyncio
async def test_block_resolution_clears_pending_by_fingerprint() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    await provider.resolve(request.approval_id, "BLOCK")
    assert provider._pending_by_fingerprint == {}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_resolved_approval_is_cleaned_after_ttl() -> None:
    store = MemoryStore()
    provider = InProcessApprovalProvider(store, ttl_ms=1)
    request = await provider.create(envelope(), context(store))
    assert request is not None
    await provider.resolve(request.approval_id, "ALLOW_ONCE")
    await asyncio.sleep(0.01)
    second = await provider.create(envelope(), context(store))
    assert second is not None
    assert second.approval_id != request.approval_id
    assert len(provider._pending_by_id) == 1  # type: ignore[attr-defined]
