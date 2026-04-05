from __future__ import annotations

import pytest

from moshe import MemoryStore, Moshe, PolicyConfig


@pytest.fixture
def memory_store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def simple_moshe(memory_store: MemoryStore) -> Moshe:
    return Moshe(
        policy=PolicyConfig(),
        store=memory_store,
        on_error="BLOCK",
        on_unhandled_review="BLOCK",
    )


@pytest.fixture
def action_kwargs() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "framework": "test",
        "action_type": "tool_call",
        "operation": "call",
        "tool_name": "search",
    }
