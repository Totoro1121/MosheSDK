from __future__ import annotations

import pytest

from moshe import MemoryStore, PolicyConfig, ReasonCode, ToolArguments
from moshe._interfaces import EngineContext
from moshe._store import ArtifactRecord, SessionState
from moshe._taint import (
    analyze_chain_risk,
    analyze_taint,
    build_chain_risk_context,
    build_taint_context,
    update_chain_risk_state,
    update_taint_state,
)
from moshe._types import ActionEnvelope, DecisionEnvelope


def envelope(**kwargs: object) -> ActionEnvelope:
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


def ctx(
    store: MemoryStore,
    *,
    session: SessionState | None = None,
    related_artifacts: dict[str, ArtifactRecord | None] | None = None,
) -> EngineContext:
    return EngineContext(
        session_id="s1",
        policy=PolicyConfig(),
        session_store=store,
        artifact_store=store,
        started_at=0.0,
        session=session,
        related_artifacts=related_artifacts,
    )


def test_build_taint_context_zeroed_for_empty_session() -> None:
    context = build_taint_context(ctx(MemoryStore()), envelope())
    assert context.session_tainted is False
    assert context.lineage_depth == 0
    assert context.origin_sources == []


def test_analyze_taint_allow_for_clean_context() -> None:
    analysis = analyze_taint(envelope(), build_taint_context(ctx(MemoryStore()), envelope()))
    assert analysis.decision == "ALLOW"


def test_analyze_taint_review_for_tainted_artifact_access() -> None:
    related = {
        "tainted.txt": ArtifactRecord(
            path="tainted.txt",
            classification="TAINTED",
            source="seed",
            reason="seed",
            first_seen="t1",
            last_seen="t1",
            provenance_chain=["origin.txt"],
        )
    }
    analysis = analyze_taint(
        envelope(action_type="file_read", arguments=ToolArguments(path="tainted.txt")),
        build_taint_context(ctx(MemoryStore(), related_artifacts=related), envelope()),
    )
    assert analysis.decision == "REVIEW"
    assert analysis.reason_code == ReasonCode.TAINTED_ARTIFACT_ACCESS


def test_analyze_taint_review_for_tainted_session_command() -> None:
    session = SessionState(
        session_id="s1",
        created_at="t1",
        updated_at="t1",
        message_count=0,
        taint_sources=["tainted.txt"],
        whitelisted_scripts={},
    )
    analysis = analyze_taint(
        envelope(action_type="command_exec", arguments=ToolArguments(command="ls")),
        build_taint_context(ctx(MemoryStore(), session=session), envelope()),
    )
    assert analysis.reason_code == ReasonCode.TAINTED_SESSION_COMMAND


def test_analyze_taint_review_for_agent_authored_execution() -> None:
    related = {
        "script.py": ArtifactRecord(
            path="script.py",
            classification="AGENT_GENERATED",
            source="seed",
            reason="seed",
            first_seen="t1",
            last_seen="t1",
            provenance_chain=[],
        )
    }
    analysis = analyze_taint(
        envelope(action_type="file_read", arguments=ToolArguments(path="script.py")),
        build_taint_context(ctx(MemoryStore(), related_artifacts=related), envelope()),
    )
    assert analysis.reason_code == ReasonCode.AGENT_AUTHORED_EXECUTION


@pytest.mark.asyncio
async def test_update_taint_state_marks_agent_generated_write() -> None:
    store = MemoryStore()
    decision = DecisionEnvelope(decision="ALLOW", reason_codes=[], summary="ok")
    await update_taint_state(
        envelope(action_type="file_write", arguments=ToolArguments(path="out.py", agent_authored=True)),
        decision,
        ctx(store),
    )
    record = await store.get_artifact("out.py")
    assert record is not None
    assert record.classification == "AGENT_GENERATED"


@pytest.mark.asyncio
async def test_update_taint_state_propagates_tainted_reference() -> None:
    store = MemoryStore()
    related = {
        "src.txt": ArtifactRecord(
            path="src.txt",
            classification="TAINTED",
            source="seed",
            reason="seed",
            first_seen="t1",
            last_seen="t1",
            provenance_chain=["origin.txt"],
        )
    }
    await update_taint_state(
        envelope(
            action_type="file_write",
            arguments=ToolArguments(path="out.txt"),
            referenced_paths=["src.txt"],
        ),
        DecisionEnvelope(decision="ALLOW", reason_codes=[], summary="ok"),
        ctx(store, related_artifacts=related),
    )
    record = await store.get_artifact("out.txt")
    assert record is not None
    assert record.classification == "TAINTED"
    assert record.provenance_chain == ["origin.txt", "src.txt"]


@pytest.mark.asyncio
async def test_update_chain_risk_state_increments_review_count() -> None:
    store = MemoryStore()
    await update_chain_risk_state(
        envelope(),
        DecisionEnvelope(decision="REVIEW", reason_codes=[ReasonCode.SENSITIVE_FILE_ACCESS], summary="review"),
        ctx(store),
    )
    session = await store.get_session("s1")
    assert session is not None
    assert session.review_count == 1


@pytest.mark.asyncio
async def test_update_chain_risk_state_escalates_high_on_block() -> None:
    store = MemoryStore()
    await update_chain_risk_state(
        envelope(),
        DecisionEnvelope(decision="BLOCK", reason_codes=[ReasonCode.FORBIDDEN_TOOL], summary="block"),
        ctx(store),
    )
    session = await store.get_session("s1")
    assert session is not None
    assert session.risk_level == "HIGH"


@pytest.mark.asyncio
async def test_update_chain_risk_state_skips_clean_allow() -> None:
    store = MemoryStore()
    await update_chain_risk_state(
        envelope(),
        DecisionEnvelope(decision="ALLOW", reason_codes=[], summary="ok"),
        ctx(store),
    )
    assert await store.get_session("s1") is None


def test_analyze_chain_risk_exfil_precursor() -> None:
    result = analyze_chain_risk(
        envelope(action_type="outbound_request", arguments=ToolArguments(url="https://exfil.test")),
        build_chain_risk_context(
            ctx(
                MemoryStore(),
                session=SessionState(
                    session_id="s1",
                    created_at="t1",
                    updated_at="t1",
                    message_count=0,
                    taint_sources=[],
                    whitelisted_scripts={},
                    sensitive_read_count=1,
                ),
            ),
            envelope(),
        ),
    )
    assert result.decision == "REVIEW"
    assert result.reason_codes == [ReasonCode.EXFIL_CHAIN_PRECURSOR]


def test_build_taint_context_origin_sources_excludes_intermediates() -> None:
    store = MemoryStore()
    related = {
        "leaf.txt": ArtifactRecord("leaf.txt", "TAINTED", "seed", "seed", "t1", "t1", ["mid.txt", "origin.txt"]),
        "mid.txt": ArtifactRecord("mid.txt", "AGENT_GENERATED", "seed", "seed", "t1", "t1", ["origin.txt"]),
        "origin.txt": ArtifactRecord("origin.txt", "CLEAN", "seed", "seed", "t1", "t1", []),
    }
    context = build_taint_context(ctx(store, related_artifacts=related), envelope())
    assert context.origin_sources == ["origin.txt"]
