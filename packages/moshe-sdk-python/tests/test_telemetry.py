from __future__ import annotations

import pytest

from moshe import FeedbackEmitter, FeedbackSubmission, MemoryTelemetrySink, ScrubbingTelemetrySink, TelemetryEvent


@pytest.mark.asyncio
async def test_memory_telemetry_sink_accumulates_events() -> None:
    sink = MemoryTelemetrySink()
    await sink.emit(TelemetryEvent(event_id="e1", event_type="ACTION_RECEIVED", action_id="a1", session_id="s1"))
    assert len(sink.get_events()) == 1


@pytest.mark.asyncio
async def test_get_events_by_type_filters_correctly() -> None:
    sink = MemoryTelemetrySink()
    await sink.emit(TelemetryEvent(event_id="e1", event_type="ACTION_RECEIVED", action_id="a1", session_id="s1"))
    await sink.emit(TelemetryEvent(event_id="e2", event_type="DECISION_MADE", action_id="a1", session_id="s1"))
    assert len(sink.get_events_by_type("DECISION_MADE")) == 1


@pytest.mark.asyncio
async def test_get_decision_event_returns_most_recent() -> None:
    sink = MemoryTelemetrySink()
    await sink.emit(TelemetryEvent(event_id="e1", event_type="DECISION_MADE", action_id="a1", session_id="s1"))
    await sink.emit(TelemetryEvent(event_id="e2", event_type="DECISION_MADE", action_id="a1", session_id="s1"))
    event = sink.get_decision_event("a1")
    assert event is not None
    assert event.event_id == "e2"


def test_clear_empties_sink() -> None:
    sink = MemoryTelemetrySink()
    sink._events.append(TelemetryEvent(event_id="e1", event_type="DECISION_MADE", action_id="a1", session_id="s1"))  # type: ignore[attr-defined]
    sink.clear()
    assert sink.get_events() == []


@pytest.mark.asyncio
async def test_feedback_emitter_emits_feedback_event() -> None:
    sink = MemoryTelemetrySink()
    emitter = FeedbackEmitter([sink])
    await emitter.submit(
        FeedbackSubmission(
            action_id="a1",
            session_id="s1",
            verdict="CORRECT",
            expected_decision="ALLOW",
            note="looks good",
        )
    )
    event = sink.get_events()[0]
    assert event.event_type == "FEEDBACK"
    assert event.debug == {
        "verdict": "CORRECT",
        "expected_decision": "ALLOW",
        "note": "looks good",
    }


@pytest.mark.asyncio
async def test_scrubbing_telemetry_sink_removes_debug() -> None:
    inner = MemoryTelemetrySink()
    sink = ScrubbingTelemetrySink(inner)
    await sink.emit(
        TelemetryEvent(
            event_id="e1",
            event_type="DECISION_MADE",
            action_id="a1",
            session_id="s1",
            debug={"secret": "value"},
        )
    )
    assert inner.get_events()[0].debug is None
