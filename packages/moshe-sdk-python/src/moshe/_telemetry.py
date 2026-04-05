from __future__ import annotations

import uuid
from dataclasses import dataclass

from ._interfaces import TelemetrySink
from ._types import Decision, FeedbackVerdict, TelemetryEvent, TelemetryEventType, clone_dataclass


class MemoryTelemetrySink(TelemetrySink):
    name = "memory"

    def __init__(self) -> None:
        self._events: list[TelemetryEvent] = []

    async def emit(self, event: TelemetryEvent) -> None:
        self._events.append(clone_dataclass(event))

    def get_events(self) -> list[TelemetryEvent]:
        return [clone_dataclass(event) for event in self._events]

    def get_events_by_type(self, event_type: TelemetryEventType) -> list[TelemetryEvent]:
        return [clone_dataclass(event) for event in self._events if event.event_type == event_type]

    def get_events_for_action(self, action_id: str) -> list[TelemetryEvent]:
        return [clone_dataclass(event) for event in self._events if event.action_id == action_id]

    def get_decision_event(self, action_id: str) -> TelemetryEvent | None:
        matches = [
            event
            for event in self._events
            if event.action_id == action_id and event.event_type == "DECISION_MADE"
        ]
        return clone_dataclass(matches[-1]) if matches else None

    def clear(self) -> None:
        self._events.clear()


@dataclass(frozen=True)
class FeedbackSubmission:
    action_id: str
    session_id: str
    verdict: FeedbackVerdict
    expected_decision: Decision | None = None
    note: str | None = None


class FeedbackEmitter:
    def __init__(self, sinks: list[TelemetrySink]) -> None:
        self._sinks = sinks

    async def submit(self, submission: FeedbackSubmission) -> None:
        event = TelemetryEvent(
            event_id=str(uuid.uuid4()),
            event_type="FEEDBACK",
            action_id=submission.action_id,
            session_id=submission.session_id,
            debug={
                "verdict": submission.verdict,
                **({"expected_decision": submission.expected_decision} if submission.expected_decision else {}),
                **({"note": submission.note} if submission.note is not None else {}),
            },
        )
        for sink in self._sinks:
            await sink.emit(event)
