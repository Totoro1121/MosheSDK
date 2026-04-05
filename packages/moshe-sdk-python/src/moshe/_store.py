from __future__ import annotations

from dataclasses import dataclass, field

from ._interfaces import ArtifactStore, SessionStore
from ._types import RiskLevel, clone_dataclass


@dataclass
class SessionState:
    session_id: str
    created_at: str
    updated_at: str
    message_count: int
    taint_sources: list[str]
    whitelisted_scripts: dict[str, str]
    suspect_until: str | None = None
    risk_level: RiskLevel | None = None
    review_count: int | None = None
    block_count: int | None = None
    sensitive_read_count: int | None = None


ArtifactClassification = str


@dataclass
class ArtifactRecord:
    path: str
    classification: ArtifactClassification
    source: str
    reason: str
    first_seen: str
    last_seen: str
    provenance_chain: list[str] | None = None


@dataclass
class ApprovalReplayEntry:
    approval_id: str
    session_id: str
    resolved_decision: str
    resolved_at: str
    expires_at: str
    path: str | None = None
    hash: str | None = None


class MemoryStore(SessionStore, ArtifactStore):
    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._artifacts: dict[str, ArtifactRecord] = {}
        self._approval_replays: dict[str, ApprovalReplayEntry] = {}

    async def get_session(self, session_id: str) -> SessionState | None:
        state = self._sessions.get(session_id)
        return clone_dataclass(state) if state is not None else None

    async def put_session(self, session_id: str, state: SessionState) -> None:
        self._sessions[session_id] = clone_dataclass(state)

    async def get_approval_replay(self, approval_id: str) -> ApprovalReplayEntry | None:
        entry = self._approval_replays.get(approval_id)
        return clone_dataclass(entry) if entry is not None else None

    async def put_approval_replay(self, entry: ApprovalReplayEntry) -> None:
        self._approval_replays[entry.approval_id] = clone_dataclass(entry)

    async def get_artifact(self, path: str) -> ArtifactRecord | None:
        record = self._artifacts.get(path)
        return clone_dataclass(record) if record is not None else None

    async def put_artifact(self, path: str, record: ArtifactRecord) -> None:
        self._artifacts[path] = clone_dataclass(record)

    async def list_artifacts(self, prefix: str = "") -> list[str]:
        return sorted([path for path in self._artifacts if path.startswith(prefix)])

    async def close(self) -> None:
        return None
