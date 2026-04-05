from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ._types import ActionEnvelope, ApprovalRequest, Decision, DecisionEnvelope, MatchedRule, PolicyConfig, TelemetryEvent


@dataclass
class StageResult:
    stage: str
    passed: bool
    decision: Decision | None = None
    reason_codes: list[str] | None = None
    matched_rules: list[MatchedRule] | None = None
    enrichments: dict[str, Any] | None = None


class SessionStore(ABC):
    @abstractmethod
    async def get_session(self, session_id: str) -> Any | None:
        raise NotImplementedError

    @abstractmethod
    async def put_session(self, session_id: str, state: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    async def get_approval_replay(self, approval_id: str) -> Any | None:
        raise NotImplementedError

    @abstractmethod
    async def put_approval_replay(self, entry: Any) -> None:
        raise NotImplementedError


class ArtifactStore(ABC):
    @abstractmethod
    async def get_artifact(self, path: str) -> Any | None:
        raise NotImplementedError

    @abstractmethod
    async def put_artifact(self, path: str, record: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    async def list_artifacts(self, prefix: str = "") -> list[str]:
        raise NotImplementedError


class PolicyProvider(ABC):
    @abstractmethod
    async def load(self) -> PolicyConfig:
        raise NotImplementedError

    @abstractmethod
    async def validate(self, config: PolicyConfig) -> None:
        raise NotImplementedError

    @abstractmethod
    async def get_effective(self) -> PolicyConfig:
        raise NotImplementedError


@dataclass
class EngineContext:
    session_id: str
    policy: PolicyConfig
    session_store: SessionStore
    artifact_store: ArtifactStore
    started_at: float
    session: Any | None = None
    related_artifacts: dict[str, Any | None] | None = None


class Analyzer(ABC):
    name: str

    @abstractmethod
    async def analyze(self, envelope: ActionEnvelope, ctx: EngineContext) -> StageResult:
        raise NotImplementedError


class DecisionProvider(ABC):
    name: str

    @abstractmethod
    async def evaluate(self, envelope: ActionEnvelope, ctx: EngineContext) -> StageResult | None:
        raise NotImplementedError


class ApprovalProvider(ABC):
    @abstractmethod
    async def create(self, envelope: ActionEnvelope, ctx: EngineContext) -> ApprovalRequest | None:
        raise NotImplementedError

    @abstractmethod
    async def check(self, approval_id: str) -> str:
        raise NotImplementedError


class TelemetrySink(ABC):
    name: str

    @abstractmethod
    async def emit(self, event: TelemetryEvent) -> None:
        raise NotImplementedError
