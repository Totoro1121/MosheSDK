from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from ._interfaces import ApprovalProvider, EngineContext
from ._types import ActionEnvelope, ApprovalRequest, clone_value


class ApprovalStoreProtocol(Protocol):
    async def get_approval_replay(self, approval_id: str) -> Any | None:
        ...

    async def put_approval_replay(self, entry: Any) -> None:
        ...


@dataclass(frozen=True)
class ApprovalContext:
    request: ApprovalRequest
    envelope: ActionEnvelope
    session_id: str


ApprovalResolution = str


@dataclass
class PendingApproval:
    approval_id: str
    fingerprint: str
    session_id: str
    created_at: str
    expires_at: str
    resolution: str | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _stable_sorted_args(value: Any) -> Any:
    if isinstance(value, list):
        return [_stable_sorted_args(item) for item in value]
    if isinstance(value, dict):
        return {key: _stable_sorted_args(value[key]) for key in sorted(value)}
    return value


def _is_expired(expires_at: str) -> bool:
    normalized = expires_at.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized) <= datetime.now(timezone.utc)


def _compute_fingerprint(envelope: ActionEnvelope, session_id: str) -> str:
    stable = json.dumps(
        {
            "s": session_id,
            "a": envelope.action_type,
            "t": envelope.tool_name,
            "g": _stable_sorted_args(clone_value(envelope.arguments.__dict__)),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(stable.encode()).hexdigest()[:32]


class InProcessApprovalProvider(ApprovalProvider):
    def __init__(
        self,
        store: ApprovalStoreProtocol,
        ttl_ms: int = 300_000,
        on_approval_required: Any | None = None,
    ) -> None:
        self._store = store
        self._ttl_ms = ttl_ms
        self._on_approval_required = on_approval_required
        self._pending_by_id: dict[str, PendingApproval] = {}
        self._pending_by_fingerprint: dict[str, str] = {}

    async def create(self, envelope: ActionEnvelope, ctx: EngineContext) -> ApprovalRequest | None:
        self._cleanup_expired()
        fingerprint = _compute_fingerprint(envelope, ctx.session_id)
        replay = await ctx.session_store.get_approval_replay(fingerprint)
        if (
            replay is not None
            and replay.session_id == ctx.session_id
            and replay.resolved_decision == "ALLOW_SESSION"
            and not _is_expired(replay.expires_at)
        ):
            return None

        existing_id = self._pending_by_fingerprint.get(fingerprint)
        if existing_id is not None:
            existing = self._pending_by_id.get(existing_id)
            if existing is not None and existing.resolution == "ALLOW_ONCE":
                del self._pending_by_id[existing_id]
                del self._pending_by_fingerprint[fingerprint]
                return None

        previous_id = self._pending_by_fingerprint.get(fingerprint)
        if previous_id is not None:
            previous = self._pending_by_id.get(previous_id)
            if previous is not None and previous.resolution == "BLOCK":
                del self._pending_by_id[previous_id]

        expires_at = (
            datetime.now(timezone.utc) + timedelta(milliseconds=self._ttl_ms)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        request = ApprovalRequest(approval_id=str(uuid.uuid4()), expires_at=expires_at)
        pending = PendingApproval(
            approval_id=request.approval_id,
            fingerprint=fingerprint,
            session_id=ctx.session_id,
            created_at=_utc_now_iso(),
            expires_at=expires_at,
        )
        self._pending_by_id[request.approval_id] = pending
        self._pending_by_fingerprint[fingerprint] = request.approval_id

        if self._on_approval_required is not None:
            callback_context = ApprovalContext(request=request, envelope=envelope, session_id=ctx.session_id)
            result = self._on_approval_required(callback_context)
            if hasattr(result, "__await__"):
                try:
                    await result
                except Exception:
                    pass

        return request

    async def resolve(self, approval_id: str, decision: str) -> None:
        self._cleanup_expired()
        pending = self._pending_by_id.get(approval_id)
        if pending is None or _is_expired(pending.expires_at):
            raise ValueError(f'Unknown or expired approval_id: "{approval_id}"')
        pending.resolution = decision
        if decision == "ALLOW_SESSION":
            from ._store import ApprovalReplayEntry

            await self._store.put_approval_replay(
                ApprovalReplayEntry(
                    approval_id=pending.fingerprint,
                    session_id=pending.session_id,
                    resolved_decision="ALLOW_SESSION",
                    resolved_at=_utc_now_iso(),
                    expires_at=(
                        datetime.now(timezone.utc) + timedelta(days=30)
                    ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                )
            )

    async def check(self, approval_id: str) -> str:
        self._cleanup_expired()
        pending = self._pending_by_id.get(approval_id)
        if pending is None:
            raise ValueError(f'Unknown or expired approval_id: "{approval_id}"')
        return pending.resolution or "PENDING"

    def _cleanup_expired(self) -> None:
        for approval_id, pending in list(self._pending_by_id.items()):
            if pending.resolution is None and _is_expired(pending.expires_at):
                del self._pending_by_id[approval_id]
                self._pending_by_fingerprint.pop(pending.fingerprint, None)
