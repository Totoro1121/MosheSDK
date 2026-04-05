from __future__ import annotations

from dataclasses import dataclass
from inspect import isawaitable
from typing import Any, Awaitable, Callable, Generic, Protocol, TypeVar

from ._types import ApprovalRequest, DecisionEnvelope, ToolArguments

T = TypeVar("T")


class SessionEvaluatorProtocol(Protocol):
    async def evaluate(self, **kwargs: Any) -> DecisionEnvelope:
        ...


class MosheAdapterError(Exception):
    def __init__(self, message: str, decision: DecisionEnvelope) -> None:
        super().__init__(message)
        self.decision = decision


class BlockedActionError(MosheAdapterError):
    def __init__(self, decision: DecisionEnvelope) -> None:
        super().__init__(f"Action blocked: {decision.summary}", decision)


class ReviewRequiredError(MosheAdapterError):
    def __init__(self, decision: DecisionEnvelope) -> None:
        super().__init__(f"Action requires review: {decision.summary}", decision)
        self.approval_request = decision.approval_request


@dataclass(frozen=True)
class AllowResult(Generic[T]):
    value: T
    decision: DecisionEnvelope
    outcome: str = "ALLOW"


@dataclass(frozen=True)
class BlockResult:
    decision: DecisionEnvelope
    outcome: str = "BLOCK"


@dataclass(frozen=True)
class ReviewResult:
    decision: DecisionEnvelope
    approval_request: ApprovalRequest | None = None
    outcome: str = "REVIEW"


AdapterResult = AllowResult[T] | BlockResult | ReviewResult


class GenericAdapter:
    def __init__(
        self,
        evaluator: SessionEvaluatorProtocol,
        framework: str = "generic",
        on_block: Callable[[DecisionEnvelope], Awaitable[None] | None] | None = None,
        on_review: Callable[[DecisionEnvelope], Awaitable[None] | None] | None = None,
    ) -> None:
        self._evaluator = evaluator
        self._framework = framework
        self._on_block = on_block
        self._on_review = on_review

    async def wrap_tool_call(
        self,
        *,
        execute: Callable[[], Awaitable[T]],
        tool_name: str,
        action_type: str = "tool_call",
        operation: str = "call",
        arguments: ToolArguments | None = None,
        referenced_paths: list[str] | None = None,
        outbound_targets: list[str] | None = None,
        agent_id: str | None = None,
        cwd: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> T:
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type=action_type,
            operation=operation,
            tool_name=tool_name,
            arguments=arguments or ToolArguments(),
            referenced_paths=referenced_paths,
            outbound_targets=outbound_targets,
            agent_id=agent_id,
            cwd=cwd,
            metadata=metadata,
        )
        return await self._handle_decision(decision, execute)

    async def try_wrap_tool_call(self, **kwargs: Any) -> AdapterResult[Any]:
        execute = kwargs.pop("execute")
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type=kwargs.pop("action_type", "tool_call"),
            operation=kwargs.pop("operation", "call"),
            tool_name=kwargs.pop("tool_name"),
            arguments=kwargs.pop("arguments", ToolArguments()),
            referenced_paths=kwargs.pop("referenced_paths", None),
            outbound_targets=kwargs.pop("outbound_targets", None),
            agent_id=kwargs.pop("agent_id", None),
            cwd=kwargs.pop("cwd", None),
            metadata=kwargs.pop("metadata", None),
        )
        return await self._handle_decision_as_result(decision, execute)

    async def wrap_command(
        self,
        *,
        execute: Callable[[], Awaitable[T]],
        command: str,
        tool_name: str = "shell",
        shell: str | None = None,
        referenced_paths: list[str] | None = None,
        agent_id: str | None = None,
        cwd: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> T:
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type="command_exec",
            operation="exec",
            tool_name=tool_name,
            arguments=ToolArguments(command=command, shell=shell),
            referenced_paths=referenced_paths,
            agent_id=agent_id,
            cwd=cwd,
            metadata=metadata,
        )
        return await self._handle_decision(decision, execute)

    async def try_wrap_command(self, **kwargs: Any) -> AdapterResult[Any]:
        execute = kwargs.pop("execute")
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type="command_exec",
            operation="exec",
            tool_name=kwargs.pop("tool_name", "shell"),
            arguments=ToolArguments(command=kwargs.pop("command"), shell=kwargs.pop("shell", None)),
            referenced_paths=kwargs.pop("referenced_paths", None),
            agent_id=kwargs.pop("agent_id", None),
            cwd=kwargs.pop("cwd", None),
            metadata=kwargs.pop("metadata", None),
        )
        return await self._handle_decision_as_result(decision, execute)

    async def wrap_outbound(
        self,
        *,
        execute: Callable[[], Awaitable[T]],
        url: str,
        method: str | None = None,
        headers: dict[str, str] | None = None,
        tool_name: str = "http_request",
        outbound_targets: list[str] | None = None,
        agent_id: str | None = None,
        cwd: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> T:
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type="outbound_request",
            operation=(method or "GET").lower(),
            tool_name=tool_name,
            arguments=ToolArguments(url=url, method=method or "GET", headers=headers),
            outbound_targets=[url, *(outbound_targets or [])],
            agent_id=agent_id,
            cwd=cwd,
            metadata=metadata,
        )
        return await self._handle_decision(decision, execute)

    async def try_wrap_outbound(self, **kwargs: Any) -> AdapterResult[Any]:
        execute = kwargs.pop("execute")
        url = kwargs.pop("url")
        method = kwargs.pop("method", None)
        headers = kwargs.pop("headers", None)
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type="outbound_request",
            operation=(method or "GET").lower(),
            tool_name=kwargs.pop("tool_name", "http_request"),
            arguments=ToolArguments(url=url, method=method or "GET", headers=headers),
            outbound_targets=[url, *(kwargs.pop("outbound_targets", None) or [])],
            agent_id=kwargs.pop("agent_id", None),
            cwd=kwargs.pop("cwd", None),
            metadata=kwargs.pop("metadata", None),
        )
        return await self._handle_decision_as_result(decision, execute)

    async def wrap_message(
        self,
        *,
        execute: Callable[[], Awaitable[T]],
        recipients: list[str],
        tool_name: str = "send_message",
        subject: str | None = None,
        body: str | None = None,
        agent_id: str | None = None,
        cwd: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> T:
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type="message_send",
            operation="send",
            tool_name=tool_name,
            arguments=ToolArguments(recipients=recipients, subject=subject, body=body),
            agent_id=agent_id,
            cwd=cwd,
            metadata=metadata,
        )
        return await self._handle_decision(decision, execute)

    async def try_wrap_message(self, **kwargs: Any) -> AdapterResult[Any]:
        execute = kwargs.pop("execute")
        decision = await self._evaluator.evaluate(
            framework=self._framework,
            action_type="message_send",
            operation="send",
            tool_name=kwargs.pop("tool_name", "send_message"),
            arguments=ToolArguments(
                recipients=kwargs.pop("recipients"),
                subject=kwargs.pop("subject", None),
                body=kwargs.pop("body", None),
            ),
            agent_id=kwargs.pop("agent_id", None),
            cwd=kwargs.pop("cwd", None),
            metadata=kwargs.pop("metadata", None),
        )
        return await self._handle_decision_as_result(decision, execute)

    async def _handle_decision(self, decision: DecisionEnvelope, execute: Callable[[], Awaitable[T]]) -> T:
        if decision.decision == "ALLOW":
            return await execute()
        if decision.decision == "BLOCK":
            if self._on_block is not None:
                result = self._on_block(decision)
                if isawaitable(result):
                    await result
            raise BlockedActionError(decision)
        if self._on_review is not None:
            result = self._on_review(decision)
            if isawaitable(result):
                await result
        raise ReviewRequiredError(decision)

    async def _handle_decision_as_result(
        self, decision: DecisionEnvelope, execute: Callable[[], Awaitable[T]]
    ) -> AdapterResult[T]:
        if decision.decision == "ALLOW":
            return AllowResult(value=await execute(), decision=decision)
        if decision.decision == "BLOCK":
            return BlockResult(decision=decision)
        return ReviewResult(decision=decision, approval_request=decision.approval_request)
