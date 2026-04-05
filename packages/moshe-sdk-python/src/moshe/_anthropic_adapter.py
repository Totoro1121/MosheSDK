from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypeVar

from ._adapter import AdapterResult, GenericAdapter
from ._types import DecisionEnvelope, ToolArguments

T = TypeVar("T")


@dataclass(frozen=True)
class AnthropicToolUseBlock:
    id: str
    name: str
    input: dict[str, Any]
    type: str = "tool_use"


class AnthropicAdapter:
    def __init__(
        self,
        evaluator: Any,
        *,
        framework: str = "anthropic",
        on_block: Callable[[DecisionEnvelope], Awaitable[None] | None] | None = None,
        on_review: Callable[[DecisionEnvelope], Awaitable[None] | None] | None = None,
    ) -> None:
        self._evaluator = evaluator
        self._framework = framework
        self._on_block = on_block
        self._on_review = on_review
        self._is_root = hasattr(evaluator, "with_session") and callable(evaluator.with_session)
        self._inner = None if self._is_root else GenericAdapter(
            evaluator,
            framework=framework,
            on_block=on_block,
            on_review=on_review,
        )

    async def wrap_tool_use(
        self,
        *,
        tool_use: AnthropicToolUseBlock,
        execute: Callable[[], Awaitable[T]],
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> T:
        return await self._get_adapter(session_id).wrap_tool_call(
            execute=execute,
            **self._build_kwargs(tool_use, agent_id),
        )

    async def try_wrap_tool_use(
        self,
        *,
        tool_use: AnthropicToolUseBlock,
        execute: Callable[[], Awaitable[T]],
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> AdapterResult[T]:
        return await self._get_adapter(session_id).try_wrap_tool_call(
            execute=execute,
            **self._build_kwargs(tool_use, agent_id),
        )

    def _get_adapter(self, session_id: str | None) -> GenericAdapter:
        if self._is_root:
            if session_id is None or session_id.strip() == "":
                raise ValueError("[MosheSDK] session_id is required when using a root evaluator")
            return GenericAdapter(
                self._evaluator.with_session(session_id),
                framework=self._framework,
                on_block=self._on_block,
                on_review=self._on_review,
            )
        if self._inner is None:
            raise ValueError("[MosheSDK] Internal adapter initialization failed")
        return self._inner

    def _to_tool_arguments(self, input: dict[str, Any]) -> ToolArguments:
        kwargs: dict[str, Any] = {}

        for key in ["command", "shell", "path", "content", "url", "method", "subject", "body"]:
            value = input.get(key)
            if isinstance(value, str):
                kwargs[key] = value

        agent_authored = input.get("agentAuthored")
        if isinstance(agent_authored, bool):
            kwargs["agent_authored"] = agent_authored

        headers = input.get("headers")
        if isinstance(headers, dict) and all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
            kwargs["headers"] = dict(headers)

        params = input.get("params")
        if isinstance(params, dict) and all(
            isinstance(key, str) and isinstance(value, (str, int, float, bool)) for key, value in params.items()
        ):
            kwargs["params"] = dict(params)

        recipients = input.get("recipients")
        if isinstance(recipients, list) and all(isinstance(recipient, str) for recipient in recipients):
            kwargs["recipients"] = list(recipients)

        return ToolArguments(**kwargs)

    def _build_kwargs(self, tool_use: AnthropicToolUseBlock, agent_id: str | None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "tool_name": tool_use.name,
            "action_type": "tool_call",
            "operation": "call",
            "arguments": self._to_tool_arguments(tool_use.input),
        }
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        return kwargs
