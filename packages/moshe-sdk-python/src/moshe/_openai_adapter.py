from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypeVar

from ._adapter import AdapterResult, GenericAdapter
from ._types import DecisionEnvelope, ToolArguments

T = TypeVar("T")


@dataclass(frozen=True)
class OpenAIFunction:
    name: str
    arguments: str


@dataclass(frozen=True)
class OpenAIToolCall:
    id: str
    function: OpenAIFunction
    type: str = "function"


class OpenAIAdapter:
    def __init__(
        self,
        evaluator: Any,
        *,
        framework: str = "openai",
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

    async def wrap_tool_call(
        self,
        *,
        tool_call: OpenAIToolCall,
        execute: Callable[[], Awaitable[T]],
        parsed_arguments: dict[str, Any] | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> T:
        return await self._get_adapter(session_id).wrap_tool_call(
            execute=execute,
            **self._build_kwargs(tool_call, parsed_arguments, agent_id),
        )

    async def try_wrap_tool_call(
        self,
        *,
        tool_call: OpenAIToolCall,
        execute: Callable[[], Awaitable[T]],
        parsed_arguments: dict[str, Any] | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> AdapterResult[T]:
        return await self._get_adapter(session_id).try_wrap_tool_call(
            execute=execute,
            **self._build_kwargs(tool_call, parsed_arguments, agent_id),
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

    def _parse_arguments(self, raw: str) -> dict[str, Any]:
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _to_tool_arguments(self, args: dict[str, Any]) -> ToolArguments:
        kwargs: dict[str, Any] = {}

        for key in ["command", "shell", "path", "content", "url", "method", "subject", "body"]:
            value = args.get(key)
            if isinstance(value, str):
                kwargs[key] = value

        agent_authored = args.get("agentAuthored")
        if isinstance(agent_authored, bool):
            kwargs["agent_authored"] = agent_authored

        headers = args.get("headers")
        if isinstance(headers, dict) and all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
            kwargs["headers"] = dict(headers)

        params = args.get("params")
        if isinstance(params, dict) and all(
            isinstance(key, str) and isinstance(value, (str, int, float, bool)) for key, value in params.items()
        ):
            kwargs["params"] = dict(params)

        recipients = args.get("recipients")
        if isinstance(recipients, list) and all(isinstance(recipient, str) for recipient in recipients):
            kwargs["recipients"] = list(recipients)

        return ToolArguments(**kwargs)

    def _build_kwargs(
        self,
        tool_call: OpenAIToolCall,
        parsed_arguments: dict[str, Any] | None,
        agent_id: str | None,
    ) -> dict[str, Any]:
        args = parsed_arguments if parsed_arguments is not None else self._parse_arguments(tool_call.function.arguments)
        kwargs: dict[str, Any] = {
            "tool_name": tool_call.function.name,
            "action_type": "tool_call",
            "operation": "call",
            "arguments": self._to_tool_arguments(args),
        }
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        return kwargs
