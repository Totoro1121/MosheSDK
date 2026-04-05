from __future__ import annotations

import asyncio
import json
import urllib.request
from inspect import isawaitable
from typing import Any, Callable, cast

from ._interfaces import DecisionProvider, EngineContext, StageResult
from ._types import ActionEnvelope, MatchedRule, dataclass_to_camel_dict, reason_code_values


VALID_REASON_CODES = reason_code_values()


class NoopDecisionProvider(DecisionProvider):
    name = "noop"

    async def evaluate(self, _envelope: ActionEnvelope, _ctx: EngineContext) -> StageResult | None:
        return None


DecisionCallback = Callable[[ActionEnvelope, EngineContext], Any]


class CallbackDecisionProvider(DecisionProvider):
    def __init__(self, callback: DecisionCallback, name: str = "callback") -> None:
        self.name = name
        self._callback = callback

    async def evaluate(self, envelope: ActionEnvelope, ctx: EngineContext) -> StageResult | None:
        result = self._callback(envelope, ctx)
        if isawaitable(result):
            return cast(StageResult | None, await result)
        return cast(StageResult | None, result)


class HttpDecisionProvider(DecisionProvider):
    def __init__(
        self,
        url: str,
        timeout_ms: int = 5000,
        headers: dict[str, str] | None = None,
        on_error: str = "null",
        name: str = "http",
    ) -> None:
        self.name = name
        self.url = url
        self._timeout_ms = timeout_ms
        self._headers = headers or {}
        self._on_error = on_error

    async def evaluate(self, envelope: ActionEnvelope, _ctx: EngineContext) -> StageResult | None:
        try:
            return await asyncio.to_thread(self._sync_fetch, envelope)
        except Exception as error:
            return self._handle_error(error)

    def _sync_fetch(self, envelope: ActionEnvelope) -> StageResult | None:
        payload = json.dumps(
            {"envelope": dataclass_to_camel_dict(envelope), "sessionId": envelope.session_id}
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json", **self._headers},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self._timeout_ms / 1000) as response:
            body = json.loads(response.read())
        return self._parse_response(body)

    def _parse_response(self, body: Any) -> StageResult | None:
        if not isinstance(body, dict) or not isinstance(body.get("passed"), bool):
            return self._handle_error(ValueError('Response missing required "passed" field'))

        result = StageResult(stage="decision_provider", passed=body["passed"])
        if body.get("decision") in {"ALLOW", "BLOCK", "REVIEW"}:
            result.decision = body["decision"]

        raw_reason_codes = body.get("reasonCodes")
        if isinstance(raw_reason_codes, list):
            result.reason_codes = [
                value for value in raw_reason_codes if isinstance(value, str) and value in VALID_REASON_CODES
            ]

        raw_matched_rules = body.get("matchedRules")
        if isinstance(raw_matched_rules, list):
            matched_rules = [self._parse_matched_rule(entry) for entry in raw_matched_rules]
            valid_rules = [rule for rule in matched_rules if rule is not None]
            if valid_rules:
                result.matched_rules = valid_rules

        summary = body.get("summary")
        if isinstance(summary, str) and summary.strip():
            result.enrichments = {"summary": summary}

        return result

    def _parse_matched_rule(self, value: Any) -> MatchedRule | None:
        if not isinstance(value, dict):
            return None
        rule_id = value.get("ruleId")
        rule_type = value.get("ruleType")
        matched_value = value.get("matchedValue")
        if isinstance(rule_id, str) and isinstance(rule_type, str) and isinstance(matched_value, str):
            return MatchedRule(rule_id=rule_id, rule_type=rule_type, matched_value=matched_value)
        return None

    def _handle_error(self, error: Exception) -> StageResult | None:
        if self._on_error == "throw":
            raise error
        return None
