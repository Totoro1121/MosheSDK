from __future__ import annotations

import json
from urllib.error import URLError

import pytest
import warnings

from moshe import CallbackDecisionProvider, HttpDecisionProvider, NoopDecisionProvider, PolicyConfig, ReasonCode, ToolArguments
from moshe._interfaces import EngineContext, StageResult
from moshe._store import MemoryStore
from moshe._types import ActionEnvelope


def envelope() -> ActionEnvelope:
    return ActionEnvelope(
        action_id="a1",
        session_id="s1",
        timestamp="2025-01-01T00:00:00Z",
        framework="test",
        action_type="tool_call",
        operation="call",
        tool_name="search",
        arguments=ToolArguments(),
    )


def context() -> EngineContext:
    store = MemoryStore()
    return EngineContext(session_id="s1", policy=PolicyConfig(), session_store=store, artifact_store=store, started_at=0.0)


@pytest.mark.asyncio
async def test_noop_decision_provider_returns_none() -> None:
    assert await NoopDecisionProvider().evaluate(envelope(), context()) is None


@pytest.mark.asyncio
async def test_callback_decision_provider_forwards_and_returns() -> None:
    seen: list[object] = []

    async def callback(env: ActionEnvelope, ctx: EngineContext) -> StageResult | None:
        seen.extend([env.action_id, ctx.session_id])
        return StageResult(stage="decision_provider", passed=False, decision="REVIEW", reason_codes=[ReasonCode.COMMAND_INTENT_SUSPICIOUS])

    result = await CallbackDecisionProvider(callback).evaluate(envelope(), context())
    assert seen == ["a1", "s1"]
    assert result is not None
    assert result.decision == "REVIEW"


@pytest.mark.asyncio
async def test_callback_decision_provider_propagates_exception() -> None:
    async def callback(_env: ActionEnvelope, _ctx: EngineContext) -> StageResult | None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await CallbackDecisionProvider(callback).evaluate(envelope(), context())


@pytest.mark.asyncio
async def test_http_decision_provider_returns_none_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = HttpDecisionProvider("https://example.com")
    monkeypatch.setattr(provider, "_sync_fetch", lambda _env: (_ for _ in ()).throw(URLError("down")))
    assert await provider.evaluate(envelope(), context()) is None


@pytest.mark.asyncio
async def test_http_decision_provider_raises_on_error_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = HttpDecisionProvider("https://example.com", on_error="throw")
    monkeypatch.setattr(provider, "_sync_fetch", lambda _env: (_ for _ in ()).throw(URLError("down")))
    with pytest.raises(URLError):
        await provider.evaluate(envelope(), context())


def test_http_decision_provider_parses_valid_response() -> None:
    provider = HttpDecisionProvider("https://example.com")
    result = provider._parse_response(  # type: ignore[attr-defined]
        {
            "passed": False,
            "decision": "REVIEW",
            "reasonCodes": [ReasonCode.COMMAND_INTENT_SUSPICIOUS],
            "summary": "flagged",
        }
    )
    assert result is not None
    assert result.stage == "decision_provider"
    assert result.reason_codes == [ReasonCode.COMMAND_INTENT_SUSPICIOUS]


def test_http_decision_provider_filters_invalid_reason_codes() -> None:
    provider = HttpDecisionProvider("https://example.com")
    result = provider._parse_response(  # type: ignore[attr-defined]
        {
            "passed": False,
            "decision": "REVIEW",
            "reasonCodes": ["BAD", ReasonCode.COMMAND_INTENT_SUSPICIOUS],
        }
    )
    assert result is not None
    assert result.reason_codes == [ReasonCode.COMMAND_INTENT_SUSPICIOUS]


def test_http_decision_provider_drops_malformed_matched_rules() -> None:
    provider = HttpDecisionProvider("https://example.com")
    result = provider._parse_response(  # type: ignore[attr-defined]
        {
            "passed": False,
            "matchedRules": [{"ruleId": "ok", "ruleType": "t", "matchedValue": "x"}, {"bad": "rule"}],
        }
    )
    assert result is not None
    assert result.matched_rules is not None
    assert len(result.matched_rules) == 1


def test_http_decision_provider_warns_on_non_https_url() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        HttpDecisionProvider("http://example.com")
    assert len(caught) == 1


def test_http_decision_provider_strips_sensitive_fields_from_payload() -> None:
    provider = HttpDecisionProvider("https://example.com")
    envelope_with_sensitive = ActionEnvelope(
        action_id="a1",
        session_id="s1",
        timestamp="2025-01-01T00:00:00Z",
        framework="test",
        action_type="tool_call",
        operation="call",
        tool_name="search",
        arguments=ToolArguments(
            command="echo hi",
            content="secret",
            body="body",
            headers={"Authorization": "x"},
            params={"secret": "x"},
        ),
    )

    captured: dict[str, object] = {}

    def fake_urlopen(request: object, timeout: float) -> object:
        captured["body"] = request.data  # type: ignore[attr-defined]

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"passed": true}'

        return Response()

    import urllib.request

    original = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
    try:
        provider._sync_fetch(envelope_with_sensitive)  # type: ignore[attr-defined]
    finally:
        urllib.request.urlopen = original  # type: ignore[assignment]

    body = json.loads(captured["body"].decode())  # type: ignore[index]
    assert body == {
        "envelope": {
            "actionId": "a1",
            "sessionId": "s1",
            "timestamp": "2025-01-01T00:00:00Z",
            "framework": "test",
            "actionType": "tool_call",
            "operation": "call",
            "toolName": "search",
            "arguments": {
                "command": "echo hi",
            },
        },
        "sessionId": "s1",
    }
