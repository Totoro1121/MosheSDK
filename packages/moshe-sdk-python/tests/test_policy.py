from __future__ import annotations

import warnings

import pytest

from moshe import (
    MemoryStore,
    OutboundRule,
    PolicyConfig,
    RecipientThreshold,
    StaticPolicyProvider,
    ToolArguments,
    apply_preset_overlays,
)
from moshe._interfaces import EngineContext
from moshe._policy import _match_path, evaluate_static_policy
from moshe._types import ActionEnvelope, ReasonCode


def make_envelope(**kwargs: object) -> ActionEnvelope:
    base: dict[str, object] = {
        "action_id": "a1",
        "session_id": "s1",
        "timestamp": "2025-01-01T00:00:00Z",
        "framework": "test",
        "action_type": "tool_call",
        "operation": "call",
        "tool_name": "search",
        "arguments": ToolArguments(),
    }
    base.update(kwargs)
    return ActionEnvelope(
        **base,
    )


async def make_ctx(policy: PolicyConfig) -> EngineContext:
    store = MemoryStore()
    return EngineContext(session_id="s1", policy=policy, session_store=store, artifact_store=store, started_at=0.0)


@pytest.mark.asyncio
async def test_evaluate_static_policy_allow_empty_policy() -> None:
    result = await evaluate_static_policy(make_envelope(), await make_ctx(PolicyConfig()))
    assert result.decision == "ALLOW"


@pytest.mark.asyncio
async def test_evaluate_static_policy_blocks_forbidden_tool() -> None:
    result = await evaluate_static_policy(
        make_envelope(tool_name="dangerous_tool"),
        await make_ctx(PolicyConfig(forbidden_tools=["dangerous_tool"])),
    )
    assert result.decision == "BLOCK"
    assert result.reason_codes == [ReasonCode.FORBIDDEN_TOOL]


@pytest.mark.asyncio
async def test_evaluate_static_policy_blocks_forbidden_command() -> None:
    result = await evaluate_static_policy(
        make_envelope(arguments=ToolArguments(command="rm -rf /")),
        await make_ctx(PolicyConfig(forbidden_commands=[r"rm\s+-rf"])),
    )
    assert result.decision == "BLOCK"
    assert result.reason_codes == [ReasonCode.FORBIDDEN_COMMAND]


@pytest.mark.asyncio
async def test_evaluate_static_policy_blocks_forbidden_path() -> None:
    result = await evaluate_static_policy(
        make_envelope(arguments=ToolArguments(path="/etc/passwd")),
        await make_ctx(PolicyConfig(forbidden_paths=["/etc/**"])),
    )
    assert result.decision == "BLOCK"
    assert result.reason_codes == [ReasonCode.FORBIDDEN_PATH]


@pytest.mark.asyncio
async def test_evaluate_static_policy_reviews_sensitive_file() -> None:
    result = await evaluate_static_policy(
        make_envelope(arguments=ToolArguments(path="/app/.env")),
        await make_ctx(PolicyConfig(sensitive_files=[".env"])),
    )
    assert result.decision == "REVIEW"
    assert ReasonCode.SENSITIVE_FILE_ACCESS in (result.reason_codes or [])


@pytest.mark.asyncio
async def test_evaluate_static_policy_reviews_recipient_threshold() -> None:
    result = await evaluate_static_policy(
        make_envelope(
            action_type="message_send",
            tool_name="send_message",
            arguments=ToolArguments(recipients=["a", "b", "c"]),
        ),
        await make_ctx(PolicyConfig(recipient_threshold=RecipientThreshold(max_recipients=2, action="review"))),
    )
    assert result.decision == "REVIEW"
    assert ReasonCode.RECIPIENT_THRESHOLD_EXCEEDED in (result.reason_codes or [])


@pytest.mark.asyncio
async def test_evaluate_static_policy_blocks_outbound_rule() -> None:
    result = await evaluate_static_policy(
        make_envelope(
            action_type="outbound_request",
            arguments=ToolArguments(url="https://evil.com/data"),
            outbound_targets=["https://evil.com/data"],
        ),
        await make_ctx(PolicyConfig(outbound_rules=[OutboundRule(pattern="evil.com", action="block")])),
    )
    assert result.decision == "BLOCK"
    assert result.reason_codes == [ReasonCode.OUTBOUND_BLOCKED]


@pytest.mark.asyncio
async def test_collect_then_decide_prefers_block_over_review() -> None:
    result = await evaluate_static_policy(
        make_envelope(arguments=ToolArguments(path="/etc/passwd", command="printenv API_KEY")),
        await make_ctx(
            PolicyConfig(
                forbidden_paths=["/etc/**"],
                sensitive_env_keys=["API_KEY"],
            )
        ),
    )
    assert result.decision == "BLOCK"
    assert ReasonCode.FORBIDDEN_PATH in (result.reason_codes or [])


@pytest.mark.parametrize(
    ("path", "pattern"),
    [
        (".env", "*.env"),
        ("/root/secrets/file.txt", "/root/**"),
        ("C:\\Users\\Admin\\file.txt", "c:/users/**"),
    ],
)
def test_match_path_patterns(path: str, pattern: str) -> None:
    assert _match_path(path, pattern)


def test_apply_preset_overlays_union_merges_arrays_developer_first() -> None:
    merged = apply_preset_overlays(
        PolicyConfig(forbidden_tools=["custom"], preset_overlays=["assistant-with-tools"]),
        ["assistant-with-tools"],
    )
    assert merged.forbidden_tools is not None
    assert merged.forbidden_tools[0] == "custom"
    assert "shell" in merged.forbidden_tools


def test_apply_preset_overlays_developer_recipient_threshold_wins() -> None:
    merged = apply_preset_overlays(
        PolicyConfig(
            recipient_threshold=RecipientThreshold(max_recipients=2, action="block"),
            preset_overlays=["assistant-with-tools"],
        ),
        ["assistant-with-tools"],
    )
    assert merged.recipient_threshold == RecipientThreshold(max_recipients=2, action="block")


def test_unknown_preset_name_warns_and_skips() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        merged = apply_preset_overlays(PolicyConfig(), ["missing-preset"])
    assert len(caught) == 1
    assert merged == PolicyConfig()


@pytest.mark.asyncio
async def test_file_policy_provider_loads_json(tmp_path: object) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"version":"0.1.0","forbidden_tools":["danger"]}', encoding="utf-8")
    from moshe import FilePolicyProvider

    provider = FilePolicyProvider(path)
    config = await provider.get_effective()
    assert config.forbidden_tools == ["danger"]


@pytest.mark.asyncio
async def test_static_policy_provider_applies_presets() -> None:
    provider = StaticPolicyProvider(PolicyConfig(preset_overlays=["assistant-with-tools"]))
    effective = await provider.get_effective()
    assert effective.forbidden_tools is not None
    assert "shell" in effective.forbidden_tools
