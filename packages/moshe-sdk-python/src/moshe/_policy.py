from __future__ import annotations

import asyncio
import fnmatch
import json
import re
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ._interfaces import EngineContext, PolicyProvider, StageResult
from ._outbound_utils import matches_outbound_pattern
from ._types import (
    ActionEnvelope,
    Decision,
    DecisionEnvelope,
    MatchedRule,
    OutboundRule,
    PolicyConfig,
    ReasonCode,
    RecipientThreshold,
    clone_dataclass,
)


def _normalize_path(value: str) -> str:
    return re.sub(r"/+", "/", value.replace("\\", "/")).strip()


def _basename(value: str) -> str:
    normalized = _normalize_path(value)
    parts = [part for part in normalized.split("/") if part]
    return parts[-1] if parts else normalized


def _collect_path_candidates(envelope: ActionEnvelope) -> list[str]:
    values: set[str] = set()
    if envelope.arguments.path and envelope.arguments.path.strip():
        values.add(envelope.arguments.path)
    for path in envelope.referenced_paths or []:
        if path.strip():
            values.add(path)
    return list(values)


def _collect_command_candidates(envelope: ActionEnvelope) -> list[str]:
    values: list[str] = []
    for candidate in [envelope.arguments.command, envelope.arguments.shell]:
        if isinstance(candidate, str) and candidate.strip():
            values.append(candidate)
    return values


def _collect_outbound_targets(envelope: ActionEnvelope) -> list[str]:
    values: set[str] = set()
    if envelope.arguments.url and envelope.arguments.url.strip():
        values.add(envelope.arguments.url)
    for target in envelope.outbound_targets or []:
        if target.strip():
            values.add(target)
    return list(values)


def _match_path(path: str, pattern: str) -> bool:
    normalized_path = _normalize_path(path).lower()
    normalized_pattern = _normalize_path(pattern).lower()
    if "**" in normalized_pattern:
        regex = re.escape(normalized_pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        return re.fullmatch(regex, normalized_path, re.IGNORECASE) is not None
    return fnmatch.fnmatch(normalized_path, normalized_pattern)


def _rule_result(
    *,
    decision: str,
    reason_code: str,
    matched_rules: list[MatchedRule] | None,
    summary: str,
) -> StageResult:
    enrichments: dict[str, object] = {"summary": summary}
    severity = resolve_severity(reason_code)
    if severity is not None:
        enrichments["severity"] = severity
    return StageResult(
        stage="static_policy",
        passed=False,
        decision=cast(Decision, decision),
        reason_codes=[reason_code],
        matched_rules=matched_rules,
        enrichments=enrichments,
    )


def resolve_severity(reason_code: str) -> str | None:
    if reason_code in {
        ReasonCode.FORBIDDEN_TOOL,
        ReasonCode.FORBIDDEN_COMMAND,
        ReasonCode.FORBIDDEN_PATH,
        ReasonCode.FORBIDDEN_FILE,
        ReasonCode.OUTBOUND_BLOCKED,
    }:
        return "high"
    if reason_code in {
        ReasonCode.SENSITIVE_FILE_ACCESS,
        ReasonCode.SENSITIVE_ENV_ACCESS,
        ReasonCode.RECIPIENT_THRESHOLD_EXCEEDED,
    }:
        return "medium"
    return None


def _evaluate_forbidden_tool(envelope: ActionEnvelope, policy: PolicyConfig) -> StageResult | None:
    if envelope.tool_name not in (policy.forbidden_tools or []):
        return None
    return _rule_result(
        decision="BLOCK",
        reason_code=ReasonCode.FORBIDDEN_TOOL,
        matched_rules=[
            MatchedRule(
                rule_id=f"forbiddenTool:{envelope.tool_name}",
                rule_type="forbidden_tool",
                matched_value=envelope.tool_name,
            )
        ],
        summary=f'Blocked forbidden tool "{envelope.tool_name}".',
    )


def _evaluate_forbidden_command(envelope: ActionEnvelope, policy: PolicyConfig) -> StageResult | None:
    commands = _collect_command_candidates(envelope)
    if not commands:
        return None
    for pattern in policy.forbidden_commands or []:
        expression = re.compile(pattern, re.IGNORECASE)
        for command in commands:
            if expression.search(command):
                return _rule_result(
                    decision="BLOCK",
                    reason_code=ReasonCode.FORBIDDEN_COMMAND,
                    matched_rules=[
                        MatchedRule(
                            rule_id=f"forbiddenCommand:{pattern}",
                            rule_type="forbidden_command",
                            matched_value=command,
                        )
                    ],
                    summary="Blocked forbidden command execution.",
                )
    return None


def _evaluate_forbidden_path(envelope: ActionEnvelope, policy: PolicyConfig) -> StageResult | None:
    for candidate in _collect_path_candidates(envelope):
        normalized = _normalize_path(candidate)
        for pattern in policy.forbidden_paths or []:
            if _match_path(normalized, pattern):
                return _rule_result(
                    decision="BLOCK",
                    reason_code=ReasonCode.FORBIDDEN_PATH,
                    matched_rules=[
                        MatchedRule(
                            rule_id=f"forbiddenPath:{pattern}",
                            rule_type="forbidden_path",
                            matched_value=normalized,
                        )
                    ],
                    summary=f'Blocked access to forbidden path "{normalized}".',
                )
    return None


def _evaluate_forbidden_file(envelope: ActionEnvelope, policy: PolicyConfig) -> StageResult | None:
    forbidden = {item.strip() for item in policy.forbidden_files or [] if item.strip()}
    if not forbidden:
        return None
    for candidate in _collect_path_candidates(envelope):
        file_name = _basename(candidate)
        if file_name in forbidden:
            return _rule_result(
                decision="BLOCK",
                reason_code=ReasonCode.FORBIDDEN_FILE,
                matched_rules=[
                    MatchedRule(
                        rule_id=f"forbiddenFile:{file_name}",
                        rule_type="forbidden_file",
                        matched_value=candidate,
                    )
                ],
                summary=f'Blocked access to forbidden file "{file_name}".',
            )
    return None


def _evaluate_sensitive_files(envelope: ActionEnvelope, policy: PolicyConfig) -> StageResult | None:
    sensitive = {_basename(value).lower() for value in policy.sensitive_files or [] if value.strip()}
    if not sensitive:
        return None
    for candidate in _collect_path_candidates(envelope):
        file_name = _basename(candidate).lower()
        if file_name in sensitive:
            return _rule_result(
                decision="REVIEW",
                reason_code=ReasonCode.SENSITIVE_FILE_ACCESS,
                matched_rules=[
                    MatchedRule(
                        rule_id=f"sensitiveFile:{file_name}",
                        rule_type="sensitive_file",
                        matched_value=candidate,
                    )
                ],
                summary=f'Action references sensitive file "{file_name}".',
            )
    return None


def _evaluate_sensitive_env_keys(envelope: ActionEnvelope, policy: PolicyConfig) -> StageResult | None:
    commands = _collect_command_candidates(envelope)
    if not commands:
        return None
    for raw_key in policy.sensitive_env_keys or []:
        key = raw_key.strip().upper()
        if key == "":
            continue
        patterns = [f"${key}", f"%{key}%", f"printenv {key}", f"env {key}"]
        for command in commands:
            normalized = command.lower()
            if any(pattern.lower() in normalized for pattern in patterns):
                return _rule_result(
                    decision="REVIEW",
                    reason_code=ReasonCode.SENSITIVE_ENV_ACCESS,
                    matched_rules=[
                        MatchedRule(
                            rule_id=f"sensitiveEnv:{key}",
                            rule_type="sensitive_env",
                            matched_value=key,
                        )
                    ],
                    summary=f'Action references sensitive environment key "{key}".',
                )
    return None


def _evaluate_outbound_rules(targets: list[str], rules: list[OutboundRule]) -> StageResult | None:
    if not targets or not rules:
        return None
    for target in targets:
        target_explicitly_allowed = False
        for rule in rules:
            if not matches_outbound_pattern(target, rule.pattern.strip()):
                continue
            if rule.action == "allow":
                target_explicitly_allowed = True
                break
            return _rule_result(
                decision="BLOCK",
                reason_code=ReasonCode.OUTBOUND_BLOCKED,
                matched_rules=[
                    MatchedRule(
                        rule_id=f"outboundRule:{rule.pattern.strip()}",
                        rule_type="outbound_rule",
                        matched_value=target,
                    )
                ],
                summary=f'Blocked outbound target "{target}".',
            )
        if target_explicitly_allowed:
            continue
    return None


def _evaluate_recipient_threshold(envelope: ActionEnvelope, policy: PolicyConfig) -> StageResult | None:
    threshold = policy.recipient_threshold
    recipients = envelope.arguments.recipients
    if threshold is None or not recipients:
        return None
    if len(recipients) <= threshold.max_recipients:
        return None
    decision = "BLOCK" if threshold.action == "block" else "REVIEW"
    return _rule_result(
        decision=decision,
        reason_code=ReasonCode.RECIPIENT_THRESHOLD_EXCEEDED,
        matched_rules=[
            MatchedRule(
                rule_id="recipientThreshold",
                rule_type="recipient_threshold",
                matched_value=str(len(recipients)),
            )
        ],
        summary=f"Recipient threshold exceeded with {len(recipients)} recipients.",
    )


async def evaluate_static_policy(envelope: ActionEnvelope, ctx: EngineContext) -> StageResult:
    results = [
        result
        for result in [
            _evaluate_forbidden_tool(envelope, ctx.policy),
            _evaluate_forbidden_command(envelope, ctx.policy),
            _evaluate_forbidden_path(envelope, ctx.policy),
            _evaluate_forbidden_file(envelope, ctx.policy),
            _evaluate_sensitive_files(envelope, ctx.policy),
            _evaluate_sensitive_env_keys(envelope, ctx.policy),
            _evaluate_outbound_rules(_collect_outbound_targets(envelope), ctx.policy.outbound_rules or []),
            _evaluate_recipient_threshold(envelope, ctx.policy),
        ]
        if result is not None
    ]

    block = next((result for result in results if result.decision == "BLOCK"), None)
    if block is not None:
        return block

    reviews = [result for result in results if result.decision == "REVIEW"]
    if reviews:
        reason_codes = list(dict.fromkeys(code for result in reviews for code in result.reason_codes or []))
        matched_rules = [rule for result in reviews for rule in result.matched_rules or []]
        summaries = [
            summary
            for result in reviews
            for summary in [result.enrichments.get("summary") if result.enrichments else None]
            if isinstance(summary, str) and summary
        ]
        return StageResult(
            stage="static_policy",
            passed=False,
            decision="REVIEW",
            reason_codes=reason_codes,
            matched_rules=matched_rules or None,
            enrichments={
                "summary": f"Action requires review: {' '.join(summaries)}".strip(),
                "severity": "medium",
            },
        )

    return StageResult(
        stage="static_policy",
        passed=True,
        decision="ALLOW",
        reason_codes=[ReasonCode.NO_POLICY_MATCH],
        enrichments={"summary": "No blocking policy rule matched."},
    )


def decision_from_results(results: list[StageResult]) -> str:
    if any(result.decision == "BLOCK" for result in results):
        return "BLOCK"
    last = results[-1] if results else None
    if (
        last is not None
        and last.stage == "approval"
        and last.decision == "ALLOW"
        and any(result.decision == "REVIEW" for result in results)
    ):
        return "ALLOW"
    if any(result.decision == "REVIEW" for result in results):
        return "REVIEW"
    return "ALLOW"


def collect_matched_rules(results: list[StageResult]) -> list[MatchedRule] | None:
    rules = [rule for result in results for rule in result.matched_rules or []]
    return rules or None


def validate_policy_rules(config: PolicyConfig) -> list[str]:
    errors: list[str] = []
    for index, pattern in enumerate(config.forbidden_commands or []):
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error:
            errors.append(f'forbidden_commands[{index}] "{pattern}": invalid regex')
    if config.recipient_threshold is not None:
        if config.recipient_threshold.max_recipients <= 0:
            errors.append("recipient_threshold.max_recipients must be a positive integer")
    for index, rule in enumerate(config.outbound_rules or []):
        if rule.pattern.strip() == "":
            errors.append(f'outbound_rules[{index}] "{rule.pattern}": pattern must be non-empty')
    return errors


CODING_AGENT_PRESET = PolicyConfig(
    version="0.1.0",
    forbidden_commands=[
        r"rm\s+-rf\s+/",
        r"chmod\s+777",
        r"curl\s+.*\|\s*bash",
        r"wget\s+.*\|\s*bash",
        r":\s*\(\s*\)\s*\{",
        r"dd\s+if=",
        r"mkfs\.",
        "shutdown",
        "reboot",
        "halt",
    ],
    forbidden_paths=[
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/**",
        "/boot/**",
        "/sys/**",
        "/proc/**",
    ],
    sensitive_files=[
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        ".npmrc",
        ".pypirc",
        "credentials",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
    ],
    sensitive_env_keys=[
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "DATABASE_URL",
        "SECRET_KEY",
        "PRIVATE_KEY",
        "API_KEY",
    ],
)

ASSISTANT_WITH_TOOLS_PRESET = PolicyConfig(
    version="0.1.0",
    forbidden_tools=["shell", "bash", "exec", "eval"],
    sensitive_files=[".env", ".env.local", "id_rsa", "id_ed25519", "credentials", "secrets.json"],
    sensitive_env_keys=["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DATABASE_URL", "API_KEY"],
    recipient_threshold=RecipientThreshold(max_recipients=5, action="review"),
)

BROWSING_AGENT_PRESET = PolicyConfig(
    version="0.1.0",
    forbidden_commands=[r"rm\s+-rf", r":\s*\(\s*\)\s*\{", r"dd\s+if=", r"mkfs\."],
    sensitive_files=[".env", ".env.local", "id_rsa", "id_ed25519", "credentials", "secrets.json"],
    sensitive_env_keys=["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "API_KEY"],
    outbound_rules=[
        OutboundRule(pattern="pastebin.com", action="block"),
        OutboundRule(pattern="hastebin.com", action="block"),
        OutboundRule(pattern="ghostbin.com", action="block"),
        OutboundRule(pattern="webhook.site", action="block"),
        OutboundRule(pattern="requestbin", action="block"),
        OutboundRule(pattern="ngrok.io", action="block"),
        OutboundRule(pattern="ngrok.app", action="block"),
        OutboundRule(pattern="pipedream.net", action="block"),
    ],
)

PRESET_NAMES = ("coding-agent", "assistant-with-tools", "browsing-agent")
PRESETS: dict[str, PolicyConfig] = {
    "coding-agent": CODING_AGENT_PRESET,
    "assistant-with-tools": ASSISTANT_WITH_TOOLS_PRESET,
    "browsing-agent": BROWSING_AGENT_PRESET,
}


def _merge_string_arrays(base_arr: list[str] | None, preset_arr: list[str] | None) -> list[str] | None:
    if not base_arr and not preset_arr:
        return None
    return list(dict.fromkeys([*(base_arr or []), *(preset_arr or [])]))


def _merge_outbound_rules(
    base_rules: list[OutboundRule] | None, preset_rules: list[OutboundRule] | None
) -> list[OutboundRule] | None:
    if not base_rules and not preset_rules:
        return None
    merged: list[OutboundRule] = []
    seen: set[tuple[str, str]] = set()
    for rule in [*(base_rules or []), *(preset_rules or [])]:
        key = (rule.pattern, rule.action)
        if key not in seen:
            seen.add(key)
            merged.append(rule)
    return merged or None


def apply_preset_overlays(config: PolicyConfig, preset_names: list[str]) -> PolicyConfig:
    result = clone_dataclass(config)
    for name in preset_names:
        preset = PRESETS.get(name)
        if preset is None:
            warnings.warn(f'[MosheSDK] Unknown preset "{name}" in preset_overlays - skipped.', stacklevel=2)
            continue
        result = PolicyConfig(
            version=result.version,
            forbidden_tools=_merge_string_arrays(result.forbidden_tools, preset.forbidden_tools),
            forbidden_commands=_merge_string_arrays(result.forbidden_commands, preset.forbidden_commands),
            forbidden_paths=_merge_string_arrays(result.forbidden_paths, preset.forbidden_paths),
            forbidden_files=_merge_string_arrays(result.forbidden_files, preset.forbidden_files),
            sensitive_files=_merge_string_arrays(result.sensitive_files, preset.sensitive_files),
            sensitive_env_keys=_merge_string_arrays(result.sensitive_env_keys, preset.sensitive_env_keys),
            outbound_rules=_merge_outbound_rules(result.outbound_rules, preset.outbound_rules),
            recipient_threshold=result.recipient_threshold or preset.recipient_threshold,
            preset_overlays=result.preset_overlays,
        )
    return result


class StaticPolicyProvider(PolicyProvider):
    def __init__(self, config: PolicyConfig) -> None:
        self._config = clone_dataclass(config)

    async def load(self) -> PolicyConfig:
        return clone_dataclass(self._config)

    async def validate(self, config: PolicyConfig) -> None:
        if config.version.strip() == "":
            raise ValueError("PolicyConfig validation failed: version must be non-empty")
        errors = validate_policy_rules(config)
        if errors:
            raise ValueError(f"PolicyConfig validation failed: {'; '.join(errors)}")

    async def get_effective(self) -> PolicyConfig:
        loaded = clone_dataclass(self._config)
        if loaded.preset_overlays:
            return apply_preset_overlays(loaded, loaded.preset_overlays)
        return loaded


class FilePolicyProvider(PolicyProvider):
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    async def load(self) -> PolicyConfig:
        def read_file() -> PolicyConfig:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("Policy file must contain a JSON object")
            return policy_config_from_mapping(raw)

        return await asyncio.to_thread(read_file)

    async def validate(self, config: PolicyConfig) -> None:
        await StaticPolicyProvider(config).validate(config)

    async def get_effective(self) -> PolicyConfig:
        loaded = await self.load()
        if loaded.preset_overlays:
            return apply_preset_overlays(loaded, loaded.preset_overlays)
        return loaded


def policy_config_from_mapping(data: dict[str, object]) -> PolicyConfig:
    outbound_rules = None
    raw_outbound_rules = data.get("outbound_rules")
    if isinstance(raw_outbound_rules, list):
        outbound_rules = [
            OutboundRule(pattern=str(item["pattern"]), action=str(item["action"]))  # type: ignore[arg-type]
            for item in raw_outbound_rules
            if isinstance(item, dict) and "pattern" in item and "action" in item
        ]

    recipient_threshold = None
    raw_threshold = data.get("recipient_threshold")
    if isinstance(raw_threshold, dict):
        action = raw_threshold.get("action")
        max_recipients = raw_threshold.get("max_recipients")
        if isinstance(action, str) and isinstance(max_recipients, int):
            recipient_threshold = RecipientThreshold(max_recipients=max_recipients, action=action)  # type: ignore[arg-type]

    def list_of_strings(key: str) -> list[str] | None:
        value = data.get(key)
        if not isinstance(value, list):
            return None
        return [str(item) for item in value]

    version = data.get("version")
    return PolicyConfig(
        version=str(version) if isinstance(version, str) else "0.1.0",
        forbidden_tools=list_of_strings("forbidden_tools"),
        forbidden_commands=list_of_strings("forbidden_commands"),
        forbidden_paths=list_of_strings("forbidden_paths"),
        forbidden_files=list_of_strings("forbidden_files"),
        sensitive_files=list_of_strings("sensitive_files"),
        sensitive_env_keys=list_of_strings("sensitive_env_keys"),
        outbound_rules=outbound_rules,
        recipient_threshold=recipient_threshold,
        preset_overlays=list_of_strings("preset_overlays"),
    )
