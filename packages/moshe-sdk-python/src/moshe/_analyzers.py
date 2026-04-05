from __future__ import annotations

import re

from ._interfaces import Analyzer, EngineContext, StageResult
from ._outbound_utils import is_local_network_host, parse_outbound_target
from ._types import ActionEnvelope, MatchedRule, ReasonCode


def _pass(stage: str) -> StageResult:
    return StageResult(stage=stage, passed=True, decision="ALLOW", reason_codes=[])


def _flag(stage: str, *, decision: str, reason_code: str, matched_value: str, summary: str) -> StageResult:
    return StageResult(
        stage=stage,
        passed=False,
        decision=decision,  # type: ignore[arg-type]
        reason_codes=[reason_code],
        matched_rules=[
            MatchedRule(
                rule_id=f"{stage}:{reason_code}",
                rule_type=stage,
                matched_value=matched_value,
            )
        ],
        enrichments={"summary": summary},
    )


def _collect_command_candidates(envelope: ActionEnvelope) -> list[str]:
    values: list[str] = []
    for candidate in [envelope.arguments.command, envelope.arguments.shell]:
        if isinstance(candidate, str) and candidate.strip():
            values.append(candidate)
    return values


def _collect_outbound_targets(envelope: ActionEnvelope) -> list[str]:
    targets: set[str] = set()
    if envelope.arguments.url and envelope.arguments.url.strip():
        targets.add(envelope.arguments.url)
    for target in envelope.outbound_targets or []:
        if target.strip():
            targets.add(target)
    return list(targets)


class CommandIntentAnalyzer(Analyzer):
    name = "command_intent"

    async def analyze(self, envelope: ActionEnvelope, _ctx: EngineContext) -> StageResult:
        commands = _collect_command_candidates(envelope)
        if not commands and envelope.action_type != "command_exec":
            return _pass(self.name)

        for candidate in commands:
            normalized = candidate.lower()
            decodes_base64 = "base64 -d" in normalized or "base64 --decode" in normalized
            pipes_to_interpreter = any(token in normalized for token in ["| bash", "| sh", "| python3", "| python", "| node"])
            if decodes_base64 and pipes_to_interpreter:
                return _flag(
                    self.name,
                    decision="BLOCK",
                    reason_code=ReasonCode.COMMAND_INTENT_SUSPICIOUS,
                    matched_value=candidate[:120],
                    summary="Blocked: command decodes and executes a base64-encoded payload.",
                )

        for candidate in commands:
            normalized = candidate.lower()
            pipe_to_interpreter = re.search(r"\|\s*(bash|sh|python3?|node|perl|ruby)\b", normalized) is not None
            decodes_base64 = "base64 -d" in normalized or "base64 --decode" in normalized
            if pipe_to_interpreter and not decodes_base64:
                return _flag(
                    self.name,
                    decision="REVIEW",
                    reason_code=ReasonCode.COMMAND_INTENT_SUSPICIOUS,
                    matched_value=candidate[:120],
                    summary="Command pipes output directly into a shell interpreter.",
                )

        for candidate in commands:
            if re.search(r"(?:bash|sh|python3?|node|pwsh|powershell)\s+-[ce]\s+", candidate, re.IGNORECASE):
                return _flag(
                    self.name,
                    decision="REVIEW",
                    reason_code=ReasonCode.COMMAND_INTENT_SUSPICIOUS,
                    matched_value=candidate[:120],
                    summary="Command executes an inline script via interpreter flag.",
                )

        enumeration_patterns = [
            re.compile(r"\bfind\s+[/~]"),
            re.compile(r"\bfind\s+\."),
            re.compile(r"\bls\s+.*-[a-z]*[lr]"),
            re.compile(r"\bdir\b.*/s"),
            re.compile(r"\btree\b"),
            re.compile(r"\bdu\s+-"),
        ]
        for candidate in commands:
            normalized = candidate.lower()
            if any(pattern.search(normalized) for pattern in enumeration_patterns):
                return _flag(
                    self.name,
                    decision="REVIEW",
                    reason_code=ReasonCode.FILE_ENUMERATION_DETECTED,
                    matched_value=candidate[:120],
                    summary="Command performs recursive filesystem enumeration.",
                )

        return _pass(self.name)


class FileAccessIntentAnalyzer(Analyzer):
    name = "file_access_intent"

    async def analyze(self, envelope: ActionEnvelope, _ctx: EngineContext) -> StageResult:
        has_path = bool(envelope.arguments.path and envelope.arguments.path.strip())
        applicable = envelope.action_type in {"file_read", "file_write"} or has_path
        if not applicable:
            return _pass(self.name)
        ref_count = len(envelope.referenced_paths or [])
        if ref_count >= 10:
            return _flag(
                self.name,
                decision="REVIEW",
                reason_code=ReasonCode.FILE_ENUMERATION_DETECTED,
                matched_value=str(ref_count),
                summary=f"File access references {ref_count} paths simultaneously - possible bulk enumeration.",
            )
        return _pass(self.name)


class OutboundClassificationAnalyzer(Analyzer):
    name = "outbound_classification"

    async def analyze(self, envelope: ActionEnvelope, _ctx: EngineContext) -> StageResult:
        targets = _collect_outbound_targets(envelope)
        if not targets and envelope.action_type != "outbound_request":
            return _pass(self.name)

        risky_hosts = [
            "pastebin.com",
            "hastebin.com",
            "ghostbin.com",
            "controlc.com",
            "requestbin",
            "webhook.site",
            "ngrok.io",
            "ngrok.app",
            "pipedream.net",
            "hookbin.com",
            "beeceptor.com",
            "typedwebhook.tools",
            "bin.sh",
        ]
        for target in targets:
            normalized = target.lower()
            if any(pattern in normalized for pattern in risky_hosts):
                return _flag(
                    self.name,
                    decision="REVIEW",
                    reason_code=ReasonCode.OUTBOUND_CLASSIFICATION_SUSPICIOUS,
                    matched_value=target[:200],
                    summary="Outbound target matches a known data-exfiltration risk host.",
                )
            if re.search(r"^https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)", target):
                return _flag(
                    self.name,
                    decision="REVIEW",
                    reason_code=ReasonCode.OUTBOUND_CLASSIFICATION_SUSPICIOUS,
                    matched_value=target[:200],
                    summary="Outbound request targets a raw IP address; DNS bypassed.",
                )
            parsed = parse_outbound_target(target)
            if parsed and is_local_network_host(parsed.hostname):
                return _flag(
                    self.name,
                    decision="REVIEW",
                    reason_code=ReasonCode.OUTBOUND_CLASSIFICATION_SUSPICIOUS,
                    matched_value=target[:200],
                    summary="Outbound request targets a local network address.",
                )
        return _pass(self.name)
