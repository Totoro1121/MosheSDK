from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass, replace
from typing import Any, Literal, TypeVar, cast

ActionType = Literal[
    "tool_call",
    "command_exec",
    "file_read",
    "file_write",
    "outbound_request",
    "message_send",
    "unknown",
]
Decision = Literal["ALLOW", "BLOCK", "REVIEW"]
Severity = Literal["low", "medium", "high", "critical"]
RiskLevel = Literal["NORMAL", "ELEVATED", "HIGH"]
TelemetryEventType = Literal[
    "ACTION_RECEIVED",
    "STAGE_COMPLETE",
    "DECISION_MADE",
    "APPROVAL_CREATED",
    "APPROVAL_RESOLVED",
    "FEEDBACK",
]
FeedbackVerdict = Literal["FALSE_POSITIVE", "FALSE_NEGATIVE", "CORRECT"]


class ReasonCode:
    NO_POLICY_MATCH = "NO_POLICY_MATCH"
    NO_APPROVAL_REQUIRED = "NO_APPROVAL_REQUIRED"
    APPROVAL_REPLAY_ALLOWED = "APPROVAL_REPLAY_ALLOWED"
    FORBIDDEN_TOOL = "FORBIDDEN_TOOL"
    FORBIDDEN_COMMAND = "FORBIDDEN_COMMAND"
    FORBIDDEN_PATH = "FORBIDDEN_PATH"
    FORBIDDEN_FILE = "FORBIDDEN_FILE"
    SENSITIVE_FILE_ACCESS = "SENSITIVE_FILE_ACCESS"
    SENSITIVE_ENV_ACCESS = "SENSITIVE_ENV_ACCESS"
    OUTBOUND_BLOCKED = "OUTBOUND_BLOCKED"
    RECIPIENT_THRESHOLD_EXCEEDED = "RECIPIENT_THRESHOLD_EXCEEDED"
    POLICY_VALIDATION_ERROR = "POLICY_VALIDATION_ERROR"
    ENGINE_ERROR = "ENGINE_ERROR"
    UNHANDLED_REVIEW = "UNHANDLED_REVIEW_FALLBACK"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    INTENT_ANALYZER_STUB = "INTENT_ANALYZER_STUB"
    COMMAND_INTENT_SUSPICIOUS = "COMMAND_INTENT_SUSPICIOUS"
    FILE_ENUMERATION_DETECTED = "FILE_ENUMERATION_DETECTED"
    OUTBOUND_CLASSIFICATION_SUSPICIOUS = "OUTBOUND_CLASSIFICATION_SUSPICIOUS"
    TAINTED_ARTIFACT_ACCESS = "TAINTED_ARTIFACT_ACCESS"
    TAINTED_SESSION_COMMAND = "TAINTED_SESSION_COMMAND"
    AGENT_AUTHORED_EXECUTION = "AGENT_AUTHORED_EXECUTION"
    CHAIN_RISK_ELEVATED = "CHAIN_RISK_ELEVATED"
    CHAIN_RISK_HIGH = "CHAIN_RISK_HIGH"
    EXFIL_CHAIN_PRECURSOR = "EXFIL_CHAIN_PRECURSOR"


def _snake_to_camel(name: str) -> str:
    head, *tail = name.split("_")
    return head + "".join(part.capitalize() for part in tail)


T = TypeVar("T")


def clone_dataclass(value: T) -> T:
    if not is_dataclass(value):
        return value
    kwargs: dict[str, Any] = {}
    for item in fields(value):
        kwargs[item.name] = clone_value(getattr(value, item.name))
    return cast(T, replace(cast(Any, value), **kwargs))


def clone_value(value: Any) -> Any:
    if is_dataclass(value):
        return clone_dataclass(value)
    if isinstance(value, list):
        return [clone_value(item) for item in value]
    if isinstance(value, dict):
        return {key: clone_value(item) for key, item in value.items()}
    return value


def dataclass_to_camel_dict(value: Any) -> Any:
    if is_dataclass(value):
        result: dict[str, Any] = {}
        for item in fields(value):
            raw = getattr(value, item.name)
            if raw is None:
                continue
            result[_snake_to_camel(item.name)] = dataclass_to_camel_dict(raw)
        return result
    if isinstance(value, list):
        return [dataclass_to_camel_dict(item) for item in value]
    if isinstance(value, dict):
        return {_snake_to_camel(str(key)): dataclass_to_camel_dict(item) for key, item in value.items()}
    return value


def reason_code_values() -> set[str]:
    return {
        value
        for key, value in vars(ReasonCode).items()
        if not key.startswith("_") and isinstance(value, str)
    }


@dataclass(frozen=True)
class ToolArguments:
    command: str | None = None
    shell: str | None = None
    path: str | None = None
    content: str | None = None
    url: str | None = None
    method: str | None = None
    headers: dict[str, str] | None = None
    recipients: list[str] | None = None
    subject: str | None = None
    body: str | None = None
    agent_authored: bool | None = None
    params: dict[str, str | int | float | bool] | None = None


@dataclass(frozen=True)
class ActionEnvelope:
    action_id: str
    session_id: str
    timestamp: str
    framework: str
    action_type: ActionType
    operation: str
    tool_name: str
    arguments: ToolArguments
    agent_id: str | None = None
    cwd: str | None = None
    referenced_paths: list[str] | None = None
    outbound_targets: list[str] | None = None
    content_refs: list[str] | None = None
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class MatchedRule:
    rule_id: str
    rule_type: str
    matched_value: str


@dataclass(frozen=True)
class ApprovalRequest:
    approval_id: str
    expires_at: str
    callback_hint: str | None = None


@dataclass(frozen=True)
class TaintSummary:
    session_tainted: bool
    taint_sources: list[str]
    artifacts_tainted: list[str]


@dataclass(frozen=True)
class ProvenanceSummary:
    agent_authored: list[str]
    propagated_from: list[str]
    lineage_depth: int | None = None
    origin_sources: list[str] | None = None


@dataclass(frozen=True)
class ChainRiskSummary:
    risk_level: RiskLevel
    review_count: int
    block_count: int
    sensitive_read_count: int


@dataclass(frozen=True)
class TelemetryRef:
    event_id: str


@dataclass(frozen=True)
class DecisionEnvelope:
    decision: Decision
    reason_codes: list[str]
    summary: str
    severity: Severity | None = None
    matched_rules: list[MatchedRule] | None = None
    approval_request: ApprovalRequest | None = None
    taint_summary: TaintSummary | None = None
    provenance_summary: ProvenanceSummary | None = None
    chain_risk_summary: ChainRiskSummary | None = None
    telemetry: TelemetryRef | None = None
    debug: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutboundRule:
    pattern: str
    action: Literal["allow", "block"]


@dataclass(frozen=True)
class RecipientThreshold:
    max_recipients: int
    action: Literal["block", "review"]


@dataclass(frozen=True)
class PolicyConfig:
    version: str = "0.1.0"
    forbidden_tools: list[str] | None = None
    forbidden_commands: list[str] | None = None
    forbidden_paths: list[str] | None = None
    forbidden_files: list[str] | None = None
    sensitive_files: list[str] | None = None
    sensitive_env_keys: list[str] | None = None
    outbound_rules: list[OutboundRule] | None = None
    recipient_threshold: RecipientThreshold | None = None
    preset_overlays: list[str] | None = None


@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str
    event_type: TelemetryEventType
    action_id: str
    session_id: str
    elapsed_ms: float | None = None
    stage: str | None = None
    decision: Decision | None = None
    reason_codes: list[str] | None = None
    debug: dict[str, Any] | None = None
