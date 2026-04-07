export const ACTION_TYPES = [
  'tool_call',
  'command_exec',
  'file_read',
  'file_write',
  'outbound_request',
  'message_send',
  'unknown'
] as const;

export type ActionType = (typeof ACTION_TYPES)[number];

export interface ToolArguments {
  command?: string;
  shell?: string;
  path?: string;
  content?: string;
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  recipients?: string[];
  subject?: string;
  body?: string;
  agentAuthored?: boolean;
  params?: Record<string, string | number | boolean>;
}

export const ReasonCode = {
  NO_POLICY_MATCH: 'NO_POLICY_MATCH',
  NO_APPROVAL_REQUIRED: 'NO_APPROVAL_REQUIRED',
  APPROVAL_REPLAY_ALLOWED: 'APPROVAL_REPLAY_ALLOWED',
  APPROVAL_REPLAY_BLOCKED: 'APPROVAL_REPLAY_BLOCKED',
  FORBIDDEN_TOOL: 'FORBIDDEN_TOOL',
  FORBIDDEN_COMMAND: 'FORBIDDEN_COMMAND',
  FORBIDDEN_PATH: 'FORBIDDEN_PATH',
  FORBIDDEN_FILE: 'FORBIDDEN_FILE',
  SENSITIVE_FILE_ACCESS: 'SENSITIVE_FILE_ACCESS',
  SENSITIVE_ENV_ACCESS: 'SENSITIVE_ENV_ACCESS',
  OUTBOUND_BLOCKED: 'OUTBOUND_BLOCKED',
  RECIPIENT_THRESHOLD_EXCEEDED: 'RECIPIENT_THRESHOLD_EXCEEDED',
  POLICY_VALIDATION_ERROR: 'POLICY_VALIDATION_ERROR',
  ENGINE_ERROR: 'ENGINE_ERROR',
  UNHANDLED_REVIEW: 'UNHANDLED_REVIEW_FALLBACK',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  INTENT_ANALYZER_STUB: 'INTENT_ANALYZER_STUB',
  COMMAND_INTENT_SUSPICIOUS: 'COMMAND_INTENT_SUSPICIOUS',
  FILE_ENUMERATION_DETECTED: 'FILE_ENUMERATION_DETECTED',
  OUTBOUND_CLASSIFICATION_SUSPICIOUS: 'OUTBOUND_CLASSIFICATION_SUSPICIOUS',
  TAINTED_ARTIFACT_ACCESS: 'TAINTED_ARTIFACT_ACCESS',
  TAINTED_SESSION_COMMAND: 'TAINTED_SESSION_COMMAND',
  AGENT_AUTHORED_EXECUTION: 'AGENT_AUTHORED_EXECUTION',
  CHAIN_RISK_ELEVATED: 'CHAIN_RISK_ELEVATED',
  CHAIN_RISK_HIGH: 'CHAIN_RISK_HIGH',
  EXFIL_CHAIN_PRECURSOR: 'EXFIL_CHAIN_PRECURSOR'
} as const;

export type ReasonCode = typeof ReasonCode[keyof typeof ReasonCode];

export interface ActionEnvelope {
  actionId: string;
  sessionId: string;
  timestamp: string;
  framework: string;
  actionType: ActionType;
  operation: string;
  toolName: string;
  arguments: ToolArguments;
  agentId?: string;
  cwd?: string;
  referencedPaths?: string[];
  outboundTargets?: string[];
  contentRefs?: string[];
  metadata?: Record<string, unknown>;
}

export const DECISIONS = ['ALLOW', 'BLOCK', 'REVIEW'] as const;
export type Decision = (typeof DECISIONS)[number];

export interface MatchedRule {
  ruleId: string;
  ruleType: string;
  matchedValue: string;
}

export interface ApprovalRequest {
  approvalId: string;
  expiresAt: string;
  callbackHint?: string;
}

export interface TaintSummary {
  sessionTainted: boolean;
  taintSources: string[];
  artifactsTainted: string[];
}

export interface ProvenanceSummary {
  agentAuthored: string[];
  propagatedFrom: string[];
  lineageDepth?: number;
  originSources?: string[];
}

export interface ChainRiskSummary {
  riskLevel: 'NORMAL' | 'ELEVATED' | 'HIGH';
  reviewCount: number;
  blockCount: number;
  sensitiveReadCount: number;
}

export interface TelemetryRef {
  eventId: string;
}

export interface DecisionEnvelope {
  decision: Decision;
  reasonCodes: ReasonCode[];
  summary: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  matchedRules?: MatchedRule[];
  approvalRequest?: ApprovalRequest;
  taintSummary?: TaintSummary;
  provenanceSummary?: ProvenanceSummary;
  chainRiskSummary?: ChainRiskSummary;
  telemetry?: TelemetryRef;
  debug?: Record<string, unknown>;
}

export interface OutboundRule {
  pattern: string;
  action: 'allow' | 'block';
}

export interface RecipientThreshold {
  maxRecipients: number;
  action: 'block' | 'review';
}

export interface PolicyConfig {
  version: string;
  forbiddenTools?: string[];
  forbiddenCommands?: string[];
  forbiddenPaths?: string[];
  forbiddenFiles?: string[];
  sensitiveFiles?: string[];
  sensitiveEnvKeys?: string[];
  outboundRules?: OutboundRule[];
  recipientThreshold?: RecipientThreshold;
  presetOverlays?: string[];
}

export const TELEMETRY_EVENT_TYPES = [
  'ACTION_RECEIVED',
  'STAGE_COMPLETE',
  'DECISION_MADE',
  'APPROVAL_CREATED',
  'APPROVAL_RESOLVED',
  'FEEDBACK'
] as const;

export type TelemetryEventType = (typeof TELEMETRY_EVENT_TYPES)[number];

export interface TelemetryEvent {
  eventId: string;
  eventType: TelemetryEventType;
  actionId: string;
  sessionId: string;
  stage?: string;
  decision?: Decision;
  reasonCodes?: ReasonCode[];
  elapsedMs?: number;
  debug?: Record<string, unknown>;
}

export const LIFECYCLE_HOOK_NAMES = [
  'beforeToolCall',
  'beforeCommandExec',
  'beforeOutboundRequest',
  'beforeMessageSend',
  'afterFileWrite',
  'afterFileRead',
  'afterDecision'
] as const;

export type LifecycleHookName = (typeof LIFECYCLE_HOOK_NAMES)[number];

export type HookPhase = 'before' | 'after';

export interface ValidationSuccess<T> {
  ok: true;
  data: T;
}

export interface ValidationFailure {
  ok: false;
  errors: string[];
}

export type ValidationResult<T> = ValidationSuccess<T> | ValidationFailure;
