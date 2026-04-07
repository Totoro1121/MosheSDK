import { Minimatch } from 'minimatch';

import { ReasonCode, type ActionEnvelope, type DecisionEnvelope, type MatchedRule, type PolicyConfig } from '@moshe/spec';

import type { EngineContext, StageResult } from './interfaces.js';
import { matchesOutboundPattern } from './outbound-utils.js';

export interface PolicyRuleValidationError {
  field: string;
  index: number;
  value: string;
  reason: string;
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, '/').replace(/\/+/g, '/').trim();
}

function basename(value: string): string {
  const normalized = normalizePath(value);
  const parts = normalized.split('/').filter(Boolean);
  return parts.at(-1) ?? normalized;
}

function collectPathCandidates(envelope: ActionEnvelope): string[] {
  const values = new Set<string>();

  if (typeof envelope.arguments.path === 'string' && envelope.arguments.path.trim() !== '') {
    values.add(envelope.arguments.path);
  }

  for (const path of envelope.referencedPaths ?? []) {
    if (path.trim() !== '') {
      values.add(path);
    }
  }

  return [...values];
}

function collectCommandCandidates(envelope: ActionEnvelope): string[] {
  return [envelope.arguments.command, envelope.arguments.shell]
    .filter((value): value is string => typeof value === 'string' && value.trim() !== '');
}

function collectOutboundTargets(envelope: ActionEnvelope): string[] {
  const values = new Set<string>();

  if (typeof envelope.arguments.url === 'string' && envelope.arguments.url.trim() !== '') {
    values.add(envelope.arguments.url);
  }

  for (const target of envelope.outboundTargets ?? []) {
    if (target.trim() !== '') {
      values.add(target);
    }
  }

  return [...values];
}

function ruleResult(base: {
  decision: DecisionEnvelope['decision'];
  reasonCode: typeof ReasonCode[keyof typeof ReasonCode];
  matchedRules?: MatchedRule[];
  summary: string;
}): StageResult {
  const severity = resolveSeverity(base.reasonCode);

  return {
    stage: 'static_policy',
    passed: false,
    decision: base.decision,
    reasonCodes: [base.reasonCode],
    ...(base.matchedRules ? { matchedRules: base.matchedRules } : {}),
    enrichments: {
      summary: base.summary,
      ...(severity ? { severity } : {})
    }
  };
}

export function resolveSeverity(reasonCode: typeof ReasonCode[keyof typeof ReasonCode]): DecisionEnvelope['severity'] {
  switch (reasonCode) {
    case ReasonCode.FORBIDDEN_TOOL:
    case ReasonCode.FORBIDDEN_COMMAND:
    case ReasonCode.FORBIDDEN_PATH:
    case ReasonCode.FORBIDDEN_FILE:
    case ReasonCode.OUTBOUND_BLOCKED:
      return 'high';
    case ReasonCode.SENSITIVE_FILE_ACCESS:
    case ReasonCode.SENSITIVE_ENV_ACCESS:
    case ReasonCode.RECIPIENT_THRESHOLD_EXCEEDED:
      return 'medium';
    default:
      return undefined;
  }
}

export function evaluateForbiddenTool(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const forbiddenTools = policy.forbiddenTools ?? [];
  if (!forbiddenTools.includes(envelope.toolName)) {
    return null;
  }

  return ruleResult({
    decision: 'BLOCK',
    reasonCode: ReasonCode.FORBIDDEN_TOOL,
    matchedRules: [
      {
        ruleId: `forbiddenTool:${envelope.toolName}`,
        ruleType: 'forbidden_tool',
        matchedValue: envelope.toolName
      }
    ],
    summary: `Blocked forbidden tool "${envelope.toolName}".`
  });
}

export function evaluateForbiddenCommand(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const commands = collectCommandCandidates(envelope);

  if (commands.length === 0) {
    return null;
  }

  for (const pattern of policy.forbiddenCommands ?? []) {
    const expression = new RegExp(pattern, 'i');
    for (const command of commands) {
      if (!expression.test(command)) {
        continue;
      }

      return ruleResult({
        decision: 'BLOCK',
        reasonCode: ReasonCode.FORBIDDEN_COMMAND,
        matchedRules: [
          {
            ruleId: `forbiddenCommand:${pattern}`,
            ruleType: 'forbidden_command',
            matchedValue: command
          }
        ],
        summary: 'Blocked forbidden command execution.'
      });
    }
  }

  return null;
}

export function evaluateForbiddenPath(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const candidates = collectPathCandidates(envelope);
  if (candidates.length === 0) {
    return null;
  }

  const matchers = (policy.forbiddenPaths ?? []).map((pattern) => ({
    pattern,
    matcher: new Minimatch(normalizePath(pattern), {
      nocase: true,
      dot: true
    })
  }));

  for (const candidate of candidates) {
    const normalizedCandidate = normalizePath(candidate);
    const matched = matchers.find(({ matcher }) => matcher.match(normalizedCandidate));
    if (!matched) {
      continue;
    }

    return ruleResult({
      decision: 'BLOCK',
      reasonCode: ReasonCode.FORBIDDEN_PATH,
      matchedRules: [
        {
          ruleId: `forbiddenPath:${matched.pattern}`,
          ruleType: 'forbidden_path',
          matchedValue: normalizedCandidate
        }
      ],
      summary: `Blocked access to forbidden path "${normalizedCandidate}".`
    });
  }

  return null;
}

export function evaluateForbiddenFile(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const forbiddenFiles = new Set((policy.forbiddenFiles ?? []).map((value) => value.trim().toLowerCase()).filter(Boolean));
  if (forbiddenFiles.size === 0) {
    return null;
  }

  for (const candidate of collectPathCandidates(envelope)) {
    const fileName = basename(candidate).toLowerCase();
    if (!forbiddenFiles.has(fileName)) {
      continue;
    }

    return ruleResult({
      decision: 'BLOCK',
      reasonCode: ReasonCode.FORBIDDEN_FILE,
      matchedRules: [
        {
          ruleId: `forbiddenFile:${fileName}`,
          ruleType: 'forbidden_file',
          matchedValue: candidate
        }
      ],
      summary: `Blocked access to forbidden file "${fileName}".`
    });
  }

  return null;
}

export function evaluateSensitiveFiles(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const sensitiveFiles = new Set((policy.sensitiveFiles ?? []).map((value) => basename(value).toLowerCase()).filter(Boolean));
  if (sensitiveFiles.size === 0) {
    return null;
  }

  for (const candidate of collectPathCandidates(envelope)) {
    const fileName = basename(candidate).toLowerCase();
    if (!sensitiveFiles.has(fileName)) {
      continue;
    }

    return ruleResult({
      decision: 'REVIEW',
      reasonCode: ReasonCode.SENSITIVE_FILE_ACCESS,
      matchedRules: [
        {
          ruleId: `sensitiveFile:${fileName}`,
          ruleType: 'sensitive_file',
          matchedValue: candidate
        }
      ],
      summary: `Action references sensitive file "${fileName}".`
    });
  }

  return null;
}

export function evaluateSensitiveEnvKeys(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const textCandidates = [
    envelope.arguments.command,
    envelope.arguments.shell,
    envelope.arguments.content,
    envelope.arguments.body
  ].filter((value): value is string => typeof value === 'string' && value.trim() !== '');

  if (textCandidates.length === 0) {
    return null;
  }

  for (const rawKey of policy.sensitiveEnvKeys ?? []) {
    const key = rawKey.trim().toUpperCase();
    if (key === '') {
      continue;
    }

    const patterns = [
      `$${key}`,
      `%${key}%`,
      `printenv ${key}`,
      `env ${key}`
    ].map((value) => value.toLowerCase());

    for (const candidate of textCandidates) {
      const normalizedCandidate = candidate.toLowerCase();
      if (!patterns.some((pattern) => normalizedCandidate.includes(pattern))) {
        continue;
      }

      return ruleResult({
        decision: 'REVIEW',
        reasonCode: ReasonCode.SENSITIVE_ENV_ACCESS,
        matchedRules: [
          {
            ruleId: `sensitiveEnv:${key}`,
            ruleType: 'sensitive_env',
            matchedValue: key
          }
        ],
        summary: `Action references sensitive environment key "${key}".`
      });
    }
  }

  return null;
}

export function evaluateOutboundRules(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const targets = collectOutboundTargets(envelope);
  const rules = policy.outboundRules ?? [];
  if (targets.length === 0 || rules.length === 0) {
    return null;
  }

  for (const target of targets) {
    let targetExplicitlyAllowed = false;
    for (const rule of rules) {
      const pattern = rule.pattern.trim();
      if (!matchesOutboundPattern(target, pattern)) {
        continue;
      }

      if (rule.action === 'allow') {
        targetExplicitlyAllowed = true;
        break;
      }

      return ruleResult({
        decision: 'BLOCK',
        reasonCode: ReasonCode.OUTBOUND_BLOCKED,
        matchedRules: [
          {
            ruleId: `outboundRule:${pattern}`,
            ruleType: 'outbound_rule',
            matchedValue: target
          }
        ],
        summary: `Blocked outbound target "${target}".`
      });
    }

    if (targetExplicitlyAllowed) {
      continue;
    }
  }

  return null;
}

export function evaluateRecipientThreshold(envelope: ActionEnvelope, policy: PolicyConfig): StageResult | null {
  const threshold = policy.recipientThreshold;
  const recipients = envelope.arguments.recipients;
  if (!threshold || !recipients || recipients.length === 0) {
    return null;
  }

  if (recipients.length <= threshold.maxRecipients) {
    return null;
  }

  return ruleResult({
    decision: threshold.action === 'block' ? 'BLOCK' : 'REVIEW',
    reasonCode: ReasonCode.RECIPIENT_THRESHOLD_EXCEEDED,
    matchedRules: [
      {
        ruleId: 'recipientThreshold',
        ruleType: 'recipient_threshold',
        matchedValue: String(recipients.length)
      }
    ],
    summary: `Recipient threshold exceeded with ${recipients.length} recipients.`
  });
}

export async function evaluateStaticPolicy(envelope: ActionEnvelope, ctx: EngineContext): Promise<StageResult> {
  const checks = [
    evaluateForbiddenTool(envelope, ctx.policy),
    evaluateForbiddenCommand(envelope, ctx.policy),
    evaluateForbiddenPath(envelope, ctx.policy),
    evaluateForbiddenFile(envelope, ctx.policy),
    evaluateSensitiveFiles(envelope, ctx.policy),
    evaluateSensitiveEnvKeys(envelope, ctx.policy),
    evaluateOutboundRules(envelope, ctx.policy),
    evaluateRecipientThreshold(envelope, ctx.policy)
  ];

  const results = checks.filter((result): result is StageResult => result !== null);

  const block = results.find((result) => result.decision === 'BLOCK');
  if (block) {
    return block;
  }

  const reviews = results.filter((result) => result.decision === 'REVIEW');
  if (reviews.length > 0) {
    const reasonCodes = [...new Set(reviews.flatMap((result) => result.reasonCodes ?? []))];
    const matchedRules = reviews.flatMap((result) => result.matchedRules ?? []);
    const summaries = reviews
      .map((result) => result.enrichments?.summary ?? '')
      .filter((summary) => summary.length > 0);

    return {
      stage: 'static_policy',
      passed: false,
      decision: 'REVIEW',
      reasonCodes,
      ...(matchedRules.length > 0 ? { matchedRules } : {}),
      enrichments: {
        summary: `Action requires review: ${summaries.join(' ')}`.trim(),
        severity: 'medium'
      }
    };
  }

  return {
    stage: 'static_policy',
    passed: true,
    decision: 'ALLOW',
    reasonCodes: [ReasonCode.NO_POLICY_MATCH],
    enrichments: {
      summary: 'No blocking policy rule matched.'
    }
  };
}

export function decisionFromResults(results: StageResult[]): DecisionEnvelope['decision'] {
  if (results.some((result) => result.decision === 'BLOCK')) {
    return 'BLOCK';
  }

  const lastResult = results.at(-1);
  if (lastResult?.stage === 'approval' && lastResult.decision === 'ALLOW' && results.some((result) => result.decision === 'REVIEW')) {
    return 'ALLOW';
  }

  if (results.some((result) => result.decision === 'REVIEW')) {
    return 'REVIEW';
  }

  return 'ALLOW';
}

export function collectMatchedRules(results: StageResult[]): MatchedRule[] | undefined {
  const rules = results.flatMap((result) => result.matchedRules ?? []);
  return rules.length > 0 ? rules : undefined;
}

export function validatePolicyRules(config: PolicyConfig): PolicyRuleValidationError[] {
  const errors: PolicyRuleValidationError[] = [];

  (config.forbiddenCommands ?? []).forEach((pattern, index) => {
    try {
      new RegExp(pattern, 'i');
    } catch {
      errors.push({
        field: 'forbiddenCommands',
        index,
        value: pattern,
        reason: 'invalid regex'
      });
    }
  });

  (config.forbiddenPaths ?? []).forEach((pattern, index) => {
    try {
      new Minimatch(normalizePath(pattern));
    } catch {
      errors.push({
        field: 'forbiddenPaths',
        index,
        value: pattern,
        reason: 'invalid glob'
      });
    }
  });

  if (config.recipientThreshold && (!Number.isInteger(config.recipientThreshold.maxRecipients) || config.recipientThreshold.maxRecipients <= 0)) {
    errors.push({
      field: 'recipientThreshold.maxRecipients',
      index: 0,
      value: String(config.recipientThreshold.maxRecipients),
      reason: 'must be a positive integer'
    });
  }

  (config.outboundRules ?? []).forEach((rule, index) => {
    if (rule.pattern.trim() !== '') {
      return;
    }

    errors.push({
      field: 'outboundRules',
      index,
      value: rule.pattern,
      reason: 'pattern must be non-empty'
    });
  });

  return errors;
}
