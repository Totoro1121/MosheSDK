import { ReasonCode, type ActionEnvelope, type Decision, type MatchedRule } from '@moshe/spec';

import type { DecisionProvider, EngineContext, StageResult } from './interfaces.js';

export class NoopDecisionProvider implements DecisionProvider {
  public readonly name = 'noop';

  public async evaluate(
    _envelope: ActionEnvelope,
    _ctx: EngineContext
  ): Promise<StageResult | null> {
    return null;
  }
}

export type DecisionCallback = (
  envelope: ActionEnvelope,
  ctx: EngineContext
) => Promise<StageResult | null>;

export interface CallbackDecisionProviderOptions {
  name?: string;
  callback: DecisionCallback;
}

export class CallbackDecisionProvider implements DecisionProvider {
  public readonly name: string;
  private readonly callback: DecisionCallback;

  public constructor(options: CallbackDecisionProviderOptions) {
    this.name = options.name ?? 'callback';
    this.callback = options.callback;
  }

  public async evaluate(
    envelope: ActionEnvelope,
    ctx: EngineContext
  ): Promise<StageResult | null> {
    return this.callback(envelope, ctx);
  }
}

export interface HttpDecisionProviderOptions {
  name?: string;
  url: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  onError?: 'null' | 'throw';
}

const VALID_REASON_CODES = new Set<string>(Object.values(ReasonCode));

function isValidReasonCode(value: string): value is typeof ReasonCode[keyof typeof ReasonCode] {
  return VALID_REASON_CODES.has(value);
}

function isValidDecision(value: unknown): value is Decision {
  return value === 'ALLOW' || value === 'BLOCK' || value === 'REVIEW';
}

function isValidMatchedRule(value: unknown): value is MatchedRule {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  return typeof candidate.ruleId === 'string'
    && typeof candidate.ruleType === 'string'
    && typeof candidate.matchedValue === 'string';
}

/**
 * HTTP-backed decision provider using the global fetch implementation available in Node 18+.
 */
export class HttpDecisionProvider implements DecisionProvider {
  public readonly name: string;
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;
  private readonly onError: 'null' | 'throw';
  private readonly warnedOnInsecureUrl: boolean;

  public constructor(options: HttpDecisionProviderOptions) {
    this.name = options.name ?? 'http';
    this.url = options.url;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.headers = options.headers ?? {};
    this.onError = options.onError ?? 'null';
    this.warnedOnInsecureUrl = !this.url.startsWith('https://');

    if (this.warnedOnInsecureUrl) {
      console.warn('[MosheSDK] HttpDecisionProvider: URL is not HTTPS. Sensitive metadata may be transmitted in cleartext.');
    }
  }

  public async evaluate(
    envelope: ActionEnvelope,
    _ctx: EngineContext
  ): Promise<StageResult | null> {
    try {
      const sanitizedArguments = { ...envelope.arguments };
      delete (sanitizedArguments as Partial<typeof sanitizedArguments>).content;
      delete (sanitizedArguments as Partial<typeof sanitizedArguments>).body;
      delete (sanitizedArguments as Partial<typeof sanitizedArguments>).headers;
      delete (sanitizedArguments as Partial<typeof sanitizedArguments>).params;

      const sanitizedEnvelope = {
        ...envelope,
        arguments: sanitizedArguments
      };

      const response = await globalThis.fetch(this.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.headers
        },
        body: JSON.stringify({ envelope: sanitizedEnvelope, sessionId: envelope.sessionId }),
        signal: AbortSignal.timeout(this.timeoutMs)
      });

      if (!response.ok) {
        return this.handleError(new Error(`HTTP ${response.status} ${response.statusText}`));
      }

      const body: unknown = await response.json();
      if (
        typeof body !== 'object'
        || body === null
        || !('passed' in body)
        || typeof (body as Record<string, unknown>).passed !== 'boolean'
      ) {
        return this.handleError(new Error('Response missing required "passed" field'));
      }

      const raw = body as Record<string, unknown>;
      const result: StageResult = {
        stage: 'decision_provider',
        passed: raw.passed as boolean
      };

      if (isValidDecision(raw.decision)) {
        result.decision = raw.decision;
      }

      if (Array.isArray(raw.reasonCodes)) {
        result.reasonCodes = raw.reasonCodes
          .filter((value): value is string => typeof value === 'string')
          .filter(isValidReasonCode);
      }

      if (Array.isArray(raw.matchedRules)) {
        const matchedRules = raw.matchedRules.filter(isValidMatchedRule);
        if (matchedRules.length > 0) {
          result.matchedRules = matchedRules;
        }
      }

      if (typeof raw.summary === 'string' && raw.summary.trim() !== '') {
        result.enrichments = { summary: raw.summary };
      }

      return result;
    } catch (error) {
      return this.handleError(error);
    }
  }

  private handleError(error: unknown): StageResult | null {
    if (this.onError === 'throw') {
      throw error instanceof Error ? error : new Error(String(error));
    }

    return null;
  }
}
