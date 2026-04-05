import type { ApprovalRequest, ActionType, DecisionEnvelope, ToolArguments } from '@moshe/spec';
import type { EvaluateInput } from '@moshe/core';

export interface SessionEvaluator {
  evaluate(input: Omit<EvaluateInput, 'sessionId'>): Promise<DecisionEnvelope>;
}

export class MosheAdapterError extends Error {
  public readonly decision: DecisionEnvelope;

  public constructor(message: string, decision: DecisionEnvelope) {
    super(message);
    this.name = 'MosheAdapterError';
    this.decision = decision;
  }
}

export class BlockedActionError extends MosheAdapterError {
  public constructor(decision: DecisionEnvelope) {
    super(`Action blocked: ${decision.summary}`, decision);
    this.name = 'BlockedActionError';
  }
}

export class ReviewRequiredError extends MosheAdapterError {
  public readonly approvalRequest: ApprovalRequest | undefined;

  public constructor(decision: DecisionEnvelope) {
    super(`Action requires review: ${decision.summary}`, decision);
    this.name = 'ReviewRequiredError';
    this.approvalRequest = decision.approvalRequest;
  }
}

export type AdapterResult<T> =
  | { outcome: 'ALLOW'; value: T; decision: DecisionEnvelope }
  | { outcome: 'BLOCK'; decision: DecisionEnvelope }
  | { outcome: 'REVIEW'; decision: DecisionEnvelope; approvalRequest?: ApprovalRequest };

interface WrapBase<T> {
  execute: () => Promise<T>;
  agentId?: string;
  cwd?: string;
  metadata?: Record<string, unknown>;
}

export interface WrapToolCallOptions<T> extends WrapBase<T> {
  toolName: string;
  actionType?: ActionType;
  operation?: string;
  arguments?: ToolArguments;
  referencedPaths?: string[];
  outboundTargets?: string[];
}

export interface WrapCommandOptions<T> extends WrapBase<T> {
  toolName?: string;
  command: string;
  shell?: string;
  referencedPaths?: string[];
}

export interface WrapOutboundOptions<T> extends WrapBase<T> {
  toolName?: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  outboundTargets?: string[];
}

export interface WrapMessageOptions<T> extends WrapBase<T> {
  toolName?: string;
  recipients: string[];
  subject?: string;
  body?: string;
}
