import { randomUUID } from 'node:crypto';

import {
  FeedbackEmitter,
  FilePolicyProvider,
  MemoryTelemetrySink,
  MosheEngine,
  StaticPolicyProvider,
  type EvaluateInput,
  validatePolicyRules,
  type Analyzer,
  type ApprovalProvider,
  type ArtifactStore,
  type DecisionProvider,
  type PolicyProvider,
  type SessionStore,
  type TelemetrySink
} from '@moshesdk/core';
import type { ActionEnvelope, DecisionEnvelope, PolicyConfig } from '@moshesdk/spec';
import { FileStore } from '@moshesdk/store-file';
import { MemoryStore } from '@moshesdk/store-memory';

type StoreLike = SessionStore & ArtifactStore & {
  close?: () => Promise<void>;
};

export interface MosheOptions {
  policy: PolicyConfig | PolicyProvider;
  store: StoreLike;
  analyzers?: Analyzer[];
  decisionProvider?: DecisionProvider;
  approvalProvider?: ApprovalProvider;
  telemetrySinks?: TelemetrySink[];
  onError: 'BLOCK' | 'ALLOW';
  onUnhandledReview: 'BLOCK' | 'ALLOW';
}

function isPolicyProvider(value: PolicyConfig | PolicyProvider): value is PolicyProvider {
  return typeof value === 'object'
    && value !== null
    && 'load' in value
    && 'validate' in value
    && 'getEffective' in value;
}

function normalizeInput(input: EvaluateInput): ActionEnvelope {
  return {
    ...input,
    actionId: input.actionId ?? randomUUID(),
    timestamp: input.timestamp ?? new Date().toISOString()
  };
}

export class Moshe {
  private readonly engine: MosheEngine;
  private readonly store: StoreLike;
  public readonly feedback: FeedbackEmitter;

  public constructor(options: MosheOptions) {
    const policyProvider = isPolicyProvider(options.policy)
      ? options.policy
      : new StaticPolicyProvider({
          ...options.policy,
          version: options.policy.version || '0.1.0'
        });

    this.store = options.store;
    const config = {
      policy: policyProvider,
      sessionStore: options.store,
      artifactStore: options.store,
      onError: options.onError,
      onUnhandledReview: options.onUnhandledReview
    };

    this.engine = new MosheEngine({
      ...config,
      ...(options.analyzers ? { analyzers: options.analyzers } : {}),
      ...(options.decisionProvider ? { decisionProvider: options.decisionProvider } : {}),
      ...(options.approvalProvider ? { approvalProvider: options.approvalProvider } : {}),
      ...(options.telemetrySinks ? { telemetrySinks: options.telemetrySinks } : {})
    });
    this.feedback = new FeedbackEmitter(options.telemetrySinks ?? []);
  }

  public async evaluate(input: EvaluateInput): Promise<DecisionEnvelope> {
    return this.engine.evaluate(normalizeInput(input));
  }

  public withSession(sessionId: string): MosheSession {
    return new MosheSession(this, sessionId);
  }

  public async close(): Promise<void> {
    await this.store.close?.();
  }
}

export class MosheSession {
  public constructor(
    private readonly moshe: Moshe,
    private readonly sessionId: string
  ) {}

  public async evaluate(input: Omit<EvaluateInput, 'sessionId'>): Promise<DecisionEnvelope> {
    return this.moshe.evaluate({
      ...input,
      sessionId: this.sessionId
    });
  }
}

export { MemoryStore, FileStore };
export {
  applyPresetOverlays,
  ASSISTANT_WITH_TOOLS_PRESET,
  BROWSING_AGENT_PRESET,
  CallbackDecisionProvider,
  CODING_AGENT_PRESET,
  CommandIntentAnalyzer,
  ApprovalBlockedError,
  HttpDecisionProvider,
  FeedbackEmitter,
  FileAccessIntentAnalyzer,
  FilePolicyProvider,
  InProcessApprovalProvider,
  MemoryTelemetrySink,
  NoopDecisionProvider,
  OutboundClassificationAnalyzer,
  PRESETS,
  PRESET_NAMES,
  resolveLineage,
  ScrubbingTelemetrySink,
  validatePolicyRules
} from '@moshesdk/core';
export { OpenAIAdapter } from '@moshesdk/adapter-openai';
export type { OpenAIAdapterOptions, OpenAIToolCall, WrapOpenAIToolCallOptions } from '@moshesdk/adapter-openai';
export { AnthropicAdapter } from '@moshesdk/adapter-anthropic';
export type { AnthropicAdapterOptions, AnthropicToolUseBlock, WrapAnthropicToolUseOptions } from '@moshesdk/adapter-anthropic';
export {
  BlockedActionError,
  GenericAdapter,
  MosheAdapterError,
  ReviewRequiredError
} from '@moshesdk/adapter-generic-tools';
export type {
  AdapterResult,
  GenericAdapterOptions,
  SessionEvaluator,
  WrapCommandOptions,
  WrapMessageOptions,
  WrapOutboundOptions,
  WrapToolCallOptions
} from '@moshesdk/adapter-generic-tools';
export type {
  ApprovalContext,
  ApprovalResolution,
  CallbackDecisionProviderOptions,
  DecisionCallback,
  HttpDecisionProviderOptions,
  InProcessApprovalProviderOptions
} from '@moshesdk/core';
export type { FeedbackSubmission } from '@moshesdk/core';
export type * from '@moshesdk/spec';
export type * from '@moshesdk/core';
