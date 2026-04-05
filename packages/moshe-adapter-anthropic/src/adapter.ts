import {
  GenericAdapter,
  type AdapterResult,
  type GenericAdapterOptions,
  type SessionEvaluator,
  type WrapToolCallOptions
} from '@moshe/adapter-generic-tools';
import type { DecisionEnvelope, ToolArguments } from '@moshe/spec';

import type { AnthropicToolUseBlock, RootEvaluator, WrapAnthropicToolUseOptions } from './types.js';

export interface AnthropicAdapterOptions {
  framework?: string;
  onBlock?: (decision: DecisionEnvelope) => void | Promise<void>;
  onReview?: (decision: DecisionEnvelope) => void | Promise<void>;
}

function isRootEvaluator(
  evaluator: SessionEvaluator | RootEvaluator
): evaluator is RootEvaluator {
  return 'withSession' in evaluator && typeof (evaluator as unknown as Record<string, unknown>).withSession === 'function';
}

export class AnthropicAdapter {
  private readonly inner: GenericAdapter | null;

  public constructor(
    private readonly evaluator: SessionEvaluator | RootEvaluator,
    private readonly options: AnthropicAdapterOptions = {}
  ) {
    this.inner = isRootEvaluator(evaluator)
      ? null
      : new GenericAdapter(evaluator, this.genericOptions());
  }

  public async wrapToolUse<T>(options: WrapAnthropicToolUseOptions<T>): Promise<T> {
    return this.getAdapter(options.sessionId).wrapToolCall(this.buildOptions(options));
  }

  public async tryWrapToolUse<T>(options: WrapAnthropicToolUseOptions<T>): Promise<AdapterResult<T>> {
    return this.getAdapter(options.sessionId).tryWrapToolCall(this.buildOptions(options));
  }

  private genericOptions(): GenericAdapterOptions {
    return {
      framework: this.options.framework ?? 'anthropic',
      ...(this.options.onBlock !== undefined ? { onBlock: this.options.onBlock } : {}),
      ...(this.options.onReview !== undefined ? { onReview: this.options.onReview } : {})
    };
  }

  private getAdapter(sessionId?: string): GenericAdapter {
    if (isRootEvaluator(this.evaluator)) {
      if (!sessionId) {
        throw new Error('[MosheSDK] sessionId is required when using a root evaluator');
      }

      return new GenericAdapter(this.evaluator.withSession(sessionId), this.genericOptions());
    }

    if (!this.inner) {
      throw new Error('[MosheSDK] Internal adapter initialization failed');
    }

    return this.inner;
  }

  private buildOptions<T>(options: WrapAnthropicToolUseOptions<T>): WrapToolCallOptions<T> {
    return {
      toolName: options.toolUse.name,
      actionType: 'tool_call',
      operation: 'call',
      arguments: this.toToolArguments(options.toolUse.input),
      execute: options.execute,
      ...(options.agentId !== undefined ? { agentId: options.agentId } : {})
    };
  }

  private toToolArguments(input: Record<string, unknown>): ToolArguments {
    const result: ToolArguments = {};

    if (typeof input.command === 'string') result.command = input.command;
    if (typeof input.shell === 'string') result.shell = input.shell;
    if (typeof input.path === 'string') result.path = input.path;
    if (typeof input.content === 'string') result.content = input.content;
    if (typeof input.url === 'string') result.url = input.url;
    if (typeof input.method === 'string') result.method = input.method;
    if (typeof input.subject === 'string') result.subject = input.subject;
    if (typeof input.body === 'string') result.body = input.body;
    if (typeof input.agentAuthored === 'boolean') result.agentAuthored = input.agentAuthored;

    if (
      typeof input.headers === 'object'
      && input.headers !== null
      && !Array.isArray(input.headers)
      && Object.values(input.headers).every((value) => typeof value === 'string')
    ) {
      result.headers = input.headers as Record<string, string>;
    }

    if (
      typeof input.params === 'object'
      && input.params !== null
      && !Array.isArray(input.params)
      && Object.values(input.params).every((value) => ['string', 'number', 'boolean'].includes(typeof value))
    ) {
      result.params = input.params as Record<string, string | number | boolean>;
    }

    if (Array.isArray(input.recipients) && input.recipients.every((recipient) => typeof recipient === 'string')) {
      result.recipients = input.recipients as string[];
    }

    return result;
  }
}
