import {
  GenericAdapter,
  type AdapterResult,
  type GenericAdapterOptions,
  type SessionEvaluator,
  type WrapToolCallOptions
} from '@moshe/adapter-generic-tools';
import type { DecisionEnvelope, ToolArguments } from '@moshe/spec';

import type { OpenAIToolCall, RootEvaluator, WrapOpenAIToolCallOptions } from './types.js';

export interface OpenAIAdapterOptions {
  framework?: string;
  onBlock?: (decision: DecisionEnvelope) => void | Promise<void>;
  onReview?: (decision: DecisionEnvelope) => void | Promise<void>;
}

function isRootEvaluator(
  evaluator: SessionEvaluator | RootEvaluator
): evaluator is RootEvaluator {
  return 'withSession' in evaluator && typeof (evaluator as unknown as Record<string, unknown>).withSession === 'function';
}

export class OpenAIAdapter {
  private readonly inner: GenericAdapter | null;

  public constructor(
    private readonly evaluator: SessionEvaluator | RootEvaluator,
    private readonly options: OpenAIAdapterOptions = {}
  ) {
    this.inner = isRootEvaluator(evaluator)
      ? null
      : new GenericAdapter(evaluator, this.genericOptions());
  }

  public async wrapToolCall<T>(options: WrapOpenAIToolCallOptions<T>): Promise<T> {
    return this.getAdapter(options.sessionId).wrapToolCall(this.buildOptions(options));
  }

  public async tryWrapToolCall<T>(options: WrapOpenAIToolCallOptions<T>): Promise<AdapterResult<T>> {
    return this.getAdapter(options.sessionId).tryWrapToolCall(this.buildOptions(options));
  }

  private genericOptions(): GenericAdapterOptions {
    return {
      framework: this.options.framework ?? 'openai',
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

  private buildOptions<T>(options: WrapOpenAIToolCallOptions<T>): WrapToolCallOptions<T> {
    const args = options.parsedArguments ?? this.parseArguments(options.toolCall.function.arguments);

    return {
      toolName: options.toolCall.function.name,
      actionType: 'tool_call',
      operation: 'call',
      arguments: this.toToolArguments(args),
      execute: options.execute,
      ...(options.agentId !== undefined ? { agentId: options.agentId } : {})
    };
  }

  private parseArguments(raw: string): Record<string, unknown> {
    try {
      const parsed = JSON.parse(raw);
      return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : {};
    } catch {
      return {};
    }
  }

  private toToolArguments(args: Record<string, unknown>): ToolArguments {
    const result: ToolArguments = {};

    if (typeof args.command === 'string') result.command = args.command;
    if (typeof args.shell === 'string') result.shell = args.shell;
    if (typeof args.path === 'string') result.path = args.path;
    if (typeof args.content === 'string') result.content = args.content;
    if (typeof args.url === 'string') result.url = args.url;
    if (typeof args.method === 'string') result.method = args.method;
    if (typeof args.subject === 'string') result.subject = args.subject;
    if (typeof args.body === 'string') result.body = args.body;
    if (typeof args.agentAuthored === 'boolean') result.agentAuthored = args.agentAuthored;

    if (
      typeof args.headers === 'object'
      && args.headers !== null
      && !Array.isArray(args.headers)
      && Object.values(args.headers).every((value) => typeof value === 'string')
    ) {
      result.headers = args.headers as Record<string, string>;
    }

    if (
      typeof args.params === 'object'
      && args.params !== null
      && !Array.isArray(args.params)
      && Object.values(args.params).every((value) => ['string', 'number', 'boolean'].includes(typeof value))
    ) {
      result.params = args.params as Record<string, string | number | boolean>;
    }

    if (Array.isArray(args.recipients) && args.recipients.every((recipient) => typeof recipient === 'string')) {
      result.recipients = args.recipients as string[];
    }

    return result;
  }
}
