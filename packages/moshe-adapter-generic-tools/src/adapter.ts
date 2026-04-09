import type { EvaluateInput } from '@moshesdk/core';
import type { DecisionEnvelope } from '@moshesdk/spec';

import {
  type AdapterResult,
  BlockedActionError,
  ReviewRequiredError,
  type SessionEvaluator,
  type WrapCommandOptions,
  type WrapMessageOptions,
  type WrapOutboundOptions,
  type WrapToolCallOptions
} from './types.js';

export interface GenericAdapterOptions {
  framework?: string;
  onBlock?: (decision: DecisionEnvelope) => void | Promise<void>;
  onReview?: (decision: DecisionEnvelope) => void | Promise<void>;
}

export class GenericAdapter {
  public constructor(
    private readonly evaluator: SessionEvaluator,
    private readonly options: GenericAdapterOptions = {}
  ) {}

  public async wrapToolCall<T>(options: WrapToolCallOptions<T>): Promise<T> {
    return this.executeWithDecision(options.execute, this.buildToolCallInput(options));
  }

  public async tryWrapToolCall<T>(options: WrapToolCallOptions<T>): Promise<AdapterResult<T>> {
    return this.tryExecuteWithDecision(options.execute, this.buildToolCallInput(options));
  }

  public async wrapCommand<T>(options: WrapCommandOptions<T>): Promise<T> {
    return this.executeWithDecision(options.execute, this.buildCommandInput(options));
  }

  public async tryWrapCommand<T>(options: WrapCommandOptions<T>): Promise<AdapterResult<T>> {
    return this.tryExecuteWithDecision(options.execute, this.buildCommandInput(options));
  }

  public async wrapOutbound<T>(options: WrapOutboundOptions<T>): Promise<T> {
    return this.executeWithDecision(options.execute, this.buildOutboundInput(options));
  }

  public async tryWrapOutbound<T>(options: WrapOutboundOptions<T>): Promise<AdapterResult<T>> {
    return this.tryExecuteWithDecision(options.execute, this.buildOutboundInput(options));
  }

  public async wrapMessage<T>(options: WrapMessageOptions<T>): Promise<T> {
    return this.executeWithDecision(options.execute, this.buildMessageInput(options));
  }

  public async tryWrapMessage<T>(options: WrapMessageOptions<T>): Promise<AdapterResult<T>> {
    return this.tryExecuteWithDecision(options.execute, this.buildMessageInput(options));
  }

  private buildToolCallInput(options: WrapToolCallOptions<unknown>): Omit<EvaluateInput, 'sessionId'> {
    return {
      framework: this.framework(),
      actionType: options.actionType ?? 'tool_call',
      operation: options.operation ?? 'call',
      toolName: options.toolName,
      arguments: options.arguments ?? {},
      ...(options.referencedPaths ? { referencedPaths: options.referencedPaths } : {}),
      ...(options.outboundTargets ? { outboundTargets: options.outboundTargets } : {}),
      ...(options.agentId !== undefined ? { agentId: options.agentId } : {}),
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
      ...(options.metadata !== undefined ? { metadata: options.metadata } : {})
    };
  }

  private buildCommandInput(options: WrapCommandOptions<unknown>): Omit<EvaluateInput, 'sessionId'> {
    return {
      framework: this.framework(),
      actionType: 'command_exec',
      operation: 'exec',
      toolName: options.toolName ?? 'shell',
      arguments: {
        command: options.command,
        ...(options.shell !== undefined ? { shell: options.shell } : {})
      },
      ...(options.referencedPaths ? { referencedPaths: options.referencedPaths } : {}),
      ...(options.agentId !== undefined ? { agentId: options.agentId } : {}),
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
      ...(options.metadata !== undefined ? { metadata: options.metadata } : {})
    };
  }

  private buildOutboundInput(options: WrapOutboundOptions<unknown>): Omit<EvaluateInput, 'sessionId'> {
    return {
      framework: this.framework(),
      actionType: 'outbound_request',
      operation: options.method?.toLowerCase() ?? 'get',
      toolName: options.toolName ?? 'http_request',
      arguments: {
        url: options.url,
        method: options.method ?? 'GET',
        ...(options.headers !== undefined ? { headers: options.headers } : {})
      },
      outboundTargets: [options.url, ...(options.outboundTargets ?? [])],
      ...(options.agentId !== undefined ? { agentId: options.agentId } : {}),
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
      ...(options.metadata !== undefined ? { metadata: options.metadata } : {})
    };
  }

  private buildMessageInput(options: WrapMessageOptions<unknown>): Omit<EvaluateInput, 'sessionId'> {
    return {
      framework: this.framework(),
      actionType: 'message_send',
      operation: 'send',
      toolName: options.toolName ?? 'send_message',
      arguments: {
        recipients: options.recipients,
        ...(options.subject !== undefined ? { subject: options.subject } : {}),
        ...(options.body !== undefined ? { body: options.body } : {})
      },
      ...(options.agentId !== undefined ? { agentId: options.agentId } : {}),
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
      ...(options.metadata !== undefined ? { metadata: options.metadata } : {})
    };
  }

  private framework(): string {
    return this.options.framework ?? 'generic';
  }

  private async executeWithDecision<T>(execute: () => Promise<T>, input: Omit<EvaluateInput, 'sessionId'>): Promise<T> {
    const decision = await this.evaluator.evaluate(input);
    return this.handleDecision(decision, execute);
  }

  private async handleDecision<T>(decision: DecisionEnvelope, execute: () => Promise<T>): Promise<T> {
    switch (decision.decision) {
      case 'ALLOW':
        return execute();
      case 'BLOCK':
        if (this.options.onBlock) {
          await this.options.onBlock(decision);
        }
        throw new BlockedActionError(decision);
      case 'REVIEW':
        if (this.options.onReview) {
          await this.options.onReview(decision);
        }
        throw new ReviewRequiredError(decision);
    }
  }

  private async handleDecisionAsResult<T>(
    decision: DecisionEnvelope,
    execute: () => Promise<T>
  ): Promise<AdapterResult<T>> {
    switch (decision.decision) {
      case 'ALLOW': {
        const value = await execute();
        return { outcome: 'ALLOW', value, decision };
      }
      case 'BLOCK':
        return { outcome: 'BLOCK', decision };
      case 'REVIEW':
        return {
          outcome: 'REVIEW',
          decision,
          ...(decision.approvalRequest !== undefined ? { approvalRequest: decision.approvalRequest } : {})
        };
    }
  }

  private async tryExecuteWithDecision<T>(
    execute: () => Promise<T>,
    input: Omit<EvaluateInput, 'sessionId'>
  ): Promise<AdapterResult<T>> {
    const decision = await this.evaluator.evaluate(input);
    return this.handleDecisionAsResult(decision, execute);
  }
}
