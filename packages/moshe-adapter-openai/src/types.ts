import type { SessionEvaluator } from '@moshesdk/adapter-generic-tools';

export interface RootEvaluator {
  withSession(sessionId: string): SessionEvaluator;
}

export interface OpenAIToolCall {
  id: string;
  type: 'function';
  function: {
    name: string;
    arguments: string;
  };
}

export interface WrapOpenAIToolCallOptions<T> {
  toolCall: OpenAIToolCall;
  execute: () => Promise<T>;
  parsedArguments?: Record<string, unknown>;
  agentId?: string;
  sessionId?: string;
}
