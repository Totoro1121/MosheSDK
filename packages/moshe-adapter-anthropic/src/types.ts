import type { SessionEvaluator } from '@moshesdk/adapter-generic-tools';

export interface RootEvaluator {
  withSession(sessionId: string): SessionEvaluator;
}

export interface AnthropicToolUseBlock {
  type: 'tool_use';
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface WrapAnthropicToolUseOptions<T> {
  toolUse: AnthropicToolUseBlock;
  execute: () => Promise<T>;
  agentId?: string;
  sessionId?: string;
}
