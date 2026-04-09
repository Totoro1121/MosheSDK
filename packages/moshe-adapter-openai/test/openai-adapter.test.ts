import { describe, expect, it, vi } from 'vitest';

import { BlockedActionError } from '@moshesdk/adapter-generic-tools';
import { MemoryStore, Moshe } from '@moshesdk/sdk';

import { OpenAIAdapter } from '../src/adapter.js';
import type { OpenAIToolCall } from '../src/types.js';

function toolCall(name: string, args: Record<string, unknown> = {}): OpenAIToolCall {
  return {
    id: `call_${name}`,
    type: 'function',
    function: {
      name,
      arguments: JSON.stringify(args)
    }
  };
}

describe('OpenAIAdapter', () => {
  it('wrapToolCall allows benign tool and calls execute', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const execute = vi.fn(async () => 'result');
    const adapter = new OpenAIAdapter(moshe.withSession('openai-allow'));

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('search', { query: 'docs' }),
      execute
    })).resolves.toBe('result');

    expect(execute).toHaveBeenCalledTimes(1);
    await moshe.close();
  });

  it('wrapToolCall maps tool name from function.name', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenTools: ['dangerous_tool'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const execute = vi.fn(async () => 'never');
    const adapter = new OpenAIAdapter(moshe.withSession('openai-forbidden-tool'));

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('dangerous_tool'),
      execute
    })).rejects.toBeInstanceOf(BlockedActionError);

    expect(execute).not.toHaveBeenCalled();
    await moshe.close();
  });

  it('wrapToolCall maps arguments.path from parsed JSON', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenPaths: ['/etc/**'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new OpenAIAdapter(moshe.withSession('openai-path'));

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('read_file', { path: '/etc/passwd' }),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('wrapToolCall handles malformed JSON arguments gracefully', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const execute = vi.fn(async () => 'ok');
    const adapter = new OpenAIAdapter(moshe.withSession('openai-malformed'));

    await expect(adapter.wrapToolCall({
      toolCall: {
        id: 'call_bad_json',
        type: 'function',
        function: {
          name: 'search',
          arguments: 'not-json'
        }
      },
      execute
    })).resolves.toBe('ok');

    expect(execute).toHaveBeenCalledTimes(1);
    await moshe.close();
  });

  it('wrapToolCall uses parsedArguments when provided', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenPaths: ['/etc/**'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new OpenAIAdapter(moshe.withSession('openai-parsed-args'));

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('read_file'),
      parsedArguments: { path: '/etc/passwd' },
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('tryWrapToolCall returns BLOCK result without throwing', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenTools: ['dangerous_tool'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new OpenAIAdapter(moshe.withSession('openai-try-block'));

    const result = await adapter.tryWrapToolCall({
      toolCall: toolCall('dangerous_tool'),
      execute: vi.fn(async () => 'never')
    });

    expect(result.outcome).toBe('BLOCK');
    await moshe.close();
  });

  it('tryWrapToolCall returns ALLOW result with value', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new OpenAIAdapter(moshe.withSession('openai-try-allow'));

    const result = await adapter.tryWrapToolCall({
      toolCall: toolCall('search'),
      execute: async () => 'value'
    });

    expect(result.outcome).toBe('ALLOW');
    if (result.outcome === 'ALLOW') {
      expect(result.value).toBe('value');
    }
    await moshe.close();
  });

  it('onBlock callback fires on BLOCK', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenTools: ['dangerous_tool'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    let fired = false;
    const adapter = new OpenAIAdapter(moshe.withSession('openai-callback'), {
      onBlock: () => {
        fired = true;
      }
    });

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('dangerous_tool'),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    expect(fired).toBe(true);
    await moshe.close();
  });

  it('wrapToolCall maps command field from arguments', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new OpenAIAdapter(moshe.withSession('openai-command'));

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('run_command', { command: 'rm -rf /' }),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('wrapToolCall maps url field - outbound rule fires', async () => {
    const moshe = new Moshe({
      policy: {
        version: '0.1.0',
        outboundRules: [{ pattern: 'evil.com', action: 'block' }]
      },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new OpenAIAdapter(moshe.withSession('openai-url'));

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('http_fetch', { url: 'https://evil.com/data' }),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('supports root evaluators when sessionId is provided', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const execute = vi.fn(async () => 'root-result');
    const adapter = new OpenAIAdapter(moshe);

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('search'),
      sessionId: 'openai-root-session',
      execute
    })).resolves.toBe('root-result');

    expect(execute).toHaveBeenCalledTimes(1);
    await moshe.close();
  });

  it('throws a descriptive error when root evaluator is used without sessionId', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new OpenAIAdapter(moshe);

    await expect(adapter.wrapToolCall({
      toolCall: toolCall('search'),
      execute: vi.fn(async () => 'never')
    })).rejects.toThrow('[MosheSDK] sessionId is required when using a root evaluator');

    await moshe.close();
  });
});
