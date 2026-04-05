import { describe, expect, it, vi } from 'vitest';

import { BlockedActionError } from '@moshe/adapter-generic-tools';
import { MemoryStore, Moshe } from '@moshe/sdk';

import { AnthropicAdapter } from '../src/adapter.js';
import type { AnthropicToolUseBlock } from '../src/types.js';

function toolUse(name: string, input: Record<string, unknown> = {}): AnthropicToolUseBlock {
  return {
    type: 'tool_use',
    id: `toolu_${name}`,
    name,
    input
  };
}

describe('AnthropicAdapter', () => {
  it('wrapToolUse allows benign tool and calls execute', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const execute = vi.fn(async () => 'result');
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-allow'));

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('search', { query: 'docs' }),
      execute
    })).resolves.toBe('result');

    expect(execute).toHaveBeenCalledTimes(1);
    await moshe.close();
  });

  it('wrapToolUse blocks forbidden tool by name', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenTools: ['dangerous_tool'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-tool'));

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('dangerous_tool'),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('wrapToolUse maps path field from input', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenPaths: ['/etc/**'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-path'));

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('read_file', { path: '/etc/shadow' }),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('wrapToolUse does not parse JSON - input is already an object', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const execute = vi.fn(async () => 'ok');
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-object-input'));

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('read_file', { path: '/app/config.json' }),
      execute
    })).resolves.toBe('ok');

    expect(execute).toHaveBeenCalledTimes(1);
    await moshe.close();
  });

  it('tryWrapToolUse returns BLOCK result without throwing', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenTools: ['bad_tool'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-try-block'));

    const result = await adapter.tryWrapToolUse({
      toolUse: toolUse('bad_tool'),
      execute: vi.fn(async () => 'never')
    });

    expect(result.outcome).toBe('BLOCK');
    await moshe.close();
  });

  it('tryWrapToolUse returns ALLOW with value', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-try-allow'));

    const result = await adapter.tryWrapToolUse({
      toolUse: toolUse('search'),
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
      policy: { version: '0.1.0', forbiddenTools: ['bad_tool'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    let fired = false;
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-callback'), {
      onBlock: () => {
        fired = true;
      }
    });

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('bad_tool'),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    expect(fired).toBe(true);
    await moshe.close();
  });

  it('wrapToolUse maps command field from input', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-command'));

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('run_command', { command: 'rm -rf /' }),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('wrapToolUse maps url field - outbound rule fires', async () => {
    const moshe = new Moshe({
      policy: {
        version: '0.1.0',
        outboundRules: [{ pattern: 'evil.com', action: 'block' }]
      },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-url'));

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('fetch', { url: 'https://evil.com/data' }),
      execute: vi.fn(async () => 'never')
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('execute is not called when blocked', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenTools: ['bad_tool'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const execute = vi.fn(async () => 'never');
    const adapter = new AnthropicAdapter(moshe.withSession('anthropic-no-exec'));

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('bad_tool'),
      execute
    })).rejects.toBeInstanceOf(BlockedActionError);

    expect(execute).not.toHaveBeenCalled();
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
    const adapter = new AnthropicAdapter(moshe);

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('search'),
      sessionId: 'anthropic-root-session',
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
    const adapter = new AnthropicAdapter(moshe);

    await expect(adapter.wrapToolUse({
      toolUse: toolUse('search'),
      execute: vi.fn(async () => 'never')
    })).rejects.toThrow('[MosheSDK] sessionId is required when using a root evaluator');

    await moshe.close();
  });
});
