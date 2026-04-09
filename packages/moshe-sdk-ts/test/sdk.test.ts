import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { describe, expect, it } from 'vitest';

import { AnthropicAdapter, ApprovalBlockedError, BlockedActionError, FilePolicyProvider, GenericAdapter, InProcessApprovalProvider, MemoryStore, Moshe, OpenAIAdapter, ScrubbingTelemetrySink } from '@moshesdk/sdk';
import type { ActionEnvelope } from '@moshesdk/spec';

import { loadFixture } from '../../../test/fixtures.js';

async function tempPolicyPath(fileName: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'moshe-sdk-policy-'));
  return join(dir, fileName);
}

describe('Moshe SDK', () => {
  it('auto-generates actionId and timestamp when absent', async () => {
    const sdk = new Moshe({
      policy: {
        version: '0.1.0'
      },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const decision = await sdk.evaluate({
      sessionId: 'sdk-session',
      framework: 'generic',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'bash',
      arguments: {
        command: 'ls'
      }
    });

    expect(decision.decision).toBe('ALLOW');
    await sdk.close();
  });

  it('supports session-scoped evaluation', async () => {
    const sdk = new Moshe({
      policy: {
        version: '0.1.0',
        forbiddenFiles: ['.env']
      },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const session = sdk.withSession('prefilled-session');
    const decision = await session.evaluate({
      framework: 'generic',
      actionType: 'file_read',
      operation: 'read',
      toolName: 'read_file',
      arguments: {
        path: '.env'
      }
    });

    expect(decision.decision).toBe('BLOCK');
    await sdk.close();
  });

  it('turns sensitive-file review into a final block when onUnhandledReview is BLOCK', async () => {
    const action = await loadFixture<ActionEnvelope>('actions/review-sensitive-file.json');
    const sdk = new Moshe({
      policy: {
        version: '0.1.0',
        sensitiveFiles: ['.env']
      },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const decision = await sdk.evaluate(action);
    expect(decision.decision).toBe('BLOCK');
    expect(decision.reasonCodes).toContain('UNHANDLED_REVIEW_FALLBACK');
    await sdk.close();
  });

  it('supports FilePolicyProvider via top-level sdk export', async () => {
    const path = await tempPolicyPath('policy.json');
    await writeFile(path, JSON.stringify({
      version: '0.1.0',
      outboundRules: [
        { pattern: 'evil.example.com', action: 'block' }
      ]
    }, null, 2), 'utf8');

    const sdk = new Moshe({
      policy: new FilePolicyProvider(path),
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const decision = await sdk.evaluate(await loadFixture<ActionEnvelope>('actions/block-outbound-rule.json'));
    expect(decision.decision).toBe('BLOCK');
    await sdk.close();
  });

  it('GenericAdapter and BlockedActionError are importable from @moshesdk/sdk', async () => {
    const moshe = new Moshe({
      policy: {
        version: '0.1.0',
        forbiddenCommands: ['rm\\s+-rf\\s+/']
      },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new GenericAdapter(moshe.withSession('test'));

    await expect(
      adapter.wrapCommand({
        command: 'rm -rf /',
        execute: async () => 'never'
      })
    ).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('InProcessApprovalProvider is importable from @moshesdk/sdk', () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });

    expect(typeof provider.create).toBe('function');
    expect(typeof provider.resolve).toBe('function');
    expect(typeof provider.check).toBe('function');
  });

  it('OpenAIAdapter and AnthropicAdapter are importable from @moshesdk/sdk', async () => {
    const moshe = new Moshe({
      policy: {
        version: '0.1.0',
        forbiddenTools: ['dangerous_tool']
      },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const openai = new OpenAIAdapter(moshe.withSession('openai-sdk-test'));
    await expect(openai.wrapToolCall({
      toolCall: {
        id: 'call_danger',
        type: 'function',
        function: {
          name: 'dangerous_tool',
          arguments: '{}'
        }
      },
      execute: async () => 'never'
    })).rejects.toBeInstanceOf(BlockedActionError);

    const anthropic = new AnthropicAdapter(moshe.withSession('anthropic-sdk-test'));
    await expect(anthropic.wrapToolUse({
      toolUse: {
        type: 'tool_use',
        id: 'toolu_danger',
        name: 'dangerous_tool',
        input: {}
      },
      execute: async () => 'never'
    })).rejects.toBeInstanceOf(BlockedActionError);

    await moshe.close();
  });

  it('ApprovalBlockedError and ScrubbingTelemetrySink are importable from @moshesdk/sdk', () => {
    const sink = new ScrubbingTelemetrySink({
      name: 'test-sink',
      emit: async () => undefined
    });

    expect(new ApprovalBlockedError('fp')).toBeInstanceOf(Error);
    expect(sink.name).toBe('scrubbing(test-sink)');
  });
});
