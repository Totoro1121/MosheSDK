import { describe, expect, it, vi } from 'vitest';

import {
  BlockedActionError,
  GenericAdapter,
  MosheAdapterError,
  ReviewRequiredError,
  type SessionEvaluator
} from '@moshe/adapter-generic-tools';
import { MemoryStore, Moshe } from '@moshe/sdk';
import type { ActionEnvelope, ApprovalRequest, DecisionEnvelope } from '@moshe/spec';

import { loadFixture } from '../../../test/fixtures.js';

describe('GenericAdapter', () => {
  it('allows wrapCommand and returns the execute result', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new GenericAdapter(moshe.withSession('allow-command'));
    const execute = vi.fn(async () => 'executed');

    await expect(adapter.wrapCommand({
      command: 'ls -la',
      execute
    })).resolves.toBe('executed');

    expect(execute).toHaveBeenCalledTimes(1);
    await moshe.close();
  });

  it('allows wrapOutbound, wrapMessage, and wrapToolCall on clean inputs', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0', recipientThreshold: { maxRecipients: 3, action: 'block' } },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new GenericAdapter(moshe.withSession('allow-others'));

    const outboundExecute = vi.fn(async () => ({ ok: true }));
    const messageExecute = vi.fn(async () => 'sent');
    const toolExecute = vi.fn(async () => 42);

    await expect(adapter.wrapOutbound({
      url: 'https://safe.example.com/data',
      execute: outboundExecute
    })).resolves.toEqual({ ok: true });

    await expect(adapter.wrapMessage({
      recipients: ['a@example.com', 'b@example.com'],
      subject: 'Hi',
      body: 'There',
      execute: messageExecute
    })).resolves.toBe('sent');

    await expect(adapter.wrapToolCall({
      toolName: 'search',
      arguments: { params: { q: 'docs' } },
      execute: toolExecute
    })).resolves.toBe(42);

    expect(outboundExecute).toHaveBeenCalledTimes(1);
    expect(messageExecute).toHaveBeenCalledTimes(1);
    expect(toolExecute).toHaveBeenCalledTimes(1);
    await moshe.close();
  });

  it('throws BlockedActionError for forbidden commands without calling execute', async () => {
    const fixture = await loadFixture<ActionEnvelope>('actions/block-forbidden-command.json');
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf\\s+/'] },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new GenericAdapter(moshe.withSession('block-command'));
    const execute = vi.fn(async () => 'never');

    let caught: unknown;
    try {
      await adapter.wrapCommand({
        command: fixture.arguments.command ?? '',
        shell: fixture.arguments.shell,
        execute
      });
    } catch (error) {
      caught = error;
    }

    expect(execute).not.toHaveBeenCalled();
    expect(caught).toBeInstanceOf(BlockedActionError);
    expect(caught).toBeInstanceOf(MosheAdapterError);
    expect((caught as BlockedActionError).decision.decision).toBe('BLOCK');
    expect((caught as BlockedActionError).decision.reasonCodes).toContain('FORBIDDEN_COMMAND');
    expect((caught as BlockedActionError).decision.severity).toBe('high');
    await moshe.close();
  });

  it('throws BlockedActionError for outbound and message threshold blocks', async () => {
    const outboundFixture = await loadFixture<ActionEnvelope>('actions/block-outbound-rule.json');
    const messageFixture = await loadFixture<ActionEnvelope>('actions/block-recipient-threshold.json');
    const moshe = new Moshe({
      policy: await loadFixture('policies/with-sensitive-and-outbound.json'),
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new GenericAdapter(moshe.withSession('block-other'));
    const outboundExecute = vi.fn(async () => 'never');
    const messageExecute = vi.fn(async () => 'never');

    await expect(adapter.wrapOutbound({
      url: outboundFixture.arguments.url ?? '',
      method: outboundFixture.arguments.method,
      execute: outboundExecute
    })).rejects.toBeInstanceOf(BlockedActionError);

    await expect(adapter.wrapMessage({
      recipients: messageFixture.arguments.recipients ?? [],
      subject: messageFixture.arguments.subject,
      body: messageFixture.arguments.body,
      execute: messageExecute
    })).rejects.toBeInstanceOf(BlockedActionError);

    expect(outboundExecute).not.toHaveBeenCalled();
    expect(messageExecute).not.toHaveBeenCalled();
    await moshe.close();
  });

  it('throws ReviewRequiredError with approval request and no execute call', async () => {
    const fixture = await loadFixture<ActionEnvelope>('actions/review-sensitive-file.json');
    const approvalRequest: ApprovalRequest = {
      approvalId: 'test-approval-001',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      callbackHint: 'Approve via test harness'
    };
    const moshe = new Moshe({
      policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
      store: new MemoryStore(),
      approvalProvider: {
        async create() {
          return approvalRequest;
        },
        async check() {
          return 'PENDING';
        }
      },
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new GenericAdapter(moshe.withSession('review-path'));
    const execute = vi.fn(async () => 'never');

    let caught: unknown;
    try {
      await adapter.wrapToolCall({
        toolName: fixture.toolName,
        actionType: fixture.actionType,
        operation: fixture.operation,
        arguments: fixture.arguments,
        execute
      });
    } catch (error) {
      caught = error;
    }

    expect(execute).not.toHaveBeenCalled();
    expect(caught).toBeInstanceOf(ReviewRequiredError);
    expect(caught).toBeInstanceOf(MosheAdapterError);
    expect((caught as ReviewRequiredError).approvalRequest?.approvalId).toBe('test-approval-001');
    expect((caught as ReviewRequiredError).decision.decision).toBe('REVIEW');
    await moshe.close();
  });

  it('propagates evaluator errors unchanged and never calls execute', async () => {
    const rootError = new Error('evaluate failed');
    const evaluator: SessionEvaluator = {
      async evaluate() {
        throw rootError;
      }
    };
    const adapter = new GenericAdapter(evaluator);
    const execute = vi.fn(async () => 'never');

    await expect(adapter.wrapToolCall({
      toolName: 'search',
      execute
    })).rejects.toBe(rootError);

    expect(execute).not.toHaveBeenCalled();
  });

  it('works with default and custom framework options', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const defaultAdapter = new GenericAdapter(moshe.withSession('default-framework'));
    const customAdapter = new GenericAdapter(moshe.withSession('custom-framework'), {
      framework: 'my-agent'
    });

    await expect(defaultAdapter.wrapToolCall({
      toolName: 'search',
      execute: async () => 'ok'
    })).resolves.toBe('ok');

    await expect(customAdapter.wrapCommand({
      command: 'echo test',
      execute: async () => 'ok'
    })).resolves.toBe('ok');

    await moshe.close();
  });

  describe('tryWrap* - non-throwing result mode', () => {
    it('tryWrapCommand returns ALLOW result with value when engine allows', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0' },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('try-allow'));

      const result = await adapter.tryWrapCommand({
        command: 'echo hello',
        execute: async () => 'output'
      });

      expect(result.outcome).toBe('ALLOW');
      if (result.outcome === 'ALLOW') {
        expect(result.value).toBe('output');
        expect(result.decision.decision).toBe('ALLOW');
      }

      await moshe.close();
    });

    it('tryWrapCommand returns BLOCK result without throwing', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('try-block'));

      const result = await adapter.tryWrapCommand({
        command: 'rm -rf /',
        execute: async () => 'done'
      });

      expect(result.outcome).toBe('BLOCK');
      expect(result.decision.decision).toBe('BLOCK');
      await moshe.close();
    });

    it('tryWrapCommand execute function is NOT called on BLOCK result', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('try-block-execute'));
      const execute = vi.fn(async () => 'result');

      const result = await adapter.tryWrapCommand({
        command: 'rm -rf /',
        execute
      });

      expect(result.outcome).toBe('BLOCK');
      expect(execute).not.toHaveBeenCalled();
      await moshe.close();
    });

    it('tryWrapCommand execute function IS called on ALLOW result', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0' },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('try-allow-execute'));
      const execute = vi.fn(async () => 'result');

      const result = await adapter.tryWrapCommand({
        command: 'echo hello',
        execute
      });

      expect(result.outcome).toBe('ALLOW');
      expect(execute).toHaveBeenCalledTimes(1);
      await moshe.close();
    });

    it('tryWrapOutbound returns BLOCK result without throwing', async () => {
      const moshe = new Moshe({
        policy: {
          version: '0.1.0',
          outboundRules: [{ pattern: 'evil.com', action: 'block' }]
        },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('try-outbound-block'));

      const result = await adapter.tryWrapOutbound({
        url: 'https://evil.com/steal',
        execute: async () => 'res'
      });

      expect(result.outcome).toBe('BLOCK');
      await moshe.close();
    });

    it('tryWrapToolCall REVIEW result includes approvalRequest when present', async () => {
      const approvalRequest: ApprovalRequest = {
        approvalId: 'try-review-approval-001',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        callbackHint: 'Approve via test harness'
      };
      const moshe = new Moshe({
        policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
        store: new MemoryStore(),
        approvalProvider: {
          async create() {
            return approvalRequest;
          },
          async check() {
            return 'PENDING';
          }
        },
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('try-review'));

      const result = await adapter.tryWrapToolCall({
        toolName: 'read_file',
        actionType: 'file_read',
        operation: 'read',
        arguments: { path: '.env' },
        execute: async () => 'contents'
      });

      expect(result.outcome).toBe('REVIEW');
      if (result.outcome === 'REVIEW') {
        expect(result.approvalRequest?.approvalId).toBe('try-review-approval-001');
      }

      await moshe.close();
    });

    it('tryWrapMessage returns ALLOW result', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0' },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('try-message'));

      const result = await adapter.tryWrapMessage({
        recipients: ['a@b.com'],
        execute: async () => true
      });

      expect(result.outcome).toBe('ALLOW');
      await moshe.close();
    });
  });

  describe('onBlock / onReview callbacks', () => {
    it('onBlock callback is called when engine returns BLOCK', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      let fired = false;
      const adapter = new GenericAdapter(moshe.withSession('callback-block-fired'), {
        onBlock: () => {
          fired = true;
        }
      });

      await expect(adapter.wrapCommand({
        command: 'rm -rf /',
        execute: async () => 'never'
      })).rejects.toBeInstanceOf(BlockedActionError);

      expect(fired).toBe(true);
      await moshe.close();
    });

    it('onBlock callback receives the blocking DecisionEnvelope', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      let captured: DecisionEnvelope | null = null;
      const adapter = new GenericAdapter(moshe.withSession('callback-block-decision'), {
        onBlock: (decision) => {
          captured = decision;
        }
      });

      await expect(adapter.wrapCommand({
        command: 'rm -rf /',
        execute: async () => 'never'
      })).rejects.toBeInstanceOf(BlockedActionError);

      expect(captured?.decision).toBe('BLOCK');
      await moshe.close();
    });

    it('BlockedActionError is still thrown after onBlock callback', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const adapter = new GenericAdapter(moshe.withSession('callback-block-throw'), {
        onBlock: () => undefined
      });

      await expect(adapter.wrapCommand({
        command: 'rm -rf /',
        execute: async () => 'never'
      })).rejects.toBeInstanceOf(BlockedActionError);

      await moshe.close();
    });

    it('async onBlock callback is awaited before throw', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      let resolved = false;
      const adapter = new GenericAdapter(moshe.withSession('callback-block-await'), {
        onBlock: async () => {
          await new Promise((resolve) => setTimeout(resolve, 5));
          resolved = true;
        }
      });

      await expect(adapter.wrapCommand({
        command: 'rm -rf /',
        execute: async () => 'never'
      })).rejects.toBeInstanceOf(BlockedActionError);

      expect(resolved).toBe(true);
      await moshe.close();
    });

    it('onBlock is NOT called when engine returns ALLOW', async () => {
      const moshe = new Moshe({
        policy: { version: '0.1.0' },
        store: new MemoryStore(),
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      const spy = vi.fn();
      const adapter = new GenericAdapter(moshe.withSession('callback-block-allow'), {
        onBlock: spy
      });

      await expect(adapter.wrapCommand({
        command: 'echo hello',
        execute: async () => 'ok'
      })).resolves.toBe('ok');

      expect(spy).not.toHaveBeenCalled();
      await moshe.close();
    });

    it('onReview callback is called when engine returns REVIEW', async () => {
      const approvalRequest: ApprovalRequest = {
        approvalId: 'callback-review-approval-001',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        callbackHint: 'Approve via test harness'
      };
      const moshe = new Moshe({
        policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
        store: new MemoryStore(),
        approvalProvider: {
          async create() {
            return approvalRequest;
          },
          async check() {
            return 'PENDING';
          }
        },
        onError: 'BLOCK',
        onUnhandledReview: 'BLOCK'
      });
      let fired = false;
      const adapter = new GenericAdapter(moshe.withSession('callback-review-fired'), {
        onReview: () => {
          fired = true;
        }
      });

      await expect(adapter.wrapToolCall({
        toolName: 'read_file',
        actionType: 'file_read',
        operation: 'read',
        arguments: { path: '.env' },
        execute: async () => 'never'
      })).rejects.toBeInstanceOf(ReviewRequiredError);

      expect(fired).toBe(true);
      await moshe.close();
    });
  });
});
