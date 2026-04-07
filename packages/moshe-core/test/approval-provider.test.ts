import { setTimeout as delay } from 'node:timers/promises';

import { describe, expect, it } from 'vitest';

import { GenericAdapter, ReviewRequiredError } from '@moshe/adapter-generic-tools';
import { Moshe } from '@moshe/sdk';
import type { ActionEnvelope, ApprovalRequest, PolicyConfig } from '@moshe/spec';
import { MemoryStore } from '@moshe/store-memory';

import { ApprovalBlockedError, InProcessApprovalProvider } from '../src/approval-provider.js';
import type { EngineContext } from '../src/interfaces.js';
import type { ArtifactStore, SessionStore } from '../src/interfaces.js';

import { loadFixture } from '../../../test/fixtures.js';

type StoreLike = SessionStore & ArtifactStore;

function makeCtx(sessionId: string, store: StoreLike, policy: PolicyConfig = { version: '0.1.0', sensitiveFiles: ['.env'] }): EngineContext {
  return {
    sessionId,
    policy,
    sessionStore: store,
    artifactStore: store,
    startedAt: Date.now(),
    session: null,
    relatedArtifacts: {}
  };
}

async function makeEnvelope(overrides: Partial<ActionEnvelope> = {}): Promise<ActionEnvelope> {
  const fixture = await loadFixture<ActionEnvelope>('actions/review-sensitive-file.json');
  return {
    ...fixture,
    ...overrides,
    arguments: {
      ...fixture.arguments,
      ...overrides.arguments
    }
  };
}

describe('InProcessApprovalProvider', () => {
  it('replays ALLOW_SESSION approvals across repeated create calls', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });
    const ctx = makeCtx('allow-session', store);
    const envelope = await makeEnvelope();

    const first = await provider.create(envelope, ctx);
    expect(first).not.toBeNull();

    await provider.resolve((first as ApprovalRequest).approvalId, 'ALLOW_SESSION');

    await expect(provider.create(envelope, ctx)).resolves.toBeNull();
    await expect(provider.create(envelope, ctx)).resolves.toBeNull();
  });

  it('consumes ALLOW_ONCE exactly once', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });
    const ctx = makeCtx('allow-once', store);
    const envelope = await makeEnvelope();

    const first = await provider.create(envelope, ctx);
    await provider.resolve((first as ApprovalRequest).approvalId, 'ALLOW_ONCE');

    await expect(provider.create(envelope, ctx)).resolves.toBeNull();

    const third = await provider.create(envelope, ctx);
    expect(third).not.toBeNull();
  });

  it('suppresses future requests during BLOCK cooldown and allows again after expiry', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store, ttlMs: 20 });
    const ctx = makeCtx('blocked-once', store);
    const envelope = await makeEnvelope();

    const first = await provider.create(envelope, ctx);
    await provider.resolve((first as ApprovalRequest).approvalId, 'BLOCK');

    await expect(provider.check((first as ApprovalRequest).approvalId)).resolves.toBe('BLOCK');
    await expect(provider.create(envelope, ctx)).rejects.toBeInstanceOf(ApprovalBlockedError);

    await delay(25);

    const second = await provider.create(envelope, ctx);
    expect(second).not.toBeNull();
  });

  it('cleans up pendingByFingerprint on BLOCK resolution', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });
    const ctx = makeCtx('block-cleanup', store);
    const envelope = await makeEnvelope();

    const first = await provider.create(envelope, ctx);
    await provider.resolve((first as ApprovalRequest).approvalId, 'BLOCK');

    const internals = provider as unknown as {
      pendingByFingerprint: Map<string, string>;
    };

    expect(internals.pendingByFingerprint.size).toBe(0);
  });

  it('cleans up expired resolved approvals', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store, ttlMs: 1 });
    const ctx = makeCtx('resolved-expiry', store);
    const envelope = await makeEnvelope();

    const first = await provider.create(envelope, ctx);
    await provider.resolve((first as ApprovalRequest).approvalId, 'ALLOW_ONCE');

    await delay(10);
    const second = await provider.create(envelope, ctx);
    expect(second).not.toBeNull();
    expect((second as ApprovalRequest).approvalId).not.toBe((first as ApprovalRequest).approvalId);

    const internals = provider as unknown as {
      pendingById: Map<string, unknown>;
    };
    expect(internals.pendingById.size).toBe(1);
  });

  it('keeps different fingerprints isolated', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });
    const ctx = makeCtx('fingerprint-split', store);
    const envelopeA = await makeEnvelope();
    const envelopeB = await makeEnvelope({ toolName: 'other_read_file' });

    const first = await provider.create(envelopeA, ctx);
    const second = await provider.create(envelopeB, ctx);

    await provider.resolve((first as ApprovalRequest).approvalId, 'ALLOW_ONCE');

    await expect(provider.create(envelopeA, ctx)).resolves.toBeNull();
    const nextForB = await provider.create(envelopeB, ctx);

    expect(second).not.toBeNull();
    expect(nextForB).not.toBeNull();
  });

  it('reports approval status through check()', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });
    const ctx = makeCtx('check-status', store);
    const envelope = await makeEnvelope();

    const pending = await provider.create(envelope, ctx);
    expect(pending).not.toBeNull();
    await expect(provider.check((pending as ApprovalRequest).approvalId)).resolves.toBe('PENDING');

    await provider.resolve((pending as ApprovalRequest).approvalId, 'ALLOW_ONCE');
    await expect(provider.check((pending as ApprovalRequest).approvalId)).resolves.toBe('ALLOW_ONCE');

    const next = await provider.create(await makeEnvelope({ toolName: 'session_approved_tool' }), ctx);
    expect(next).not.toBeNull();
    await provider.resolve((next as ApprovalRequest).approvalId, 'ALLOW_SESSION');
    await expect(provider.check((next as ApprovalRequest).approvalId)).resolves.toBe('ALLOW_SESSION');

    const different = await provider.create(await makeEnvelope({ toolName: 'blocked_tool' }), ctx);
    expect(different).not.toBeNull();
    await provider.resolve((different as ApprovalRequest).approvalId, 'BLOCK');
    await expect(provider.check((different as ApprovalRequest).approvalId)).resolves.toBe('BLOCK');
  });

  it('throws on unknown approval ids in check() and resolve()', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });

    await expect(provider.check('missing-approval')).rejects.toThrow('missing-approval');
    await expect(provider.resolve('missing-approval', 'ALLOW_ONCE')).rejects.toThrow('missing-approval');
  });

  it('fires onApprovalRequired for new requests but not replay hits', async () => {
    const store = new MemoryStore();
    const seen: string[] = [];
    const provider = new InProcessApprovalProvider({
      store,
      onApprovalRequired(context) {
        seen.push(context.request.approvalId);
      }
    });
    const ctx = makeCtx('callback-seen', store);
    const envelope = await makeEnvelope();

    const first = await provider.create(envelope, ctx);
    expect(seen).toEqual([(first as ApprovalRequest).approvalId]);

    await provider.resolve((first as ApprovalRequest).approvalId, 'ALLOW_ONCE');
    await expect(provider.create(envelope, ctx)).resolves.toBeNull();

    expect(seen).toEqual([(first as ApprovalRequest).approvalId]);
  });

  it('does not await a slow onApprovalRequired callback', async () => {
    const store = new MemoryStore();
    let release!: () => void;
    let callbackStarted = false;
    const callbackDone = new Promise<void>((resolve) => {
      release = resolve;
    });
    const provider = new InProcessApprovalProvider({
      store,
      async onApprovalRequired() {
        callbackStarted = true;
        await callbackDone;
      }
    });
    const ctx = makeCtx('callback-fast', store);
    const envelope = await makeEnvelope();

    const outcome = await Promise.race([
      provider.create(envelope, ctx).then(() => 'returned'),
      delay(50).then(() => 'timed_out')
    ]);

    expect(outcome).toBe('returned');
    expect(callbackStarted).toBe(true);
    release();
    await callbackDone;
  });

  it('prunes unresolved expired approvals', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store, ttlMs: 1 });
    const ctx = makeCtx('expiry', store);
    const envelope = await makeEnvelope();

    const first = await provider.create(envelope, ctx);
    await delay(10);

    const second = await provider.create(envelope, ctx);
    expect(second).not.toBeNull();
    await expect(provider.check((first as ApprovalRequest).approvalId)).rejects.toThrow((first as ApprovalRequest).approvalId);
  });

  it('supports the full approval lifecycle through Moshe and GenericAdapter', async () => {
    const store = new MemoryStore();
    const provider = new InProcessApprovalProvider({ store });
    const moshe = new Moshe({
      policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
      store,
      approvalProvider: provider,
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });
    const adapter = new GenericAdapter(moshe.withSession('e2e-session'));
    const execute = async () => 'executed';

    let firstError: unknown;
    try {
      await adapter.wrapToolCall({
        toolName: 'read_file',
        actionType: 'file_read',
        operation: 'read',
        arguments: { path: '.env' },
        execute
      });
    } catch (error) {
      firstError = error;
    }

    expect(firstError).toBeInstanceOf(ReviewRequiredError);
    const firstApprovalId = (firstError as ReviewRequiredError).approvalRequest?.approvalId;
    expect(firstApprovalId).toBeTruthy();

    await provider.resolve(firstApprovalId as string, 'ALLOW_ONCE');
    await expect(adapter.wrapToolCall({
      toolName: 'read_file',
      actionType: 'file_read',
      operation: 'read',
      arguments: { path: '.env' },
      execute
    })).resolves.toBe('executed');

    let secondError: unknown;
    try {
      await adapter.wrapToolCall({
        toolName: 'read_file',
        actionType: 'file_read',
        operation: 'read',
        arguments: { path: '.env' },
        execute
      });
    } catch (error) {
      secondError = error;
    }

    expect(secondError).toBeInstanceOf(ReviewRequiredError);
    const secondApprovalId = (secondError as ReviewRequiredError).approvalRequest?.approvalId;
    expect(secondApprovalId).toBeTruthy();

    await provider.resolve(secondApprovalId as string, 'ALLOW_SESSION');
    await expect(adapter.wrapToolCall({
      toolName: 'read_file',
      actionType: 'file_read',
      operation: 'read',
      arguments: { path: '.env' },
      execute
    })).resolves.toBe('executed');
    await expect(adapter.wrapToolCall({
      toolName: 'read_file',
      actionType: 'file_read',
      operation: 'read',
      arguments: { path: '.env' },
      execute
    })).resolves.toBe('executed');

    await moshe.close();
  });
});
