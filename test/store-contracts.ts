import { describe, expect, it } from 'vitest';

import type { ArtifactStore, SessionStore, SessionState } from '@moshesdk/core';

interface ReplayStore {
  getApprovalReplay(approvalId: string): Promise<{
    approvalId: string;
    sessionId: string;
    resolvedDecision: 'ALLOW_ONCE' | 'ALLOW_SESSION' | 'BLOCK';
    resolvedAt: string;
    expiresAt: string;
  } | null>;
  putApprovalReplay(entry: {
    approvalId: string;
    sessionId: string;
    resolvedDecision: 'ALLOW_ONCE' | 'ALLOW_SESSION' | 'BLOCK';
    resolvedAt: string;
    expiresAt: string;
  }): Promise<void>;
}

interface StoreBundle {
  sessionStore: SessionStore;
  artifactStore: ArtifactStore;
  replayStore: ReplayStore;
}

function sessionFixture(): SessionState {
  return {
    sessionId: 'session-1',
    createdAt: '2026-04-01T00:00:00.000Z',
    updatedAt: '2026-04-01T00:00:00.000Z',
    messageCount: 1,
    taintSources: ['seed'],
    whitelistedScripts: {
      'script-a.ts': 'hash-a'
    }
  };
}

export function runStoreContractTests(label: string, createStores: () => Promise<StoreBundle>): void {
  describe(`${label} session store contract`, () => {
    it('supports get/put roundtrip and deep copy isolation', async () => {
      const { sessionStore } = await createStores();
      const input = sessionFixture();
      await sessionStore.putSession(input.sessionId, input);

      const stored = await sessionStore.getSession(input.sessionId);
      expect(stored).toEqual(input);

      stored?.taintSources.push('changed');
      const afterMutation = await sessionStore.getSession(input.sessionId);
      expect(afterMutation?.taintSources).toEqual(['seed']);
    });

    it('merges by default and replaces when requested', async () => {
      const { sessionStore } = await createStores();
      await sessionStore.putSession('session-1', sessionFixture());
      await sessionStore.putSession('session-1', {
        sessionId: 'session-1',
        createdAt: '2026-04-01T00:00:00.000Z',
        updatedAt: '2026-04-01T00:01:00.000Z',
        messageCount: 2,
        taintSources: ['seed', 'updated'],
        whitelistedScripts: {
          'script-b.ts': 'hash-b'
        }
      });

      const merged = await sessionStore.getSession('session-1');
      expect(merged?.whitelistedScripts).toEqual({
        'script-a.ts': 'hash-a',
        'script-b.ts': 'hash-b'
      });
      expect(merged?.taintSources).toEqual(['seed', 'updated']);

      await sessionStore.putSession(
        'session-1',
        {
          sessionId: 'session-1',
          createdAt: '2026-04-01T00:00:00.000Z',
          updatedAt: '2026-04-01T00:02:00.000Z',
          messageCount: 3,
          taintSources: [],
          whitelistedScripts: {}
        },
        { replace: true }
      );

      const replaced = await sessionStore.getSession('session-1');
      expect(replaced?.whitelistedScripts).toEqual({});
    });

    it('supports approval replay roundtrip', async () => {
      const { replayStore } = await createStores();
      const entry = {
        approvalId: 'approval-1',
        sessionId: 'session-1',
        resolvedDecision: 'ALLOW_ONCE' as const,
        resolvedAt: '2026-04-01T00:00:00.000Z',
        expiresAt: '2026-04-01T00:05:00.000Z'
      };

      await replayStore.putApprovalReplay(entry);
      await expect(replayStore.getApprovalReplay(entry.approvalId)).resolves.toEqual(entry);
    });
  });

  describe(`${label} artifact store contract`, () => {
    it('supports get/put/list roundtrip', async () => {
      const { artifactStore } = await createStores();
      await artifactStore.putArtifact('/tmp/file.txt', {
        path: '/tmp/file.txt',
        classification: 'CLEAN',
        source: 'test',
        reason: 'fixture',
        firstSeen: '2026-04-01T00:00:00.000Z',
        lastSeen: '2026-04-01T00:00:00.000Z'
      });

      const artifact = await artifactStore.getArtifact('/tmp/file.txt');
      expect(artifact?.classification).toBe('CLEAN');
      await expect(artifactStore.listArtifacts('/tmp')).resolves.toEqual(['/tmp/file.txt']);
    });
  });
}
