import { describe, expect, it } from 'vitest';

import { MemoryStore } from '@moshe/store-memory';

import { runStoreContractTests } from '../../../test/store-contracts.js';

runStoreContractTests('memory store', async () => {
  const store = new MemoryStore();
  return {
    sessionStore: store,
    artifactStore: store,
    replayStore: store
  };
});

describe('MemoryStore', () => {
  it('reset clears all state', async () => {
    const store = new MemoryStore();
    await store.putArtifact('/tmp/file.txt', {
      path: '/tmp/file.txt',
      classification: 'CLEAN',
      source: 'test',
      reason: 'fixture',
      firstSeen: '2026-04-01T00:00:00.000Z',
      lastSeen: '2026-04-01T00:00:00.000Z'
    });

    store.reset();
    await expect(store.listArtifacts()).resolves.toEqual([]);
  });
});

