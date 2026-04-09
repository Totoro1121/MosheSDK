import { mkdtemp, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { describe, expect, it } from 'vitest';

import { FileStore } from '@moshesdk/store-file';

import { runStoreContractTests } from '../../../test/store-contracts.js';

async function tempStorePath(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'moshe-store-file-'));
  return join(dir, 'store.json');
}

runStoreContractTests('file store', async () => {
  const store = new FileStore({ path: await tempStorePath() });
  return {
    sessionStore: store,
    artifactStore: store,
    replayStore: store
  };
});

describe('FileStore', () => {
  it('removes tmp file after atomic write', async () => {
    const path = await tempStorePath();
    const store = new FileStore({ path });
    await store.putArtifact('/tmp/file.txt', {
      path: '/tmp/file.txt',
      classification: 'CLEAN',
      source: 'test',
      reason: 'fixture',
      firstSeen: '2026-04-01T00:00:00.000Z',
      lastSeen: '2026-04-01T00:00:00.000Z'
    });

    await store.close();
    await expect(readFile(`${path}.tmp`, 'utf8')).rejects.toBeTruthy();
  });

  it('loads existing file on startup', async () => {
    const path = await tempStorePath();
    const first = new FileStore({ path });
    await first.putArtifact('/tmp/file.txt', {
      path: '/tmp/file.txt',
      classification: 'CLEAN',
      source: 'test',
      reason: 'fixture',
      firstSeen: '2026-04-01T00:00:00.000Z',
      lastSeen: '2026-04-01T00:00:00.000Z'
    });
    await first.close();

    const second = new FileStore({ path });
    const artifact = await second.getArtifact('/tmp/file.txt');
    expect(artifact?.classification).toBe('CLEAN');
    await second.close();
  });

  it('serializes writes without corrupting state', async () => {
    const path = await tempStorePath();
    const store = new FileStore({ path });

    await Promise.all([
      store.putArtifact('/tmp/a.txt', {
        path: '/tmp/a.txt',
        classification: 'CLEAN',
        source: 'test',
        reason: 'a',
        firstSeen: '2026-04-01T00:00:00.000Z',
        lastSeen: '2026-04-01T00:00:00.000Z'
      }),
      store.putArtifact('/tmp/b.txt', {
        path: '/tmp/b.txt',
        classification: 'TAINTED',
        source: 'test',
        reason: 'b',
        firstSeen: '2026-04-01T00:00:00.000Z',
        lastSeen: '2026-04-01T00:00:00.000Z'
      })
    ]);

    expect(await store.listArtifacts('/tmp')).toEqual(['/tmp/a.txt', '/tmp/b.txt']);
    await store.close();
  });
});

