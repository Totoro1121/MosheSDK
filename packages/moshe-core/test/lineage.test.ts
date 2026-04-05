import { describe, expect, it } from 'vitest';

import { MemoryStore } from '@moshe/store-memory';

import { resolveLineage } from '../src/lineage.js';
import type { ArtifactRecord } from '../src/state.js';

function artifact(path: string, classification: ArtifactRecord['classification'], provenanceChain: string[] = []): ArtifactRecord {
  return {
    path,
    classification,
    source: 'test',
    reason: 'test',
    firstSeen: '2026-01-01T00:00:00.000Z',
    lastSeen: '2026-01-01T00:00:00.000Z',
    provenanceChain
  };
}

describe('resolveLineage', () => {
  it('returns found false and empty nodes when root path is missing', async () => {
    const store = new MemoryStore();
    const report = await resolveLineage(store, 'missing.txt');

    expect(report).toEqual({
      root: 'missing.txt',
      found: false,
      maxDepth: 0,
      nodes: []
    });
  });

  it('returns a single-node report for an artifact with no provenanceChain', async () => {
    const store = new MemoryStore();
    await store.putArtifact('a.txt', artifact('a.txt', 'TAINTED'));

    const report = await resolveLineage(store, 'a.txt');

    expect(report.found).toBe(true);
    expect(report.maxDepth).toBe(0);
    expect(report.nodes).toEqual([
      {
        path: 'a.txt',
        classification: 'TAINTED',
        depth: 0,
        sources: []
      }
    ]);
  });

  it('returns a two-node report for A to B', async () => {
    const store = new MemoryStore();
    await store.putArtifact('a.txt', artifact('a.txt', 'TAINTED', ['b.txt']));
    await store.putArtifact('b.txt', artifact('b.txt', 'TAINTED'));

    const report = await resolveLineage(store, 'a.txt');

    expect(report.nodes.map((node) => node.path)).toEqual(['a.txt', 'b.txt']);
    expect(report.maxDepth).toBe(1);
  });

  it('returns a three-node BFS report for A to B to C', async () => {
    const store = new MemoryStore();
    await store.putArtifact('a.txt', artifact('a.txt', 'TAINTED', ['b.txt']));
    await store.putArtifact('b.txt', artifact('b.txt', 'TAINTED', ['c.txt']));
    await store.putArtifact('c.txt', artifact('c.txt', 'TAINTED'));

    const report = await resolveLineage(store, 'a.txt');

    expect(report.nodes.map((node) => node.path)).toEqual(['a.txt', 'b.txt', 'c.txt']);
    expect(report.maxDepth).toBe(2);
  });

  it('handles cycles without infinite loops', async () => {
    const store = new MemoryStore();
    await store.putArtifact('a.txt', artifact('a.txt', 'TAINTED', ['b.txt']));
    await store.putArtifact('b.txt', artifact('b.txt', 'TAINTED', ['a.txt']));

    const report = await resolveLineage(store, 'a.txt');

    expect(report.nodes.map((node) => node.path)).toEqual(['a.txt', 'b.txt']);
    expect(report.maxDepth).toBe(1);
  });

  it('respects maxDepth truncation', async () => {
    const store = new MemoryStore();
    await store.putArtifact('a.txt', artifact('a.txt', 'TAINTED', ['b.txt']));
    await store.putArtifact('b.txt', artifact('b.txt', 'TAINTED', ['c.txt']));
    await store.putArtifact('c.txt', artifact('c.txt', 'TAINTED', ['d.txt']));
    await store.putArtifact('d.txt', artifact('d.txt', 'TAINTED'));

    const report = await resolveLineage(store, 'a.txt', 1);

    expect(report.nodes.map((node) => node.path)).toEqual(['a.txt', 'b.txt']);
    expect(report.maxDepth).toBe(1);
  });

  it('includes unknown provenance paths as CLEAN terminal nodes', async () => {
    const store = new MemoryStore();
    await store.putArtifact('a.txt', artifact('a.txt', 'TAINTED', ['ghost.txt']));

    const report = await resolveLineage(store, 'a.txt');

    expect(report.nodes).toEqual([
      {
        path: 'a.txt',
        classification: 'TAINTED',
        depth: 0,
        sources: ['ghost.txt']
      },
      {
        path: 'ghost.txt',
        classification: 'CLEAN',
        depth: 1,
        sources: []
      }
    ]);
  });

  it('uses maxDepth default of 10', async () => {
    const store = new MemoryStore();

    for (let index = 0; index < 12; index += 1) {
      const path = `node-${index}.txt`;
      const nextPath = index < 11 ? [`node-${index + 1}.txt`] : [];
      await store.putArtifact(path, artifact(path, 'TAINTED', nextPath));
    }

    const report = await resolveLineage(store, 'node-0.txt');

    expect(report.nodes).toHaveLength(11);
    expect(report.maxDepth).toBe(10);
    expect(report.nodes.at(-1)?.path).toBe('node-10.txt');
  });
});
