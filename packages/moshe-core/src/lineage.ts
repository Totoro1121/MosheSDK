import type { ArtifactStore } from './interfaces.js';
import type { ArtifactRecord } from './state.js';

export interface LineageNode {
  path: string;
  classification: ArtifactRecord['classification'];
  depth: number;
  sources: string[];
}

export interface LineageReport {
  root: string;
  found: boolean;
  maxDepth: number;
  nodes: LineageNode[];
}

export async function resolveLineage(
  store: ArtifactStore,
  rootPath: string,
  maxDepth = 10
): Promise<LineageReport> {
  const rootArtifact = await store.getArtifact(rootPath);
  if (!rootArtifact) {
    return {
      root: rootPath,
      found: false,
      maxDepth: 0,
      nodes: []
    };
  }

  const nodes: LineageNode[] = [];
  const visited = new Set<string>();
  const queue: Array<{ path: string; depth: number }> = [{ path: rootPath, depth: 0 }];

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current.path)) {
      continue;
    }

    visited.add(current.path);

    const artifact = await store.getArtifact(current.path);
    const sources = artifact?.provenanceChain ?? [];
    nodes.push({
      path: current.path,
      classification: artifact?.classification ?? 'CLEAN',
      depth: current.depth,
      sources
    });

    if (current.depth >= maxDepth) {
      continue;
    }

    for (const sourcePath of sources) {
      if (!visited.has(sourcePath)) {
        queue.push({ path: sourcePath, depth: current.depth + 1 });
      }
    }
  }

  return {
    root: rootPath,
    found: true,
    maxDepth: nodes.reduce((max, node) => Math.max(max, node.depth), 0),
    nodes
  };
}
