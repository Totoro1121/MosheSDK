import { describe, expect, it } from 'vitest';

import { ReasonCode, type ActionEnvelope, type DecisionEnvelope } from '@moshesdk/spec';
import { MemoryStore } from '@moshesdk/store-memory';
import { Moshe } from '@moshesdk/sdk';

import {
  analyzeTaint,
  buildTaintContext,
  buildTaintStageResult,
  updateTaintState,
  type TaintContext
} from '../src/taint-engine.js';
import type { EngineContext } from '../src/interfaces.js';
import { resolveLineage } from '../src/lineage.js';
import type { ArtifactRecord, SessionState } from '../src/state.js';

function makeCtx(): EngineContext {
  const store = new MemoryStore();

  return {
    sessionId: 'test-session',
    policy: { version: '0.1.0' },
    sessionStore: store,
    artifactStore: store,
    startedAt: 0,
    session: null,
    relatedArtifacts: {}
  };
}

function makeCtxWithSession(session: Partial<SessionState>): EngineContext {
  const store = new MemoryStore();
  const fullSession: SessionState = {
    sessionId: session.sessionId ?? 'test-session',
    createdAt: session.createdAt ?? '2026-01-01T00:00:00.000Z',
    updatedAt: session.updatedAt ?? '2026-01-01T00:00:00.000Z',
    messageCount: session.messageCount ?? 0,
    taintSources: session.taintSources ?? [],
    whitelistedScripts: session.whitelistedScripts ?? {},
    ...(session.suspectUntil ? { suspectUntil: session.suspectUntil } : {}),
    ...(session.riskLevel !== undefined ? { riskLevel: session.riskLevel } : {}),
    ...(session.reviewCount !== undefined ? { reviewCount: session.reviewCount } : {}),
    ...(session.blockCount !== undefined ? { blockCount: session.blockCount } : {}),
    ...(session.sensitiveReadCount !== undefined ? { sensitiveReadCount: session.sensitiveReadCount } : {})
  };

  return {
    sessionId: fullSession.sessionId,
    policy: { version: '0.1.0' },
    sessionStore: store,
    artifactStore: store,
    startedAt: 0,
    session: fullSession,
    relatedArtifacts: {}
  };
}

function envelope(overrides: Partial<ActionEnvelope>): ActionEnvelope {
  const { arguments: overrideArguments, ...rest } = overrides;

  const base: ActionEnvelope = {
    actionId: 'test-id',
    sessionId: 'test-session',
    timestamp: '2026-01-01T00:00:00.000Z',
    framework: 'test',
    actionType: 'unknown',
    operation: 'test',
    toolName: 'test',
    arguments: {},
    ...rest
  };

  base.arguments = {
    ...overrideArguments
  };

  return base;
}

function artifact(path: string, classification: ArtifactRecord['classification'], extra: Partial<ArtifactRecord> = {}): ArtifactRecord {
  return {
    path,
    classification,
    source: extra.source ?? 'test',
    reason: extra.reason ?? 'test',
    firstSeen: extra.firstSeen ?? '2026-01-01T00:00:00.000Z',
    lastSeen: extra.lastSeen ?? '2026-01-01T00:00:00.000Z',
    ...(extra.provenanceChain !== undefined ? { provenanceChain: extra.provenanceChain } : {})
  };
}

function decision(overrides: Partial<DecisionEnvelope> = {}): DecisionEnvelope {
  return {
    decision: 'ALLOW',
    reasonCodes: [],
    summary: 'ok',
    ...overrides
  };
}

describe('buildTaintContext', () => {
  it('returns clean context when session is null and no artifacts', () => {
    const result = buildTaintContext(makeCtx(), envelope({}));
    expect(result).toEqual({
      sessionTainted: false,
      taintSources: [],
      taintedArtifacts: [],
      agentAuthoredPaths: [],
      lineageDepth: 0,
      originSources: []
    });
  });

  it('detects tainted session from taintSources', () => {
    const ctx = makeCtxWithSession({ taintSources: ['prompt-injection:ext-doc'] });
    const result = buildTaintContext(ctx, envelope({}));
    expect(result.sessionTainted).toBe(true);
    expect(result.taintSources).toContain('prompt-injection:ext-doc');
  });

  it('collects tainted artifacts from relatedArtifacts', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tmp/evil.sh': artifact('/tmp/evil.sh', 'TAINTED')
    };

    const result = buildTaintContext(ctx, envelope({}));
    expect(result.taintedArtifacts).toContain('/tmp/evil.sh');
  });

  it('collects agent-authored paths from relatedArtifacts', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/app/gen.py': artifact('/app/gen.py', 'AGENT_GENERATED')
    };

    const result = buildTaintContext(ctx, envelope({}));
    expect(result.agentAuthoredPaths).toContain('/app/gen.py');
  });

  it('lineageDepth is 0 when there are no TAINTED artifacts', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/app/gen.py': artifact('/app/gen.py', 'AGENT_GENERATED')
    };

    expect(buildTaintContext(ctx, envelope({})).lineageDepth).toBe(0);
  });

  it('lineageDepth equals the provenanceChain length of a single TAINTED artifact', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tmp/evil.sh': artifact('/tmp/evil.sh', 'TAINTED', {
        provenanceChain: ['origin.txt', 'seed.txt']
      })
    };

    expect(buildTaintContext(ctx, envelope({})).lineageDepth).toBe(2);
  });

  it('lineageDepth equals the maximum across multiple TAINTED artifacts', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tmp/a': artifact('/tmp/a', 'TAINTED', {
        provenanceChain: ['x']
      }),
      '/tmp/b': artifact('/tmp/b', 'TAINTED', {
        provenanceChain: ['x', 'y', 'z']
      })
    };

    expect(buildTaintContext(ctx, envelope({})).lineageDepth).toBe(3);
  });

  it('originSources is empty when there are no TAINTED artifacts', () => {
    expect(buildTaintContext(makeCtx(), envelope({})).originSources).toEqual([]);
  });

  it('originSources includes visible roots that are not TAINTED, FORBIDDEN, or AGENT_GENERATED', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tmp/derived.txt': artifact('/tmp/derived.txt', 'TAINTED', {
        provenanceChain: ['origin.txt', 'clean.txt', 'sensitive.txt']
      }),
      'clean.txt': artifact('clean.txt', 'CLEAN'),
      'sensitive.txt': artifact('sensitive.txt', 'SENSITIVE')
    };

    expect(buildTaintContext(ctx, envelope({})).originSources).toEqual([
      'origin.txt',
      'clean.txt',
      'sensitive.txt'
    ]);
  });

  it('originSources excludes visible TAINTED and AGENT_GENERATED intermediates', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tmp/derived.txt': artifact('/tmp/derived.txt', 'TAINTED', {
        provenanceChain: ['tainted-mid.txt', 'generated-mid.txt', 'origin.txt']
      }),
      'tainted-mid.txt': artifact('tainted-mid.txt', 'TAINTED'),
      'generated-mid.txt': artifact('generated-mid.txt', 'AGENT_GENERATED')
    };

    expect(buildTaintContext(ctx, envelope({})).originSources).toEqual(['origin.txt']);
  });

  it('originSources excludes visible FORBIDDEN intermediates', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tmp/derived.txt': artifact('/tmp/derived.txt', 'TAINTED', {
        provenanceChain: ['forbidden-mid.txt', 'origin.txt']
      }),
      'forbidden-mid.txt': artifact('forbidden-mid.txt', 'FORBIDDEN')
    };

    expect(buildTaintContext(ctx, envelope({})).originSources).toEqual(['origin.txt']);
  });

  it('originSources is deduplicated', () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tmp/a': artifact('/tmp/a', 'TAINTED', {
        provenanceChain: ['origin.txt', 'origin.txt']
      }),
      '/tmp/b': artifact('/tmp/b', 'TAINTED', {
        provenanceChain: ['origin.txt']
      })
    };

    expect(buildTaintContext(ctx, envelope({})).originSources).toEqual(['origin.txt']);
  });
});

describe('analyzeTaint', () => {
  const cleanCtx: TaintContext = {
    sessionTainted: false,
    taintSources: [],
    taintedArtifacts: [],
    agentAuthoredPaths: [],
    lineageDepth: 0,
    originSources: []
  };

  it('returns ALLOW when no taint signals', () => {
    const result = analyzeTaint(envelope({}), cleanCtx);
    expect(result.decision).toBe('ALLOW');
    expect(result.reasonCode).toBeNull();
  });

  it('returns REVIEW for tainted artifact access', () => {
    const result = analyzeTaint(envelope({}), {
      ...cleanCtx,
      taintedArtifacts: ['/tmp/evil.sh']
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCode).toBe(ReasonCode.TAINTED_ARTIFACT_ACCESS);
    expect(result.taintSummary.artifactsTainted).toContain('/tmp/evil.sh');
  });

  it('returns REVIEW for tainted session + command_exec', () => {
    const result = analyzeTaint(envelope({
      actionType: 'command_exec',
      arguments: { command: 'ls' }
    }), {
      ...cleanCtx,
      sessionTainted: true,
      taintSources: ['ext-doc']
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCode).toBe(ReasonCode.TAINTED_SESSION_COMMAND);
  });

  it('tainted session does not escalate non-command actions', () => {
    const result = analyzeTaint(envelope({
      actionType: 'message_send'
    }), {
      ...cleanCtx,
      sessionTainted: true,
      taintSources: ['ext-doc']
    });

    expect(result.decision).toBe('ALLOW');
  });

  it('returns REVIEW for agent-authored path + file_read', () => {
    const result = analyzeTaint(envelope({
      actionType: 'file_read',
      arguments: { path: '/app/gen.py' }
    }), {
      ...cleanCtx,
      agentAuthoredPaths: ['/app/gen.py']
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCode).toBe(ReasonCode.AGENT_AUTHORED_EXECUTION);
  });

  it('tainted artifact takes priority over tainted session command', () => {
    const result = analyzeTaint(envelope({
      actionType: 'command_exec',
      arguments: { command: 'ls' }
    }), {
      ...cleanCtx,
      sessionTainted: true,
      taintSources: ['ext-doc'],
      taintedArtifacts: ['/tmp/evil.sh']
    });

    expect(result.reasonCode).toBe(ReasonCode.TAINTED_ARTIFACT_ACCESS);
  });

  it('taintSummary is always populated, even on ALLOW', () => {
    const result = analyzeTaint(envelope({}), cleanCtx);
    expect(result.taintSummary.sessionTainted).toBe(false);
    expect(result.taintSummary.artifactsTainted).toEqual([]);
  });

  it('provenanceSummary reflects agentAuthored flag on envelope', () => {
    const result = analyzeTaint(envelope({
      arguments: {
        agentAuthored: true,
        path: '/out/script.sh'
      }
    }), cleanCtx);

    expect(result.provenanceSummary.agentAuthored).toContain('/out/script.sh');
  });

  it('lineageDepth is omitted from ProvenanceSummary when there are no tainted artifacts', () => {
    const result = analyzeTaint(envelope({}), cleanCtx);
    expect(result.provenanceSummary.lineageDepth).toBeUndefined();
  });

  it('lineageDepth is included in ProvenanceSummary when tainted artifacts exist', () => {
    const result = analyzeTaint(envelope({}), {
      ...cleanCtx,
      taintedArtifacts: ['/tmp/evil.sh'],
      lineageDepth: 2
    });

    expect(result.provenanceSummary.lineageDepth).toBe(2);
  });

  it('originSources is omitted from ProvenanceSummary when empty', () => {
    const result = analyzeTaint(envelope({}), cleanCtx);
    expect(result.provenanceSummary.originSources).toBeUndefined();
  });

  it('originSources is included in ProvenanceSummary when identifiable', () => {
    const result = analyzeTaint(envelope({}), {
      ...cleanCtx,
      taintedArtifacts: ['/tmp/evil.sh'],
      originSources: ['origin.txt']
    });

    expect(result.provenanceSummary.originSources).toEqual(['origin.txt']);
  });

  it('builds a pass-through taint stage result on ALLOW', () => {
    const result = buildTaintStageResult(analyzeTaint(envelope({}), cleanCtx));
    expect(result.decision).toBe('ALLOW');
    expect(result.reasonCodes).toEqual([]);
    expect(result.enrichments?.taintSummary).toBeDefined();
  });
});

describe('updateTaintState', () => {
  it('tags file_write as AGENT_GENERATED when agentAuthored is true', async () => {
    const ctx = makeCtx();
    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/gen.py', agentAuthored: true }
      }),
      decision(),
      ctx
    );

    const record = await ctx.artifactStore.getArtifact('/out/gen.py');
    expect(record?.classification).toBe('AGENT_GENERATED');
  });

  it('does not tag file_write when agentAuthored is false', async () => {
    const ctx = makeCtx();
    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/normal.py', agentAuthored: false }
      }),
      decision(),
      ctx
    );

    expect(await ctx.artifactStore.getArtifact('/out/normal.py')).toBeNull();
  });

  it('does not propagate lineage for file_write with no referencedPaths', async () => {
    const ctx = makeCtx();
    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/plain.txt' }
      }),
      decision(),
      ctx
    );

    expect(await ctx.artifactStore.getArtifact('/out/plain.txt')).toBeNull();
  });

  it('does not propagate lineage for file_write with only CLEAN referenced paths', async () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/src/clean.txt': artifact('/src/clean.txt', 'CLEAN')
    };

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/plain.txt' },
        referencedPaths: ['/src/clean.txt']
      }),
      decision(),
      ctx
    );

    expect(await ctx.artifactStore.getArtifact('/out/plain.txt')).toBeNull();
  });

  it('propagates TAINTED referenced artifacts into the written file', async () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/src/tainted.txt': artifact('/src/tainted.txt', 'TAINTED', {
        provenanceChain: ['origin.txt']
      })
    };

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/derived.txt' },
        referencedPaths: ['/src/tainted.txt']
      }),
      decision(),
      ctx
    );

    const record = await ctx.artifactStore.getArtifact('/out/derived.txt');
    expect(record?.classification).toBe('TAINTED');
    expect(record?.provenanceChain).toEqual(['origin.txt', '/src/tainted.txt']);
  });

  it('propagates AGENT_GENERATED referenced artifacts into the written file', async () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/src/generated.txt': artifact('/src/generated.txt', 'AGENT_GENERATED', {
        provenanceChain: ['seed.txt']
      })
    };

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/derived.txt' },
        referencedPaths: ['/src/generated.txt']
      }),
      decision(),
      ctx
    );

    const record = await ctx.artifactStore.getArtifact('/out/derived.txt');
    expect(record?.classification).toBe('AGENT_GENERATED');
    expect(record?.provenanceChain).toEqual(['seed.txt', '/src/generated.txt']);
  });

  it('mixed TAINTED and AGENT_GENERATED refs escalate the written file to TAINTED', async () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/src/tainted.txt': artifact('/src/tainted.txt', 'TAINTED', {
        provenanceChain: ['origin.txt']
      }),
      '/src/generated.txt': artifact('/src/generated.txt', 'AGENT_GENERATED', {
        provenanceChain: ['seed.txt']
      })
    };

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/derived.txt' },
        referencedPaths: ['/src/generated.txt', '/src/tainted.txt']
      }),
      decision(),
      ctx
    );

    const record = await ctx.artifactStore.getArtifact('/out/derived.txt');
    expect(record?.classification).toBe('TAINTED');
  });

  it('deduplicates merged provenanceChain entries and includes source paths', async () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/src/a.txt': artifact('/src/a.txt', 'TAINTED', {
        provenanceChain: ['origin.txt', 'shared.txt']
      }),
      '/src/b.txt': artifact('/src/b.txt', 'TAINTED', {
        provenanceChain: ['shared.txt', 'origin.txt']
      })
    };

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/merged.txt' },
        referencedPaths: ['/src/a.txt', '/src/b.txt']
      }),
      decision(),
      ctx
    );

    const record = await ctx.artifactStore.getArtifact('/out/merged.txt');
    expect(record?.provenanceChain).toEqual([
      'origin.txt',
      'shared.txt',
      '/src/a.txt',
      '/src/b.txt'
    ]);
  });

  it('skips self-reference in referencedPaths during propagation', async () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/out/self.txt': artifact('/out/self.txt', 'TAINTED', {
        provenanceChain: ['origin.txt']
      })
    };

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/self.txt' },
        referencedPaths: ['/out/self.txt']
      }),
      decision(),
      ctx
    );

    expect(await ctx.artifactStore.getArtifact('/out/self.txt')).toBeNull();
  });

  it('tags file_write path as TAINTED when session is tainted', async () => {
    const ctx = makeCtxWithSession({ taintSources: ['external-doc'] });
    await updateTaintState(
      envelope({
        sessionId: ctx.sessionId,
        actionType: 'file_write',
        arguments: { path: '/out/generated.txt' }
      }),
      decision(),
      ctx
    );

    const record = await ctx.artifactStore.getArtifact('/out/generated.txt');
    expect(record?.classification).toBe('TAINTED');
    expect(record?.provenanceChain).toContain('external-doc');
  });

  it('never downgrades classification (TAINTED stays TAINTED when AGENT_GENERATED write happens)', async () => {
    const ctx = makeCtx();
    await ctx.artifactStore.putArtifact('/out/gen.py', artifact('/out/gen.py', 'TAINTED'));

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/gen.py', agentAuthored: true }
      }),
      decision(),
      ctx
    );

    expect((await ctx.artifactStore.getArtifact('/out/gen.py'))?.classification).toBe('TAINTED');
  });

  it('does not downgrade an existing FORBIDDEN artifact during propagation', async () => {
    const ctx = makeCtx();
    await ctx.artifactStore.putArtifact('/out/locked.txt', artifact('/out/locked.txt', 'FORBIDDEN'));
    ctx.relatedArtifacts = {
      '/src/tainted.txt': artifact('/src/tainted.txt', 'TAINTED', {
        provenanceChain: ['origin.txt']
      })
    };

    await updateTaintState(
      envelope({
        actionType: 'file_write',
        arguments: { path: '/out/locked.txt' },
        referencedPaths: ['/src/tainted.txt']
      }),
      decision(),
      ctx
    );

    expect((await ctx.artifactStore.getArtifact('/out/locked.txt'))?.classification).toBe('FORBIDDEN');
  });

  it('tags path as SENSITIVE when decision contains SENSITIVE_FILE_ACCESS', async () => {
    const ctx = makeCtx();
    await updateTaintState(
      envelope({
        actionType: 'file_read',
        arguments: { path: '/home/.env' }
      }),
      decision({
        decision: 'REVIEW',
        reasonCodes: [ReasonCode.SENSITIVE_FILE_ACCESS],
        summary: 'sensitive'
      }),
      ctx
    );

    expect((await ctx.artifactStore.getArtifact('/home/.env'))?.classification).toBe('SENSITIVE');
  });

  it('propagates taint to session when tainted artifact is read', async () => {
    const ctx = makeCtx();
    ctx.relatedArtifacts = {
      '/tainted/doc.txt': artifact('/tainted/doc.txt', 'TAINTED', {
        provenanceChain: ['prompt-injection']
      })
    };

    await updateTaintState(
      envelope({
        actionType: 'file_read',
        arguments: { path: '/tainted/doc.txt' }
      }),
      decision(),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.taintSources).toContain('/tainted/doc.txt');
  });
});

describe('integration - taint flows through engine', () => {
  it('agent-authored file write gets AGENT_GENERATED tag in store', async () => {
    const store = new MemoryStore();
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    await moshe.evaluate({
      sessionId: 'taint-int-session',
      framework: 'test',
      actionType: 'file_write',
      operation: 'write',
      toolName: 'write_file',
      arguments: { path: '/out/x.py', agentAuthored: true }
    });

    expect((await store.getArtifact('/out/x.py'))?.classification).toBe('AGENT_GENERATED');
    await moshe.close();
  });

  it('tainted session causes subsequent command to be flagged', async () => {
    const store = new MemoryStore();
    await store.putSession('taint-int-session', {
      sessionId: 'taint-int-session',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      messageCount: 0,
      taintSources: ['injected'],
      whitelistedScripts: {}
    });

    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const result = await moshe.evaluate({
      sessionId: 'taint-int-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'bash',
      arguments: { command: 'ls' }
    });

    expect(result.decision).toBe('BLOCK');
    expect(result.reasonCodes).toContain(ReasonCode.TAINTED_SESSION_COMMAND);
    await moshe.close();
  });

  it('sensitive file access tags artifact as SENSITIVE in store', async () => {
    const store = new MemoryStore();
    const moshe = new Moshe({
      policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    await moshe.evaluate({
      sessionId: 'taint-int-session',
      framework: 'test',
      actionType: 'file_read',
      operation: 'read',
      toolName: 'read_file',
      arguments: { path: '/home/.env' }
    });

    expect((await store.getArtifact('/home/.env'))?.classification).toBe('SENSITIVE');
    await moshe.close();
  });

  it('taintSummary is present in final DecisionEnvelope on ALLOW', async () => {
    const store = new MemoryStore();
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    const result = await moshe.evaluate({
      sessionId: 'taint-int-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'bash',
      arguments: { command: 'echo hello' }
    });

    expect(result.taintSummary).toBeDefined();
    expect(result.taintSummary?.sessionTainted).toBe(false);
    await moshe.close();
  });

  it('referenced tainted artifact causes written output to inherit lineage and resolveLineage returns the ancestry', async () => {
    const store = new MemoryStore();
    await store.putArtifact('/src/a.txt', artifact('/src/a.txt', 'TAINTED', {
      provenanceChain: ['origin.txt']
    }));

    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    const result = await moshe.evaluate({
      sessionId: 'taint-int-session',
      framework: 'test',
      actionType: 'file_write',
      operation: 'write',
      toolName: 'write_file',
      arguments: { path: '/out/b.txt' },
      referencedPaths: ['/src/a.txt']
    });

    const record = await store.getArtifact('/out/b.txt');
    expect(record?.classification).toBe('TAINTED');
    expect(record?.provenanceChain).toEqual(['origin.txt', '/src/a.txt']);

    const report = await resolveLineage(store, '/out/b.txt');
    expect(report.found).toBe(true);
    expect(report.nodes.map((node) => node.path)).toEqual(['/out/b.txt', 'origin.txt', '/src/a.txt']);
    expect(result.provenanceSummary?.propagatedFrom).toContain('/src/a.txt');
    await moshe.close();
  });

  it('ProvenanceSummary lineageDepth on a file_write reflects the referenced chain depth', async () => {
    const store = new MemoryStore();
    await store.putArtifact('/src/a.txt', artifact('/src/a.txt', 'TAINTED', {
      provenanceChain: ['mid.txt', 'origin.txt']
    }));

    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    const result = await moshe.evaluate({
      sessionId: 'taint-int-session',
      framework: 'test',
      actionType: 'file_write',
      operation: 'write',
      toolName: 'write_file',
      arguments: { path: '/out/b.txt' },
      referencedPaths: ['/src/a.txt']
    });

    expect(result.provenanceSummary?.lineageDepth).toBe(2);
    await moshe.close();
  });

  it('ProvenanceSummary originSources identifies the visible root source for a two-hop artifact', async () => {
    const store = new MemoryStore();
    await store.putArtifact('/src/a.txt', artifact('/src/a.txt', 'TAINTED', {
      provenanceChain: ['mid.txt', 'origin.txt']
    }));
    await store.putArtifact('mid.txt', artifact('mid.txt', 'AGENT_GENERATED'));

    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    const result = await moshe.evaluate({
      sessionId: 'taint-int-session',
      framework: 'test',
      actionType: 'file_write',
      operation: 'write',
      toolName: 'write_file',
      arguments: { path: '/out/b.txt' },
      referencedPaths: ['/src/a.txt', 'mid.txt']
    });

    expect(result.provenanceSummary?.originSources).toEqual(['origin.txt']);
    await moshe.close();
  });
});
