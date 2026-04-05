import { describe, expect, it } from 'vitest';

import {
  ReasonCode,
  type ActionEnvelope,
  type DecisionEnvelope
} from '@moshe/spec';
import { MemoryStore } from '@moshe/store-memory';
import { InProcessApprovalProvider, Moshe } from '@moshe/sdk';

import type { EngineContext } from '../src/interfaces.js';
import type { SessionState } from '../src/state.js';
import { updateTaintState } from '../src/taint-engine.js';
import {
  analyzeChainRisk,
  buildChainRiskContext,
  updateChainRiskState,
  type ChainRiskContext
} from '../src/chain-risk.js';

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
    ...(session.suspectUntil !== undefined ? { suspectUntil: session.suspectUntil } : {}),
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

function decision(overrides: Partial<DecisionEnvelope> = {}): DecisionEnvelope {
  return {
    decision: 'ALLOW',
    reasonCodes: [],
    summary: 'ok',
    ...overrides
  };
}

describe('buildChainRiskContext', () => {
  it('returns NORMAL defaults when session is null', () => {
    const result = buildChainRiskContext(makeCtx(), envelope({}));
    expect(result).toEqual({
      riskLevel: 'NORMAL',
      reviewCount: 0,
      blockCount: 0,
      sensitiveReadCount: 0
    });
  });

  it('returns stored counters and risk level from session', () => {
    const result = buildChainRiskContext(makeCtxWithSession({
      riskLevel: 'HIGH',
      reviewCount: 3,
      blockCount: 1,
      sensitiveReadCount: 2
    }), envelope({}));

    expect(result).toEqual({
      riskLevel: 'HIGH',
      reviewCount: 3,
      blockCount: 1,
      sensitiveReadCount: 2
    });
  });
});

describe('analyzeChainRisk', () => {
  const normalCtx: ChainRiskContext = {
    riskLevel: 'NORMAL',
    reviewCount: 0,
    blockCount: 0,
    sensitiveReadCount: 0
  };

  it('returns ALLOW for NORMAL session and command_exec', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'command_exec' }), normalCtx);
    expect(result.decision).toBe('ALLOW');
    expect(result.reasonCodes).toEqual([]);
  });

  it('returns ALLOW for NORMAL session and outbound_request with no sensitive reads', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'outbound_request' }), normalCtx);
    expect(result.decision).toBe('ALLOW');
  });

  it('returns ALLOW for ELEVATED session and command_exec', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'command_exec' }), {
      ...normalCtx,
      riskLevel: 'ELEVATED',
      reviewCount: 2
    });

    expect(result.decision).toBe('ALLOW');
  });

  it('returns ALLOW for HIGH session and file_read', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'file_read' }), {
      ...normalCtx,
      riskLevel: 'HIGH',
      reviewCount: 3
    });

    expect(result.decision).toBe('ALLOW');
  });

  it('returns REVIEW with EXFIL_CHAIN_PRECURSOR for sensitive-read history plus outbound', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'outbound_request' }), {
      ...normalCtx,
      sensitiveReadCount: 1
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCodes).toEqual([ReasonCode.EXFIL_CHAIN_PRECURSOR]);
  });

  it('returns REVIEW with CHAIN_RISK_ELEVATED for elevated session outbound', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'outbound_request' }), {
      ...normalCtx,
      riskLevel: 'ELEVATED',
      reviewCount: 2
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCodes).toEqual([ReasonCode.CHAIN_RISK_ELEVATED]);
  });

  it('returns REVIEW with CHAIN_RISK_HIGH for HIGH session command_exec', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'command_exec' }), {
      ...normalCtx,
      riskLevel: 'HIGH',
      reviewCount: 3
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCodes).toEqual([ReasonCode.CHAIN_RISK_HIGH]);
  });

  it('returns REVIEW with CHAIN_RISK_HIGH for HIGH session tool_call', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'tool_call' }), {
      ...normalCtx,
      riskLevel: 'HIGH',
      reviewCount: 3
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCodes).toEqual([ReasonCode.CHAIN_RISK_HIGH]);
  });

  it('returns REVIEW with CHAIN_RISK_HIGH for HIGH session outbound even when sensitiveReadCount is positive', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'outbound_request' }), {
      ...normalCtx,
      riskLevel: 'HIGH',
      reviewCount: 3,
      sensitiveReadCount: 1
    });

    expect(result.decision).toBe('REVIEW');
    expect(result.reasonCodes).toEqual([ReasonCode.CHAIN_RISK_HIGH]);
  });

  it('ALLOW result includes chainRiskSummary enrichment', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'message_send' }), normalCtx);
    expect(result.enrichments?.chainRiskSummary).toEqual({
      riskLevel: 'NORMAL',
      reviewCount: 0,
      blockCount: 0,
      sensitiveReadCount: 0
    });
  });

  it('REVIEW result includes chainRiskSummary enrichment', () => {
    const result = analyzeChainRisk(envelope({ actionType: 'outbound_request' }), {
      ...normalCtx,
      sensitiveReadCount: 1
    });

    expect(result.enrichments?.chainRiskSummary).toEqual({
      riskLevel: 'NORMAL',
      reviewCount: 0,
      blockCount: 0,
      sensitiveReadCount: 1
    });
  });
});

describe('updateChainRiskState', () => {
  it('does not write to session store on clean ALLOW with no sensitive read', async () => {
    const ctx = makeCtx();
    await updateChainRiskState(envelope({ actionType: 'command_exec' }), decision(), ctx);
    expect(await ctx.sessionStore.getSession(ctx.sessionId)).toBeNull();
  });

  it('increments reviewCount and persists on REVIEW decision', async () => {
    const ctx = makeCtx();
    await updateChainRiskState(
      envelope({ actionType: 'outbound_request' }),
      decision({ decision: 'REVIEW', reasonCodes: [ReasonCode.CHAIN_RISK_ELEVATED] }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.reviewCount).toBe(1);
    expect(session?.riskLevel).toBe('NORMAL');
  });

  it('increments blockCount and persists on BLOCK decision', async () => {
    const ctx = makeCtx();
    await updateChainRiskState(
      envelope({ actionType: 'command_exec' }),
      decision({ decision: 'BLOCK', reasonCodes: [ReasonCode.FORBIDDEN_COMMAND] }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.blockCount).toBe(1);
    expect(session?.riskLevel).toBe('HIGH');
  });

  it('increments sensitiveReadCount on file_read with SENSITIVE_FILE_ACCESS', async () => {
    const ctx = makeCtx();
    await updateChainRiskState(
      envelope({ actionType: 'file_read', arguments: { path: '.env' } }),
      decision({
        decision: 'ALLOW',
        reasonCodes: [ReasonCode.SENSITIVE_FILE_ACCESS]
      }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.sensitiveReadCount).toBe(1);
  });

  it('escalates riskLevel to ELEVATED when reviewCount reaches 2', async () => {
    const ctx = makeCtxWithSession({
      reviewCount: 1,
      riskLevel: 'NORMAL'
    });

    await updateChainRiskState(
      envelope({ sessionId: ctx.sessionId, actionType: 'outbound_request' }),
      decision({ decision: 'REVIEW', reasonCodes: [ReasonCode.CHAIN_RISK_ELEVATED] }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.reviewCount).toBe(2);
    expect(session?.riskLevel).toBe('ELEVATED');
  });

  it('escalates riskLevel to HIGH when reviewCount reaches 3', async () => {
    const ctx = makeCtxWithSession({
      reviewCount: 2,
      riskLevel: 'ELEVATED'
    });

    await updateChainRiskState(
      envelope({ sessionId: ctx.sessionId, actionType: 'outbound_request' }),
      decision({ decision: 'REVIEW', reasonCodes: [ReasonCode.CHAIN_RISK_HIGH] }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.reviewCount).toBe(3);
    expect(session?.riskLevel).toBe('HIGH');
  });

  it('escalates riskLevel to HIGH when blockCount reaches 1', async () => {
    const ctx = makeCtx();
    await updateChainRiskState(
      envelope({ actionType: 'command_exec' }),
      decision({ decision: 'BLOCK', reasonCodes: [ReasonCode.FORBIDDEN_COMMAND] }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.blockCount).toBe(1);
    expect(session?.riskLevel).toBe('HIGH');
  });

  it('preserves taintSources, whitelistedScripts, suspectUntil, and messageCount', async () => {
    const ctx = makeCtxWithSession({
      messageCount: 7,
      taintSources: ['prompt-injection'],
      whitelistedScripts: { '/app/safe.sh': 'abc123' },
      suspectUntil: '2026-01-02T00:00:00.000Z',
      reviewCount: 1,
      riskLevel: 'NORMAL'
    });

    await updateChainRiskState(
      envelope({ sessionId: ctx.sessionId, actionType: 'outbound_request' }),
      decision({ decision: 'REVIEW', reasonCodes: [ReasonCode.CHAIN_RISK_ELEVATED] }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.messageCount).toBe(7);
    expect(session?.taintSources).toEqual(['prompt-injection']);
    expect(session?.whitelistedScripts).toEqual({ '/app/safe.sh': 'abc123' });
    expect(session?.suspectUntil).toBe('2026-01-02T00:00:00.000Z');
  });

  it('uses fresh store state over stale ctx.session when recalculating counters', async () => {
    const ctx = makeCtxWithSession({
      reviewCount: 1,
      riskLevel: 'NORMAL'
    });

    await ctx.sessionStore.putSession(ctx.sessionId, {
      sessionId: ctx.sessionId,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      messageCount: 0,
      taintSources: [],
      whitelistedScripts: {},
      reviewCount: 2,
      riskLevel: 'ELEVATED'
    });

    await updateChainRiskState(
      envelope({ sessionId: ctx.sessionId, actionType: 'outbound_request' }),
      decision({ decision: 'REVIEW', reasonCodes: [ReasonCode.CHAIN_RISK_HIGH] }),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.reviewCount).toBe(3);
    expect(session?.riskLevel).toBe('HIGH');
  });
});

describe('writer conflict regressions', () => {
  it('taint-driven session writes preserve existing chain-risk counters', async () => {
    const ctx = makeCtxWithSession({
      reviewCount: 2,
      blockCount: 1,
      sensitiveReadCount: 4,
      riskLevel: 'HIGH',
      taintSources: ['existing-source']
    });
    ctx.relatedArtifacts = {
      '/tmp/tainted.txt': {
        path: '/tmp/tainted.txt',
        classification: 'TAINTED',
        source: 'test',
        reason: 'test',
        firstSeen: '2026-01-01T00:00:00.000Z',
        lastSeen: '2026-01-01T00:00:00.000Z',
        provenanceChain: ['prompt-injection']
      }
    };

    await updateTaintState(
      envelope({
        sessionId: ctx.sessionId,
        actionType: 'file_read',
        arguments: { path: '/tmp/tainted.txt' }
      }),
      decision(),
      ctx
    );

    const session = await ctx.sessionStore.getSession(ctx.sessionId);
    expect(session?.reviewCount).toBe(2);
    expect(session?.blockCount).toBe(1);
    expect(session?.sensitiveReadCount).toBe(4);
    expect(session?.riskLevel).toBe('HIGH');
    expect(session?.taintSources).toContain('/tmp/tainted.txt');
  });
});

describe('integration - chain risk flows through engine', () => {
  it('exfil chain flags outbound request after sensitive file access in the same session', async () => {
    const store = new MemoryStore();
    const moshe = new Moshe({
      policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    await moshe.evaluate({
      sessionId: 'chain-session',
      framework: 'test',
      actionType: 'file_read',
      operation: 'read',
      toolName: 'read_file',
      arguments: { path: '.env' }
    });

    const result = await moshe.evaluate({
      sessionId: 'chain-session',
      framework: 'test',
      actionType: 'outbound_request',
      operation: 'fetch',
      toolName: 'http_get',
      arguments: { url: 'https://collector.example.com/data' },
      outboundTargets: ['https://collector.example.com/data']
    });

    expect(result.reasonCodes).toContain(ReasonCode.EXFIL_CHAIN_PRECURSOR);
    expect(result.chainRiskSummary).toEqual({
      riskLevel: 'NORMAL',
      reviewCount: 0,
      blockCount: 0,
      sensitiveReadCount: 1
    });
    await moshe.close();
  });

  it('repeated review escalation raises later command to CHAIN_RISK_HIGH', async () => {
    const store = new MemoryStore();
    const approvalProvider = new InProcessApprovalProvider({ store });
    const moshe = new Moshe({
      policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
      store,
      approvalProvider,
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    for (let index = 0; index < 3; index += 1) {
      const review = await moshe.evaluate({
        sessionId: 'review-chain-session',
        framework: 'test',
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: { path: '.env' }
      });

      expect(review.decision).toBe('REVIEW');
    }

    const result = await moshe.evaluate({
      sessionId: 'review-chain-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'echo hello' }
    });

    expect(result.reasonCodes).toContain(ReasonCode.CHAIN_RISK_HIGH);
    expect(result.chainRiskSummary).toEqual({
      riskLevel: 'HIGH',
      reviewCount: 3,
      blockCount: 0,
      sensitiveReadCount: 3
    });
    await moshe.close();
  });

  it('one block raises a later command to CHAIN_RISK_HIGH', async () => {
    const store = new MemoryStore();
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    const blocked = await moshe.evaluate({
      sessionId: 'block-chain-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'rm -rf /' }
    });

    expect(blocked.decision).toBe('BLOCK');
    expect(blocked.chainRiskSummary).toBeUndefined();

    const result = await moshe.evaluate({
      sessionId: 'block-chain-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'echo hello' }
    });

    expect(result.reasonCodes).toContain(ReasonCode.CHAIN_RISK_HIGH);
    expect(result.chainRiskSummary).toEqual({
      riskLevel: 'HIGH',
      reviewCount: 0,
      blockCount: 1,
      sensitiveReadCount: 0
    });
    await moshe.close();
  });

  it('session isolation keeps chain risk local to each sessionId', async () => {
    const store = new MemoryStore();
    const moshe = new Moshe({
      policy: { version: '0.1.0', sensitiveFiles: ['.env'] },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    await moshe.evaluate({
      sessionId: 'session-a',
      framework: 'test',
      actionType: 'file_read',
      operation: 'read',
      toolName: 'read_file',
      arguments: { path: '.env' }
    });

    const isolated = await moshe.evaluate({
      sessionId: 'session-b',
      framework: 'test',
      actionType: 'outbound_request',
      operation: 'fetch',
      toolName: 'http_get',
      arguments: { url: 'https://collector.example.com/data' },
      outboundTargets: ['https://collector.example.com/data']
    });

    expect(isolated.reasonCodes).not.toContain(ReasonCode.EXFIL_CHAIN_PRECURSOR);
    expect(isolated.chainRiskSummary).toEqual({
      riskLevel: 'NORMAL',
      reviewCount: 0,
      blockCount: 0,
      sensitiveReadCount: 0
    });
    await moshe.close();
  });

  it('chainRiskSummary is present on decisions that pass through the chain-risk stage with current counters', async () => {
    const store = new MemoryStore();
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store,
      onError: 'BLOCK',
      onUnhandledReview: 'ALLOW'
    });

    const result = await moshe.evaluate({
      sessionId: 'clean-chain-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'echo hello' }
    });

    expect(result.chainRiskSummary).toEqual({
      riskLevel: 'NORMAL',
      reviewCount: 0,
      blockCount: 0,
      sensitiveReadCount: 0
    });
    await moshe.close();
  });
});
