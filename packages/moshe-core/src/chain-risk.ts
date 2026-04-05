import {
  ReasonCode,
  type ActionEnvelope,
  type ChainRiskSummary,
  type DecisionEnvelope
} from '@moshe/spec';

import type { EngineContext, StageResult } from './interfaces.js';
import type { SessionState } from './state.js';

export type SessionRiskLevel = 'NORMAL' | 'ELEVATED' | 'HIGH';

export interface ChainRiskContext {
  riskLevel: SessionRiskLevel;
  reviewCount: number;
  blockCount: number;
  sensitiveReadCount: number;
}

function buildChainRiskSummary(chainCtx: ChainRiskContext): ChainRiskSummary {
  return {
    riskLevel: chainCtx.riskLevel,
    reviewCount: chainCtx.reviewCount,
    blockCount: chainCtx.blockCount,
    sensitiveReadCount: chainCtx.sensitiveReadCount
  };
}

function buildBaseSession(sessionId: string, timestamp: string, existing?: SessionState | null): SessionState {
  return {
    sessionId,
    createdAt: existing?.createdAt ?? timestamp,
    updatedAt: timestamp,
    messageCount: existing?.messageCount ?? 0,
    taintSources: existing?.taintSources ?? [],
    whitelistedScripts: existing?.whitelistedScripts ?? {},
    ...(existing?.suspectUntil !== undefined ? { suspectUntil: existing.suspectUntil } : {})
  };
}

export function buildChainRiskContext(ctx: EngineContext, _envelope: ActionEnvelope): ChainRiskContext {
  const session = ctx.session;
  return {
    riskLevel: session?.riskLevel ?? 'NORMAL',
    reviewCount: session?.reviewCount ?? 0,
    blockCount: session?.blockCount ?? 0,
    sensitiveReadCount: session?.sensitiveReadCount ?? 0
  };
}

export function analyzeChainRisk(
  envelope: ActionEnvelope,
  chainCtx: ChainRiskContext
): StageResult {
  const chainRiskSummary = buildChainRiskSummary(chainCtx);
  const highRiskAction = envelope.actionType === 'command_exec'
    || envelope.actionType === 'tool_call'
    || envelope.actionType === 'outbound_request';

  if (chainCtx.riskLevel === 'HIGH' && highRiskAction) {
    return {
      stage: 'chain_risk',
      passed: false,
      decision: 'REVIEW',
      reasonCodes: [ReasonCode.CHAIN_RISK_HIGH],
      enrichments: {
        summary: 'Session has accumulated high risk; action requires review.',
        chainRiskSummary
      }
    };
  }

  if (chainCtx.sensitiveReadCount > 0 && envelope.actionType === 'outbound_request') {
    return {
      stage: 'chain_risk',
      passed: false,
      decision: 'REVIEW',
      reasonCodes: [ReasonCode.EXFIL_CHAIN_PRECURSOR],
      enrichments: {
        summary: 'Outbound request follows sensitive file access in this session.',
        chainRiskSummary
      }
    };
  }

  if (chainCtx.riskLevel === 'ELEVATED' && envelope.actionType === 'outbound_request') {
    return {
      stage: 'chain_risk',
      passed: false,
      decision: 'REVIEW',
      reasonCodes: [ReasonCode.CHAIN_RISK_ELEVATED],
      enrichments: {
        summary: 'Outbound request from elevated-risk session requires review.',
        chainRiskSummary
      }
    };
  }

  return {
    stage: 'chain_risk',
    passed: true,
    decision: 'ALLOW',
    reasonCodes: [],
    enrichments: {
      chainRiskSummary
    }
  };
}

export async function updateChainRiskState(
  envelope: ActionEnvelope,
  decision: DecisionEnvelope,
  ctx: EngineContext
): Promise<void> {
  const existing = await ctx.sessionStore.getSession(envelope.sessionId) ?? ctx.session ?? null;
  const prevReviewCount = existing?.reviewCount ?? 0;
  const prevBlockCount = existing?.blockCount ?? 0;
  const prevSensitiveReadCount = existing?.sensitiveReadCount ?? 0;

  let reviewCount = prevReviewCount;
  let blockCount = prevBlockCount;
  let sensitiveReadCount = prevSensitiveReadCount;

  if (decision.decision === 'REVIEW') {
    reviewCount += 1;
  }

  if (decision.decision === 'BLOCK') {
    blockCount += 1;
  }

  if (
    envelope.actionType === 'file_read'
    && decision.reasonCodes.includes(ReasonCode.SENSITIVE_FILE_ACCESS)
  ) {
    sensitiveReadCount += 1;
  }

  if (
    reviewCount === prevReviewCount
    && blockCount === prevBlockCount
    && sensitiveReadCount === prevSensitiveReadCount
  ) {
    return;
  }

  let riskLevel: SessionRiskLevel;
  if (blockCount >= 1 || reviewCount >= 3) {
    riskLevel = 'HIGH';
  } else if (reviewCount >= 2) {
    riskLevel = 'ELEVATED';
  } else {
    riskLevel = 'NORMAL';
  }

  const next: SessionState = {
    ...buildBaseSession(envelope.sessionId, envelope.timestamp, existing),
    riskLevel,
    reviewCount,
    blockCount,
    sensitiveReadCount
  };

  await ctx.sessionStore.putSession(envelope.sessionId, next);
}
