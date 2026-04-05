import {
  ReasonCode,
  type ActionEnvelope,
  type DecisionEnvelope,
  type ProvenanceSummary,
  type TaintSummary
} from '@moshe/spec';

import type { ArtifactRecord, SessionState } from './state.js';
import type { EngineContext, StageResult } from './interfaces.js';

export interface TaintContext {
  sessionTainted: boolean;
  taintSources: string[];
  taintedArtifacts: string[];
  agentAuthoredPaths: string[];
  lineageDepth: number;
  originSources: string[];
}

export interface TaintAnalysisResult {
  decision: 'ALLOW' | 'REVIEW' | 'BLOCK';
  reasonCode: ((typeof ReasonCode)[keyof typeof ReasonCode]) | null;
  summary: string;
  taintSummary: TaintSummary;
  provenanceSummary: ProvenanceSummary;
}

const CLASSIFICATION_PRECEDENCE: Record<ArtifactRecord['classification'], number> = {
  CLEAN: 0,
  AGENT_GENERATED: 1,
  SENSITIVE: 2,
  TAINTED: 3,
  FORBIDDEN: 4
};

function buildBaseSession(sessionId: string, timestamp: string, existing?: SessionState | null): SessionState {
  return {
    sessionId,
    createdAt: existing?.createdAt ?? timestamp,
    updatedAt: timestamp,
    messageCount: existing?.messageCount ?? 0,
    taintSources: existing?.taintSources ?? [],
    whitelistedScripts: existing?.whitelistedScripts ?? {},
    ...(existing?.suspectUntil !== undefined ? { suspectUntil: existing.suspectUntil } : {}),
    ...(existing?.riskLevel !== undefined ? { riskLevel: existing.riskLevel } : {}),
    ...(existing?.reviewCount !== undefined ? { reviewCount: existing.reviewCount } : {}),
    ...(existing?.blockCount !== undefined ? { blockCount: existing.blockCount } : {}),
    ...(existing?.sensitiveReadCount !== undefined ? { sensitiveReadCount: existing.sensitiveReadCount } : {})
  };
}

function readTouchedPath(envelope: ActionEnvelope): string | null {
  const path = envelope.arguments.path;
  if (typeof path === 'string' && path.trim() !== '') {
    return path;
  }

  return null;
}

async function putArtifactIfEscalation(
  ctx: EngineContext,
  path: string,
  next: Omit<ArtifactRecord, 'path'>
): Promise<void> {
  const existing = await ctx.artifactStore.getArtifact(path);
  if (existing && CLASSIFICATION_PRECEDENCE[existing.classification] > CLASSIFICATION_PRECEDENCE[next.classification]) {
    return;
  }

  await ctx.artifactStore.putArtifact(path, {
    path,
    classification: next.classification,
    source: next.source,
    reason: next.reason,
    firstSeen: existing?.firstSeen ?? next.firstSeen,
    lastSeen: next.lastSeen,
    ...(next.provenanceChain !== undefined
      ? { provenanceChain: next.provenanceChain }
      : existing?.provenanceChain !== undefined
        ? { provenanceChain: existing.provenanceChain }
        : {})
  });
}

export function buildTaintContext(ctx: EngineContext, _envelope: ActionEnvelope): TaintContext {
  const taintedArtifacts: string[] = [];
  const agentAuthoredPaths: string[] = [];
  let lineageDepth = 0;
  const originSourceSet = new Set<string>();

  for (const [path, record] of Object.entries(ctx.relatedArtifacts ?? {})) {
    if (!record) {
      continue;
    }

    if (record.classification === 'TAINTED') {
      taintedArtifacts.push(path);
    }

    if (record.classification === 'AGENT_GENERATED') {
      agentAuthoredPaths.push(path);
    }

    if (record.classification === 'TAINTED') {
      const chain = record.provenanceChain ?? [];
      if (chain.length > lineageDepth) {
        lineageDepth = chain.length;
      }

      for (const entry of chain) {
        const entryRecord = ctx.relatedArtifacts?.[entry];
        if (
          !entryRecord
          || entryRecord.classification === 'CLEAN'
          || entryRecord.classification === 'SENSITIVE'
        ) {
          originSourceSet.add(entry);
        }
      }
    }
  }

  return {
    sessionTainted: (ctx.session?.taintSources ?? []).length > 0,
    taintSources: [...(ctx.session?.taintSources ?? [])],
    taintedArtifacts,
    agentAuthoredPaths,
    lineageDepth,
    originSources: [...originSourceSet]
  };
}

export function analyzeTaint(
  envelope: ActionEnvelope,
  taintCtx: TaintContext
): TaintAnalysisResult {
  const path = envelope.arguments.path;
  const taintSummary: TaintSummary = {
    sessionTainted: taintCtx.sessionTainted,
    taintSources: taintCtx.taintSources,
    artifactsTainted: taintCtx.taintedArtifacts
  };

  const provenanceSummary: ProvenanceSummary = {
    agentAuthored: envelope.arguments.agentAuthored === true
      ? [path ?? envelope.toolName].filter((value): value is string => typeof value === 'string' && value.trim() !== '')
      : taintCtx.agentAuthoredPaths,
    propagatedFrom: taintCtx.taintedArtifacts,
    ...(taintCtx.lineageDepth > 0 ? { lineageDepth: taintCtx.lineageDepth } : {}),
    ...(taintCtx.originSources.length > 0 ? { originSources: taintCtx.originSources } : {})
  };

  if (taintCtx.taintedArtifacts.length > 0) {
    return {
      decision: 'REVIEW',
      reasonCode: ReasonCode.TAINTED_ARTIFACT_ACCESS,
      summary: 'Action touches an artifact previously tagged as tainted.',
      taintSummary,
      provenanceSummary
    };
  }

  if (taintCtx.sessionTainted && (envelope.actionType === 'command_exec' || envelope.actionType === 'tool_call')) {
    return {
      decision: 'REVIEW',
      reasonCode: ReasonCode.TAINTED_SESSION_COMMAND,
      summary: 'Tainted session is attempting to execute a command or tool.',
      taintSummary,
      provenanceSummary
    };
  }

  if (taintCtx.agentAuthoredPaths.length > 0 && (envelope.actionType === 'command_exec' || envelope.actionType === 'file_read')) {
    return {
      decision: 'REVIEW',
      reasonCode: ReasonCode.AGENT_AUTHORED_EXECUTION,
      summary: 'Action is reading or executing agent-authored content.',
      taintSummary,
      provenanceSummary
    };
  }

  return {
    decision: 'ALLOW',
    reasonCode: null,
    summary: 'No taint or provenance signals detected.',
    taintSummary,
    provenanceSummary
  };
}

export function buildTaintStageResult(analysis: TaintAnalysisResult): StageResult {
  if (analysis.decision === 'ALLOW') {
    return {
      stage: 'taint',
      passed: true,
      decision: 'ALLOW',
      reasonCodes: [],
      enrichments: {
        taintSummary: analysis.taintSummary,
        provenanceSummary: analysis.provenanceSummary
      }
    };
  }

  return {
    stage: 'taint',
    passed: false,
    decision: analysis.decision,
    reasonCodes: [analysis.reasonCode!],
    enrichments: {
      summary: analysis.summary,
      taintSummary: analysis.taintSummary,
      provenanceSummary: analysis.provenanceSummary
    }
  };
}

export async function updateTaintState(
  envelope: ActionEnvelope,
  decision: DecisionEnvelope,
  ctx: EngineContext
): Promise<void> {
  const timestamp = envelope.timestamp;
  const path = readTouchedPath(envelope);
  const taintCtx = buildTaintContext(ctx, envelope);

  if (envelope.actionType === 'file_write' && envelope.arguments.agentAuthored === true && path) {
    await putArtifactIfEscalation(ctx, path, {
      classification: 'AGENT_GENERATED',
      source: 'agent_write',
      reason: 'agentAuthored flag set',
      firstSeen: timestamp,
      lastSeen: timestamp,
      provenanceChain: []
    });
  }

  if (envelope.actionType === 'file_write' && path) {
    const sourceChains: string[] = [];
    let maxRefClassification: ArtifactRecord['classification'] = 'CLEAN';

    for (const refPath of envelope.referencedPaths ?? []) {
      if (refPath === path) {
        continue;
      }

      const refArtifact = ctx.relatedArtifacts?.[refPath] ?? null;
      if (
        refArtifact
        && (refArtifact.classification === 'TAINTED' || refArtifact.classification === 'AGENT_GENERATED')
      ) {
        sourceChains.push(...(refArtifact.provenanceChain ?? []), refPath);
        if (CLASSIFICATION_PRECEDENCE[refArtifact.classification] > CLASSIFICATION_PRECEDENCE[maxRefClassification]) {
          maxRefClassification = refArtifact.classification;
        }
      }
    }

    if (sourceChains.length > 0) {
      await putArtifactIfEscalation(ctx, path, {
        classification: maxRefClassification,
        source: 'artifact_write_propagation',
        reason: 'file written from action that referenced tainted or agent-generated artifacts',
        firstSeen: timestamp,
        lastSeen: timestamp,
        provenanceChain: [...new Set(sourceChains)]
      });
    }
  }

  if ((ctx.session?.taintSources.length ?? 0) > 0 && envelope.actionType === 'file_write' && path) {
    await putArtifactIfEscalation(ctx, path, {
      classification: 'TAINTED',
      source: 'tainted_session_write',
      reason: 'file written from tainted session context',
      firstSeen: timestamp,
      lastSeen: timestamp,
      provenanceChain: [...ctx.session!.taintSources]
    });
  }

  if (envelope.actionType === 'file_read' && path && taintCtx.taintedArtifacts.includes(path)) {
    const existing = ctx.session ?? await ctx.sessionStore.getSession(ctx.sessionId);
    const current = buildBaseSession(ctx.sessionId, timestamp, existing);
    current.taintSources = [...new Set([...current.taintSources, path])];
    await ctx.sessionStore.putSession(ctx.sessionId, current);
  }

  if (decision.reasonCodes.includes(ReasonCode.SENSITIVE_FILE_ACCESS) && path) {
    await putArtifactIfEscalation(ctx, path, {
      classification: 'SENSITIVE',
      source: 'policy_sensitive_file',
      reason: 'matched sensitiveFiles policy',
      firstSeen: timestamp,
      lastSeen: timestamp,
      provenanceChain: []
    });
  }
}
