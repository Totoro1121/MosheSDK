import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';

import {
  ReasonCode,
  validateActionEnvelope,
  validateDecisionEnvelope,
  validatePolicyConfig,
  type ActionEnvelope,
  type ApprovalRequest,
  type DecisionEnvelope,
  type PolicyConfig,
  type TelemetryEvent
} from '@moshesdk/spec';

import type { EngineConfig, EngineContext, StageResult } from './interfaces.js';
import { collectMatchedRules, decisionFromResults, evaluateStaticPolicy, validatePolicyRules } from './policy.js';
import { analyzeChainRisk, buildChainRiskContext, updateChainRiskState } from './chain-risk.js';
import { analyzeTaint, buildTaintContext, buildTaintStageResult, updateTaintState } from './taint-engine.js';
import { ApprovalBlockedError } from './approval-provider.js';
import { applyPresetOverlays } from './policy-presets.js';

function fallbackActionId(envelope: unknown): string {
  if (typeof envelope === 'object' && envelope && 'actionId' in envelope) {
    const value = (envelope as Record<string, unknown>).actionId;
    if (typeof value === 'string' && value.trim() !== '') {
      return value;
    }
  }

  return randomUUID();
}

function fallbackSessionId(envelope: unknown): string {
  if (typeof envelope === 'object' && envelope && 'sessionId' in envelope) {
    const value = (envelope as Record<string, unknown>).sessionId;
    if (typeof value === 'string' && value.trim() !== '') {
      return value;
    }
  }

  return 'unknown-session';
}

function mergeReasonCodes(results: StageResult[]): DecisionEnvelope['reasonCodes'] {
  const merged = new Set<ReasonCode>();
  for (const result of results) {
    for (const code of result.reasonCodes ?? []) {
      merged.add(code);
    }
  }

  return [...merged];
}

function summaryForDecision(decision: DecisionEnvelope['decision'], reasonCodes: string[]): string {
  switch (decision) {
    case 'BLOCK':
      return reasonCodes.length > 0
        ? `Blocked action due to ${reasonCodes.join(', ')}.`
        : 'Blocked action.';
    case 'REVIEW':
      return reasonCodes.length > 0
        ? `Action requires review due to ${reasonCodes.join(', ')}.`
        : 'Action requires review.';
    default:
      return 'Action allowed.';
  }
}

function buildTelemetryEvent(base: {
  eventType: TelemetryEvent['eventType'];
  actionId: string;
  sessionId: string;
  elapsedMs?: number;
  stage?: string;
  decision?: DecisionEnvelope['decision'];
  reasonCodes?: DecisionEnvelope['reasonCodes'];
  debug?: Record<string, unknown>;
}): TelemetryEvent {
  const event: TelemetryEvent = {
    eventId: randomUUID(),
    eventType: base.eventType,
    actionId: base.actionId,
    sessionId: base.sessionId
  };

  if (base.elapsedMs !== undefined) {
    event.elapsedMs = base.elapsedMs;
  }

  if (base.stage !== undefined) {
    event.stage = base.stage;
  }

  if (base.decision !== undefined) {
    event.decision = base.decision;
  }

  if (base.reasonCodes !== undefined) {
    event.reasonCodes = base.reasonCodes;
  }

  if (base.debug !== undefined) {
    event.debug = base.debug;
  }

  return event;
}

function buildStageResult(base: {
  stage: string;
  passed: boolean;
  decision?: DecisionEnvelope['decision'];
  reasonCodes?: DecisionEnvelope['reasonCodes'];
  matchedRules?: DecisionEnvelope['matchedRules'];
  enrichments?: Partial<DecisionEnvelope>;
}): StageResult {
  const result: StageResult = {
    stage: base.stage,
    passed: base.passed
  };

  if (base.decision !== undefined) {
    result.decision = base.decision;
  }

  if (base.reasonCodes !== undefined) {
    result.reasonCodes = base.reasonCodes;
  }

  if (base.matchedRules !== undefined) {
    result.matchedRules = base.matchedRules;
  }

  if (base.enrichments !== undefined) {
    result.enrichments = base.enrichments;
  }

  return result;
}

export class MosheEngine {
  public constructor(protected readonly config: EngineConfig) {}

  public async evaluate(envelope: ActionEnvelope): Promise<DecisionEnvelope> {
    const startedAt = performance.now();
    let currentEnvelope: ActionEnvelope | undefined;
    let currentContext: EngineContext | undefined;

    try {
      currentEnvelope = await this.normalize(envelope);
      await this.emitSingleTelemetry(buildTelemetryEvent({
        eventType: 'ACTION_RECEIVED',
        actionId: currentEnvelope.actionId,
        sessionId: currentEnvelope.sessionId,
        elapsedMs: 0
      }));

      currentContext = await this.enrich(currentEnvelope, startedAt);
      await this.emitStageEvent(currentEnvelope, currentContext, 'enrich');

      const policyResult = await this.evaluatePolicy(currentEnvelope, currentContext);
      await this.emitStageEvent(currentEnvelope, currentContext, 'static_policy', policyResult);

      if (policyResult.decision === 'BLOCK') {
        const decision = this.compose(currentEnvelope, currentContext, [policyResult]);
        await this.emitDecisionTelemetry(currentEnvelope, currentContext, decision);
        await this.emitTelemetry(currentEnvelope, currentContext, decision);
        await updateTaintState(currentEnvelope, decision, currentContext);
        await updateChainRiskState(currentEnvelope, decision, currentContext);
        return decision;
      }

      const analysisResults = await this.runAnalyzers(currentEnvelope, currentContext);
      await this.emitStageEvent(currentEnvelope, currentContext, 'analysis', buildStageResult({
        stage: 'analysis',
        passed: analysisResults.every((result) => result.passed),
        decision: decisionFromResults(analysisResults),
        reasonCodes: mergeReasonCodes(analysisResults),
        matchedRules: collectMatchedRules(analysisResults)
      }));

      const approvalResult = await this.checkApproval(currentEnvelope, currentContext, [policyResult, ...analysisResults]);
      await this.emitStageEvent(currentEnvelope, currentContext, 'approval', approvalResult);

      const decision = this.compose(currentEnvelope, currentContext, [policyResult, ...analysisResults, approvalResult]);
      await this.emitDecisionTelemetry(currentEnvelope, currentContext, decision);
      await this.emitTelemetry(currentEnvelope, currentContext, decision);
      await updateTaintState(currentEnvelope, decision, currentContext);
      await updateChainRiskState(currentEnvelope, decision, currentContext);
      return decision;
    } catch (error) {
      const actionId = currentEnvelope?.actionId ?? fallbackActionId(envelope);
      const sessionId = currentEnvelope?.sessionId ?? fallbackSessionId(envelope);
      const elapsedMs = performance.now() - startedAt;
      const decision: DecisionEnvelope = {
        decision: this.config.onError,
        reasonCodes: [ReasonCode.ENGINE_ERROR],
        summary: `Engine failed and returned configured ${this.config.onError}.`,
        debug: {
          error: error instanceof Error ? error.message : String(error)
        }
      };

      await this.emitSingleTelemetry(buildTelemetryEvent({
        eventType: 'DECISION_MADE',
        actionId,
        sessionId,
        decision: decision.decision,
        reasonCodes: decision.reasonCodes,
        elapsedMs,
        ...(decision.debug ? { debug: decision.debug } : {})
      })).catch(() => undefined);

      return decision;
    }
  }

  protected async normalize(envelope: ActionEnvelope): Promise<ActionEnvelope> {
    const result = validateActionEnvelope(envelope);
    if (!result.ok) {
      throw new Error(`ActionEnvelope validation failed: ${result.errors.join('; ')}`);
    }

    return result.data;
  }

  protected async enrich(envelope: ActionEnvelope, startedAt: number): Promise<EngineContext> {
    const effectivePolicy = await this.config.policy.getEffective();
    await this.config.policy.validate(effectivePolicy);

    const pathCandidates = new Set<string>();
    if (typeof envelope.arguments.path === 'string' && envelope.arguments.path.trim() !== '') {
      pathCandidates.add(envelope.arguments.path);
    }

    for (const path of envelope.referencedPaths ?? []) {
      if (path.trim() !== '') {
        pathCandidates.add(path);
      }
    }

    // Wave 0 only preloads artifact records for local path-like references.
    // Outbound targets stay on the envelope for later outbound analysis PRDs.

    const relatedArtifacts: NonNullable<EngineContext['relatedArtifacts']> = {};
    for (const path of pathCandidates) {
      relatedArtifacts[path] = await this.config.artifactStore.getArtifact(path);
    }

    return {
      sessionId: envelope.sessionId,
      policy: effectivePolicy,
      sessionStore: this.config.sessionStore,
      artifactStore: this.config.artifactStore,
      startedAt,
      session: await this.config.sessionStore.getSession(envelope.sessionId),
      relatedArtifacts
    };
  }

  protected async evaluatePolicy(envelope: ActionEnvelope, ctx: EngineContext): Promise<StageResult> {
    return evaluateStaticPolicy(envelope, ctx);
  }

  protected async runAnalyzers(envelope: ActionEnvelope, ctx: EngineContext): Promise<StageResult[]> {
    const results: StageResult[] = [];

    for (const analyzer of this.config.analyzers ?? []) {
      const result = await analyzer.analyze(envelope, ctx);
      results.push(result);
    }

    if (this.config.decisionProvider) {
      const providerResult = await this.config.decisionProvider.evaluate(envelope, ctx);
      if (providerResult) {
        results.push(providerResult);
      }
    }

    const taintCtx = buildTaintContext(ctx, envelope);
    const taintAnalysis = analyzeTaint(envelope, taintCtx);
    results.push(buildTaintStageResult(taintAnalysis));

    const chainCtx = buildChainRiskContext(ctx, envelope);
    results.push(analyzeChainRisk(envelope, chainCtx));

    return results;
  }

  protected async checkApproval(
    envelope: ActionEnvelope,
    ctx: EngineContext,
    analysisResults: StageResult[]
  ): Promise<StageResult> {
    const reviewResult = analysisResults.find((result) => result.decision === 'REVIEW');
    if (!reviewResult) {
      return {
        stage: 'approval',
        passed: true,
        decision: 'ALLOW',
        reasonCodes: [ReasonCode.NO_APPROVAL_REQUIRED],
        enrichments: {
          summary: 'No approval required.'
        }
      };
    }

    if (!this.config.approvalProvider) {
      return buildStageResult({
        stage: 'approval',
        passed: this.config.onUnhandledReview === 'ALLOW',
        decision: this.config.onUnhandledReview,
        reasonCodes: [ReasonCode.UNHANDLED_REVIEW],
        matchedRules: reviewResult.matchedRules,
        enrichments: {
          summary: `Review requested without approval provider; fell back to ${this.config.onUnhandledReview}.`
        }
      });
    }

    let approvalRequest: ApprovalRequest | null;
    try {
      approvalRequest = await this.config.approvalProvider.create(envelope, ctx);
    } catch (error) {
      if (error instanceof ApprovalBlockedError) {
        return buildStageResult({
          stage: 'approval',
          passed: false,
          decision: 'BLOCK',
          reasonCodes: [ReasonCode.APPROVAL_REPLAY_BLOCKED],
          enrichments: {
            summary: 'Action blocked: previously BLOCK-resolved within cooldown period.'
          }
        });
      }

      throw error;
    }
    if (!approvalRequest) {
      return buildStageResult({
        stage: 'approval',
        passed: true,
        decision: 'ALLOW',
        reasonCodes: [ReasonCode.APPROVAL_REPLAY_ALLOWED],
        enrichments: {
          summary: 'Action allowed via prior approval.'
        }
      });
    }

    return buildStageResult({
      stage: 'approval',
      passed: false,
      decision: 'REVIEW',
      reasonCodes: [ReasonCode.APPROVAL_REQUIRED],
      matchedRules: reviewResult.matchedRules,
      enrichments: {
        summary: 'Approval required before this action can proceed.',
        approvalRequest
      }
    });
  }

  protected compose(envelope: ActionEnvelope, ctx: EngineContext, results: StageResult[]): DecisionEnvelope {
    const decision = decisionFromResults(results);
    const reasonCodes = mergeReasonCodes(results);
    const enrichments = results
      .map((result) => result.enrichments)
      .filter((value): value is Partial<DecisionEnvelope> => value !== undefined);

    const composed: DecisionEnvelope = {
      decision,
      reasonCodes,
      summary: enrichments.map((value) => value.summary).find((value): value is string => typeof value === 'string')
        ?? summaryForDecision(decision, reasonCodes),
      debug: {
        stageCount: results.length,
        sessionId: ctx.sessionId,
        actionId: envelope.actionId
      }
    };

    const matchedRules = collectMatchedRules(results);
    if (matchedRules) {
      composed.matchedRules = matchedRules;
    }

    for (const enrichment of enrichments) {
      Object.assign(composed, enrichment);
    }

    const validation = validateDecisionEnvelope(composed);
    if (!validation.ok) {
      throw new Error(`DecisionEnvelope validation failed: ${validation.errors.join('; ')}`);
    }

    return validation.data;
  }

  protected async emitTelemetry(
    envelope: ActionEnvelope,
    ctx: EngineContext,
    decision: DecisionEnvelope
  ): Promise<void> {
    await this.emitSingleTelemetry(buildTelemetryEvent({
      eventType: 'STAGE_COMPLETE',
      actionId: envelope.actionId,
      sessionId: envelope.sessionId,
      stage: 'compose',
      decision: decision.decision,
      reasonCodes: decision.reasonCodes,
      elapsedMs: performance.now() - ctx.startedAt
    }));
  }

  protected async emitStageEvent(
    envelope: ActionEnvelope,
    ctx: EngineContext,
    stage: string,
    result?: StageResult
  ): Promise<void> {
    await this.emitSingleTelemetry(buildTelemetryEvent({
      eventType: 'STAGE_COMPLETE',
      actionId: envelope.actionId,
      sessionId: envelope.sessionId,
      stage,
      elapsedMs: performance.now() - ctx.startedAt,
      ...(result?.decision ? { decision: result.decision } : {}),
      ...(result?.reasonCodes ? { reasonCodes: result.reasonCodes } : {})
    }));
  }

  protected async emitDecisionTelemetry(
    envelope: ActionEnvelope,
    ctx: EngineContext,
    decision: DecisionEnvelope
  ): Promise<void> {
    await this.emitSingleTelemetry(buildTelemetryEvent({
      eventType: 'DECISION_MADE',
      actionId: envelope.actionId,
      sessionId: envelope.sessionId,
      decision: decision.decision,
      reasonCodes: decision.reasonCodes,
      elapsedMs: performance.now() - ctx.startedAt
    }));
  }

  protected async emitSingleTelemetry(event: TelemetryEvent): Promise<void> {
    for (const sink of this.config.telemetrySinks ?? []) {
      await sink.emit(event);
    }
  }
}

export class StaticPolicyProvider {
  public constructor(private readonly policy: PolicyConfig) {}

  public async load(): Promise<PolicyConfig> {
    return structuredClone(this.policy);
  }

  public async validate(config: PolicyConfig): Promise<void> {
    const result = validatePolicyConfig(config);
    if (!result.ok) {
      throw new Error(`PolicyConfig validation failed: ${result.errors.join('; ')}`);
    }

    const ruleErrors = validatePolicyRules(config);
    if (ruleErrors.length > 0) {
      throw new Error(`PolicyConfig validation failed: ${ruleErrors.map((error) => `${error.field}[${error.index}] "${error.value}": ${error.reason}`).join('; ')}`);
    }
  }

  public async getEffective(): Promise<PolicyConfig> {
    const config = structuredClone(this.policy);
    if (config.presetOverlays && config.presetOverlays.length > 0) {
      return applyPresetOverlays(config, config.presetOverlays);
    }

    return config;
  }
}
