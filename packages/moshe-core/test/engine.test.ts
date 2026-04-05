import { randomUUID } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { MosheEngine, StaticPolicyProvider, type ActionEnvelope, type Analyzer, type DecisionEnvelope, type StageResult, type TelemetrySink } from '@moshe/core';
import { ReasonCode } from '@moshe/spec';
import { MemoryStore } from '@moshe/store-memory';

function actionFixture(overrides: Partial<ActionEnvelope> = {}): ActionEnvelope {
  return {
    actionId: randomUUID(),
    sessionId: 'session-core',
    timestamp: '2026-04-01T00:00:00.000Z',
    framework: 'generic',
    actionType: 'command_exec',
    operation: 'exec',
    toolName: 'bash',
    arguments: {
      command: 'ls -la'
    },
    ...overrides
  };
}

function createEngine(options: {
  policy?: Record<string, unknown>;
  analyzers?: Analyzer[];
  onError?: 'BLOCK' | 'ALLOW';
  onUnhandledReview?: 'BLOCK' | 'ALLOW';
  telemetrySinks?: TelemetrySink[];
}) {
  const store = new MemoryStore();
  return new MosheEngine({
    policy: new StaticPolicyProvider({
      version: '0.1.0',
      ...(options.policy ?? {})
    }),
    sessionStore: store,
    artifactStore: store,
    analyzers: options.analyzers,
    telemetrySinks: options.telemetrySinks,
    onError: options.onError ?? 'BLOCK',
    onUnhandledReview: options.onUnhandledReview ?? 'BLOCK'
  });
}

class RecordingEngine extends MosheEngine {
  public readonly order: string[] = [];

  protected override async normalize(envelope: ActionEnvelope): Promise<ActionEnvelope> {
    this.order.push('normalize');
    return super.normalize(envelope);
  }

  protected override async enrich(envelope: ActionEnvelope, startedAt: number) {
    this.order.push('enrich');
    return super.enrich(envelope, startedAt);
  }

  protected override async evaluatePolicy(envelope: ActionEnvelope, ctx: Parameters<MosheEngine['evaluatePolicy']>[1]): Promise<StageResult> {
    this.order.push('evaluatePolicy');
    return super.evaluatePolicy(envelope, ctx);
  }

  protected override async runAnalyzers(envelope: ActionEnvelope, ctx: Parameters<MosheEngine['runAnalyzers']>[1]): Promise<StageResult[]> {
    this.order.push('runAnalyzers');
    return super.runAnalyzers(envelope, ctx);
  }

  protected override async checkApproval(
    envelope: ActionEnvelope,
    ctx: Parameters<MosheEngine['checkApproval']>[1],
    analysisResults: StageResult[]
  ): Promise<StageResult> {
    this.order.push('checkApproval');
    return super.checkApproval(envelope, ctx, analysisResults);
  }

  protected override compose(
    envelope: ActionEnvelope,
    ctx: Parameters<MosheEngine['compose']>[1],
    results: StageResult[]
  ): DecisionEnvelope {
    this.order.push('compose');
    return super.compose(envelope, ctx, results);
  }

  protected override async emitTelemetry(
    envelope: ActionEnvelope,
    ctx: Parameters<MosheEngine['emitTelemetry']>[1],
    decision: DecisionEnvelope
  ): Promise<void> {
    this.order.push('emitTelemetry');
    return super.emitTelemetry(envelope, ctx, decision);
  }
}

describe('moshe-core engine', () => {
  it('executes the seven-stage pipeline in order', async () => {
    const store = new MemoryStore();
    const engine = new RecordingEngine({
      policy: new StaticPolicyProvider({ version: '0.1.0' }),
      sessionStore: store,
      artifactStore: store,
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    await engine.evaluate(actionFixture());

    expect(engine.order).toEqual([
      'normalize',
      'enrich',
      'evaluatePolicy',
      'runAnalyzers',
      'checkApproval',
      'compose',
      'emitTelemetry'
    ]);
  });

  it('returns ALLOW on the happy path', async () => {
    const decision = await createEngine({}).evaluate(actionFixture());
    expect(decision.decision).toBe('ALLOW');
    expect(decision.reasonCodes).toContain(ReasonCode.NO_POLICY_MATCH);
  });

  it('short-circuits analyzers when policy blocks', async () => {
    const analyzer = vi.fn<Analyzer['analyze']>().mockResolvedValue({
      stage: 'analysis:test',
      passed: true,
      decision: 'ALLOW'
    });

    const engine = createEngine({
      policy: {
        forbiddenCommands: ['rm\\s+-rf\\s+/']
      },
      analyzers: [
        {
          name: 'spy',
          analyze: analyzer
        }
      ]
    });

    const decision = await engine.evaluate(
      actionFixture({
        arguments: {
          command: 'rm -rf /'
        }
      })
    );

    expect(decision.decision).toBe('BLOCK');
    expect(analyzer).not.toHaveBeenCalled();
  });

  it('checks forbidden command rules against shell text as well as command text', async () => {
    const decision = await createEngine({
      policy: {
        forbiddenCommands: ['rm\\s+-rf\\s+/']
      }
    }).evaluate(
      actionFixture({
        arguments: {
          shell: 'bash -lc "rm -rf /"'
        }
      })
    );

    expect(decision.decision).toBe('BLOCK');
    expect(decision.reasonCodes).toContain(ReasonCode.FORBIDDEN_COMMAND);
  });

  it('returns configured onError decision and emits telemetry when a stage throws', async () => {
    const telemetry = vi.fn<TelemetrySink['emit']>().mockResolvedValue();
    const decision = await createEngine({
      analyzers: [
        {
          name: 'thrower',
          analyze: async () => {
            throw new Error('boom');
          }
        }
      ],
      telemetrySinks: [
        {
          name: 'spy',
          emit: telemetry
        }
      ],
      onError: 'BLOCK'
    }).evaluate(actionFixture());

    expect(decision.decision).toBe('BLOCK');
    expect(decision.reasonCodes).toContain(ReasonCode.ENGINE_ERROR);
    expect(telemetry).toHaveBeenCalled();
  });

  it('maps unhandled review through configured fallback', async () => {
    const decision = await createEngine({
      analyzers: [
        {
          name: 'reviewer',
          analyze: async () => ({
            stage: 'analysis:reviewer',
            passed: false,
            decision: 'REVIEW',
            reasonCodes: [ReasonCode.UNHANDLED_REVIEW]
          })
        }
      ],
      onUnhandledReview: 'BLOCK'
    }).evaluate(actionFixture());

    expect(decision.decision).toBe('BLOCK');
    expect(decision.reasonCodes).toContain(ReasonCode.UNHANDLED_REVIEW);
  });

  it('applies unhandled review fallback to policy-stage reviews', async () => {
    const decision = await createEngine({
      policy: {
        sensitiveFiles: ['.env']
      },
      onUnhandledReview: 'BLOCK'
    }).evaluate(actionFixture({
      actionType: 'file_read',
      operation: 'read',
      toolName: 'read_file',
      arguments: {
        path: '.env'
      }
    }));

    expect(decision.decision).toBe('BLOCK');
    expect(decision.reasonCodes).toContain(ReasonCode.UNHANDLED_REVIEW);
    expect(decision.reasonCodes).toContain(ReasonCode.SENSITIVE_FILE_ACCESS);
  });

  it('allows PRD-D style analyzers to plug in without changing engine internals', async () => {
    const analyzer: Analyzer = {
      name: 'stub-intent',
      analyze: async () => ({
        stage: 'analysis:stub-intent',
        passed: true,
        decision: 'ALLOW',
        reasonCodes: [ReasonCode.INTENT_ANALYZER_STUB]
      })
    };

    const decision = await createEngine({
      analyzers: [analyzer]
    }).evaluate(actionFixture());

    expect(decision.decision).toBe('ALLOW');
    expect(decision.reasonCodes).toContain(ReasonCode.INTENT_ANALYZER_STUB);
  });
});
