import { randomUUID } from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CallbackDecisionProvider,
  HttpDecisionProvider,
  InProcessApprovalProvider,
  MosheEngine,
  NoopDecisionProvider,
  StaticPolicyProvider,
  type ActionEnvelope,
  type DecisionProvider,
  type EngineContext,
  type StageResult
} from '@moshe/core';
import { ReasonCode } from '@moshe/spec';
import { MemoryStore } from '@moshe/store-memory';

function actionFixture(overrides: Partial<ActionEnvelope> = {}): ActionEnvelope {
  return {
    actionId: randomUUID(),
    sessionId: 'session-provider',
    timestamp: '2026-04-05T00:00:00.000Z',
    framework: 'generic',
    actionType: 'command_exec',
    operation: 'exec',
    toolName: 'bash',
    arguments: {
      command: 'echo hello'
    },
    ...overrides
  };
}

function makeCtx(): EngineContext {
  const store = new MemoryStore();

  return {
    sessionId: 'session-provider',
    policy: { version: '0.1.0' },
    sessionStore: store,
    artifactStore: store,
    startedAt: 0,
    session: null,
    relatedArtifacts: {}
  };
}

function createEngine(options: {
  policy?: Record<string, unknown>;
  decisionProvider?: DecisionProvider;
  approvalProvider?: InProcessApprovalProvider;
  store?: MemoryStore;
  onError?: 'BLOCK' | 'ALLOW';
  onUnhandledReview?: 'BLOCK' | 'ALLOW';
}) {
  const store = options.store ?? new MemoryStore();
  return new MosheEngine({
    policy: new StaticPolicyProvider({
      version: '0.1.0',
      ...(options.policy ?? {})
    }),
    sessionStore: store,
    artifactStore: store,
    ...(options.decisionProvider ? { decisionProvider: options.decisionProvider } : {}),
    ...(options.approvalProvider ? { approvalProvider: options.approvalProvider } : {}),
    onError: options.onError ?? 'BLOCK',
    onUnhandledReview: options.onUnhandledReview ?? 'BLOCK'
  });
}

function mockResponse(init: {
  ok: boolean;
  status: number;
  statusText?: string;
  body: unknown;
}): Response {
  return {
    ok: init.ok,
    status: init.status,
    statusText: init.statusText ?? '',
    json: async () => init.body
  } as Response;
}

const originalFetch = globalThis.fetch;
const originalWarn = console.warn;

afterEach(() => {
  globalThis.fetch = originalFetch;
  console.warn = originalWarn;
});

describe('NoopDecisionProvider', () => {
  it('evaluate always returns null', async () => {
    const provider = new NoopDecisionProvider();
    const result = await provider.evaluate(actionFixture(), makeCtx());
    expect(result).toBeNull();
  });

  it('name is noop', () => {
    expect(new NoopDecisionProvider().name).toBe('noop');
  });
});

describe('CallbackDecisionProvider', () => {
  it('forwards envelope and ctx to callback and returns callback result', async () => {
    const ctx = makeCtx();
    const envelope = actionFixture();
    const expected: StageResult = {
      stage: 'decision_provider',
      passed: false,
      decision: 'REVIEW',
      reasonCodes: [ReasonCode.COMMAND_INTENT_SUSPICIOUS]
    };
    const callback = vi.fn(async (receivedEnvelope: ActionEnvelope, receivedCtx: EngineContext) => {
      expect(receivedEnvelope).toBe(envelope);
      expect(receivedCtx).toBe(ctx);
      return expected;
    });

    const provider = new CallbackDecisionProvider({ callback });
    const result = await provider.evaluate(envelope, ctx);

    expect(callback).toHaveBeenCalledOnce();
    expect(result).toEqual(expected);
  });

  it('returns null when callback returns null', async () => {
    const provider = new CallbackDecisionProvider({
      callback: async () => null
    });

    expect(await provider.evaluate(actionFixture(), makeCtx())).toBeNull();
  });

  it('uses callback as the default name', () => {
    expect(new CallbackDecisionProvider({
      callback: async () => null
    }).name).toBe('callback');
  });

  it('respects a custom name', () => {
    expect(new CallbackDecisionProvider({
      name: 'semantic-check',
      callback: async () => null
    }).name).toBe('semantic-check');
  });

  it('propagates callback errors', async () => {
    const provider = new CallbackDecisionProvider({
      callback: async () => {
        throw new Error('callback exploded');
      }
    });

    await expect(provider.evaluate(actionFixture(), makeCtx())).rejects.toThrow('callback exploded');
  });
});

describe('HttpDecisionProvider', () => {
  beforeEach(() => {
    console.warn = vi.fn();
  });

  it('returns null on network error by default', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error('network down');
    }) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    await expect(provider.evaluate(actionFixture(), makeCtx())).resolves.toBeNull();
  });

  it('throws on network error when onError is throw', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error('network down');
    }) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({
      url: 'https://example.test/review',
      onError: 'throw'
    });

    await expect(provider.evaluate(actionFixture(), makeCtx())).rejects.toThrow('network down');
  });

  it('returns null on non-2xx response by default', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      body: {}
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    await expect(provider.evaluate(actionFixture(), makeCtx())).resolves.toBeNull();
  });

  it('throws on non-2xx response when onError is throw', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      body: {}
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({
      url: 'https://example.test/review',
      onError: 'throw'
    });

    await expect(provider.evaluate(actionFixture(), makeCtx())).rejects.toThrow('HTTP 500 Internal Server Error');
  });

  it('returns null when response body is missing passed', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: { decision: 'ALLOW' }
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    await expect(provider.evaluate(actionFixture(), makeCtx())).resolves.toBeNull();
  });

  it('returns null when response body is not an object', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: 'not-an-object'
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    await expect(provider.evaluate(actionFixture(), makeCtx())).resolves.toBeNull();
  });

  it('correctly parses a full response', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: {
        passed: false,
        decision: 'REVIEW',
        reasonCodes: [ReasonCode.COMMAND_INTENT_SUSPICIOUS],
        summary: 'flagged',
        matchedRules: [
          {
            ruleId: 'semantic-1',
            ruleType: 'semantic',
            matchedValue: 'curl http://host'
          }
        ]
      }
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    const result = await provider.evaluate(actionFixture(), makeCtx());

    expect(result).toEqual({
      stage: 'decision_provider',
      passed: false,
      decision: 'REVIEW',
      reasonCodes: [ReasonCode.COMMAND_INTENT_SUSPICIOUS],
      matchedRules: [
        {
          ruleId: 'semantic-1',
          ruleType: 'semantic',
          matchedValue: 'curl http://host'
        }
      ],
      enrichments: { summary: 'flagged' }
    });
  });

  it('correctly parses a minimal response', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: { passed: true }
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    const result = await provider.evaluate(actionFixture(), makeCtx());

    expect(result).toEqual({
      stage: 'decision_provider',
      passed: true
    });
  });

  it('filters invalid reason codes from the response', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: {
        passed: false,
        reasonCodes: ['NOT_A_REASON', ReasonCode.OUTBOUND_BLOCKED]
      }
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    const result = await provider.evaluate(actionFixture(), makeCtx());

    expect(result?.reasonCodes).toEqual([ReasonCode.OUTBOUND_BLOCKED]);
  });

  it('drops malformed matchedRules entries', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: {
        passed: false,
        matchedRules: [
          { ruleId: 'valid', ruleType: 'semantic', matchedValue: 'value' },
          { ruleId: 'bad', matchedValue: 'missing-rule-type' }
        ]
      }
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    const result = await provider.evaluate(actionFixture(), makeCtx());

    expect(result?.matchedRules).toEqual([
      { ruleId: 'valid', ruleType: 'semantic', matchedValue: 'value' }
    ]);
  });

  it('sends correct headers including custom Authorization header', async () => {
    const fetchMock = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: { passed: true }
    }));
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({
      url: 'https://example.test/review',
      headers: { Authorization: 'Bearer token' }
    });

    await provider.evaluate(actionFixture(), makeCtx());

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(options.headers).toEqual({
      'Content-Type': 'application/json',
      Authorization: 'Bearer token'
    });
  });

  it('uses http as default name and respects custom name', () => {
    expect(new HttpDecisionProvider({ url: 'https://example.test/review' }).name).toBe('http');
    expect(new HttpDecisionProvider({
      url: 'https://example.test/review',
      name: 'semantic-http'
    }).name).toBe('semantic-http');
  });

  it('sends request body with envelope and sessionId', async () => {
    const fetchMock = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: { passed: true }
    }));
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    const envelope = actionFixture();
    await provider.evaluate(envelope, makeCtx());

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(options.body))).toEqual({
      envelope,
      sessionId: envelope.sessionId
    });
  });

  it('strips sensitive argument fields from the POST body', async () => {
    const fetchMock = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: { passed: true }
    }));
    globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    const envelope = actionFixture({
      arguments: {
        command: 'echo hello',
        content: 'secret body',
        body: 'message body',
        headers: { Authorization: 'Bearer token' },
        params: { secret: 'value' }
      }
    });
    await provider.evaluate(envelope, makeCtx());

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(options.body))).toEqual({
      envelope: {
        ...envelope,
        arguments: {
          command: 'echo hello'
        }
      },
      sessionId: envelope.sessionId
    });
  });

  it('warns once when configured with a non-HTTPS URL', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    new HttpDecisionProvider({ url: 'http://example.test/review' });
    expect(warn).toHaveBeenCalledOnce();
  });

  it('always returns decision_provider as the stage', async () => {
    globalThis.fetch = vi.fn(async () => mockResponse({
      ok: true,
      status: 200,
      body: {
        passed: false,
        decision: 'BLOCK',
        reasonCodes: [ReasonCode.FORBIDDEN_COMMAND]
      }
    })) as unknown as typeof globalThis.fetch;

    const provider = new HttpDecisionProvider({ url: 'https://example.test/review' });
    const result = await provider.evaluate(actionFixture(), makeCtx());

    expect(result?.stage).toBe('decision_provider');
  });
});

describe('decision provider integration through engine', () => {
  it('callback provider returning null behaves like no provider configured', async () => {
    const action = actionFixture();
    const withoutProvider = await createEngine({}).evaluate(action);
    const withNullProvider = await createEngine({
      decisionProvider: new CallbackDecisionProvider({
        callback: async () => null
      })
    }).evaluate(action);

    expect(withNullProvider.decision).toBe(withoutProvider.decision);
    expect(withNullProvider.reasonCodes).toEqual(withoutProvider.reasonCodes);
  });

  it('callback provider returning REVIEW contributes to the final review decision', async () => {
    const store = new MemoryStore();
    const decision = await createEngine({
      store,
      approvalProvider: new InProcessApprovalProvider({ store }),
      decisionProvider: new CallbackDecisionProvider({
        callback: async () => ({
          stage: 'decision_provider',
          passed: false,
          decision: 'REVIEW',
          reasonCodes: [ReasonCode.COMMAND_INTENT_SUSPICIOUS]
        })
      })
    }).evaluate(actionFixture());

    expect(decision.decision).toBe('REVIEW');
    expect(decision.reasonCodes).toContain(ReasonCode.COMMAND_INTENT_SUSPICIOUS);
  });

  it('callback provider returning BLOCK contributes to the final block decision', async () => {
    const decision = await createEngine({
      decisionProvider: new CallbackDecisionProvider({
        callback: async () => ({
          stage: 'decision_provider',
          passed: false,
          decision: 'BLOCK',
          reasonCodes: [ReasonCode.FORBIDDEN_COMMAND]
        })
      })
    }).evaluate(actionFixture());

    expect(decision.decision).toBe('BLOCK');
    expect(decision.reasonCodes).toContain(ReasonCode.FORBIDDEN_COMMAND);
  });

  it('noop provider behaves like no decision provider at all', async () => {
    const action = actionFixture();
    const withoutProvider = await createEngine({}).evaluate(action);
    const withNoop = await createEngine({
      decisionProvider: new NoopDecisionProvider()
    }).evaluate(action);

    expect(withNoop.decision).toBe(withoutProvider.decision);
    expect(withNoop.reasonCodes).toEqual(withoutProvider.reasonCodes);
  });

  it('thrown callback bubbles to engine catch and results in configured onError', async () => {
    const decision = await createEngine({
      decisionProvider: new CallbackDecisionProvider({
        callback: async () => {
          throw new Error('semantic provider failed');
        }
      }),
      onError: 'BLOCK'
    }).evaluate(actionFixture());

    expect(decision.decision).toBe('BLOCK');
    expect(decision.reasonCodes).toContain(ReasonCode.ENGINE_ERROR);
  });
});
