import { randomUUID } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import type { TelemetryEvent } from '@moshesdk/spec';
import { MemoryStore, Moshe } from '@moshesdk/sdk';

import type { FeedbackSubmission } from '../src/telemetry.js';
import { FeedbackEmitter, MemoryTelemetrySink, ScrubbingTelemetrySink } from '../src/telemetry.js';

function event(overrides: Partial<TelemetryEvent> = {}): TelemetryEvent {
  return {
    eventId: randomUUID(),
    eventType: 'ACTION_RECEIVED',
    actionId: 'action-1',
    sessionId: 'session-1',
    ...overrides
  };
}

describe('MemoryTelemetrySink', () => {
  it('emit() stores events and getEvents() returns them', async () => {
    const sink = new MemoryTelemetrySink();

    await sink.emit(event({ eventType: 'ACTION_RECEIVED' }));
    await sink.emit(event({ eventType: 'DECISION_MADE' }));

    expect(sink.getEvents()).toHaveLength(2);
  });

  it('getEventsByType() filters by eventType', async () => {
    const sink = new MemoryTelemetrySink();

    await sink.emit(event({ eventType: 'ACTION_RECEIVED' }));
    await sink.emit(event({ eventType: 'DECISION_MADE' }));

    const decisionEvents = sink.getEventsByType('DECISION_MADE');
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]?.eventType).toBe('DECISION_MADE');
  });

  it('getEventsForAction() filters by actionId', async () => {
    const sink = new MemoryTelemetrySink();

    await sink.emit(event({ actionId: 'action-1' }));
    await sink.emit(event({ actionId: 'action-2' }));

    expect(sink.getEventsForAction('action-1')).toHaveLength(1);
    expect(sink.getEventsForAction('action-1')[0]?.actionId).toBe('action-1');
  });

  it('getDecisionEvent() returns the most recent DECISION_MADE for the actionId', async () => {
    const sink = new MemoryTelemetrySink();
    const first = event({ eventType: 'DECISION_MADE', actionId: 'action-1', eventId: 'first' });
    const second = event({ eventType: 'DECISION_MADE', actionId: 'action-1', eventId: 'second' });

    await sink.emit(first);
    await sink.emit(second);

    expect(sink.getDecisionEvent('action-1')?.eventId).toBe('second');
  });

  it('getDecisionEvent() returns undefined when no matching event', () => {
    const sink = new MemoryTelemetrySink();

    expect(sink.getDecisionEvent('unknown-id')).toBeUndefined();
  });

  it('clear() removes all events', async () => {
    const sink = new MemoryTelemetrySink();

    await sink.emit(event());
    sink.clear();

    expect(sink.getEvents()).toHaveLength(0);
  });

  it('emitted events survive across multiple emit() calls in insertion order', async () => {
    const sink = new MemoryTelemetrySink();
    const a = event({ eventId: 'a' });
    const b = event({ eventId: 'b' });
    const c = event({ eventId: 'c' });

    await sink.emit(a);
    await sink.emit(b);
    await sink.emit(c);

    expect(sink.getEvents()[0]?.eventId).toBe('a');
    expect(sink.getEvents()[1]?.eventId).toBe('b');
    expect(sink.getEvents()[2]?.eventId).toBe('c');
  });
});

describe('FeedbackEmitter', () => {
  it('submit() emits a FEEDBACK event to all sinks', async () => {
    const sink1 = new MemoryTelemetrySink();
    const sink2 = new MemoryTelemetrySink();
    const emitter = new FeedbackEmitter([sink1, sink2]);

    await emitter.submit({
      actionId: 'a1',
      sessionId: 's1',
      verdict: 'CORRECT'
    });

    expect(sink1.getEventsByType('FEEDBACK')).toHaveLength(1);
    expect(sink2.getEventsByType('FEEDBACK')).toHaveLength(1);
  });

  it('FEEDBACK event carries the verdict in debug', async () => {
    const sink = new MemoryTelemetrySink();
    const emitter = new FeedbackEmitter([sink]);

    await emitter.submit({
      actionId: 'a1',
      sessionId: 's1',
      verdict: 'FALSE_POSITIVE'
    });

    expect(sink.getEventsByType('FEEDBACK')[0]?.debug?.verdict).toBe('FALSE_POSITIVE');
  });

  it('FEEDBACK event carries expectedDecision when provided', async () => {
    const sink = new MemoryTelemetrySink();
    const emitter = new FeedbackEmitter([sink]);

    await emitter.submit({
      actionId: 'a1',
      sessionId: 's1',
      verdict: 'FALSE_POSITIVE',
      expectedDecision: 'ALLOW'
    });

    expect(sink.getEventsByType('FEEDBACK')[0]?.debug?.expectedDecision).toBe('ALLOW');
  });

  it('FEEDBACK event carries note when provided', async () => {
    const sink = new MemoryTelemetrySink();
    const emitter = new FeedbackEmitter([sink]);

    await emitter.submit({
      actionId: 'a1',
      sessionId: 's1',
      verdict: 'FALSE_POSITIVE',
      note: 'this was a safe command'
    });

    expect(sink.getEventsByType('FEEDBACK')[0]?.debug?.note).toBe('this was a safe command');
  });

  it('submit() with no sinks is a no-op and does not throw', async () => {
    const emitter = new FeedbackEmitter([]);

    await expect(emitter.submit({
      actionId: 'a1',
      sessionId: 's1',
      verdict: 'CORRECT'
    })).resolves.toBeUndefined();
  });

  it('FEEDBACK event has unique eventId', async () => {
    const sink = new MemoryTelemetrySink();
    const emitter = new FeedbackEmitter([sink]);

    await emitter.submit({
      actionId: 'a1',
      sessionId: 's1',
      verdict: 'CORRECT'
    });
    await emitter.submit({
      actionId: 'a1',
      sessionId: 's1',
      verdict: 'FALSE_NEGATIVE'
    });

    const events = sink.getEventsByType('FEEDBACK');
    expect(events[0]?.eventId).not.toBe(events[1]?.eventId);
  });
});

describe('ScrubbingTelemetrySink', () => {
  it('removes debug before forwarding', async () => {
    const inner = new MemoryTelemetrySink();
    const sink = new ScrubbingTelemetrySink(inner);

    await sink.emit(event({
      eventType: 'DECISION_MADE',
      debug: { secret: 'value' }
    }));

    expect(inner.getEvents()[0]?.debug).toBeUndefined();
  });
});

describe('integration - MemoryTelemetrySink with Moshe engine', () => {
  it('engine emits ACTION_RECEIVED and DECISION_MADE for each evaluation', async () => {
    const sink = new MemoryTelemetrySink();
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      telemetrySinks: [sink],
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    await moshe.evaluate({
      actionId: 'telemetry-action-1',
      sessionId: 'telemetry-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'echo hello' }
    });

    expect(sink.getEventsByType('ACTION_RECEIVED')).toHaveLength(1);
    expect(sink.getEventsByType('DECISION_MADE')).toHaveLength(1);
    await moshe.close();
  });

  it('DECISION_MADE event carries correct decision and reasonCodes', async () => {
    const sink = new MemoryTelemetrySink();
    const moshe = new Moshe({
      policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf'] },
      store: new MemoryStore(),
      telemetrySinks: [sink],
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    await moshe.evaluate({
      actionId: 'telemetry-action-block',
      sessionId: 'telemetry-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'rm -rf /' }
    });

    const decisionEvent = sink.getDecisionEvent('telemetry-action-block');
    expect(decisionEvent?.decision).toBe('BLOCK');
    expect(decisionEvent?.reasonCodes).toContain('FORBIDDEN_COMMAND');
    await moshe.close();
  });

  it('engine emits STAGE_COMPLETE events for each pipeline stage', async () => {
    const sink = new MemoryTelemetrySink();
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      telemetrySinks: [sink],
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    await moshe.evaluate({
      actionId: 'telemetry-action-stages',
      sessionId: 'telemetry-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'echo hello' }
    });

    expect(sink.getEventsByType('STAGE_COMPLETE').length).toBeGreaterThanOrEqual(3);
    await moshe.close();
  });

  it('multiple evaluations accumulate events; clear() resets', async () => {
    const sink = new MemoryTelemetrySink();
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      telemetrySinks: [sink],
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    await moshe.evaluate({
      actionId: 'telemetry-action-a',
      sessionId: 'telemetry-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'echo a' }
    });
    await moshe.evaluate({
      actionId: 'telemetry-action-b',
      sessionId: 'telemetry-session',
      framework: 'test',
      actionType: 'command_exec',
      operation: 'exec',
      toolName: 'shell',
      arguments: { command: 'echo b' }
    });

    expect(sink.getEvents().length).toBeGreaterThan(2);
    sink.clear();
    expect(sink.getEvents()).toHaveLength(0);
    await moshe.close();
  });

  it('Moshe.feedback.submit() routes to the same sink', async () => {
    const sink = new MemoryTelemetrySink();
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      telemetrySinks: [sink],
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    await moshe.feedback.submit({
      actionId: 'feedback-action',
      sessionId: 'feedback-session',
      verdict: 'CORRECT'
    });

    expect(sink.getEventsByType('FEEDBACK')).toHaveLength(1);
    await moshe.close();
  });

  it('Moshe.feedback is always defined even with no sinks configured', async () => {
    const moshe = new Moshe({
      policy: { version: '0.1.0' },
      store: new MemoryStore(),
      onError: 'BLOCK',
      onUnhandledReview: 'BLOCK'
    });

    expect(moshe.feedback).toBeDefined();
    await expect(moshe.feedback.submit({
      actionId: 'feedback-no-sinks',
      sessionId: 'feedback-session',
      verdict: 'CORRECT'
    } satisfies FeedbackSubmission)).resolves.toBeUndefined();
    await moshe.close();
  });
});
