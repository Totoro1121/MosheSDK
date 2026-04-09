import { randomUUID } from 'node:crypto';

import type { TelemetryEvent, TelemetryEventType } from '@moshesdk/spec';

import type { TelemetrySink } from './interfaces.js';

export class MemoryTelemetrySink implements TelemetrySink {
  public readonly name = 'memory';
  private readonly events: TelemetryEvent[] = [];

  public async emit(event: TelemetryEvent): Promise<void> {
    this.events.push(event);
  }

  public getEvents(): readonly TelemetryEvent[] {
    return this.events;
  }

  public getEventsByType(eventType: TelemetryEventType): readonly TelemetryEvent[] {
    return this.events.filter((event) => event.eventType === eventType);
  }

  public getEventsForAction(actionId: string): readonly TelemetryEvent[] {
    return this.events.filter((event) => event.actionId === actionId);
  }

  public getDecisionEvent(actionId: string): TelemetryEvent | undefined {
    return this.events
      .filter((event) => event.actionId === actionId && event.eventType === 'DECISION_MADE')
      .at(-1);
  }

  public clear(): void {
    this.events.length = 0;
  }
}

export class ScrubbingTelemetrySink implements TelemetrySink {
  public readonly name: string;

  public constructor(private readonly inner: TelemetrySink) {
    this.name = `scrubbing(${inner.name})`;
  }

  public async emit(event: TelemetryEvent): Promise<void> {
    const { debug: _debug, ...scrubbed } = event;
    await this.inner.emit(scrubbed as TelemetryEvent);
  }
}

export interface FeedbackSubmission {
  actionId: string;
  sessionId: string;
  verdict: 'FALSE_POSITIVE' | 'FALSE_NEGATIVE' | 'CORRECT';
  expectedDecision?: 'ALLOW' | 'BLOCK' | 'REVIEW';
  note?: string;
}

export class FeedbackEmitter {
  public constructor(private readonly sinks: TelemetrySink[]) {}

  public async submit(feedback: FeedbackSubmission): Promise<void> {
    const event: TelemetryEvent = {
      eventId: randomUUID(),
      eventType: 'FEEDBACK',
      actionId: feedback.actionId,
      sessionId: feedback.sessionId,
      debug: {
        verdict: feedback.verdict,
        ...(feedback.expectedDecision !== undefined ? { expectedDecision: feedback.expectedDecision } : {}),
        ...(feedback.note !== undefined ? { note: feedback.note } : {})
      }
    };

    for (const sink of this.sinks) {
      await sink.emit(event);
    }
  }
}
