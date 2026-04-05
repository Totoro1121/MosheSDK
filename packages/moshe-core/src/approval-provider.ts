import { createHash, randomUUID } from 'node:crypto';

import type { ActionEnvelope, ApprovalRequest } from '@moshe/spec';

import type { ApprovalProvider, ArtifactStore, EngineContext, SessionStore } from './interfaces.js';

export type ApprovalResolution = 'ALLOW_ONCE' | 'ALLOW_SESSION' | 'BLOCK';

export interface PendingApproval {
  approvalId: string;
  fingerprint: string;
  sessionId: string;
  createdAt: string;
  expiresAt: string;
  resolution?: ApprovalResolution;
}

export interface ApprovalContext {
  request: ApprovalRequest;
  envelope: ActionEnvelope;
  sessionId: string;
}

export interface InProcessApprovalProviderOptions {
  store: SessionStore & ArtifactStore;
  ttlMs?: number;
  onApprovalRequired?: (context: ApprovalContext) => void | Promise<void>;
}

function stableSortedArgs(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => stableSortedArgs(entry));
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, stableSortedArgs(entry)])
    );
  }

  return value;
}

function isExpired(expiresAt: string): boolean {
  return Date.parse(expiresAt) <= Date.now();
}

function computeFingerprint(envelope: ActionEnvelope, sessionId: string): string {
  const stable = JSON.stringify({
    s: sessionId,
    a: envelope.actionType,
    t: envelope.toolName,
    g: stableSortedArgs(envelope.arguments)
  });

  return createHash('sha256').update(stable).digest('hex').slice(0, 32);
}

export class InProcessApprovalProvider implements ApprovalProvider {
  private readonly ttlMs: number;
  private readonly onApprovalRequired: ((context: ApprovalContext) => void | Promise<void>) | undefined;
  private readonly pendingById = new Map<string, PendingApproval>();
  private readonly pendingByFingerprint = new Map<string, string>();

  public constructor(private readonly options: InProcessApprovalProviderOptions) {
    this.ttlMs = options.ttlMs ?? 300_000;
    this.onApprovalRequired = options.onApprovalRequired;
  }

  public async create(envelope: ActionEnvelope, ctx: EngineContext): Promise<ApprovalRequest | null> {
    this.cleanupExpired();

    const fingerprint = computeFingerprint(envelope, ctx.sessionId);
    const replay = await ctx.sessionStore.getApprovalReplay(fingerprint);
    if (replay && replay.sessionId === ctx.sessionId && replay.resolvedDecision === 'ALLOW_SESSION' && !isExpired(replay.expiresAt)) {
      return null;
    }

    const existingId = this.pendingByFingerprint.get(fingerprint);
    if (existingId) {
      const existing = this.pendingById.get(existingId);
      if (existing?.resolution === 'ALLOW_ONCE') {
        this.pendingById.delete(existingId);
        this.pendingByFingerprint.delete(fingerprint);
        return null;
      }
    }

    const previousId = this.pendingByFingerprint.get(fingerprint);
    if (previousId) {
      const previous = this.pendingById.get(previousId);
      if (previous?.resolution === 'BLOCK') {
        this.pendingById.delete(previousId);
      }
    }

    const now = new Date().toISOString();
    const request: ApprovalRequest = {
      approvalId: randomUUID(),
      expiresAt: new Date(Date.now() + this.ttlMs).toISOString()
    };

    const pending: PendingApproval = {
      approvalId: request.approvalId,
      fingerprint,
      sessionId: ctx.sessionId,
      createdAt: now,
      expiresAt: request.expiresAt
    };

    this.pendingById.set(request.approvalId, pending);
    this.pendingByFingerprint.set(fingerprint, request.approvalId);

    if (this.onApprovalRequired) {
      const callbackContext: ApprovalContext = {
        request: structuredClone(request),
        envelope: structuredClone(envelope),
        sessionId: ctx.sessionId
      };

      void Promise.resolve(this.onApprovalRequired(callbackContext)).catch(() => undefined);
    }

    return request;
  }

  public async resolve(approvalId: string, decision: ApprovalResolution): Promise<void> {
    this.cleanupExpired();

    const pending = this.pendingById.get(approvalId);
    if (!pending || isExpired(pending.expiresAt)) {
      throw new Error(`Unknown or expired approvalId: "${approvalId}"`);
    }

    pending.resolution = decision;

    if (decision === 'ALLOW_SESSION') {
      // TODO(PRD-J): revisit replay expiry policy and observability for long-lived approvals.
      await this.options.store.putApprovalReplay({
        approvalId: pending.fingerprint,
        sessionId: pending.sessionId,
        resolvedDecision: 'ALLOW_SESSION',
        resolvedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)).toISOString()
      });
    }
  }

  public async check(approvalId: string): Promise<'ALLOW_ONCE' | 'ALLOW_SESSION' | 'BLOCK' | 'PENDING'> {
    this.cleanupExpired();

    const pending = this.pendingById.get(approvalId);
    if (!pending) {
      throw new Error(`Unknown or expired approvalId: "${approvalId}"`);
    }

    return pending.resolution ?? 'PENDING';
  }

  private cleanupExpired(): void {
    for (const [approvalId, pending] of this.pendingById) {
      if (!pending.resolution && isExpired(pending.expiresAt)) {
        this.pendingById.delete(approvalId);
        this.pendingByFingerprint.delete(pending.fingerprint);
      }
    }
  }
}
