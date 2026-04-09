import type {
  ApprovalReplayEntry,
  ArtifactRecord,
  ArtifactStore,
  SessionPutOptions,
  SessionState,
  SessionStore
} from '@moshesdk/core';

function clone<T>(value: T): T {
  return structuredClone(value);
}

function mergeSession(existing: SessionState | undefined, incoming: SessionState, options?: SessionPutOptions): SessionState {
  if (!existing || options?.replace) {
    return clone(incoming);
  }

  return {
    ...existing,
    ...incoming,
    taintSources: [...new Set([...existing.taintSources, ...incoming.taintSources])],
    whitelistedScripts: {
      ...existing.whitelistedScripts,
      ...incoming.whitelistedScripts
    }
  };
}

export class MemoryStore implements SessionStore, ArtifactStore {
  private readonly sessions = new Map<string, SessionState>();
  private readonly approvals = new Map<string, ApprovalReplayEntry>();
  private readonly artifacts = new Map<string, ArtifactRecord>();

  public async getSession(sessionId: string): Promise<SessionState | null> {
    const session = this.sessions.get(sessionId);
    return session ? clone(session) : null;
  }

  public async putSession(sessionId: string, state: SessionState, options?: SessionPutOptions): Promise<void> {
    const merged = mergeSession(this.sessions.get(sessionId), state, options);
    this.sessions.set(sessionId, merged);
  }

  public async getApprovalReplay(approvalId: string): Promise<ApprovalReplayEntry | null> {
    const replay = this.approvals.get(approvalId);
    return replay ? clone(replay) : null;
  }

  public async putApprovalReplay(entry: ApprovalReplayEntry): Promise<void> {
    this.approvals.set(entry.approvalId, clone(entry));
  }

  public async getArtifact(path: string): Promise<ArtifactRecord | null> {
    const artifact = this.artifacts.get(path);
    return artifact ? clone(artifact) : null;
  }

  public async putArtifact(path: string, record: ArtifactRecord): Promise<void> {
    this.artifacts.set(path, clone({ ...record, path }));
  }

  public async listArtifacts(prefix?: string): Promise<string[]> {
    const keys = [...this.artifacts.keys()];
    if (!prefix) {
      return keys;
    }

    return keys.filter((key) => key.startsWith(prefix));
  }

  public reset(): void {
    this.sessions.clear();
    this.approvals.clear();
    this.artifacts.clear();
  }
}
