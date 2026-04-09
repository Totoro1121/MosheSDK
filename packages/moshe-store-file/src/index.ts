import { dirname, resolve } from 'node:path';
import { promises as fs } from 'node:fs';

import type {
  ApprovalReplayEntry,
  ArtifactRecord,
  ArtifactStore,
  SessionPutOptions,
  SessionState,
  SessionStore
} from '@moshesdk/core';

interface FileStoreData {
  sessions: Record<string, SessionState>;
  approvals: Record<string, ApprovalReplayEntry>;
  artifacts: Record<string, ArtifactRecord>;
}

export interface FileStoreOptions {
  path: string;
}

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

export class FileStore implements SessionStore, ArtifactStore {
  private readonly filePath: string;
  private state: FileStoreData = {
    sessions: {},
    approvals: {},
    artifacts: {}
  };
  private readonly initPromise: Promise<void>;
  private writeChain: Promise<void> = Promise.resolve();

  public constructor(options: FileStoreOptions | string) {
    this.filePath = resolve(typeof options === 'string' ? options : options.path);
    this.initPromise = this.initialize();
  }

  public async getSession(sessionId: string): Promise<SessionState | null> {
    await this.initPromise;
    const session = this.state.sessions[sessionId];
    return session ? clone(session) : null;
  }

  public async putSession(sessionId: string, state: SessionState, options?: SessionPutOptions): Promise<void> {
    await this.initPromise;
    this.state.sessions[sessionId] = mergeSession(this.state.sessions[sessionId], state, options);
    await this.enqueueWrite();
  }

  public async getApprovalReplay(approvalId: string): Promise<ApprovalReplayEntry | null> {
    await this.initPromise;
    const replay = this.state.approvals[approvalId];
    return replay ? clone(replay) : null;
  }

  public async putApprovalReplay(entry: ApprovalReplayEntry): Promise<void> {
    await this.initPromise;
    this.state.approvals[entry.approvalId] = clone(entry);
    await this.enqueueWrite();
  }

  public async getArtifact(path: string): Promise<ArtifactRecord | null> {
    await this.initPromise;
    const artifact = this.state.artifacts[path];
    return artifact ? clone(artifact) : null;
  }

  public async putArtifact(path: string, record: ArtifactRecord): Promise<void> {
    await this.initPromise;
    this.state.artifacts[path] = clone({ ...record, path });
    await this.enqueueWrite();
  }

  public async listArtifacts(prefix?: string): Promise<string[]> {
    await this.initPromise;
    const keys = Object.keys(this.state.artifacts);
    if (!prefix) {
      return keys;
    }

    return keys.filter((key) => key.startsWith(prefix));
  }

  public async close(): Promise<void> {
    await this.initPromise;
    await this.writeChain;
  }

  private async initialize(): Promise<void> {
    await fs.mkdir(dirname(this.filePath), { recursive: true });

    try {
      const contents = await fs.readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(contents) as Partial<FileStoreData>;
      this.state = {
        sessions: parsed.sessions ?? {},
        approvals: parsed.approvals ?? {},
        artifacts: parsed.artifacts ?? {}
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }

      await this.persist();
    }
  }

  private async enqueueWrite(): Promise<void> {
    this.writeChain = this.writeChain.then(() => this.persist());
    await this.writeChain;
  }

  private async persist(): Promise<void> {
    const tmpPath = `${this.filePath}.tmp`;
    const data = JSON.stringify(this.state, null, 2);
    await fs.writeFile(tmpPath, data, 'utf8');
    await fs.rename(tmpPath, this.filePath);
  }
}
