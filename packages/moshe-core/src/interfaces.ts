import type {
  ActionEnvelope,
  ApprovalRequest,
  Decision,
  DecisionEnvelope,
  MatchedRule,
  PolicyConfig,
  ReasonCode,
  TelemetryEvent
} from '@moshe/spec';

import type {
  ApprovalReplayEntry,
  ArtifactRecord,
  SessionPutOptions,
  SessionState
} from './state.js';

export interface PolicyProvider {
  load(): Promise<PolicyConfig>;
  validate(config: PolicyConfig): Promise<void>;
  getEffective(): Promise<PolicyConfig>;
}

export interface StageResult {
  stage: string;
  passed: boolean;
  decision?: Decision;
  reasonCodes?: ReasonCode[];
  matchedRules?: MatchedRule[];
  enrichments?: Partial<DecisionEnvelope>;
}

export interface Analyzer {
  name: string;
  analyze(envelope: ActionEnvelope, ctx: EngineContext): Promise<StageResult>;
}

export interface DecisionProvider {
  name: string;
  evaluate(envelope: ActionEnvelope, ctx: EngineContext): Promise<StageResult | null>;
}

export interface ApprovalProvider {
  create(envelope: ActionEnvelope, ctx: EngineContext): Promise<ApprovalRequest | null>;
  check(approvalId: string): Promise<'ALLOW_ONCE' | 'ALLOW_SESSION' | 'BLOCK' | 'PENDING'>;
  resolve?(approvalId: string, decision: 'ALLOW_ONCE' | 'ALLOW_SESSION' | 'BLOCK'): Promise<void>;
}

export interface TelemetrySink {
  name: string;
  emit(event: TelemetryEvent): Promise<void>;
}

export interface SessionStore {
  getSession(sessionId: string): Promise<SessionState | null>;
  putSession(sessionId: string, state: SessionState, options?: SessionPutOptions): Promise<void>;
  getApprovalReplay(approvalId: string): Promise<ApprovalReplayEntry | null>;
  putApprovalReplay(entry: ApprovalReplayEntry): Promise<void>;
}

export interface ArtifactStore {
  getArtifact(path: string): Promise<ArtifactRecord | null>;
  putArtifact(path: string, record: ArtifactRecord): Promise<void>;
  listArtifacts(prefix?: string): Promise<string[]>;
}

export interface EngineContext {
  sessionId: string;
  policy: PolicyConfig;
  sessionStore: SessionStore;
  artifactStore: ArtifactStore;
  startedAt: number;
  session?: SessionState | null;
  relatedArtifacts?: Record<string, ArtifactRecord | null>;
}

export interface EngineConfig {
  policy: PolicyProvider;
  sessionStore: SessionStore;
  artifactStore: ArtifactStore;
  analyzers?: Analyzer[];
  decisionProvider?: DecisionProvider;
  approvalProvider?: ApprovalProvider;
  telemetrySinks?: TelemetrySink[];
  onError: 'BLOCK' | 'ALLOW';
  onUnhandledReview: 'BLOCK' | 'ALLOW';
}
