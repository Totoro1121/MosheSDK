export interface SessionState {
  sessionId: string;
  createdAt: string;
  updatedAt: string;
  messageCount: number;
  taintSources: string[];
  whitelistedScripts: Record<string, string>;
  suspectUntil?: string;
  riskLevel?: 'NORMAL' | 'ELEVATED' | 'HIGH';
  reviewCount?: number;
  blockCount?: number;
  sensitiveReadCount?: number;
}

export interface ArtifactRecord {
  path: string;
  classification: 'SENSITIVE' | 'FORBIDDEN' | 'AGENT_GENERATED' | 'TAINTED' | 'CLEAN';
  source: string;
  reason: string;
  firstSeen: string;
  lastSeen: string;
  provenanceChain?: string[];
}

export interface ApprovalReplayEntry {
  approvalId: string;
  sessionId: string;
  resolvedDecision: 'ALLOW_ONCE' | 'ALLOW_SESSION' | 'BLOCK';
  resolvedAt: string;
  path?: string;
  hash?: string;
  expiresAt: string;
}

export interface SessionPutOptions {
  replace?: boolean;
}
