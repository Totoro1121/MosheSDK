import type { ActionEnvelope } from '@moshe/spec';

export type EvaluateInput = Omit<ActionEnvelope, 'actionId' | 'timestamp'>
  & Partial<Pick<ActionEnvelope, 'actionId' | 'timestamp'>>;

export * from './state.js';
export * from './interfaces.js';
export * from './policy.js';
export * from './engine.js';
export * from './policy-file-provider.js';
export * from './approval-provider.js';
export * from './intent-analyzers.js';
export * from './taint-engine.js';
export * from './outbound-utils.js';
export * from './policy-presets.js';
export * from './telemetry.js';
export * from './chain-risk.js';
export * from './decision-provider.js';
export * from './lineage.js';
