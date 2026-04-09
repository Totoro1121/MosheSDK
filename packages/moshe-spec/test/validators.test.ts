import { describe, expect, it } from 'vitest';

import {
  SPEC_VERSION,
  ReasonCode,
  validateActionEnvelope,
  validateDecisionEnvelope,
  validatePolicyConfig
} from '@moshesdk/spec';
import type { ActionEnvelope, PolicyConfig } from '@moshesdk/spec';

import { loadFixture } from '../../../test/fixtures.js';

describe('moshe-spec validators', () => {
  it('validates every action fixture', async () => {
    const files = [
      'actions/allow-simple-command.json',
      'actions/block-forbidden-command.json',
      'actions/block-sensitive-file-read.json',
      'actions/review-sensitive-file.json',
      'actions/review-sensitive-env.json',
      'actions/block-outbound-rule.json',
      'actions/block-recipient-threshold.json',
      'actions/outbound-post-request.json',
      'actions/file-write-agent-generated.json'
    ] as const;

    for (const file of files) {
      const fixture = await loadFixture<ActionEnvelope>(file);
      const result = validateActionEnvelope(fixture);
      expect(result.ok, file).toBe(true);
    }
  });

  it('validates every policy fixture', async () => {
    const files = [
      'policies/empty.json',
      'policies/coding-agent-minimal.json',
      'policies/with-sensitive-and-outbound.json'
    ] as const;

    for (const file of files) {
      const fixture = await loadFixture<PolicyConfig>(file);
      const result = validatePolicyConfig(fixture);
      expect(result.ok, file).toBe(true);
    }
  });

  it('treats empty policy as valid', async () => {
    const fixture = await loadFixture<PolicyConfig>('policies/empty.json');
    const result = validatePolicyConfig(fixture);
    expect(result.ok).toBe(true);
  });

  it('rejects missing required action fields', () => {
    const result = validateActionEnvelope({
      sessionId: 'missing-required'
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });

  it('accepts optional action fields without changing the core schema contract', () => {
    const action: ActionEnvelope = {
      actionId: '66666666-6666-6666-6666-666666666666',
      sessionId: 'fixture-session',
      timestamp: '2026-04-01T00:00:06.000Z',
      framework: 'generic',
      actionType: 'tool_call',
      operation: 'call',
      toolName: 'search',
      arguments: {
        params: {
          limit: 5,
          enabled: true
        }
      },
      agentId: 'agent-1',
      metadata: {
        futureOptionalField: 'kept opaque'
      }
    };

    expect(validateActionEnvelope(action).ok).toBe(true);
  });

  it('validates canonical decision fixtures', async () => {
    const allowDecision = await loadFixture('decisions/allow.json');
    const blockDecision = await loadFixture('decisions/block.json');

    expect(validateDecisionEnvelope(allowDecision).ok).toBe(true);
    expect(validateDecisionEnvelope(blockDecision).ok).toBe(true);
  });

  it('exports stable foundation spec constants', () => {
    expect(SPEC_VERSION).toBe('0.1.0');
    expect(ReasonCode.FORBIDDEN_COMMAND).toBe('FORBIDDEN_COMMAND');
  });
});
