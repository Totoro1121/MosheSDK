import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { describe, expect, it, vi } from 'vitest';

import type { PolicyConfig } from '@moshesdk/spec';

import {
  applyPresetOverlays,
  ASSISTANT_WITH_TOOLS_PRESET,
  BROWSING_AGENT_PRESET,
  CODING_AGENT_PRESET,
  FilePolicyProvider,
  PRESETS,
  PRESET_NAMES
} from '../src/index.js';

async function tempPolicyPath(fileName: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'moshe-policy-presets-'));
  return join(dir, fileName);
}

describe('preset registry', () => {
  it('PRESET_NAMES contains all three preset names', () => {
    expect(PRESET_NAMES).toContain('coding-agent');
    expect(PRESET_NAMES).toContain('assistant-with-tools');
    expect(PRESET_NAMES).toContain('browsing-agent');
  });

  it('PRESETS map contains an entry for every PRESET_NAME', () => {
    for (const name of PRESET_NAMES) {
      expect(PRESETS[name]).toBeDefined();
    }
  });

  it('each preset has a valid version field', () => {
    for (const name of PRESET_NAMES) {
      expect(typeof PRESETS[name].version).toBe('string');
    }
  });

  it('coding-agent preset includes rm -rf in forbiddenCommands', () => {
    expect(CODING_AGENT_PRESET.forbiddenCommands).toContain('rm\\s+-rf\\s+/');
  });

  it('assistant-with-tools preset includes recipientThreshold', () => {
    expect(ASSISTANT_WITH_TOOLS_PRESET.recipientThreshold?.maxRecipients).toBe(5);
  });

  it('browsing-agent preset includes block rules for known exfil hosts', () => {
    expect(BROWSING_AGENT_PRESET.outboundRules).toContainEqual({ pattern: 'pastebin.com', action: 'block' });
  });
});

describe('applyPresetOverlays', () => {
  it('returns base config unchanged when presetNames is empty', () => {
    const base: PolicyConfig = {
      version: '0.1.0',
      forbiddenTools: ['my-tool']
    };

    expect(applyPresetOverlays(base, [])).toEqual(base);
  });

  it('merges coding-agent forbiddenCommands into base', () => {
    const result = applyPresetOverlays({ version: '0.1.0' }, ['coding-agent']);

    expect(result.forbiddenCommands).toContain(CODING_AGENT_PRESET.forbiddenCommands?.[0] ?? '');
  });

  it('developer forbiddenCommands are preserved after merge', () => {
    const result = applyPresetOverlays({
      version: '0.1.0',
      forbiddenCommands: ['my-custom-pattern']
    }, ['coding-agent']);

    expect(result.forbiddenCommands).toContain('my-custom-pattern');
  });

  it('developer values are not duplicated in merged arrays', () => {
    const duplicate = CODING_AGENT_PRESET.forbiddenCommands?.[0] ?? '';
    const result = applyPresetOverlays({
      version: '0.1.0',
      forbiddenCommands: [duplicate]
    }, ['coding-agent']);

    expect(result.forbiddenCommands?.filter((entry) => entry === duplicate)).toHaveLength(1);
  });

  it('developer sensitiveFiles are union-merged with preset', () => {
    const result = applyPresetOverlays({
      version: '0.1.0',
      sensitiveFiles: ['my-secret.txt']
    }, ['coding-agent']);

    expect(result.sensitiveFiles).toContain('my-secret.txt');
    expect(result.sensitiveFiles).toContain('.env');
  });

  it('developer recipientThreshold wins over preset', () => {
    const result = applyPresetOverlays({
      version: '0.1.0',
      recipientThreshold: { maxRecipients: 10, action: 'block' }
    }, ['assistant-with-tools']);

    expect(result.recipientThreshold?.maxRecipients).toBe(10);
    expect(result.recipientThreshold?.action).toBe('block');
  });

  it('preset recipientThreshold is used when developer has none', () => {
    const result = applyPresetOverlays({ version: '0.1.0' }, ['assistant-with-tools']);

    expect(result.recipientThreshold?.maxRecipients).toBe(5);
  });

  it('developer outboundRules come before preset rules in merged array', () => {
    const result = applyPresetOverlays({
      version: '0.1.0',
      outboundRules: [{ pattern: 'my-domain.com', action: 'allow' }]
    }, ['browsing-agent']);

    expect(result.outboundRules?.[0]).toEqual({ pattern: 'my-domain.com', action: 'allow' });
  });

  it('outboundRules are deduplicated by pattern+action', () => {
    const result = applyPresetOverlays({
      version: '0.1.0',
      outboundRules: [{ pattern: 'pastebin.com', action: 'block' }]
    }, ['browsing-agent']);

    expect(result.outboundRules?.filter((rule) => rule.pattern === 'pastebin.com' && rule.action === 'block')).toHaveLength(1);
  });

  it('presetOverlays field is preserved in result', () => {
    const result = applyPresetOverlays({
      version: '0.1.0',
      presetOverlays: ['coding-agent']
    }, ['coding-agent']);

    expect(result.presetOverlays).toEqual(['coding-agent']);
  });

  it('unknown preset name is skipped with console.warn', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    const result = applyPresetOverlays({ version: '0.1.0' }, ['nonexistent-preset']);

    expect(warn).toHaveBeenCalledWith(expect.stringContaining('nonexistent-preset'));
    expect(result).toEqual({ version: '0.1.0' });
    warn.mockRestore();
  });

  it('multiple presets are applied in order', () => {
    const result = applyPresetOverlays({ version: '0.1.0' }, ['coding-agent', 'browsing-agent']);

    expect(result.forbiddenCommands).toContain(CODING_AGENT_PRESET.forbiddenCommands?.[0] ?? '');
    expect(result.outboundRules).toContainEqual(BROWSING_AGENT_PRESET.outboundRules?.[0] ?? { pattern: '', action: 'block' });
  });

  it('version is always taken from developer base config', () => {
    const result = applyPresetOverlays({ version: '2.0.0' }, ['coding-agent']);

    expect(result.version).toBe('2.0.0');
  });
});

describe('integration - FilePolicyProvider applies presets', () => {
  it('getEffective() applies preset when presetOverlays is set', async () => {
    const path = await tempPolicyPath('preset-policy.json');
    await writeFile(path, JSON.stringify({
      version: '0.1.0',
      presetOverlays: ['coding-agent']
    }, null, 2), 'utf8');

    const provider = new FilePolicyProvider(path);
    const effective = await provider.getEffective();

    expect(effective.forbiddenCommands).toContain(CODING_AGENT_PRESET.forbiddenCommands?.[0] ?? '');
  });

  it('getEffective() preserves developer-specific rules alongside preset rules', async () => {
    const path = await tempPolicyPath('preset-and-custom-policy.json');
    await writeFile(path, JSON.stringify({
      version: '0.1.0',
      forbiddenTools: ['my-tool'],
      presetOverlays: ['assistant-with-tools']
    }, null, 2), 'utf8');

    const provider = new FilePolicyProvider(path);
    const effective = await provider.getEffective();

    expect(effective.forbiddenTools).toContain('my-tool');
    expect(effective.sensitiveFiles).toContain('.env');
  });

  it('getEffective() returns base config unchanged when no presetOverlays', async () => {
    const base = {
      version: '0.1.0',
      forbiddenTools: ['my-tool']
    };
    const path = await tempPolicyPath('base-policy.json');
    await writeFile(path, JSON.stringify(base, null, 2), 'utf8');

    const provider = new FilePolicyProvider(path);

    await expect(provider.getEffective()).resolves.toEqual(base);
  });
});
