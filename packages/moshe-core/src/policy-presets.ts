import type { OutboundRule, PolicyConfig } from '@moshesdk/spec';

export const PRESET_NAMES = ['coding-agent', 'assistant-with-tools', 'browsing-agent'] as const;
export type PresetName = (typeof PRESET_NAMES)[number];

export const CODING_AGENT_PRESET: Readonly<PolicyConfig> = {
  version: '0.1.0',
  forbiddenCommands: [
    'rm\\s+-rf\\s+/',
    'chmod\\s+777',
    'curl\\s+.*\\|\\s*bash',
    'wget\\s+.*\\|\\s*bash',
    ':\\s*\\(\\s*\\)\\s*\\{',
    'dd\\s+if=',
    'mkfs\\.',
    'shutdown',
    'reboot',
    'halt'
  ],
  forbiddenPaths: [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/root/**',
    '/boot/**',
    '/sys/**',
    '/proc/**'
  ],
  sensitiveFiles: [
    '.env',
    '.env.local',
    '.env.production',
    'id_rsa',
    'id_ed25519',
    '.npmrc',
    '.pypirc',
    'credentials',
    'secrets.json',
    'secrets.yaml',
    'secrets.yml'
  ],
  sensitiveEnvKeys: [
    'AWS_SECRET_ACCESS_KEY',
    'AWS_ACCESS_KEY_ID',
    'GITHUB_TOKEN',
    'NPM_TOKEN',
    'DATABASE_URL',
    'SECRET_KEY',
    'PRIVATE_KEY',
    'API_KEY'
  ]
};

export const ASSISTANT_WITH_TOOLS_PRESET: Readonly<PolicyConfig> = {
  version: '0.1.0',
  forbiddenTools: [
    'shell',
    'bash',
    'exec',
    'eval'
  ],
  sensitiveFiles: [
    '.env',
    '.env.local',
    'id_rsa',
    'id_ed25519',
    'credentials',
    'secrets.json'
  ],
  sensitiveEnvKeys: [
    'AWS_SECRET_ACCESS_KEY',
    'GITHUB_TOKEN',
    'DATABASE_URL',
    'API_KEY'
  ],
  recipientThreshold: {
    maxRecipients: 5,
    action: 'review'
  }
};

export const BROWSING_AGENT_PRESET: Readonly<PolicyConfig> = {
  version: '0.1.0',
  forbiddenCommands: [
    'rm\\s+-rf',
    ':\\s*\\(\\s*\\)\\s*\\{',
    'dd\\s+if=',
    'mkfs\\.'
  ],
  sensitiveFiles: [
    '.env',
    '.env.local',
    'id_rsa',
    'id_ed25519',
    'credentials',
    'secrets.json'
  ],
  sensitiveEnvKeys: [
    'AWS_SECRET_ACCESS_KEY',
    'GITHUB_TOKEN',
    'API_KEY'
  ],
  outboundRules: [
    { pattern: 'pastebin.com', action: 'block' },
    { pattern: 'hastebin.com', action: 'block' },
    { pattern: 'ghostbin.com', action: 'block' },
    { pattern: 'webhook.site', action: 'block' },
    { pattern: 'requestbin', action: 'block' },
    { pattern: 'ngrok.io', action: 'block' },
    { pattern: 'ngrok.app', action: 'block' },
    { pattern: 'pipedream.net', action: 'block' }
  ]
};

export const PRESETS: Record<PresetName, Readonly<PolicyConfig>> = {
  'coding-agent': CODING_AGENT_PRESET,
  'assistant-with-tools': ASSISTANT_WITH_TOOLS_PRESET,
  'browsing-agent': BROWSING_AGENT_PRESET
};

function mergeStringArray(baseArr: string[] | undefined, presetArr: string[] | undefined): string[] | undefined {
  if (!presetArr?.length && !baseArr?.length) {
    return undefined;
  }

  return [...new Set([...(baseArr ?? []), ...(presetArr ?? [])])];
}

function mergeOutboundRules(
  baseRules: PolicyConfig['outboundRules'],
  presetRules: PolicyConfig['outboundRules']
): PolicyConfig['outboundRules'] {
  if (!presetRules?.length && !baseRules?.length) {
    return undefined;
  }

  const seen = new Set<string>();
  const merged: OutboundRule[] = [];

  for (const rule of [...(baseRules ?? []), ...(presetRules ?? [])]) {
    const key = `${rule.pattern}:${rule.action}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(rule);
    }
  }

  return merged.length > 0 ? merged : undefined;
}

function mergePreset(base: PolicyConfig, preset: Readonly<PolicyConfig>): PolicyConfig {
  const forbiddenTools = mergeStringArray(base.forbiddenTools, preset.forbiddenTools);
  const forbiddenCommands = mergeStringArray(base.forbiddenCommands, preset.forbiddenCommands);
  const forbiddenPaths = mergeStringArray(base.forbiddenPaths, preset.forbiddenPaths);
  const forbiddenFiles = mergeStringArray(base.forbiddenFiles, preset.forbiddenFiles);
  const sensitiveFiles = mergeStringArray(base.sensitiveFiles, preset.sensitiveFiles);
  const sensitiveEnvKeys = mergeStringArray(base.sensitiveEnvKeys, preset.sensitiveEnvKeys);
  const outboundRules = mergeOutboundRules(base.outboundRules, preset.outboundRules);
  const recipientThreshold = base.recipientThreshold ?? preset.recipientThreshold;

  return {
    version: base.version,
    ...(forbiddenTools !== undefined ? { forbiddenTools } : {}),
    ...(forbiddenCommands !== undefined ? { forbiddenCommands } : {}),
    ...(forbiddenPaths !== undefined ? { forbiddenPaths } : {}),
    ...(forbiddenFiles !== undefined ? { forbiddenFiles } : {}),
    ...(sensitiveFiles !== undefined ? { sensitiveFiles } : {}),
    ...(sensitiveEnvKeys !== undefined ? { sensitiveEnvKeys } : {}),
    ...(outboundRules !== undefined ? { outboundRules } : {}),
    ...(recipientThreshold !== undefined ? { recipientThreshold } : {}),
    ...(base.presetOverlays !== undefined ? { presetOverlays: base.presetOverlays } : {})
  };
}

export function applyPresetOverlays(base: PolicyConfig, presetNames: string[]): PolicyConfig {
  let result: PolicyConfig = structuredClone(base);

  for (const name of presetNames) {
    if (!Object.hasOwn(PRESETS, name)) {
      console.warn(`[MosheSDK] Unknown preset "${name}" in presetOverlays - skipped.`);
      continue;
    }

    const preset = PRESETS[name as PresetName];
    result = mergePreset(result, preset);
  }

  return result;
}
