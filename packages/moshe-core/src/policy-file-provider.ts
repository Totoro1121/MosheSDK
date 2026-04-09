import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { ReasonCode, validatePolicyConfig, type PolicyConfig } from '@moshesdk/spec';

import type { PolicyProvider } from './interfaces.js';
import { validatePolicyRules } from './policy.js';
import { applyPresetOverlays } from './policy-presets.js';

export interface FilePolicyProviderOptions {
  path: string;
}

export class FilePolicyProvider implements PolicyProvider {
  private readonly path: string;

  public constructor(options: FilePolicyProviderOptions | string) {
    this.path = resolve(typeof options === 'string' ? options : options.path);
  }

  public async load(): Promise<PolicyConfig> {
    let contents: string;

    try {
      contents = await readFile(this.path, 'utf8');
    } catch (error) {
      throw new Error(`[${ReasonCode.POLICY_VALIDATION_ERROR}] Failed to read policy file at "${this.path}": ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
      return JSON.parse(contents) as PolicyConfig;
    } catch (error) {
      throw new Error(`[${ReasonCode.POLICY_VALIDATION_ERROR}] Failed to parse policy file at "${this.path}": ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  public async validate(config: PolicyConfig): Promise<void> {
    const schema = validatePolicyConfig(config);
    const ruleErrors = validatePolicyRules(config);

    const messages: string[] = [];
    if (!schema.ok) {
      messages.push(...schema.errors);
    }

    if (ruleErrors.length > 0) {
      messages.push(...ruleErrors.map((error) => `${error.field}[${error.index}] "${error.value}": ${error.reason}`));
    }

    if (messages.length > 0) {
      throw new Error(`[${ReasonCode.POLICY_VALIDATION_ERROR}] Invalid policy at "${this.path}": ${messages.join('; ')}`);
    }
  }

  public async getEffective(): Promise<PolicyConfig> {
    const config = await this.load();
    await this.validate(config);
    const overlays = config.presetOverlays ?? [];

    if (overlays.length === 0) {
      return structuredClone(config);
    }

    return applyPresetOverlays(config, overlays);
  }
}
