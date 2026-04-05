import { ReasonCode, type ActionEnvelope } from '@moshe/spec';

import type { Analyzer, EngineContext, StageResult } from './interfaces.js';
import { isLocalNetworkHost, parseOutboundTarget } from './outbound-utils.js';

function pass(stage: string): StageResult {
  return {
    stage,
    passed: true,
    decision: 'ALLOW',
    reasonCodes: []
  };
}

function flag(stage: string, opts: {
  decision: 'BLOCK' | 'REVIEW';
  reasonCode: (typeof ReasonCode)[keyof typeof ReasonCode];
  matchedValue: string;
  summary: string;
}): StageResult {
  return {
    stage,
    passed: false,
    decision: opts.decision,
    reasonCodes: [opts.reasonCode],
    matchedRules: [
      {
        ruleId: `${stage}:${opts.reasonCode}`,
        ruleType: stage,
        matchedValue: opts.matchedValue
      }
    ],
    enrichments: {
      summary: opts.summary
    }
  };
}

function collectCommandCandidates(envelope: ActionEnvelope): string[] {
  return [envelope.arguments.command, envelope.arguments.shell]
    .filter((value): value is string => typeof value === 'string' && value.trim() !== '');
}

function collectOutboundTargets(envelope: ActionEnvelope): string[] {
  const targets = new Set<string>();

  if (typeof envelope.arguments.url === 'string' && envelope.arguments.url.trim() !== '') {
    targets.add(envelope.arguments.url);
  }

  for (const target of envelope.outboundTargets ?? []) {
    if (target.trim() !== '') {
      targets.add(target);
    }
  }

  return [...targets];
}

export class CommandIntentAnalyzer implements Analyzer {
  public readonly name = 'command_intent';

  public async analyze(envelope: ActionEnvelope, _ctx: EngineContext): Promise<StageResult> {
    const commands = collectCommandCandidates(envelope);
    if (commands.length === 0 && envelope.actionType !== 'command_exec') {
      return pass(this.name);
    }

    for (const candidate of commands) {
      const normalized = candidate.toLowerCase();
      const decodesBase64 = normalized.includes('base64 -d') || normalized.includes('base64 --decode');
      const pipesToInterpreter = normalized.includes('| bash')
        || normalized.includes('| sh')
        || normalized.includes('| python3')
        || normalized.includes('| python')
        || normalized.includes('| node');

      if (decodesBase64 && pipesToInterpreter) {
        return flag(this.name, {
          decision: 'BLOCK',
          reasonCode: ReasonCode.COMMAND_INTENT_SUSPICIOUS,
          matchedValue: candidate.slice(0, 120),
          summary: 'Blocked: command decodes and executes a base64-encoded payload.'
        });
      }
    }

    for (const candidate of commands) {
      const normalized = candidate.toLowerCase();
      const pipeToInterpreter = /\|\s*(bash|sh|python3?|node|perl|ruby)\b/.test(normalized);
      const decodesBase64 = normalized.includes('base64 -d') || normalized.includes('base64 --decode');

      if (pipeToInterpreter && !decodesBase64) {
        return flag(this.name, {
          decision: 'REVIEW',
          reasonCode: ReasonCode.COMMAND_INTENT_SUSPICIOUS,
          matchedValue: candidate.slice(0, 120),
          summary: 'Command pipes output directly into a shell interpreter.'
        });
      }
    }

    for (const candidate of commands) {
      if (/(?:bash|sh|python3?|node|pwsh|powershell)\s+-[ce]\s+/i.test(candidate)) {
        return flag(this.name, {
          decision: 'REVIEW',
          reasonCode: ReasonCode.COMMAND_INTENT_SUSPICIOUS,
          matchedValue: candidate.slice(0, 120),
          summary: 'Command executes an inline script via interpreter flag.'
        });
      }
    }

    const enumerationPatterns = [
      /\bfind\s+[/~]/,
      /\bfind\s+\./,
      /\bls\s+.*-[a-z]*[lr]/,
      /\bdir\b.*\/s/,
      /\btree\b/,
      /\bdu\s+-/
    ];

    for (const candidate of commands) {
      const normalized = candidate.toLowerCase();
      if (enumerationPatterns.some((pattern) => pattern.test(normalized))) {
        return flag(this.name, {
          decision: 'REVIEW',
          reasonCode: ReasonCode.FILE_ENUMERATION_DETECTED,
          matchedValue: candidate.slice(0, 120),
          summary: 'Command performs recursive filesystem enumeration.'
        });
      }
    }

    return pass(this.name);
  }
}

export class FileAccessIntentAnalyzer implements Analyzer {
  public readonly name = 'file_access_intent';

  public async analyze(envelope: ActionEnvelope, _ctx: EngineContext): Promise<StageResult> {
    const hasPath = typeof envelope.arguments.path === 'string' && envelope.arguments.path.trim() !== '';
    const applicable = envelope.actionType === 'file_read' || envelope.actionType === 'file_write' || hasPath;

    if (!applicable) {
      return pass(this.name);
    }

    const refCount = (envelope.referencedPaths ?? []).length;
    if (refCount >= 10) {
      return flag(this.name, {
        decision: 'REVIEW',
        reasonCode: ReasonCode.FILE_ENUMERATION_DETECTED,
        matchedValue: String(refCount),
        summary: `File access references ${refCount} paths simultaneously - possible bulk enumeration.`
      });
    }

    return pass(this.name);
  }
}

export class OutboundClassificationAnalyzer implements Analyzer {
  public readonly name = 'outbound_classification';

  public async analyze(envelope: ActionEnvelope, _ctx: EngineContext): Promise<StageResult> {
    const targets = collectOutboundTargets(envelope);
    if (targets.length === 0 && envelope.actionType !== 'outbound_request') {
      return pass(this.name);
    }

    const riskyHosts = [
      'pastebin.com',
      'hastebin.com',
      'ghostbin.com',
      'controlc.com',
      'requestbin',
      'webhook.site',
      'ngrok.io',
      'ngrok.app',
      'pipedream.net',
      'hookbin.com',
      'beeceptor.com',
      'typedwebhook.tools',
      'bin.sh'
    ];

    for (const target of targets) {
      const normalized = target.toLowerCase();

      if (riskyHosts.some((pattern) => normalized.includes(pattern))) {
        return flag(this.name, {
          decision: 'REVIEW',
          reasonCode: ReasonCode.OUTBOUND_CLASSIFICATION_SUSPICIOUS,
          matchedValue: target.slice(0, 200),
          summary: 'Outbound target matches a known data-exfiltration risk host.'
        });
      }

      if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:\/|$)/.test(target)) {
        return flag(this.name, {
          decision: 'REVIEW',
          reasonCode: ReasonCode.OUTBOUND_CLASSIFICATION_SUSPICIOUS,
          matchedValue: target.slice(0, 200),
          summary: 'Outbound request targets a raw IP address — DNS bypassed.'
        });
      }

      const parsed = parseOutboundTarget(target);
      if (parsed && isLocalNetworkHost(parsed.hostname)) {
        return flag(this.name, {
          decision: 'REVIEW',
          reasonCode: ReasonCode.OUTBOUND_CLASSIFICATION_SUSPICIOUS,
          matchedValue: target.slice(0, 200),
          summary: 'Outbound request targets a local network address.'
        });
      }
    }

    return pass(this.name);
  }
}
