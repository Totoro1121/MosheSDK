import type {
  ActionEnvelope,
  DecisionEnvelope,
  PolicyConfig,
  TelemetryEvent
} from './types.js';

export const actionEnvelopeSchema = {
  $id: 'moshe.actionEnvelope',
  type: 'object',
  additionalProperties: false,
  required: [
    'actionId',
    'sessionId',
    'timestamp',
    'framework',
    'actionType',
    'operation',
    'toolName',
    'arguments'
  ],
  properties: {
    actionId: { type: 'string', minLength: 1 },
    sessionId: { type: 'string', minLength: 1 },
    timestamp: { type: 'string', minLength: 1 },
    framework: { type: 'string', minLength: 1 },
    actionType: {
      type: 'string',
      enum: [
        'tool_call',
        'command_exec',
        'file_read',
        'file_write',
        'outbound_request',
        'message_send',
        'unknown'
      ]
    },
    operation: { type: 'string', minLength: 1 },
    toolName: { type: 'string', minLength: 1 },
    arguments: {
      type: 'object',
      additionalProperties: false,
      properties: {
        command: { type: 'string' },
        shell: { type: 'string' },
        path: { type: 'string' },
        content: { type: 'string' },
        url: { type: 'string' },
        method: { type: 'string' },
        headers: {
          type: 'object',
          nullable: true,
          additionalProperties: { type: 'string' }
        },
        recipients: {
          type: 'array',
          nullable: true,
          items: { type: 'string' }
        },
        subject: { type: 'string' },
        body: { type: 'string' },
        agentAuthored: { type: 'boolean' },
        params: {
          type: 'object',
          nullable: true,
          additionalProperties: {
            anyOf: [
              { type: 'string' },
              { type: 'number' },
              { type: 'boolean' }
            ]
          }
        }
      }
    },
    agentId: { type: 'string', nullable: true },
    cwd: { type: 'string', nullable: true },
    referencedPaths: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    outboundTargets: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    contentRefs: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    metadata: {
      type: 'object',
      nullable: true,
      additionalProperties: true
    }
  }
} as const;

export const decisionEnvelopeSchema = {
  $id: 'moshe.decisionEnvelope',
  type: 'object',
  additionalProperties: false,
  required: ['decision', 'reasonCodes', 'summary'],
  properties: {
    decision: {
      type: 'string',
      enum: ['ALLOW', 'BLOCK', 'REVIEW']
    },
    reasonCodes: {
      type: 'array',
      items: { type: 'string' }
    },
    summary: { type: 'string', minLength: 1 },
    severity: {
      type: 'string',
      nullable: true,
      enum: ['low', 'medium', 'high', 'critical']
    },
    matchedRules: {
      type: 'array',
      nullable: true,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['ruleId', 'ruleType', 'matchedValue'],
        properties: {
          ruleId: { type: 'string' },
          ruleType: { type: 'string' },
          matchedValue: { type: 'string' }
        }
      }
    },
    approvalRequest: {
      type: 'object',
      nullable: true,
      additionalProperties: false,
      required: ['approvalId', 'expiresAt'],
      properties: {
        approvalId: { type: 'string' },
        expiresAt: { type: 'string' },
        callbackHint: { type: 'string', nullable: true }
      }
    },
    taintSummary: {
      type: 'object',
      nullable: true,
      additionalProperties: false,
      required: ['sessionTainted', 'taintSources', 'artifactsTainted'],
      properties: {
        sessionTainted: { type: 'boolean' },
        taintSources: { type: 'array', items: { type: 'string' } },
        artifactsTainted: { type: 'array', items: { type: 'string' } }
      }
    },
    provenanceSummary: {
      type: 'object',
      nullable: true,
      additionalProperties: false,
      required: ['agentAuthored', 'propagatedFrom'],
      properties: {
        agentAuthored: { type: 'array', items: { type: 'string' } },
        propagatedFrom: { type: 'array', items: { type: 'string' } },
        lineageDepth: { type: 'number', nullable: true },
        originSources: { type: 'array', nullable: true, items: { type: 'string' } }
      }
    },
    chainRiskSummary: {
      type: 'object',
      nullable: true,
      additionalProperties: false,
      required: ['riskLevel', 'reviewCount', 'blockCount', 'sensitiveReadCount'],
      properties: {
        riskLevel: {
          type: 'string',
          enum: ['NORMAL', 'ELEVATED', 'HIGH']
        },
        reviewCount: { type: 'number' },
        blockCount: { type: 'number' },
        sensitiveReadCount: { type: 'number' }
      }
    },
    telemetry: {
      type: 'object',
      nullable: true,
      additionalProperties: false,
      required: ['eventId'],
      properties: {
        eventId: { type: 'string' }
      }
    },
    debug: {
      type: 'object',
      nullable: true,
      additionalProperties: true
    }
  }
} as const;

export const policyConfigSchema = {
  $id: 'moshe.policyConfig',
  type: 'object',
  additionalProperties: false,
  required: ['version'],
  properties: {
    version: { type: 'string', minLength: 1 },
    forbiddenTools: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    forbiddenCommands: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    forbiddenPaths: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    forbiddenFiles: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    sensitiveFiles: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    sensitiveEnvKeys: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    outboundRules: {
      type: 'array',
      nullable: true,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['pattern', 'action'],
        properties: {
          pattern: { type: 'string' },
          action: {
            type: 'string',
            enum: ['allow', 'block']
          }
        }
      }
    },
    recipientThreshold: {
      type: 'object',
      nullable: true,
      additionalProperties: false,
      required: ['maxRecipients', 'action'],
      properties: {
        maxRecipients: { type: 'number' },
        action: {
          type: 'string',
          enum: ['block', 'review']
        }
      }
    },
    presetOverlays: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    }
  }
} as const;

export const telemetryEventSchema = {
  $id: 'moshe.telemetryEvent',
  type: 'object',
  additionalProperties: false,
  required: ['eventId', 'eventType', 'actionId', 'sessionId'],
  properties: {
    eventId: { type: 'string', minLength: 1 },
    eventType: {
      type: 'string',
      enum: [
        'ACTION_RECEIVED',
        'STAGE_COMPLETE',
        'DECISION_MADE',
        'APPROVAL_CREATED',
        'APPROVAL_RESOLVED',
        'FEEDBACK'
      ]
    },
    actionId: { type: 'string', minLength: 1 },
    sessionId: { type: 'string', minLength: 1 },
    stage: { type: 'string', nullable: true },
    decision: {
      type: 'string',
      nullable: true,
      enum: ['ALLOW', 'BLOCK', 'REVIEW']
    },
    reasonCodes: {
      type: 'array',
      nullable: true,
      items: { type: 'string' }
    },
    elapsedMs: { type: 'number', nullable: true },
    debug: {
      type: 'object',
      nullable: true,
      additionalProperties: true
    }
  }
} as const;

export type ActionEnvelopeSchema = typeof actionEnvelopeSchema;
export type DecisionEnvelopeSchema = typeof decisionEnvelopeSchema;
export type PolicyConfigSchema = typeof policyConfigSchema;
export type TelemetryEventSchema = typeof telemetryEventSchema;

export const schemas = {
  actionEnvelope: actionEnvelopeSchema,
  decisionEnvelope: decisionEnvelopeSchema,
  policyConfig: policyConfigSchema,
  telemetryEvent: telemetryEventSchema
} as const;

export type SpecSchemaMap = {
  actionEnvelope: ActionEnvelope;
  decisionEnvelope: DecisionEnvelope;
  policyConfig: PolicyConfig;
  telemetryEvent: TelemetryEvent;
};
