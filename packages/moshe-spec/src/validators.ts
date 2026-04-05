import { Ajv, type ErrorObject, type ValidateFunction } from 'ajv';

import {
  actionEnvelopeSchema,
  decisionEnvelopeSchema,
  policyConfigSchema,
  telemetryEventSchema
} from './schemas.js';
import type {
  ActionEnvelope,
  DecisionEnvelope,
  PolicyConfig,
  TelemetryEvent,
  ValidationResult
} from './types.js';

const ajv = new Ajv({
  allErrors: true,
  allowUnionTypes: true
});

function formatErrors(errors: ErrorObject[] | null | undefined): string[] {
  if (!errors || errors.length === 0) {
    return ['Unknown validation error'];
  }

  return errors.map((error) => {
    const path = error.instancePath || '/';
    return `${path} ${error.message ?? 'is invalid'}`.trim();
  });
}

function makeValidator<T>(validator: ValidateFunction<T>, input: unknown): ValidationResult<T> {
  if (validator(input)) {
    return {
      ok: true,
      data: input as T
    };
  }

  return {
    ok: false,
    errors: formatErrors(validator.errors)
  };
}

const actionEnvelopeValidator = ajv.compile<ActionEnvelope>(actionEnvelopeSchema);
const decisionEnvelopeValidator = ajv.compile<DecisionEnvelope>(decisionEnvelopeSchema);
const policyConfigValidator = ajv.compile<PolicyConfig>(policyConfigSchema);
const telemetryEventValidator = ajv.compile<TelemetryEvent>(telemetryEventSchema);

export function validateActionEnvelope(input: unknown): ValidationResult<ActionEnvelope> {
  return makeValidator(actionEnvelopeValidator, input);
}

export function validateDecisionEnvelope(input: unknown): ValidationResult<DecisionEnvelope> {
  return makeValidator(decisionEnvelopeValidator, input);
}

export function validatePolicyConfig(input: unknown): ValidationResult<PolicyConfig> {
  return makeValidator(policyConfigValidator, input);
}

export function validateTelemetryEvent(input: unknown): ValidationResult<TelemetryEvent> {
  return makeValidator(telemetryEventValidator, input);
}
