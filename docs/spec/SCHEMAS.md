# Schema Reference

## ActionEnvelope

Required fields:

- `actionId`
- `sessionId`
- `timestamp`
- `framework`
- `actionType`
- `operation`
- `toolName`
- `arguments`

Optional fields include:

- `agentId`
- `cwd`
- `referencedPaths`
- `outboundTargets`
- `contentRefs`
- `metadata`

The `arguments` object is normalized per action type. Typed provenance hints belong in `arguments`, such as `agentAuthored`, rather than `metadata`.

## DecisionEnvelope

Required fields:

- `decision`
- `reasonCodes`
- `summary`

Optional sections include:

- `severity`
- `matchedRules`
- `approvalRequest`
- `taintSummary`
- `provenanceSummary`
- `chainRiskSummary`
- `telemetry`
- `debug`

## PolicyConfig

An empty policy is valid.

Supported policy fields include:

- `forbiddenTools`
- `forbiddenCommands`
- `forbiddenPaths`
- `forbiddenFiles`
- `sensitiveFiles`
- `sensitiveEnvKeys`
- `outboundRules`
- `recipientThreshold`
- `presetOverlays`

## Reason Codes

Reason codes are exported from `@moshe/spec` through the `ReasonCode` constant so SDK and adapter integrations share one canonical decision vocabulary.

## TelemetryEvent

Telemetry events include an event id, event type, action id, session id, and optional stage, decision, reason codes, elapsed milliseconds, and debug metadata.

## Validator Behavior

- All validator entry points return a typed success result or a list of schema errors.
- The JSON Schema definitions live in `@moshe/spec` and are used by the validator layer.
