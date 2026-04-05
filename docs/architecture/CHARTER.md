# MosheSDK Architecture Charter

## Four-Layer Model

```text
Spec -> Engine -> SDK -> Differentiation
```

- Spec: stable contracts, schemas, validators
- Engine: orchestration, stage execution, core interfaces
- SDK: developer-facing ergonomics and inline policy support
- Differentiation: adapters, approvals, taint, intelligence, and ecosystem layers

## Seven-Stage Pipeline

1. Normalize - fill defaults and validate the incoming action envelope shape.
2. Enrich - load policy, session state, and artifact state context.
3. Static policy evaluation - run deterministic policy checks.
4. Analysis - execute registered analyzers and optional decision-provider hooks.
5. Approval check - translate review outcomes through the approval layer or configured fallback.
6. Compose - combine stage outputs into the final `DecisionEnvelope`.
7. Emit telemetry - publish pipeline telemetry events and sanitized stage metadata.

## Package Dependency Graph

- `@moshe/spec` has no workspace-package dependencies
- `@moshe/core` depends on `@moshe/spec` only
- `@moshe/store-memory` depends on `@moshe/core`
- `@moshe/store-file` depends on `@moshe/core`
- `@moshe/adapter-generic-tools` depends on `@moshe/spec` and `@moshe/core`
- `@moshe/adapter-openai` depends on `@moshe/adapter-generic-tools` and `@moshe/spec`
- `@moshe/adapter-anthropic` depends on `@moshe/adapter-generic-tools` and `@moshe/spec`
- `@moshe/sdk` depends on `@moshe/spec`, `@moshe/core`, both stores, and the adapter packages
- `packages/moshe-sdk-python` is a standalone Python package and is not part of the pnpm dependency graph

Circular dependencies are not allowed.

## Public Contract Stability

- Required fields on `ActionEnvelope` and `DecisionEnvelope` are intended to remain stable.
- New capabilities should prefer optional fields and additive APIs.
- Opaque passthrough metadata must remain outside core analyzer logic.

## Metadata Restriction

Core analyzers must not read `ActionEnvelope.metadata`. Framework-specific adapters may write metadata for host use, but engine logic must treat it as opaque passthrough.

Typed action semantics needed by analyzers must live in the public contract, not in `metadata`.

## Store Concurrency Contract

- Memory store is single-process only.
- File store is single-writer only.

## Telemetry Scrubbing Rule

Core engine telemetry may include full debug detail in-process. Any sink that emits outside the process is responsible for stripping `debug` and excluding raw `arguments.content`, `arguments.body`, and `arguments.headers`.
