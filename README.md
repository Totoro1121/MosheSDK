# MosheSDK

MosheSDK is an open source agent-safety SDK that brings CrabShield-inspired policy, approval, provenance, observability, and adapter concepts into a modular developer-facing toolkit.

The project is headless by design and currently ships both a TypeScript SDK and a standalone Python SDK.

## Current State

- Version: `0.1.0`
- Status: `Wave 6 in progress`
- Runtime targets: Node.js 18+ and Python 3.11+
- UI: deferred until a later phase

## Packages

- `@moshe/spec` - canonical schemas, types, enums, validators
- `@moshe/core` - engine pipeline, policy hooks, interfaces, orchestration
- `@moshe/store-memory` - in-memory store implementation
- `@moshe/store-file` - atomic JSON file-backed store implementation
- `@moshe/sdk` - developer-facing TypeScript SDK surface
- `moshe` - standalone Python SDK with core, telemetry, approval, lineage, and adapter support

## What It Does

The SDK now supports:

- deterministic policy evaluation for forbidden tools, commands, paths, files, outbound rules, and recipient thresholds
- sensitive file and sensitive environment key review flows
- approval and replay handling
- deterministic intent analyzers for command, file-access, and outbound behavior
- taint, provenance, chain-risk, and lineage tracking
- telemetry sinks and feedback submission
- generic adapter wrappers plus vendor adapters for OpenAI and Anthropic

## Quick Start

Install dependencies with pinned pnpm:

```powershell
npx pnpm@9.15.9 install
```

Build, test, and run the TypeScript smoke example:

```powershell
npx pnpm@9.15.9 build
npx pnpm@9.15.9 test
node examples/minimal-ts/index.js
```

Install and test the Python package:

```powershell
cd packages/moshe-sdk-python
python -m pip install -e ".[dev]"
python -m pytest
python -m mypy
```

## TypeScript Hello World

```typescript
import { MemoryStore, Moshe } from '@moshe/sdk';

const moshe = new Moshe({
  policy: {
    forbiddenCommands: ['rm\\s+-rf\\s+/'],
    forbiddenFiles: ['.env']
  },
  store: new MemoryStore(),
  onError: 'BLOCK',
  onUnhandledReview: 'BLOCK'
});

const decision = await moshe.evaluate({
  sessionId: 'session-abc',
  framework: 'generic',
  actionType: 'command_exec',
  operation: 'exec',
  toolName: 'bash',
  arguments: {
    command: 'ls -la'
  }
});

console.log(decision);
```

## Documentation

- [Versions](./docs/Versions.md)
- [Architecture Charter](./docs/architecture/CHARTER.md)
- [Schema Reference](./docs/spec/SCHEMAS.md)
