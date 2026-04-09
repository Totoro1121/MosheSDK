# @moshesdk/sdk

TypeScript SDK for [MosheSDK](../../README.md) — runtime security for AI agents.

## Installation

```bash
pnpm add @moshesdk/sdk
# or
npm install @moshesdk/sdk
```

Requires Node.js ≥ 18. Zero mandatory runtime dependencies.

## Quick Start

```typescript
import { GenericAdapter, MemoryStore, Moshe } from '@moshesdk/sdk';

const moshe = new Moshe({
  policy: {
    forbiddenCommands: ['rm\\s+-rf'],
    forbiddenFiles: ['.env'],
    sensitiveFiles: ['id_rsa']
  },
  store: new MemoryStore(),
  onError: 'BLOCK',
  onUnhandledReview: 'BLOCK'
});

const session = moshe.withSession('run-001');
const adapter = new GenericAdapter(session, { framework: 'my-agent' });

const result = await adapter.wrapCommand({
  command: 'ls -la',
  toolName: 'shell',
  execute: async () => runShell('ls -la')
});
```

## Adapters

```typescript
import { AnthropicAdapter, OpenAIAdapter } from '@moshesdk/sdk';

// OpenAI tool calls
const oa = new OpenAIAdapter(session);
const result = await oa.wrapToolCall({ toolCall, execute });

// Anthropic tool_use blocks
const aa = new AnthropicAdapter(session);
const result = await aa.wrapToolUse({ toolUse, execute });
```

## Documentation

See the [root README](../../README.md) for the full integration guide, feature
overview, and use cases.
