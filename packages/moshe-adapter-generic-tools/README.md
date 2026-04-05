# @moshe/adapter-generic-tools

`@moshe/adapter-generic-tools` provides lightweight wrapper helpers that turn normal tool, command, outbound request, and message-send calls into MosheSDK policy checks. It sits between your agent code and the engine so you can integrate enforcement without manually building `ActionEnvelope` objects.

## Installation

If you already use `@moshe/sdk`, this adapter is included through the top-level SDK export surface.

For custom integrations that only need the adapter layer:

```bash
pnpm add @moshe/adapter-generic-tools @moshe/core @moshe/spec
```

## Basic Usage

```typescript
import { GenericAdapter, Moshe } from '@moshe/sdk';

const moshe = new Moshe({
  policy: { version: '0.1.0', forbiddenCommands: ['rm\\s+-rf\\s+/'] },
  store: new MemoryStore(),
  onError: 'BLOCK',
  onUnhandledReview: 'BLOCK'
});

const adapter = new GenericAdapter(moshe.withSession('session-1'));

await adapter.wrapCommand({
  command: 'ls -la',
  execute: async () => 'ok'
});

await adapter.wrapToolCall({
  toolName: 'search',
  arguments: { params: { q: 'docs' } },
  execute: async () => ['result']
});

await adapter.wrapOutbound({
  url: 'https://api.example.com/data',
  method: 'POST',
  execute: async () => ({ ok: true })
});

await adapter.wrapMessage({
  recipients: ['a@example.com'],
  subject: 'Hello',
  body: 'World',
  execute: async () => 'sent'
});
```

## Error Handling

```typescript
import { BlockedActionError, ReviewRequiredError } from '@moshe/sdk';

try {
  await adapter.wrapCommand({
    command: 'rm -rf /',
    execute: async () => 'never'
  });
} catch (error) {
  if (error instanceof BlockedActionError) {
    console.log(error.decision.reasonCodes);
  }

  if (error instanceof ReviewRequiredError) {
    console.log(error.approvalRequest?.approvalId);
  }
}
```

## SessionEvaluator

Any object with a compatible `evaluate()` method can be used as the adapter backend. In practice this is usually `moshe.withSession(sessionId)`, but the adapter does not require a concrete `Moshe` class instance.

