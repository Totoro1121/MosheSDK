# MosheSDK

MosheSDK is an open source agent-safety SDK for developers building LLM agents with tool use, command execution, file access, outbound requests, and approval workflows.

It is headless by design and currently ships:

- a TypeScript SDK centered on `@moshe/sdk`
- a standalone Python SDK published as `moshe`

## What MosheSDK Gives You

MosheSDK sits between your agent and the real side effects it wants to perform.

It can:

- deterministically block or review risky actions before execution
- apply policy to tools, commands, files, outbound requests, and recipients
- require operator approval for reviewable actions
- track taint, provenance, lineage, and session-level chain risk
- emit telemetry and accept feedback
- wrap generic tool execution or vendor-specific tool-call formats

## Where It Fits

The integration pattern is simple:

1. Your model decides it wants to call a tool.
2. You convert that intent into a Moshe-evaluable action, or use one of Moshe’s adapters.
3. Moshe returns `ALLOW`, `REVIEW`, or `BLOCK`.
4. Only `ALLOW` reaches the real side effect.

In practice, Moshe becomes the safety gate in your agent runtime.

## Quick Start

TypeScript workspace:

```powershell
npx pnpm@9.15.9 install
npx pnpm@9.15.9 build
npx pnpm@9.15.9 test
node examples/minimal-ts/index.js
```

Python package:

```powershell
cd packages/moshe-sdk-python
python -m pip install -e ".[dev]"
python -m pytest
python -m mypy
```

## Agent Integration Guide

### 1. Create One Shared Moshe Instance

Create one `Moshe` instance for your agent runtime and keep it alive for the life of the worker or process.

TypeScript:

```typescript
import {
  InProcessApprovalProvider,
  MemoryStore,
  MemoryTelemetrySink,
  Moshe
} from '@moshe/sdk';

const store = new MemoryStore();
const telemetry = new MemoryTelemetrySink();

const moshe = new Moshe({
  policy: {
    version: '0.1.0',
    forbiddenCommands: ['rm\\s+-rf\\s+/'],
    forbiddenFiles: ['.env'],
    sensitiveFiles: ['id_rsa', '.env'],
    outboundRules: [
      { pattern: 'pastebin.com', action: 'block' },
      { pattern: 'webhook.site', action: 'block' }
    ]
  },
  store,
  approvalProvider: new InProcessApprovalProvider({ store }),
  telemetrySinks: [telemetry],
  onError: 'BLOCK',
  onUnhandledReview: 'BLOCK'
});
```

Python:

```python
from moshe import InProcessApprovalProvider, MemoryStore, MemoryTelemetrySink, Moshe, PolicyConfig

store = MemoryStore()
telemetry = MemoryTelemetrySink()

moshe = Moshe(
    policy=PolicyConfig(
        forbidden_commands=[r"rm\s+-rf\s+/"],
        forbidden_files=[".env"],
        sensitive_files=["id_rsa", ".env"],
        outbound_rules=[],
    ),
    store=store,
    approval_provider=InProcessApprovalProvider(store),
    telemetry_sinks=[telemetry],
    on_error="BLOCK",
    on_unhandled_review="BLOCK",
)
```

### 2. Bind Each Agent Conversation or Run to a Session

Use one session per user conversation, run, task, or workflow. Session state is how Moshe tracks approval replay, taint, and chain risk.

TypeScript:

```typescript
const session = moshe.withSession(`run-${runId}`);
```

Python:

```python
session = moshe.with_session(f"run-{run_id}")
```

### 3. Put Moshe in Front of Real Tools

If your agent has tools like `shell`, `read_file`, `write_file`, or `http_request`, do not call them directly from model output.

Wrap them through:

- `GenericAdapter` if your runtime already has its own normalized tool abstraction
- `OpenAIAdapter` if you receive OpenAI function/tool calls
- `AnthropicAdapter` if you receive Anthropic `tool_use` blocks

#### Generic TypeScript Example

```typescript
import { BlockedActionError, GenericAdapter, ReviewRequiredError } from '@moshe/sdk';

const adapter = new GenericAdapter(session, {
  framework: 'my-agent-runtime'
});

try {
  const result = await adapter.wrapCommand({
    command: 'ls -la',
    toolName: 'shell',
    execute: async () => {
      return await actuallyRunShellCommand('ls -la');
    }
  });

  console.log(result);
} catch (error) {
  if (error instanceof BlockedActionError) {
    console.error('Blocked:', error.decision);
  }

  if (error instanceof ReviewRequiredError) {
    console.error('Needs review:', error.decision);
  }
}
```

#### Generic Python Example

```python
from moshe import BlockedActionError, GenericAdapter, ReviewRequiredError

adapter = GenericAdapter(session, framework="my-agent-runtime")

try:
    result = await adapter.wrap_command(
        command="ls -la",
        tool_name="shell",
        execute=lambda: actually_run_shell_command("ls -la"),
    )
    print(result)
except BlockedActionError as error:
    print("Blocked:", error.decision)
except ReviewRequiredError as error:
    print("Needs review:", error.decision)
```

### 4. Use Vendor Adapters When Your Model Already Produces Tool-Call Objects

If your agent framework gives you vendor-native tool-call payloads, use the matching Moshe adapter instead of building envelopes by hand.

#### OpenAI TypeScript Example

```typescript
import { OpenAIAdapter } from '@moshe/sdk';

const adapter = new OpenAIAdapter(session);

const value = await adapter.wrapToolCall({
  toolCall,
  execute: async () => actuallyRunTool(toolCall)
});
```

#### OpenAI Python Example

```python
from moshe import OpenAIAdapter

adapter = OpenAIAdapter(session)

value = await adapter.wrap_tool_call(
    tool_call=tool_call,
    execute=lambda: actually_run_tool(tool_call),
)
```

#### Anthropic TypeScript Example

```typescript
import { AnthropicAdapter } from '@moshe/sdk';

const adapter = new AnthropicAdapter(session);

const value = await adapter.wrapToolUse({
  toolUse,
  execute: async () => actuallyRunTool(toolUse)
});
```

#### Anthropic Python Example

```python
from moshe import AnthropicAdapter

adapter = AnthropicAdapter(session)

value = await adapter.wrap_tool_use(
    tool_use=tool_use,
    execute=lambda: actually_run_tool(tool_use),
)
```

### 5. Decide How You Want Review to Work

`REVIEW` only becomes useful when you define what happens next.

Common options:

- `onUnhandledReview: 'BLOCK'` for strict unattended agents
- `onUnhandledReview: 'ALLOW'` for sandboxed or low-risk environments
- `InProcessApprovalProvider` for a real approval loop with replay
- `CallbackDecisionProvider` or `HttpDecisionProvider` if you want a semantic or external review plugin

Practical rule:

- Use `BLOCK` by default in production until you have a deliberate approval story.

### 6. Attach Telemetry Early

Telemetry is one of the fastest ways to debug agent safety behavior.

TypeScript:

```typescript
import { MemoryTelemetrySink } from '@moshe/sdk';

const sink = new MemoryTelemetrySink();
const moshe = new Moshe({
  policy,
  store,
  telemetrySinks: [sink],
  onError: 'BLOCK',
  onUnhandledReview: 'BLOCK'
});

const decision = await moshe.evaluate(action);
console.log(sink.getDecisionEvent(action.actionId));
```

Python:

```python
from moshe import MemoryTelemetrySink

sink = MemoryTelemetrySink()
moshe = Moshe(
    policy=policy,
    store=store,
    telemetry_sinks=[sink],
    on_error="BLOCK",
    on_unhandled_review="BLOCK",
)
```

### 7. Start Small With Policy

A good first production policy is usually:

- block obviously destructive commands
- block known exfil domains
- review sensitive file access
- review or block mass-recipient actions

You do not need to model every risk on day one. Moshe is most effective when it guards a few high-value boundaries first, then expands.

## Recommended Integration Patterns

### Pattern A: Safety Gate Around Existing Tools

Best when you already have an agent framework and just need a policy/approval layer.

Use:

- `Moshe`
- `MemoryStore` or your own store implementation
- `GenericAdapter`

### Pattern B: Vendor Tool-Call Interception

Best when your model already emits OpenAI or Anthropic tool calls directly.

Use:

- `OpenAIAdapter` or `AnthropicAdapter`
- `MosheSession` or root `Moshe`

### Pattern C: Centralized Review Service

Best when you want one shared safety backend across many agent workers.

Use:

- `HttpDecisionProvider`
- telemetry sinks
- persistent store implementation

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
