# MosheSDK

**Runtime security for AI agents.** Deterministic policy enforcement, approval
workflows, taint tracking, and chain-risk detection — all in-process, without
model calls.

[![npm](https://img.shields.io/npm/v/@moshesdk/sdk)](https://www.npmjs.com/package/@moshesdk/sdk)
[![PyPI](https://img.shields.io/pypi/v/moshe)](https://pypi.org/project/moshe/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](packages/moshe-sdk-ts)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](packages/moshe-sdk-python)

> **Status: Developer Preview — v0.1.2.**
> The public API is stabilising. Minor breaking changes may occur before v1.0.
> We welcome early adopters and contributors; evaluate carefully before
> production use.

> 📹 **Demo video coming soon.**

---

## The Problem

LLM agents are increasingly trusted to call tools, execute commands, read files,
and make outbound requests on behalf of users. The model decides what to do —
but there is no guarantee the decision is safe.

Prompt injection, data exfiltration chains, tainted artifact propagation, and
runaway multi-step risk are real attack surfaces that grow with every new
capability you give your agent.

Most guardrails evaluate actions one at a time and rely on a model to judge them.
That is slow, probabilistic, and expensive. **Moshe takes a different approach.**

---

## Why Moshe?

**Deterministic, not probabilistic.**
Every enforcement decision is a rule evaluation. A blocked command is blocked
every time, in under a millisecond, with no LLM involved. There is no "97%"
confidence in a block.

**Session memory across the full agent run.**
A single read of `/etc/passwd` is suspicious but permitted. That same read
followed by an outbound POST three turns later triggers `EXFIL_CHAIN_PRECURSOR`.
Moshe tracks taint, provenance, and risk counters across the entire session — not
just the current action.

**In-process, no network hop.**
Moshe runs as a library inside your existing agent runtime. No sidecar, no proxy,
no extra infrastructure. Add it with a one-line import.

**TypeScript and Python, same mental model.**
Identical 7-stage pipeline, identical concepts, identical defaults. No context
switch when working across stacks.

**Composable at every layer.**
Plug in custom analyzers, external review services via HTTP, your own approval
backend, or multiple telemetry sinks. Nothing is hardwired.

**Vendor-agnostic.**
First-class adapters for OpenAI tool calls and Anthropic `tool_use` blocks — with
no dependency on either vendor SDK. Works with any agent framework or custom
runner.

---

## What It Protects Against

| Threat | How Moshe Handles It |
|---|---|
| Prompt injection → destructive command | `forbiddenCommands` rules; `CommandIntentAnalyzer` detects encoded payloads and pipe-to-shell patterns |
| Sensitive credential access | `forbiddenFiles` / `sensitiveFiles` block or review access to `.env`, `id_rsa`, and similar |
| Data exfiltration chain | Taint engine marks the session after a sensitive read; a later outbound request triggers `EXFIL_CHAIN_PRECURSOR` |
| Outbound to attacker-controlled domain | `outboundRules` with exact match, subdomain wildcard (`*.evil.com`), or local-network detection |
| Mass recipient messaging | `recipientThreshold` blocks sends above the configured limit |
| Tainted artifact propagation | Writes that reference tainted artifacts inherit taint — tracked across the artifact store with full provenance chains |
| Runaway escalation | `reviewCount` and `blockCount` escalate session `riskLevel`; `CHAIN_RISK_HIGH` locks down further high-risk operations |
| Agent-authored code execution | `agentAuthored` flag triggers `AGENT_AUTHORED_EXECUTION` review before the generated code runs |

---

## Feature Overview

| Feature | TypeScript | Python |
|---|:---:|:---:|
| 7-stage deterministic pipeline | ✓ | ✓ |
| Static policy engine (commands, files, outbound, recipients) | ✓ | ✓ |
| Intent analyzers (command, file enumeration, outbound classification) | ✓ | ✓ |
| Outbound and network guard (domain, wildcard, local-network) | ✓ | ✓ |
| Taint and provenance engine | ✓ | ✓ |
| Advanced lineage (BFS traversal, cycle detection, configurable depth) | ✓ | ✓ |
| Chain risk and session context (EXFIL precursor, CHAIN_RISK_HIGH) | ✓ | ✓ |
| Approval workflows (in-process, ALLOW_ONCE, ALLOW_SESSION replay) | ✓ | ✓ |
| Semantic review plugin (Noop / Callback / HTTP decision provider) | ✓ | ✓ |
| Policy presets (coding agent, browsing agent, assistant with tools) | ✓ | ✓ |
| Telemetry pipeline and feedback (false-positive / false-negative) | ✓ | ✓ |
| GenericAdapter | ✓ | ✓ |
| OpenAI tool-call adapter | ✓ | ✓ |
| Anthropic tool-use adapter | ✓ | ✓ |
| MemoryStore | ✓ | ✓ |
| FileStore | ✓ | — |
| Zero mandatory runtime dependencies | ✓ | ✓ |

---

## Use Cases

### Coding Agent

A coding agent with shell access and unrestricted file writes is one of the
highest-risk agent configurations in existence. Moshe provides policy-enforced
boundaries: block destructive commands, review writes to sensitive paths, and flag
taint when the agent reads its own outputs and later tries to execute them.

### Browsing and Research Agent

Outbound requests are the primary exfil surface for a browsing agent. Moshe
blocks known bad domains, detects raw-IP targets, and catches staged exfil chains
where the agent reads sensitive data and later attempts to POST it externally.

### Email and Communication Agent

Moshe enforces recipient limits and blocks outbound sends to unconfigured domains,
preventing a compromised agent from becoming a mass mailer or leaking data through
a communication channel.

### Autonomous Multi-Step Workflow

For long-running unattended agents, chain risk memory is essential. Moshe
escalates session risk level as blocks and reviews accumulate, reaching a lockdown
state before a compromised agent can cause serious damage — without requiring
human intervention at every step.

---

## How It Works

Every action passes through a deterministic 7-stage pipeline:

```
ActionEnvelope
     │
     ▼
1. Normalize      — validate shape, fill defaults
2. Enrich         — load policy, session state, artifact context
3. StaticPolicy   — deterministic rule evaluation (block / review / allow)
4. Analyze        — intent analyzers + taint engine + chain risk + plugins
5. ApprovalCheck  — replay stored approvals or invoke approval provider
6. Compose        — merge all stage outputs into the final DecisionEnvelope
7. Telemetry      — publish pipeline events to configured sinks
     │
     ▼
DecisionEnvelope  →  ALLOW | REVIEW | BLOCK
```

`ALLOW` is the only outcome that reaches the real side effect. The adapter layer
ensures this invariant at the call site — `execute()` is never called on `BLOCK`
or `REVIEW`.

---

## Installation

**TypeScript:**

```bash
pnpm add @moshesdk/sdk
# or
npm install @moshesdk/sdk
```

> The TypeScript SDK is ESM-first. Use `import` (or dynamic `import()`), not
> CommonJS `require()`.

**Python:**

```bash
pip install moshe
```

No transitive runtime dependencies in either SDK.

---

## Quick Start

**TypeScript:**

```typescript
import { GenericAdapter, MemoryStore, Moshe } from '@moshesdk/sdk';

const moshe = new Moshe({
  policy: {
    forbiddenCommands: ['rm\\s+-rf'],
    forbiddenFiles: ['.env'],
    sensitiveFiles: ['id_rsa'],
    outboundRules: [{ pattern: 'pastebin.com', action: 'block' }]
  },
  store: new MemoryStore(),
  onError: 'BLOCK',
  onUnhandledReview: 'BLOCK'
});

const session = moshe.withSession('run-001');
const adapter = new GenericAdapter(session, { framework: 'my-agent' });

// execute() is only called if the engine returns ALLOW
const output = await adapter.wrapCommand({
  command: 'ls -la',
  toolName: 'shell',
  execute: async () => runShell('ls -la')
});
```

**Python:**

```python
from moshe import GenericAdapter, MemoryStore, Moshe, PolicyConfig

moshe = Moshe(
    policy=PolicyConfig(
        forbidden_commands=[r"rm\s+-rf"],
        forbidden_files=[".env"],
        sensitive_files=["id_rsa"],
    ),
    store=MemoryStore(),
    on_error="BLOCK",
    on_unhandled_review="BLOCK",
)

session = moshe.with_session("run-001")
adapter = GenericAdapter(session, framework="my-agent")

output = await adapter.wrap_command(
    command="ls -la",
    tool_name="shell",
    execute=lambda: run_shell("ls -la"),
)
```

> **Outbound rule evaluation order:** Rules are evaluated first-match-wins.
> The first rule whose pattern matches the target determines the outcome -
> subsequent rules are not evaluated. Place more specific `allow` rules
> **before** broader `block` rules, not after.
>
> ```json
> { "pattern": "internal.api.corp.com", "action": "allow" },
> { "pattern": "*.corp.com",            "action": "block" }
> ```
> Reversing this order would block `internal.api.corp.com`.

---

## Agent Integration Guide

### 1. One Moshe Instance Per Process

Create one `Moshe` instance for the life of your worker or process. It is
safe to share across concurrent sessions.

**TypeScript:**

```typescript
import {
  InProcessApprovalProvider,
  MemoryStore,
  MemoryTelemetrySink,
  Moshe
} from '@moshesdk/sdk';

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

**Python:**

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

### 2. One Session Per Conversation or Run

Session state is how Moshe tracks approval replay, taint, and chain risk. Use one
session per user conversation, agent run, or workflow. Session IDs are opaque
strings — use whatever is natural for your runtime.

**TypeScript:**

```typescript
const session = moshe.withSession(`run-${runId}`);
```

**Python:**

```python
session = moshe.with_session(f"run-{run_id}")
```

### 3. Choose Your Adapter

Use the adapter that matches how your agent framework delivers tool calls:

- **`GenericAdapter`** — your framework already normalises tool intent
- **`OpenAIAdapter`** — you receive OpenAI `ChatCompletionMessageToolCall` objects
- **`AnthropicAdapter`** — you receive Anthropic `ToolUseBlock` objects

**OpenAI (TypeScript):**

```typescript
import { OpenAIAdapter } from '@moshesdk/sdk';

const adapter = new OpenAIAdapter(session);
const result = await adapter.wrapToolCall({
  toolCall,            // OpenAI tool call object
  execute: async () => runTool(toolCall)
});
```

**OpenAI (Python):**

```python
from moshe import OpenAIAdapter

adapter = OpenAIAdapter(session)
result = await adapter.wrap_tool_call(
    tool_call=tool_call,
    execute=lambda: run_tool(tool_call),
)
```

**Anthropic (TypeScript):**

```typescript
import { AnthropicAdapter } from '@moshesdk/sdk';

const adapter = new AnthropicAdapter(session);
const result = await adapter.wrapToolUse({
  toolUse,             // Anthropic tool_use block
  execute: async () => runTool(toolUse)
});
```

**Anthropic (Python):**

```python
from moshe import AnthropicAdapter

adapter = AnthropicAdapter(session)
result = await adapter.wrap_tool_use(
    tool_use=tool_use,
    execute=lambda: run_tool(tool_use),
)
```

### 4. Non-Throwing Variant for Inline Handling

All `wrap*` methods throw on `BLOCK` and `REVIEW`. Every method has a `tryWrap*`
(`try_wrap_*` in Python) variant that returns an `AdapterResult` discriminated
union instead of throwing, for callers that prefer explicit branching.

**TypeScript:**

```typescript
const result = await adapter.tryWrapCommand({ command, toolName, execute });

if (result.outcome === 'ALLOW') {
  console.log(result.value);
} else if (result.outcome === 'BLOCK') {
  console.error('Blocked:', result.decision.summary);
} else {
  console.warn('Review required:', result.decision.approvalRequest);
}
```

**Python:**

```python
from moshe import AllowResult, BlockResult, ReviewResult

result = await adapter.try_wrap_command(command=cmd, tool_name="shell", execute=execute)

if isinstance(result, AllowResult):
    print(result.value)
elif isinstance(result, BlockResult):
    print("Blocked:", result.decision.summary)
else:
    print("Review required:", result.decision.approval_request)
```

### 5. Configure Review Handling

`REVIEW` is only useful when you define what happens next:

- `onUnhandledReview: 'BLOCK'` — safest default for unattended agents
- `onUnhandledReview: 'ALLOW'` — permissive mode for sandboxed environments
- `InProcessApprovalProvider` — real human-in-the-loop approval with replay
- `HttpDecisionProvider` — delegate review to an external service

In production, default to `BLOCK` until you have a deliberate approval story.

### 6. Attach Telemetry Early

Telemetry is the fastest way to debug agent safety behavior in development.

**TypeScript:**

```typescript
const sink = new MemoryTelemetrySink();
// ... build moshe with telemetrySinks: [sink] ...

const decision = await session.evaluate(action);
console.log(sink.getDecisionEvent(action.actionId));
```

**Python:**

```python
sink = MemoryTelemetrySink()
# ... build moshe with telemetry_sinks=[sink] ...

decision = await session.evaluate(...)
print(sink.get_decision_event(action_id))
```

### 7. Start Small With Policy

A strong first production policy:

- Block obviously destructive commands
- Block known exfil domains
- Review sensitive file access
- Review or block mass-recipient actions

You do not need to model every risk on day one. Moshe is most effective when
guarding a few high-value boundaries first.

---

## Recommended Patterns

**Pattern A — Safety Gate Around Existing Tools**
You already have an agent framework and need a policy/approval layer.
Use: `Moshe` + `MemoryStore` + `GenericAdapter`.

**Pattern B — Vendor Tool-Call Interception**
Your model emits OpenAI or Anthropic tool calls directly.
Use: `OpenAIAdapter` or `AnthropicAdapter` with `MosheSession` or root `Moshe`.

**Pattern C — Centralised Review Service**
One shared safety backend across many agent workers.
Use: `HttpDecisionProvider` + telemetry sinks + a persistent store implementation.

---

## Repository Layout

```
packages/
  moshe-spec/              TypeScript types, schemas, validators (@moshesdk/spec)
  moshe-core/              Engine, policy, analyzers, taint, chain risk (@moshesdk/core)
  moshe-store-memory/      In-memory store (@moshesdk/store-memory)
  moshe-store-file/        File-backed store (@moshesdk/store-file)
  moshe-adapter-generic-tools/  GenericAdapter (@moshesdk/adapter-generic-tools)
  moshe-adapter-openai/    OpenAI tool-call adapter (@moshesdk/adapter-openai)
  moshe-adapter-anthropic/ Anthropic tool-use adapter (@moshesdk/adapter-anthropic)
  moshe-sdk-ts/            TypeScript SDK entry point (@moshesdk/sdk)
  moshe-sdk-python/        Python SDK (moshe on PyPI)
examples/
  minimal-ts/              End-to-end TypeScript example
docs/
  architecture/CHARTER.md  Package dependency rules, pipeline contract
  spec/SCHEMAS.md          Schema reference
  Versions.md              Changelog
```

---

## Development

**TypeScript workspace:**

```bash
npx pnpm@9.15.9 install
npx pnpm@9.15.9 build
npx pnpm@9.15.9 test
node examples/minimal-ts/index.js
```

**Python package:**

```bash
cd packages/moshe-sdk-python
python -m pip install -e ".[dev]"
python -m pytest
python -m mypy src
```

**Full check (build + test + example):**

```bash
npx pnpm@9.15.9 check
```

---

## Documentation

- [Architecture Charter](./docs/architecture/CHARTER.md)
- [Schema Reference](./docs/spec/SCHEMAS.md)
- [Changelog](./docs/Versions.md)

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request, and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Security

Please do not open public GitHub issues for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
