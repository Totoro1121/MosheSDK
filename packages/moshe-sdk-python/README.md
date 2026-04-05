# moshe

Python SDK for [MosheSDK](../../README.md) — runtime security for AI agents.

## Installation

```bash
pip install moshe
```

Requires Python ≥ 3.11. Zero mandatory runtime dependencies.

## Quick Start

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

result = await adapter.wrap_command(
    command="ls -la",
    tool_name="shell",
    execute=lambda: run_shell("ls -la"),
)
```

## Adapters

```python
from moshe import OpenAIAdapter, AnthropicAdapter

# OpenAI tool calls
adapter = OpenAIAdapter(session)
result = await adapter.wrap_tool_call(tool_call=tc, execute=lambda: run(tc))

# Anthropic tool_use blocks
adapter = AnthropicAdapter(session)
result = await adapter.wrap_tool_use(tool_use=tu, execute=lambda: run(tu))
```

## Documentation

See the [root README](../../README.md) for the full integration guide, feature
overview, and use cases.
