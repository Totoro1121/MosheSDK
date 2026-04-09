# Versions

## 0.1.2 - Current

npm follow-up release that replaces publish-time `workspace:*` internal
dependencies in all TypeScript packages with concrete semver dependencies to
support clean installs from the public npm registry.

## 0.1.1

Patch release following the first PyPI publish, adding the missing Python
`moshe.__version__` export required by the release verification script.

## 0.1.0

Initial public release line for MosheSDK.

Included in the current codebase:

- TypeScript spec, core engine, memory store, file store, and top-level SDK
- deterministic policy evaluation, approval/replay, intent analyzers, taint/provenance, chain-risk, and lineage
- telemetry sinks and feedback submission
- generic, OpenAI, and Anthropic adapters for TypeScript
- standalone Python SDK with generic, OpenAI, and Anthropic adapters
