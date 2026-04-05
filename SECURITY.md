# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✓ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, email the maintainers privately at:

```
kejun.cheng@prophettechnology.com
```

Include:

- A description of the vulnerability
- Steps to reproduce or a minimal proof of concept
- The potential impact
- Any suggested mitigations if you have them

You will receive an acknowledgement within **72 hours** and a substantive
response within **7 days**. We will keep you informed as we work on a fix.

## Scope

In scope: the MosheSDK engine, policy evaluation logic, taint tracking,
adapters, stores, and the Python SDK.

Out of scope: third-party dependencies, issues in vendor SDKs that Moshe
adapters translate from (OpenAI, Anthropic), and the example code in `examples/`.

## Disclosure Policy

We follow coordinated disclosure. Once a fix is ready, we will:

1. Release a patched version
2. Publish a security advisory on GitHub
3. Credit the reporter (unless you prefer to remain anonymous)
