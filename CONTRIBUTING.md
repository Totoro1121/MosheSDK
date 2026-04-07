# Contributing to MosheSDK

Thank you for your interest in contributing. This document covers how to get
the project running locally, the coding standards we follow, and the pull
request process.

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.

---

## Getting Started

### TypeScript workspace

Requires Node.js ≥ 18 and pnpm 9.

```bash
npx pnpm@9.15.9 install
npx pnpm@9.15.9 build
npx pnpm@9.15.9 test
```

### Python package

Requires Python ≥ 3.11.

```bash
cd packages/moshe-sdk-python
python -m pip install -e ".[dev]"
python -m pytest
python -m mypy src
```

### Full CI check

```bash
npx pnpm@9.15.9 check   # build + TypeScript tests + minimal example
```

All of these must pass before a PR is submitted.

---

## Project Structure

The repository is a pnpm workspace (TypeScript) plus a standalone Python package.
See the [Architecture Charter](docs/architecture/CHARTER.md) for the package
dependency graph and pipeline contract.

---

## Coding Standards

### TypeScript

- `strict: true` TypeScript throughout
- No `any` casts in production code paths
- Each package's public API is determined by its `index.ts` re-exports only
- Analyzers must not read `ActionEnvelope.metadata`
- New required fields on `ActionEnvelope` or `DecisionEnvelope` are not accepted —
  use optional fields only

### Python

- `mypy --strict` clean on all source files
- `snake_case` everywhere; frozen dataclasses for value objects
- Zero new mandatory dependencies — stdlib only
- No `# type: ignore` in production code unless unavoidable and explained

### Both

- Every new feature needs tests
- Deterministic-first: features must work without any model call
- No version bumps in PRs unless explicitly part of the change

---

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes. Add tests. Ensure `pnpm check` and Python tests pass.
3. Open a pull request against `main` using the PR template.
4. A maintainer will review within a reasonable time. Please be patient.
5. Address review feedback. Once approved, a maintainer will merge.

Small, focused PRs are much easier to review than large ones. If you are
planning a significant change, open an issue first to discuss the approach.

---

## Reporting Bugs

Open a GitHub issue using the bug report template. Include steps to reproduce,
expected behaviour, and the environment (Node version, Python version, OS).

---

## Suggesting Features

Open a GitHub issue using the feature request template. Describe the use case
and proposed API before writing code.

---

## Release Process

MosheSDK follows [Semantic Versioning](https://semver.org/).

During the `0.x` series: minor version bumps (`0.1 → 0.2`) may include breaking
API changes announced in [docs/Versions.md](docs/Versions.md). Patch bumps
(`0.1.0 → 0.1.1`) are backwards-compatible fixes only. The API stabilises at
`1.0.0`.

### Steps to cut a release (maintainers only)

1. Update `version` in every `packages/*/package.json` and in
   `packages/moshe-sdk-python/pyproject.toml`.
2. Add a release entry to [docs/Versions.md](docs/Versions.md).
3. Commit: `git commit -m "chore: release vX.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push origin main --tags`

### Publishing

**TypeScript** — all eight `@moshe/*` packages:

```bash
pnpm -r publish --access public
```

**Python:**

```bash
cd packages/moshe-sdk-python
python -m pip install build twine
python -m build
twine upload dist/*
```
