# AGENTS.md

This file contains standing repository instructions for coding agents working on ChunkShift.

Keep this file concise. Read only the project material needed for the task; do not load the entire documentation tree for routine changes.

## Scope and precedence

- Follow the user's explicit task and the host agent's higher-priority instructions.
- This root `AGENTS.md` applies repository-wide.
- If a deeper directory contains its own `AGENTS.md`, use it only to refine rules for that subtree. It must not weaken repository-wide compatibility, security, or release constraints.
- Avoid duplicating these rules into `CLAUDE.md`, `GEMINI.md`, or tool-specific instruction files unless a concrete harness requires additional behavior. `AGENTS.md` is the canonical cross-agent instruction file.
- If repository instructions, normative specifications, tests, and committed compatibility vectors disagree, do not silently choose one and rewrite the others. Report the inconsistency.

## Investigate before changing

- Open the files relevant to the requested change before making claims about their behavior.
- Search for the nearest tests and governing architecture/specification when the change can affect public API, persisted data, deterministic output, ownership, cancellation, security, or performance.
- Do not infer implementation behavior from README examples alone.
- Prefer repository truth over assumptions from prior tasks, cached context, or external copies.

## Keep the change narrow

- Make the smallest coherent change that solves the requested problem.
- Do not refactor neighboring code, rename unrelated symbols, reformat unrelated files, or add configurability "for later" unless required by the task.
- Do not create helper abstractions, interfaces, files, or dependencies for hypothetical future use.
- Remove temporary scripts/files created only for investigation before finishing, unless they are intentionally part of the requested change.
- Preserve existing public behavior unless the task explicitly authorizes a compatibility change.

## Core architecture boundaries

Unless an accepted compatibility decision explicitly changes them:

- `ChunkShift` Core remains usable without ASP.NET Core, dependency injection, repository/storage implementations, or transport-specific types.
- Do not add public strategy abstractions such as `IChunker`, `IChunkHasher`, `IRepository`, or similar extension-point interfaces without a demonstrated substitution need.
- Prefer a small public surface: concrete types and delegates are preferred when they express the actual contract.
- Streaming paths must remain bounded-memory; do not materialize complete inputs or manifests merely for convenience.
- Caller-provided streams remain caller-owned unless an API explicitly transfers ownership.
- Borrowed chunk memory is valid only for its documented callback lease.
- Scanner callbacks remain ordered and non-concurrent unless the public contract explicitly changes.
- Cancellation is cooperative; do not introduce hidden preemption semantics.
- Host policy stays outside Core: authentication, authorization, request limits, decompression, rate limiting, caching, and transport policy belong to the host.

## Compatibility invariants

Treat the following as compatibility-sensitive:

- public API and exceptions/results;
- CSM persisted representation and verification semantics;
- `ProfileId` / `ProfileFingerprint`;
- HashSuite identifiers and hash domains;
- `ManifestId` / `FileDigest` meaning;
- FastCDC boundary semantics and deterministic chunk sequences;
- stream ownership and borrowed-memory lifetime;
- supported target/runtime behavior;
- NativeAOT/trimming behavior.

Rules:

- Never silently reinterpret an existing persisted identifier.
- An optimization must preserve exact persisted semantics and deterministic output unless a reviewed compatibility change says otherwise.
- Do not update golden/conformance vectors merely because a new implementation disagrees with them. Investigate the mismatch first.
- Keep logical identity separate from physical representation: `ManifestId` is not a substitute for the physical `FileDigest`.
- A cryptographic content hash proves integrity relative to an expected value; it is not an authenticity/signature guarantee.
- A NuGet/package version change does not itself authorize a persisted-format or identity change.
- A change to the BLAKE3 implementation or its package version (`Blake3` in `Directory.Packages.props`) is compatibility-sensitive, even as a dependency-only update: it must reproduce every persisted BLAKE3/`ChunkId`/`ManifestId` conformance vector before merge, and swapping the implementation never changes a `HashSuiteId`.
- Once a public API baseline is shipped, treat it as a downstream consumer contract and use package/API compatibility tooling rather than source compilation alone.

## Code style and implementation quality

- Follow `.editorconfig`, analyzers, compiler diagnostics, and the established style in the touched area.
- Do not suppress warnings or analyzer diagnostics merely to make CI green. Fix the issue or document a justified suppression.
- Prefer BCL/runtime primitives and the existing dependency set.
- A new runtime dependency requires a concrete need plus review of AOT/trimming, package size, transitive dependencies, licensing, security, and maintenance impact.
- Avoid reflection/convention discovery when a simple strongly typed path is sufficient, especially on public or NativeAOT-sensitive paths.
- Validate at system boundaries; do not add speculative defensive layers to impossible internal states.
- Tests should verify general behavior, not hard-code around one fixture or expected test input.

## Validation

Use risk-based validation. Do not run expensive repository-wide checks for a documentation-only edit unless the change affects generated content, commands, or build/release behavior.

For normal code changes, run:

```bash
dotnet restore ChunkShift.slnx
dotnet build ChunkShift.slnx -c Release --no-restore
dotnet test ChunkShift.slnx -c Release --no-build --no-restore
```

Run narrower relevant tests while iterating. Before completion, run the checks appropriate to the affected contract:

| Area changed | Additional evidence to consider |
| --- | --- |
| Public API / package | PublicAPI + package validation + clean package consumer |
| FastCDC / profile | deterministic vectors + independent reference + unchanged identity evidence |
| CSM parser/writer | independent fixtures/decoder + malformed/corrupt cases |
| NativeAOT / trimming | package consumer + AOT/trim validation |
| Security / parser bounds | hostile-input, fuzz, checked-arithmetic, resource-bound tests |
| Hot path / performance | repeatable benchmark (for example BenchmarkDotNet) with comparable baseline/candidate samples |
| Host integration | real Kestrel/host check against `docs/ASPNET-CORE.md` when transport behavior matters |
| Cross-platform deterministic behavior | x64/ARM64 comparison |

Do not claim a performance improvement from a single stopwatch run. Record the baseline/candidate identity, workload, environment, repeated samples, useful summary statistics, and output-equivalence evidence.

If a relevant heavy check can only run in CI, state that clearly instead of claiming it was executed locally.

## Safe autonomy

Local, reversible work is normally safe: reading files, editing the requested scope, running tests, and fixing failures caused by the requested change.

Do not perform hard-to-reverse or externally visible operations unless the task explicitly authorizes them, including:

- force-pushing or rewriting published history;
- deleting branches/tags or destructive cleanup;
- creating or publishing release tags;
- publishing NuGet packages or other release artifacts;
- changing repository/security settings;
- posting comments, closing issues, merging PRs, or modifying shared infrastructure when the task did not request those actions;
- bypassing hooks, required checks, or safety gates as a shortcut.

When blocked, report the blocker rather than weakening a safety or compatibility gate.

## Security

- Treat binary parsers, sizes/counts/offsets, decompression, file publication, pooled-memory lifetime, and integrity handling as security-sensitive boundaries.
- Use checked arithmetic and explicit resource bounds where external data controls sizes or offsets.
- Do not expose suspected exploitable vulnerabilities in a public issue or PR. Follow `SECURITY.md`.
- Do not commit secrets, credentials, tokens, private keys, or captured production data.
- Do not weaken pinned-action, least-privilege, dependency-review, or release-integrity controls incidentally.

## Git and pull requests

Follow `CONTRIBUTING.md` for contributor workflow.

For agent-authored repository changes:

- work from a non-`main` branch unless the environment explicitly provides a different safe workflow;
- keep one logical change per PR;
- use the repository's Conventional-Commit PR-title convention;
- intermediate commits may be WIP/fixup when the PR will be squash-merged;
- do not add "generated by", model names, agent signatures, or similar attribution to code, commits, or PR text unless the user asks for it or policy requires it.

## Completion

Before reporting completion:

- inspect the final diff for accidental scope expansion;
- verify no temporary files or debug changes remain;
- report the files changed;
- report the validation actually run and its result;
- call out validation not run, unresolved risks, or compatibility implications;
- never invent command output, benchmark data, source citations, CI status, or test results.
