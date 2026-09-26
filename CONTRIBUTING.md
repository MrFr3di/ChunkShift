# Contributing to ChunkShift

Thank you for helping improve ChunkShift.

ChunkShift is a low-level .NET library with persisted identities, binary formats, deterministic chunking, and streaming lifetime rules. Small changes are welcome, but changes that affect observable or persisted behavior need stronger review because downstream consumers may depend on them for years.

## Contribution decision tree

```text
Security vulnerability?
├─ yes -> follow SECURITY.md; do not open a public issue
└─ no
   |
   Docs / typo / test clarity only?
   ├─ yes -> a focused PR is usually enough
   └─ no
      |
      Public API, persisted format/identity, deterministic output,
      ownership/cancellation, or support-surface change?
      ├─ yes -> governing issue/spec first
      └─ no
         |
         Hot-path / performance change?
         ├─ yes -> define the measurement plan + benchmark evidence
         └─ no -> issue recommended; focused PR + tests
```

## Start here

Before opening a pull request:

1. Search existing issues and pull requests.
2. For a small bug fix, test improvement, or documentation correction, a pull request is usually enough.
3. For a new feature or a change to public API, persisted formats, profile/hash identities, security boundaries, or observable behavior, open or link an issue first.
4. Read [`AGENTS.md`](AGENTS.md) if you use a coding agent or automation.
5. Keep the change focused on one problem.

Draft pull requests are welcome when you want early design feedback.

You do not need to update `CHANGELOG.md` for every contribution. Release notes are curated at release time to avoid merge conflicts and noisy changelog entries.

## Development setup

Requirements:

- .NET 10 SDK;
- .NET 8 runtime for the `net8.0` test target;
- Git.

Restore, build, and test:

```bash
dotnet restore ChunkShift.slnx
dotnet build ChunkShift.slnx -c Release --no-restore
dotnet test ChunkShift.slnx -c Release --no-build --no-restore
```

When working on a narrow area, run the smallest relevant test set while iterating. Run the repository-required checks before considering the change complete.

CI is authoritative for the final merge decision.

## Choose the right contribution path

| Change | Before coding | Expected validation |
| --- | --- | --- |
| Docs, typo, comments | PR is usually enough | relevant docs/build checks |
| Bug fix with no contract change | existing or new issue is helpful | targeted tests + normal build/test |
| New behavior or API | issue/design discussion first | tests + compatibility review |
| CSM/profile/hash/persisted identity | governing issue/spec required | vectors + compatibility validation |
| Security/parser/resource-bound change | issue or private security report, depending on sensitivity | hostile-input/resource tests |
| Hot-path/performance change | explain hypothesis first | project benchmark evidence |
| NativeAOT/trim-sensitive change | identify the affected path | package-consumer/AOT validation |

If you are unsure which path applies, open an issue with the problem you are trying to solve. You do not need to arrive with a complete design.

## Architecture and compatibility rules

For compatibility-sensitive work, read the relevant document under `docs/architecture/` before editing implementation code.

In particular:

- Core must remain usable without ASP.NET Core, dependency injection, repository/storage, or transport-specific types.
- Do not introduce public strategy abstractions such as `IChunker`, `IChunkHasher`, or similar extension points without a demonstrated substitution need and an accepted design decision.
- Existing CSM, ProfileId/ProfileFingerprint, HashSuite, and manifest identity semantics are contracts.
- Optimizations must not silently change chunk boundaries, persisted IDs, format semantics, or deterministic output.
- Streaming paths must remain bounded-memory.
- Streams passed to Core remain caller-owned unless an API explicitly says otherwise.
- Borrowed chunk memory must not outlive its documented callback lease.
- Cancellation is cooperative; an already-running handler is not forcibly preempted.
- Golden/conformance vectors are evidence. Do not regenerate them merely to make an implementation change pass.

If a change intentionally alters a compatibility contract, make that explicit in the issue and pull request.

## Branches

Do not work directly on `main`.

For maintainer branches, use:

```text
<type>/<issue>-<short-slug>
```

Examples:

```text
fix/123-short-read-boundary
feat/140-manifest-inspection
perf/151-scan-loop
docs/contributing
```

This naming convention is guidance, not a requirement for contributors working from forks.

Keep branches short-lived and delete them after merge.

## Pull requests

### Title

PR titles become squash-commit titles and must follow Conventional Commits:

```text
<type>[optional scope][!]: <imperative description>
```

Common types:

- `feat` — user/developer-visible capability;
- `fix` — bug fix;
- `perf` — measured performance improvement;
- `refactor` — behavior-preserving structural change;
- `docs` — documentation only;
- `test` — tests/fixtures only;
- `build` — build/package/dependency mechanics;
- `ci` — CI automation;
- `chore` — maintenance not covered above;
- `revert` — revert an earlier change.

Examples:

```text
fix(core): preserve chunk sequence across short reads
perf(core): reduce scan-loop bounds checks
docs: clarify borrowed-memory lifetime
feat(core)!: change manifest verification behavior
```

Use `!` for an intentional breaking change and explain the impact and migration path in the PR body.

Intermediate branch commits may be WIP/fixup commits. They do not need to follow Conventional Commits because normal PRs are squash-merged.

### Body

A good PR explains:

- the problem and related issue;
- the important design or implementation choices;
- how the change was validated;
- public API, persisted-format, deterministic-output, or compatibility impact;
- benchmark evidence when making a performance claim;
- any follow-up work intentionally left out.

Use `Closes #N` only when the PR fully completes the issue. Otherwise use `Refs #N`.

Do not mix unrelated cleanup, formatting, or opportunistic refactors into the same PR.

## Tests and evidence

Tests should prove the behavior being changed, not only increase coverage.

For normal code changes:

```bash
dotnet restore ChunkShift.slnx
dotnet build ChunkShift.slnx -c Release --no-restore
dotnet test ChunkShift.slnx -c Release --no-build --no-restore
```

For compatibility-sensitive changes, additional evidence may be required:

- independent FastCDC reference vectors;
- independent CSM generator/decoder fixtures;
- x64/ARM64 deterministic comparison;
- JIT/NativeAOT package-consumer validation;
- fuzzing or malformed-input tests;
- larger-than-memory/resource-bound validation;
- real-host validation where transport behavior matters.

Do not claim a performance improvement from a stopwatch-only run. Use the project benchmark harness and report enough raw data for the result to be reviewed.

## Dependencies

Adding a dependency is a design decision, not just a package-reference change.

A dependency PR should explain:

- why the dependency is needed;
- why the functionality does not belong in the BCL or existing dependency set;
- runtime/package-size/AOT/trimming implications;
- license and security considerations.

Avoid adding dependencies for hypothetical future use.

## Security

Do not open a public issue for a vulnerability that could enable exploitation, data corruption, denial of service, authenticity bypass, or unsafe parser behavior.

Follow [`SECURITY.md`](SECURITY.md) and use GitHub private vulnerability reporting when enabled.

Ordinary correctness bugs that are not security-sensitive can use the normal issue flow.

## AI-assisted contributions

AI-assisted contributions are welcome.

The submitting contributor remains responsible for the change:

- understand the code you submit;
- review generated changes before opening a PR;
- verify tests and claims yourself;
- do not fabricate benchmark results, citations, or validation;
- follow [`AGENTS.md`](AGENTS.md) when an agent edits the repository.

You do not need to advertise which editor, model, or agent produced routine implementation text unless that information is relevant to reviewing the change.

## Review and merge

Reviewers prioritize:

1. correctness;
2. compatibility and deterministic behavior;
3. security and resource bounds;
4. ownership/cancellation/lifetime semantics;
5. performance and allocations on hot paths;
6. NativeAOT/trimming/cross-platform behavior;
7. maintainability.

Review should stay scoped to the contribution. Unrelated cleanup is normally a separate issue or PR.

Before merge:

- required CI checks must pass;
- review conversations must be resolved;
- compatibility/performance evidence must be present when required;
- the PR must remain one logical change.

ChunkShift uses squash merge for normal pull requests. Contributors do not need to rewrite branch history to make it pretty before review.

## Contributor paperwork

ChunkShift does not require a CLA, DCO sign-off, or signed contributor commits unless the repository policy changes explicitly.

By submitting a contribution, you confirm that you have the right to contribute it under the repository's license.

## Need help?

If the contribution rules are unclear, open an issue describing the problem or intended change.

A good problem statement is more useful than a premature implementation.
