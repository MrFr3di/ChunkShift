# Release and versioning policy

Status: Active  
Last reviewed: 2026-09-27

This document is normative for package versions, Git tags, GitHub Releases and the changelog.

## 1. Versioning model

ChunkShift follows Semantic Versioning 2.0.0 and is in its major-zero initial-development phase. The first public release is `0.1.0`.

Until an explicit decision to release `1.0.0`, normal releases use one monotonic patch train:

```text
0.1.0 -> 0.1.1 -> 0.1.2 -> ...
```

- every normal release increments PATCH by one;
- `0.2.0` is not used to signal a feature release;
- features, fixes, performance changes and deliberate breaking pre-1.0 changes can all appear in the next `0.1.Z` release;
- the version number alone promises no backward compatibility before `1.0.0`;
- breaking changes are always explicit in the PR, the changelog and the release notes;
- `1.0.0` requires a separate recorded compatibility decision.

## 2. Package versions are not format versions

These compatibility domains are versioned or identified independently from the NuGet package:

- the CSM format (FormatMajor);
- HashSuite identifiers;
- chunking profiles (`ChunkingProfileId` / `ProfileFingerprint`).

A package release never silently reinterprets an existing persisted format, profile or HashSuite identifier. Changing those semantics requires a new identifier or format version, even during `0.1.Z`.

## 3. Pre-releases

When validation before a normal release is useful, use SemVer pre-release suffixes:

```text
0.1.4-alpha.1 -> 0.1.4-beta.1 -> 0.1.4-rc.1 -> 0.1.4
```

- `alpha`: incomplete or experimental;
- `beta`: feature-complete enough for broader testing;
- `rc`: expected to become the normal release unless a blocking defect appears.

CI builds of ordinary commits are not releases and never create tags.

## 4. Git tags

Each published version has exactly one tag: a lowercase `v` followed by the exact package version, for example `v0.1.0` or `v0.1.3-rc.1`.

- The release workflow creates the tag on the exact commit it built and published.
- Tags are immutable: never moved, force-updated, deleted or reused.
- There are no floating `v0` or `v0.1` aliases.

## 5. Changelog and release notes

`CHANGELOG.md` is written for users, not copied from the Git log. It follows Keep a Changelog (`Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`). The maintainer curates it in the release PR; contributors do not edit it in every PR.

Every release gets a dated changelog section and GitHub release notes, with explicit breaking-change and migration notes where they apply. GitHub-generated notes, grouped by the PR labels configured in `.github/release.yml`, are an input to the final text, not a replacement for it.

## 6. Release procedure

1. **Release PR.** Title `chore(release): prepare X.Y.Z`. It sets `VersionPrefix` in `src/ChunkShift/ChunkShift.csproj`, moves the `PublicAPI.Unshipped.txt` entries into `PublicAPI.Shipped.txt` (§8.1) and dates the changelog section. Merge it after all intended changes are on `main` and CI is green.
2. **Dry run.** Dispatch the `Release` workflow from `main` with the version and `publish_nuget: false`. Inspect the uploaded `.nupkg`, `.snupkg` and `SHA256SUMS`.
3. **Publish.** Dispatch the workflow again with `publish_nuget: true`. Approve the `release` environment deployment when prompted.
4. **Release notes.** The workflow leaves a draft GitHub Release with the packages and checksums attached. Edit the notes, then publish it. With immutable releases enabled, its tag and assets cannot change afterwards.
5. **Check.** Install the published version into a clean project from nuget.org.

The workflow refuses a version whose `X.Y.Z` differs from `VersionPrefix`, that is not higher than every version already on nuget.org, or whose tag already exists. It builds, tests, packs, inspects and consumes the package (JIT and NativeAOT) once, then publishes those exact files; nothing is rebuilt after validation.

If a release turns out to be wrong, publish a new version. Never mutate or reuse an old one.

### 6.1 Recovering a partial run

- **Package published, symbols failed:** re-push the `.snupkg` from the run's `chunkshift-<version>` artifact with `dotnet nuget push <file>.snupkg --skip-duplicate`. Re-running the workflow is refused because the version is already published.
- **Package published, `github-release` failed:** create the tag on the exact commit the run built (the run's `GITHUB_SHA`), for example `gh api repos/MrFr3di/ChunkShift/git/refs -f ref=refs/tags/v<version> -f sha=<run SHA>`, then create the draft release from the run's artifacts. Never tag a different commit.

## 7. Release infrastructure

Publication uses nuget.org [Trusted Publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing): the workflow exchanges a short-lived GitHub OIDC token for a temporary nuget.org API key. There is no long-lived NuGet API key.

Required configuration before the first publication:

1. a GitHub environment named `release`, limited to the `main` branch, with required reviewers;
2. a nuget.org Trusted Publishing policy for owner `MrFr3di`, repository `ChunkShift`, workflow file `release.yml` and environment `release`;
3. the repository or environment variable `NUGET_USER` set to the nuget.org profile name that owns the policy;
4. repository rules protecting `main` and `v*` tags, and immutable releases enabled.

Only the publishing job receives `id-token: write`, and it runs no repository code: it downloads the validated artifacts, checks their SHA-256 sums, attests their provenance and pushes them. Tag and release creation run in a separate job that holds the only `contents: write` permission.

## 8. Breaking changes before 1.0.0

A breaking change is allowed during the `0.1.Z` train only when it is deliberate. It needs:

- `!` in the Conventional Commits PR title, or a `BREAKING CHANGE:` footer;
- a compatibility and migration explanation in the PR;
- updated tests and vectors for the affected contracts;
- a prominent changelog and release-note entry.

Persisted-format and identity changes additionally follow §2.

### 8.1 Public API baseline files

The PublicAPI analyzer tracks the public surface:

- `PublicAPI.Unshipped.txt` holds every public symbol not yet in a published version. Before the first publication the whole surface lives here.
- `PublicAPI.Shipped.txt` holds the symbols of the last published version.
- Entries move from Unshipped to Shipped only in the release PR (§6 step 1), so `Shipped.txt` always describes something consumers could install.
- Removing or changing a Shipped entry is a breaking change under §8.

From the release after `0.1.0` on, package validation also compares the package with the previous published version (`PackageValidationBaselineVersion`), which catches binary breaks that source compilation misses.

## 9. Releasing 1.0.0

`1.0.0` is a separate project decision, recorded in an issue, that the public API and compatibility policy are ready for SemVer stability. After it, PATCH is for compatible fixes, MINOR for compatible features and MAJOR for incompatible API changes.

## 10. References

- [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
- [NuGet package versioning](https://learn.microsoft.com/nuget/concepts/package-versioning)
- [.NET library versioning](https://learn.microsoft.com/dotnet/standard/library-guidance/versioning)
- [NuGet Trusted Publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing)
- [.NET package validation](https://learn.microsoft.com/dotnet/fundamentals/apicompat/package-validation/overview)
- [GitHub immutable releases](https://docs.github.com/code-security/concepts/supply-chain-security/immutable-releases)
- [GitHub automatically generated release notes](https://docs.github.com/repositories/releasing-projects-on-github/automatically-generated-release-notes)
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
