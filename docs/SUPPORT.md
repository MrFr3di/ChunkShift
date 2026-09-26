# Support and validation matrix

Status: Active pre-1.0 policy  
Last reviewed: 2026-09-27

This document separates **package target compatibility**, **continuously tested environments** and **architecture validation targets**.

## Runtime and package targets

| Surface | Status | Notes |
| --- | --- | --- |
| .NET 10 (`net10.0`) | recommended target | LTS; development and runtime baseline |
| .NET 8 (`net8.0`) | compatibility target | the package and tests target it; Microsoft support ends 2026-11-10 |
| Windows x64 | tested on every PR | `build-test` (CI) |
| Linux x64 | tested on every PR | `build-test`, `package-smoke` (CI) and the conformance lanes |
| Linux ARM64 | tested by the conformance workflow | NativeAOT package consumer and cross-architecture determinism; runs on relevant PRs, weekly and before release |
| Windows ARM64 | architecture target | continuous validation is added when usage warrants it |
| macOS | best effort | no compatibility promise until CI evidence exists |

Compatibility with a target framework is not the same as vendor support for the runtime. See the [.NET support policy](https://dotnet.microsoft.com/platform/support/policy/dotnet-core) for runtime lifecycles. Dropping `net8.0` after its end of support is a package-surface change and is announced in the release notes.

## NativeAOT and trimming

Core is NativeAOT- and trim-compatible. `IsAotCompatible=true` alone is not treated as evidence: the conformance and release workflows publish a clean consumer of the produced package with `PublishAot=true` and `PublishTrimmed=true` and compare its output with the JIT consumer.

ASP.NET Core hosting may have its own AOT constraints, but it does not leak host requirements into Core ([ASPNET-CORE.md](ASPNET-CORE.md)).

## Determinism

The same input, profile and HashSuite produce identical chunk boundaries and identities on every supported architecture and execution mode. The conformance workflow checks this on each run: x64 and ARM64 NativeAOT consumers must produce byte-identical evidence, and each must match its JIT counterpart. Running ARM64 outside the per-PR lane does not weaken the requirement.

## Pre-1.0 support policy

ChunkShift follows the `0.1.Z` release train described in [RELEASES.md](RELEASES.md).

Before `1.0.0`:

- breaking API changes are possible but always explicit in the release notes;
- persisted identifiers and formats follow their own compatibility rules and never change silently;
- users should upgrade to the latest `0.1.Z` release for fixes;
- security fixes are not guaranteed to be backported to older pre-1.0 releases.

The support promise for `1.0.0` will be defined by a separate compatibility decision.
