# Changelog

All notable user-facing changes to ChunkShift are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). ChunkShift uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the pre-1.0 patch-train policy defined in [docs/RELEASES.md](docs/RELEASES.md).

## [Unreleased]

## [0.1.1-rc.1] - 2026-11-23

First release of `ChunkShift.Patching`, published together with ChunkShift Core `0.1.1-rc.1`. Both packages share one version from now on.

### Added

- New package `ChunkShift.Patching` (`net10.0`): verified binary patches over CSM manifests in the CSP v1 format.
  - `ChunkPatch.PlanAsync` reports the reuse between a base and a target manifest before anything is built.
  - `ChunkPatch.CreateAsync` writes base-dependent or self-contained patches. A patch carries the target manifest and only the chunks the base does not already have, raw or as a zstd frame that can use up to four base chunks as a dictionary.
  - `ChunkPatch.ApplyAsync` checks every chunk against its identity and publishes the destination only after every check has passed; integrity failures are reported through `PatchApplyResult`, and the destination keeps its previous content.
  - Apply also re-chunks the reconstruction and compares it with the embedded manifest, can update the base file in place, and reports exceeded CSP resource limits as `PatchApplyFailure.ResourceLimit`.
  - Trimming and NativeAOT support.
- CSP v1 format specification ([docs/architecture/CSP-V1.md](https://github.com/MrFr3di/ChunkShift/blob/main/docs/architecture/CSP-V1.md)) with committed conformance vectors and an independent Python generator, decoder and forward-only apply.

### Changed

- `Hash256.FixedTimeEquals` now delegates to `CryptographicOperations.FixedTimeEquals`, whose run time is documented to depend only on the input length. Results are unchanged.

### Compatibility

- No public API change in ChunkShift Core; every persisted identity, profile and CSM output is unchanged.
- CSP patch bytes are not a contract: a later version may encode the same inputs differently, but never reconstructs a different target.

## [0.1.0] - 2026-09-27

First public release of ChunkShift Core.

### Added

- `ChunkScanner.ScanAsync`: forward-only, bounded-memory content-defined chunking of any `Stream`, with ordered, backpressured callbacks over borrowed chunk memory and cooperative cancellation.
- Stable default chunking profile `fastcdc.gear.chunkshift.v1.64k` (FastCDC, 16 / 64 / 256 KiB) with ProfileFingerprint `054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0`.
- HashSuites `chunkshift.blake3-256.v1` (default) and `chunkshift.sha256.v1` for 256-bit `ChunkId` and `ManifestId` identities.
- CSM v1 binary manifests: `ChunkManifest.CreateAsync`, `VerifyAsync` and `VerifyManifestAsync`, and the streaming `ManifestReader`, with an optional block index (BIDX).
- Verification results that separate block CRC, logical totals, `ManifestId`, physical `FileDigest`, profile semantics and content mismatches.
- `net8.0` and `net10.0` targets; trimming and NativeAOT support.

[Unreleased]: https://github.com/MrFr3di/ChunkShift/compare/v0.1.1-rc.1...HEAD
[0.1.1-rc.1]: https://github.com/MrFr3di/ChunkShift/releases/tag/v0.1.1-rc.1
[0.1.0]: https://github.com/MrFr3di/ChunkShift/releases/tag/v0.1.0
