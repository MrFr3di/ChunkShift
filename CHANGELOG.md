# Changelog

All notable user-facing changes to ChunkShift are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). ChunkShift uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the pre-1.0 patch-train policy defined in [docs/RELEASES.md](docs/RELEASES.md).

## [Unreleased]

The first public release is `0.1.0`.

### Added

- `ChunkScanner.ScanAsync`: forward-only, bounded-memory content-defined chunking of any `Stream`, with ordered, backpressured callbacks over borrowed chunk memory and cooperative cancellation.
- Stable default chunking profile `fastcdc.gear.chunkshift.v1.64k` (FastCDC, 16 / 64 / 256 KiB) with ProfileFingerprint `054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0`.
- HashSuites `chunkshift.blake3-256.v1` (default) and `chunkshift.sha256.v1` for 256-bit `ChunkId` and `ManifestId` identities.
- CSM v1 binary manifests: `ChunkManifest.CreateAsync`, `VerifyAsync` and `VerifyManifestAsync`, and the streaming `ManifestReader`, with an optional block index (BIDX).
- Verification results that separate block CRC, logical totals, `ManifestId`, physical `FileDigest`, profile semantics and content mismatches.
- `net8.0` and `net10.0` targets; trimming and NativeAOT support.

[Unreleased]: https://github.com/MrFr3di/ChunkShift/commits/main
