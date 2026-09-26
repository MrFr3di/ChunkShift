# Core 0.1 public API contract

Status: Frozen API candidate for the first published `ChunkShift` package  
Last reviewed: 2026-09-27  
Surface of record: [`src/ChunkShift/PublicAPI.Unshipped.txt`](../../src/ChunkShift/PublicAPI.Unshipped.txt) (moves to `PublicAPI.Shipped.txt` in the release PR that first publishes it; see [RELEASES.md §8.1](../RELEASES.md#81-public-api-baseline-files))

This document states what the Core 0.1 public surface promises and which tests pin each promise. The PublicAPI analyzer fails the build on any unrecorded surface change.

## 1. Change policy

- A new public Core member needs concrete evidence: a defect, or a consumer that cannot work without it. Propose it in an issue first.
- Until the first publication, `PublicAPI.Unshipped.txt` may change only through reviewed PRs under that rule. After it, removing or changing a shipped entry is a breaking change ([RELEASES.md §8](../RELEASES.md#8-breaking-changes-before-100)).
- Profile and HashSuite selection change no API shape: `ChunkingProfileId` and `HashSuiteId` are open string identities, and `null` selects the default.

## 2. Scanner

| Symbol | Contract | Pinned by |
|---|---|---|
| `ChunkScanner.ScanAsync(Stream, ChunkScanHandler, ChunkScanOptions?, CancellationToken)` | forward-only scan of any readable stream | `ChunkScannerTests` |
| `ChunkScanHandler` (delegate returning `ValueTask`) | one call per chunk; the returned task is consumed exactly once | `HandlerValueTask_IsConsumedExactlyOnce` |
| `ChunkScanOptions` (`ProfileId?`, `HashSuite?`, init-only) | `null` selects the default | `NullSelections_UseTheDefaults`, `InvalidArgumentsAndUnsupportedSemantics_FailBeforeReading` |
| `ChunkInfo` (`Index`, `Offset`: `long`; `Length`: `int`; `Id`) | shared with `ManifestReader` | `Offset_IsRelativeToBeginningOfScan` |

Behavioral contract:

- **Borrowed-memory lifetime.** `content` is valid until the returned `ValueTask` completes. Tests: `BorrowedContent_RemainsStableUntilAsyncHandlerCompletes`, `BorrowedContent_IsReusedAfterCallbackCompletes`.
- **Sequential, non-concurrent delivery with backpressure.** Test: `Callbacks_AreOrderedAndNeverConcurrent`.
- **Cooperative cancellation; a running handler is not preempted.** Tests: `CancellationDuringHandler_StopsBeforeNextCallback`, `Cancellation_DoesNotPreemptHandlerThatIgnoresToken`, `CancellationAfterFirstChunk_DoesNotReadToEnd`.
- **`Index` and `Offset` are relative to the start of the scan**, even on a seekable stream at a non-zero position.
- **The caller owns the stream.** It is never disposed; its position after a failure is unspecified. Test: `HandlerFailure_PropagatesAndDoesNotDisposeSource`.
- **Argument and unsupported-semantics errors are thrown synchronously**, not by the returned task. Tests: `PublicArgumentContractTests`, `InvalidArgumentsAndUnsupportedSemantics_FailBeforeReading`.
- **Read segmentation does not change output.** One-byte and random short reads produce the same chunk sequence as a contiguous source ([FASTCDC-V1 §5](FASTCDC-V1.md#5-stream-independence)).

## 3. Manifest

| Symbol | Contract |
|---|---|
| `ChunkManifest.CreateAsync` / `VerifyAsync` / `VerifyManifestAsync` | one-shot, `Task`-returning, caller-owned streams |
| `ManifestCreationOptions` (`ProfileId?`, `HashSuite?`, `IncludeBlockIndex`) | semantic selections plus one physical, identity-neutral option |
| `ManifestReader` (`OpenAsync`, `ReadAsync(Memory<ChunkInfo>)`, `IsCompleted`, `VerificationResult`, `Dispose`/`DisposeAsync`) | concrete buffered reader; never materializes the whole manifest (`CsmStreamingScaleTests`) |
| `ManifestVerificationResult` (`IsValid`, `Failures`, `Manifest`) | a mismatch is a result, not an exception |
| `ManifestVerificationFailure` (flags: `BlockCrc`, `LogicalTotals`, `ManifestId`, `FileDigest`, `ProfileSemantics`, `Content`) | outcome matrix in [CSM-V1 §14](CSM-V1.md#14-verification-levels), pinned by `VerificationSemanticsMatrixTests` |
| `ManifestInfo` | logical identity plus the physical artifact that carries it (§3.1) |

Malformed CSM input throws `InvalidDataException`. An unknown HashSuite, or an unknown profile when content must be re-chunked, throws `NotSupportedException`.

### 3.1 `ManifestInfo` physical properties

`ManifestInfo` describes **one emitted CSM representation**: its logical identity and the physical artifact that carries it.

| Property | Kind | Why it is public |
|---|---|---|
| `HashSuite`, `ProfileId`, `ProfileFingerprint`, `ManifestId`, `ChunkCount`, `ContentLength` | logical | identity and totals every consumer needs |
| `FileDigest` | physical | digest of the exact artifact bytes, for transport/cache integrity (for example a strong HTTP ETag) |
| `PhysicalLength` | physical | exact artifact length, for `Content-Length` and range bounds |
| `ChunkBlockCount` | physical | inspection and tooling |
| `HasBlockIndex` | physical | tells the consumer whether BIDX-based positioning is available |

The physical values are fixed by the CSM v1 TRAILER and FOOT and change only with a new CSM format major. Exposing them does not bind `ManifestId`, which stays independent of physical encoding: two valid representations of the same content, with and without BIDX, share a `ManifestId` and differ in `FileDigest`.

## 4. Identities

| Symbol | Shape |
|---|---|
| `Hash256` | 256-bit value struct; lowercase-hex format/parse; all-zero is valid |
| `ChunkId`, `ManifestId`, `ProfileFingerprint` | value structs wrapping `Hash256`; `default` is the valid all-zero value |
| `ChunkingProfileId`, `HashSuiteId` | immutable reference types over a validated string |
| `HashSuiteIds` (`Blake3256V1`, `Sha256V1`, `Default`) | well-known values; `Default` is BLAKE3-256 |

Not in 0.1, because no consumer needs them yet and each can be added later without a break: `IParsable<T>`, `ISpanFormattable`, `TypeConverter`, JSON converters, profile or HashSuite registries.

## 5. Deliberately absent

| Not in Core | Why |
|---|---|
| `IChunker`, `IChunkHasher`, `IChunkBoundaryFinder` or similar strategy interfaces | no demonstrated substitution need; see [AGENTS.md](../../AGENTS.md) |
| pipeline ownership, buffer/pool/SIMD/worker tuning options | implementation details; options carry only semantic selections plus `IncludeBlockIndex` |
| mandatory per-chunk allocation | the scanner steady state is O(1) allocations |
| compare/diff/patch types | not part of Core 0.1 |
| DI, `HttpContext` or ASP.NET Core types | Core composes with any host through `Stream`; see [ASPNET-CORE.md](../ASPNET-CORE.md) |
| progress, compression, signature or anti-rollback surface | not part of Core 0.1; none is reserved |
