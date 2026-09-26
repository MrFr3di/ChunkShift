# ChunkShift

**Deterministic content-defined chunking and streaming manifests for .NET.**

ChunkShift is a small embeddable Core library for splitting binary streams into stable content-defined chunks, creating compact CSM manifests, and verifying content with bounded memory.

It is aimed at software that needs reliable binary identity and reuse information without adopting a storage platform or custom network protocol: launchers, application updaters, build systems, artifact pipelines, desktop software, and services.

## Highlights

- **Content-defined chunking.** Unchanged regions can be recognized again after insertions or deletions shift byte offsets.
- **Deterministic identities.** Stable chunk/profile/manifest semantics are treated as compatibility contracts.
- **Streaming by default.** Forward-only and non-seekable `Stream` inputs are supported without full-file materialization.
- **Small Core API.** No DI container, ASP.NET dependency, repository abstraction, or public strategy-interface zoo.
- **BLAKE3-256 default.** SHA-256 is available as a compatibility HashSuite.
- **Portable validation.** x64/ARM64 determinism, JIT/NativeAOT consumers, independent vectors, fuzzing, and larger-than-memory paths are part of the evidence.
- **Ordinary ASP.NET Core integration.** `HttpRequest.Body` + `RequestAborted`; no ChunkShift-specific middleware required.

## Install

After the first public release:

```bash
dotnet add package ChunkShift --version 0.1.0
```

## Quick start

### Stream chunks

```csharp
using ChunkShift;

await using FileStream source = File.OpenRead("payload.bin");

await ChunkScanner.ScanAsync(
    source,
    (chunk, content, cancellationToken) =>
    {
        Console.WriteLine(
            $"{chunk.Offset,12}  {chunk.Length,8}  {chunk.Id}");

        // `content` is borrowed. Consume/copy it before this ValueTask ends.
        return ValueTask.CompletedTask;
    });
```

The callback is invoked once per chunk, in order. ChunkShift does not dispose the source stream.

### Create a CSM manifest

```csharp
await using FileStream content = File.OpenRead("payload.bin");
await using FileStream output = new(
    "payload.csm.tmp",
    FileMode.CreateNew,
    FileAccess.Write,
    FileShare.None);

ManifestInfo info =
    await ChunkManifest.CreateAsync(content, output);

Console.WriteLine($"{info.ManifestId} — {info.ChunkCount} chunks");
```

Treat manifest publication as an application transaction: write to a temporary destination and move it into place only after `CreateAsync` succeeds.

### Verify later

```csharp
await using FileStream content = File.OpenRead("payload.bin");
await using FileStream manifest = File.OpenRead("payload.csm");

ManifestVerificationResult verification =
    await ChunkManifest.VerifyAsync(content, manifest);

if (!verification.IsValid)
{
    Console.Error.WriteLine(verification.Failures);
}
```

## Stable Core identity

Core `0.1.0` registers one stable FastCDC profile:

| Field | Value |
| --- | --- |
| `AlgorithmId` | `fastcdc.gear.chunkshift.v1` |
| `ProfileId` | `fastcdc.gear.chunkshift.v1.64k` |
| Minimum | 16 KiB |
| Nominal target | 64 KiB |
| Maximum | 256 KiB |
| `ProfileFingerprint` | `054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0` |

The nominal 64 KiB value is a profile parameter, not a promise that every chunk is 64 KiB.

Existing profile/hash/format identifiers are never silently reinterpreted by an optimization or package update.

## CSM: logical vs physical identity

ChunkShift keeps two concepts intentionally separate:

```text
ManifestId
    logical manifest identity

FileDigest
    digest of one exact physical CSM representation
```

A CSM with an optional physical index can have the same `ManifestId` and a different `FileDigest`.

This makes the distinction explicit for caches, HTTP validators, storage, and future update layers.

## Streaming and ownership

Core is designed around ordinary `Stream` ownership:

- the caller owns input/output streams;
- the scanner does not dispose its source;
- callbacks are sequential;
- callback completion provides backpressure;
- chunk content is borrowed memory;
- cancellation is cooperative;
- an already running handler is not forcibly preempted.

The same model works with files, generated/non-seekable streams, and ASP.NET Core request bodies.

```csharp
await ChunkScanner.ScanAsync(
    context.Request.Body,
    handler,
    cancellationToken: context.RequestAborted);
```

Authentication, request limits, decompression, rate limiting, caching, and HTTP transport policy remain application/host concerns.

## Validation philosophy

ChunkShift treats behavior that becomes persisted or observable as a contract.

The current Core has evidence for:

- deterministic short-read segmentation;
- independent FastCDC and CSM verification;
- corruption/resource-bound testing and differential fuzzing;
- x64/ARM64 output equality;
- JIT/NativeAOT clean consumers;
- larger-than-memory streaming;
- real Kestrel request streaming;
- request cancellation and handler non-preemption;
- slow-consumer backpressure;
- CSM HTTP Range and strong ETag behavior.

Decision evidence is kept in the repository rather than reduced to benchmark claims in this README.

## Repository map

```text
src/ChunkShift/        Core implementation
tests/                 correctness and compatibility gates
samples/               minimal consumers
docs/architecture/     normative contracts
docs/validation/       integration evidence
docs/benchmarks/       evidence behind design/profile decisions
tools/                 independent/reference verification
AGENTS.md              standing rules for coding agents
```

### For coding agents

Read [`AGENTS.md`](AGENTS.md) first.

Use the README for orientation, then follow the nearest normative architecture/spec document before changing compatibility-sensitive code. In particular, do not casually rewrite stable vectors, persisted IDs, format semantics, or stream-ownership rules.

## Build

Requirements: .NET 10 SDK and the .NET 8 runtime for the `net8.0` test target.

```bash
dotnet restore ChunkShift.slnx
dotnet build ChunkShift.slnx -c Release --no-restore
dotnet test ChunkShift.slnx -c Release --no-build --no-restore
```

## Documentation

- [Core 0.1 API freeze](docs/architecture/CORE-0.1-API-FREEZE.md)
- [CSM format](docs/architecture/CSM-V1-CANDIDATE.md)
- [FastCDC semantics](docs/architecture/FASTCDC-V1-CANDIDATE.md)
- [Profile fingerprint contract](docs/architecture/PROFILE-FINGERPRINT-V1.md)
- [Profile selection evidence](docs/benchmarks/CDC-0.1-PROFILE-DECISION-2026-09.md)
- [ASP.NET Core host validation](docs/validation/ASPNET-CORE-HOST-VALIDATION-2026-09.md)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Public API, persisted-format, profile/hash identity, and compatibility changes require explicit review and evidence.

## Security

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.

## License

MIT — see [`LICENSE`](LICENSE).
