# ChunkShift

Deterministic content-defined chunking, streaming binary manifests and verification for .NET.

ChunkShift splits any `Stream` into content-defined chunks, gives each chunk a stable 256-bit content identity, and records the result in a compact binary manifest (CSM) that can be verified later. Because boundaries follow the content rather than fixed offsets, an insertion or deletion only changes the chunks around it — useful for deduplicating uploads and build artifacts, measuring reuse between versions, and verifying large files.

- **FastCDC boundaries**, identical on every supported architecture and execution mode.
- **BLAKE3-256** chunk identities by default, **SHA-256** available.
- **Streaming and bounded-memory**; forward-only and non-seekable streams work.
- **No dependencies on ASP.NET Core, DI or storage abstractions**; trimming- and NativeAOT-compatible.
- Targets **.NET 8** and **.NET 10**.

## Install

```bash
dotnet add package ChunkShift
```

## Chunk a stream

```csharp
using ChunkShift;

await using FileStream source = File.OpenRead("build.bin");

await ChunkScanner.ScanAsync(
    source,
    (chunk, content, cancellationToken) =>
    {
        // `content` is borrowed: consume or copy it before the returned ValueTask completes.
        Console.WriteLine($"{chunk.Offset} {chunk.Length} {chunk.Id}");
        return ValueTask.CompletedTask;
    });
```

The handler runs once per chunk, in order, and the scanner waits for it before reading further. ChunkShift never disposes the caller's stream.

## Create and verify a manifest

```csharp
using ChunkShift;

await using (FileStream content = File.OpenRead("build.bin"))
await using (FileStream manifest = new("build.csm", FileMode.CreateNew, FileAccess.Write))
{
    ManifestInfo info = await ChunkManifest.CreateAsync(content, manifest);
    Console.WriteLine($"{info.ManifestId}: {info.ChunkCount} chunks");
}

await using (FileStream content = File.OpenRead("build.bin"))
await using (FileStream manifest = File.OpenRead("build.csm"))
{
    ManifestVerificationResult result = await ChunkManifest.VerifyAsync(content, manifest);
    Console.WriteLine(result.IsValid ? "valid" : $"invalid: {result.Failures}");
}
```

A content or integrity mismatch is reported through `ManifestVerificationResult`; malformed manifest input throws `InvalidDataException`, and an unknown HashSuite or profile throws `NotSupportedException`. A matching hash proves integrity against the expected manifest, not authenticity.

## Persisted contracts

| Contract | Value |
| --- | --- |
| Default chunking profile | `fastcdc.gear.chunkshift.v1.64k` (16 / 64 / 256 KiB) |
| Profile fingerprint | `054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0` |
| HashSuites | `chunkshift.blake3-256.v1` (default), `chunkshift.sha256.v1` |
| Manifest format | CSM v1 |

The package version does not change persisted formats or identities. While ChunkShift is `0.x`, deliberate public API changes can still happen and are always called out in the [changelog](https://github.com/MrFr3di/ChunkShift/blob/main/CHANGELOG.md); see the [release policy](https://github.com/MrFr3di/ChunkShift/blob/main/docs/RELEASES.md).

## Learn more

- [Full README](https://github.com/MrFr3di/ChunkShift) and [samples](https://github.com/MrFr3di/ChunkShift/tree/main/samples)
- [Core API contract](https://github.com/MrFr3di/ChunkShift/blob/main/docs/architecture/CORE-0.1-API.md), [CSM v1 format](https://github.com/MrFr3di/ChunkShift/blob/main/docs/architecture/CSM-V1.md), [FastCDC profile semantics](https://github.com/MrFr3di/ChunkShift/blob/main/docs/architecture/FASTCDC-V1.md)
- [ASP.NET Core hosting](https://github.com/MrFr3di/ChunkShift/blob/main/docs/ASPNET-CORE.md)

## Feedback

Questions and bug reports go to [GitHub Issues](https://github.com/MrFr3di/ChunkShift/issues). Report security vulnerabilities privately as described in [SECURITY.md](https://github.com/MrFr3di/ChunkShift/blob/main/SECURITY.md). ChunkShift is licensed under MIT.
