# ChunkShift.Patching

Verified binary patches over [ChunkShift](https://www.nuget.org/packages/ChunkShift) manifests for .NET.

ChunkShift.Patching turns two versions of a file into a compact CSP patch and rebuilds the new version from the old one. A patch carries the target manifest and only the chunks the base does not already have, each stored raw or as a zstd frame that can use nearby base chunks as a dictionary. Apply checks every chunk against its content identity and publishes the result only after every check has passed.

- **Plan** the reuse between two manifests before building anything.
- **Create** base-dependent or self-contained patches.
- **Apply** with full verification; a wrong base or a corrupt patch never replaces the destination.
- **Declarative format**: no instruction stream, no executable content; patch bytes are bound by a physical digest.
- Trimming- and NativeAOT-compatible. Targets **.NET 10**.

## Install

```bash
dotnet add package ChunkShift.Patching
```

## Plan, create and apply

Both versions need a CSM manifest, created with `ChunkManifest.CreateAsync` from the `ChunkShift` package.

```csharp
using ChunkShift.Patching;

// How much of the target can be reused from the base?
await using (FileStream baseManifest = File.OpenRead("v1.csm"))
await using (FileStream targetManifest = File.OpenRead("v2.csm"))
{
    PatchPlan plan = await ChunkPatch.PlanAsync(baseManifest, targetManifest);
    Console.WriteLine($"reused {plan.ReusedBytes} bytes, missing {plan.UniqueMissingBytes} bytes");
}

// Create a patch from v1 to v2. Write it to a temporary file and move it into
// place only after CreateAsync completes.
await using (FileStream baseManifest = File.OpenRead("v1.csm"))
await using (FileStream baseContent = File.OpenRead("v1.bin"))
await using (FileStream targetManifest = File.OpenRead("v2.csm"))
await using (FileStream targetContent = File.OpenRead("v2.bin"))
await using (FileStream patch = new("v1-to-v2.csp.tmp", FileMode.CreateNew, FileAccess.Write))
{
    PatchInfo info = await ChunkPatch.CreateAsync(
        baseManifest, baseContent, targetManifest, targetContent, patch);
    Console.WriteLine($"{info.PhysicalLength} bytes, {info.PayloadEntryCount} payload entries");
}
File.Move("v1-to-v2.csp.tmp", "v1-to-v2.csp");

// Rebuild v2 next to v1.
await using (FileStream patch = File.OpenRead("v1-to-v2.csp"))
await using (FileStream baseManifest = File.OpenRead("v1.csm"))
await using (FileStream baseContent = File.OpenRead("v1.bin"))
{
    PatchApplyResult result = await ChunkPatch.ApplyAsync(patch, baseManifest, baseContent, "v2.bin");
    Console.WriteLine(result.IsApplied ? "applied" : $"rejected: {result.Failures}");
}
```

`ChunkPatch.CreateAsync(targetManifest, targetContent, destination)` and `ChunkPatch.ApplyAsync(patch, destinationPath)` do the same without a base.

An integrity failure or an exceeded apply limit is reported through `PatchApplyResult.Failures`, and the destination keeps its previous content; malformed input throws `InvalidDataException`; an unsupported HashSuite or encoding, or a manifest over a planning or creation limit, throws `NotSupportedException`. A matching hash proves integrity against the expected manifest, not authenticity: verify where a patch comes from before applying it.

## Persisted contracts

| Contract | Value |
| --- | --- |
| Patch format | CSP v1 |
| Embedded manifest | CSM v1 |
| Payload encodings | raw, zstd (RFC 8878) with up to four base chunks as a dictionary |
| HashSuites | `chunkshift.blake3-256.v1`, `chunkshift.sha256.v1` |

The CSP format version is independent of the package version. Patch bytes are not a contract: another package version may emit different bytes for the same inputs, but the reconstructed target and its identities never change. While ChunkShift is `0.x`, deliberate public API changes can still happen and are always called out in the [changelog](https://github.com/MrFr3di/ChunkShift/blob/main/CHANGELOG.md); see the [release policy](https://github.com/MrFr3di/ChunkShift/blob/main/docs/RELEASES.md).

## Learn more

- [Full README](https://github.com/MrFr3di/ChunkShift)
- [CSP v1 format](https://github.com/MrFr3di/ChunkShift/blob/main/docs/architecture/CSP-V1.md), [CSM v1 format](https://github.com/MrFr3di/ChunkShift/blob/main/docs/architecture/CSM-V1.md)

## Feedback

Questions and bug reports go to [GitHub Issues](https://github.com/MrFr3di/ChunkShift/issues). Report security vulnerabilities privately as described in [SECURITY.md](https://github.com/MrFr3di/ChunkShift/blob/main/SECURITY.md). ChunkShift is licensed under MIT.
