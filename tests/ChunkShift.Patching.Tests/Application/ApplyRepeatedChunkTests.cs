using ChunkShift.Patching.Application;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// A repeated target chunk replays the bytes verified at its first
/// occurrence, and every occurrence must still have its own record length
/// (CSP-V1 rule 19).
/// </summary>
public sealed class ApplyRepeatedChunkTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-apply-repeat-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Theory]
    [InlineData(nameof(ChunkingCheck.Off))]
    [InlineData(nameof(ChunkingCheck.Sequential))]
    [InlineData(nameof(ChunkingCheck.Overlapped))]
    [InlineData(nameof(ChunkingCheck.Boundary))]
    public async Task RepeatedChunkWithAnotherLength_IsPayloadChunk(string checkName)
    {
        // The embedded manifest names A with lengths 10 and 20 and B with 15
        // and 5: replaying the first occurrences writes 10 + 15 + 10 + 15
        // bytes, exactly the declared total, so only the per-record length
        // check tells the layout apart. The profile is unregistered, so no
        // re-chunk check runs either.
        HashSuiteId suite = HashSuiteIds.Sha256V1;
        byte[] a = CspBytes.CreateXorShiftBytes(10, 0x5EED7001u);
        byte[] b = CspBytes.CreateXorShiftBytes(15, 0x5EED7002u);
        var idA = new ChunkId(PatchHashing.Hash(suite, a));
        var idB = new ChunkId(PatchHashing.Hash(suite, b));
        byte[] manifest = await RecutManifests.WriteRecordsAsync(
            [(idA, 10), (idB, 15), (idA, 20), (idB, 5)],
            suite,
            new ChunkingProfileId("fixture.csm.synthetic.v1"),
            new ProfileFingerprint(Hash256.FromBytes(new byte[32])));
        Assert.True((await ChunkManifest.VerifyManifestAsync(
            new MemoryStream(manifest, writable: false))).IsValid);

        byte[] patch = await WritePatchAsync(suite, manifest, [(idA, 0, a), (idB, 1, b)]);
        string destination = Path.Combine(_directory, "repeat.bin");

        PatchApplyResult result = await CspApplier.ApplyAsync(
            new MemoryStream(patch, writable: false),
            baseManifest: null,
            baseContent: null,
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            Enum.Parse<ChunkingCheck>(checkName),
            CancellationToken.None);

        Assert.False(result.IsApplied);
        Assert.Equal(PatchApplyFailure.PayloadChunk, result.Failures);
        Assert.Empty(Directory.GetFileSystemEntries(_directory));
    }

    [Fact]
    public async Task RepeatedChunkWithItsLength_Applies()
    {
        HashSuiteId suite = HashSuiteIds.Sha256V1;
        byte[] a = CspBytes.CreateXorShiftBytes(10, 0x5EED7003u);
        byte[] b = CspBytes.CreateXorShiftBytes(15, 0x5EED7004u);
        var idA = new ChunkId(PatchHashing.Hash(suite, a));
        var idB = new ChunkId(PatchHashing.Hash(suite, b));
        byte[] manifest = await RecutManifests.WriteRecordsAsync(
            [(idA, 10), (idB, 15), (idA, 10), (idB, 15)],
            suite,
            new ChunkingProfileId("fixture.csm.synthetic.v1"),
            new ProfileFingerprint(Hash256.FromBytes(new byte[32])));

        byte[] patch = await WritePatchAsync(suite, manifest, [(idA, 0, a), (idB, 1, b)]);
        string destination = Path.Combine(_directory, "repeat.bin");

        PatchApplyResult result = await CspApplier.ApplyAsync(
            new MemoryStream(patch, writable: false),
            baseManifest: null,
            baseContent: null,
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            CspApplier.DefaultChunkingCheck,
            CancellationToken.None);

        Assert.True(result.IsApplied, result.Failures.ToString());
        Assert.Equal([.. a, .. b, .. a, .. b], File.ReadAllBytes(destination));
    }

    private static async Task<byte[]> WritePatchAsync(
        HashSuiteId suite,
        byte[] manifest,
        IReadOnlyList<(ChunkId Id, ulong FirstTargetIndex, byte[] Raw)> entries)
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(destination, suite);

        await writer.WriteTargetManifestAsync(
            new MemoryStream(manifest, writable: false),
            manifest.Length,
            CancellationToken.None);

        foreach ((ChunkId id, ulong firstTargetIndex, byte[] raw) in entries)
        {
            await writer.AddPayloadEntryAsync(
                new CspPayloadEntry(id, firstTargetIndex, CspFormat.EncodingRaw, ReadOnlyMemory<ChunkId>.Empty),
                raw,
                CancellationToken.None);
        }

        _ = await writer.CompleteAsync(CancellationToken.None);
        return destination.ToArray();
    }
}
