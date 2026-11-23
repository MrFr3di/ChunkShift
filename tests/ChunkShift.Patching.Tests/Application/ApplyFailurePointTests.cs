using ChunkShift.Patching.Application;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Creation;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// The publication failure-point matrix: every pre-publication
/// failure keeps an existing destination file byte for byte and leaves no
/// temporary file behind, whichever way the re-chunk check runs.
/// </summary>
public sealed class ApplyFailurePointTests : IDisposable
{
    private static readonly byte[] DestinationBytes = [1, 2, 3, 4, 5, 6, 7, 8];

    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-apply-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string Destination => Path.Combine(_directory, "target.bin");

    /// <summary>Gets every way of running the re-chunk check.</summary>
    public static TheoryData<string> Checks => new(Enum.GetNames<ChunkingCheck>());

    [Theory]
    [MemberData(nameof(Checks))]
    public async Task WrongBase_KeepsTheDestination(string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        (PatchScenario scenario, _, _, byte[] patch) = await CreateInsertedPatchAsync();
        byte[] otherContent = CspBytes.CreateXorShiftBytes(
            scenario.BaseContent.Length,
            0x5EED3001u);
        byte[] otherManifest = await CreationTestSupport.CreateManifestAsync(
            otherContent,
            HashSuiteIds.Sha256V1);

        File.WriteAllBytes(Destination, DestinationBytes);

        PatchApplyResult result = await ApplyAsync(
            check,
            new MemoryStream(patch, writable: false),
            new MemoryStream(otherManifest, writable: false),
            new MemoryStream(otherContent, writable: false),
            Destination);

        Assert.False(result.IsApplied);
        Assert.Equal(PatchApplyFailure.BaseMismatch, result.Failures);
        AssertDestinationUnchanged();
    }

    [Theory]
    [MemberData(nameof(Checks))]
    public async Task CorruptPatchByte_KeepsTheDestination(string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        (PatchScenario scenario, byte[] baseManifest, _, byte[] patch) =
            await CreateInsertedPatchAsync();
        CspReader reader = await CreationTestSupport.OpenAsync(patch);
        CspIndexEntry first = reader.Index[0];
        int storedAt = checked(
            (int)first.PayloadOffset +
            CspFormat.PaylEntryHeaderSize +
            (first.DictionaryCount * CspFormat.DictionaryReferenceSize));

        byte[] corrupted = (byte[])patch.Clone();
        corrupted[storedAt] ^= 0xFF;

        File.WriteAllBytes(Destination, DestinationBytes);

        await Assert.ThrowsAsync<InvalidDataException>(() => ApplyAsync(
            check,
            new MemoryStream(corrupted, writable: false),
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(scenario.BaseContent, writable: false),
            Destination));

        AssertDestinationUnchanged();
    }

    [Theory]
    [MemberData(nameof(Checks))]
    public async Task PayloadHashFailure_KeepsTheDestination(string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        // The committed vector stores payload bytes that decode to a length the
        // entry claims but that do not hash to its ChunkId.
        CspApplyVector vector = CspApplyVectors.Find("payload-hash.csp");

        File.WriteAllBytes(Destination, DestinationBytes);

        PatchApplyResult result = await ApplyAsync(
            check,
            new MemoryStream(CspApplyVectors.ReadPatch(vector.Name), writable: false),
            new MemoryStream(CspApplyVectors.ReadBaseManifest(vector), writable: false),
            new MemoryStream(CspApplyVectors.ReadBaseContent(vector), writable: false),
            Destination);

        Assert.False(result.IsApplied);
        Assert.Equal(PatchApplyFailure.PayloadChunk, result.Failures);
        AssertDestinationUnchanged();
    }

    [Theory]
    [InlineData(1, nameof(ChunkingCheck.Off))]
    [InlineData(1, nameof(ChunkingCheck.Sequential))]
    [InlineData(1, nameof(ChunkingCheck.Overlapped))]
    [InlineData(1, nameof(ChunkingCheck.Boundary))]
    [InlineData(5, nameof(ChunkingCheck.Off))]
    [InlineData(5, nameof(ChunkingCheck.Sequential))]
    [InlineData(5, nameof(ChunkingCheck.Overlapped))]
    [InlineData(5, nameof(ChunkingCheck.Boundary))]
    public async Task CancelledBaseRead_KeepsTheDestination(int readsBeforeCancel, string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        (PatchScenario scenario, byte[] baseManifest, _, byte[] patch) =
            await CreateInsertedPatchAsync();

        File.WriteAllBytes(Destination, DestinationBytes);

        using var cancellation = new CancellationTokenSource();
        using var baseContent = new InterruptingReadStream(
            new MemoryStream(scenario.BaseContent, writable: false),
            cancellation,
            readsBeforeCancel);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ApplyAsync(
                check,
                new MemoryStream(patch, writable: false),
                new MemoryStream(baseManifest, writable: false),
                baseContent,
                Destination,
                cancellation.Token));

        AssertDestinationUnchanged();
    }

    [Theory]
    [MemberData(nameof(Checks))]
    public async Task BaseStreamIoFailureMidApply_KeepsTheDestination(string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        (PatchScenario scenario, byte[] baseManifest, _, byte[] patch) =
            await CreateInsertedPatchAsync();

        File.WriteAllBytes(Destination, DestinationBytes);

        using var baseContent = new InterruptingReadStream(
            new MemoryStream(scenario.BaseContent, writable: false),
            5);

        await Assert.ThrowsAsync<IOException>(() => ApplyAsync(
            check,
            new MemoryStream(patch, writable: false),
            new MemoryStream(baseManifest, writable: false),
            baseContent,
            Destination));

        AssertDestinationUnchanged();
    }

    private static async Task<(PatchScenario Scenario, byte[] BaseManifest, byte[] TargetManifest, byte[] Patch)>
        CreateInsertedPatchAsync()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.Inserted);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);
        (byte[] patch, _) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        return (scenario, baseManifest, targetManifest, patch);
    }

    /// <summary>
    /// Applies through the public API when <paramref name="check"/> is its
    /// default, and through the internal applier otherwise.
    /// </summary>
    private static Task<PatchApplyResult> ApplyAsync(
        ChunkingCheck check,
        Stream patch,
        Stream baseManifest,
        Stream baseContent,
        string destination,
        CancellationToken cancellationToken = default) =>
        check == CspApplier.DefaultChunkingCheck
            ? ChunkPatch.ApplyAsync(patch, baseManifest, baseContent, destination, cancellationToken)
            : CspApplier.ApplyAsync(
                patch,
                baseManifest,
                baseContent,
                destination,
                CspFormat.DefaultMaximumPayloadEntries,
                check,
                cancellationToken);

    private void AssertDestinationUnchanged()
    {
        Assert.Equal(DestinationBytes, File.ReadAllBytes(Destination));
        Assert.Equal([Destination], Directory.GetFiles(_directory));
    }
}
