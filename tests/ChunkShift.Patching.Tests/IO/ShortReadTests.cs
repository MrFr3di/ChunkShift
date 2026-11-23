using ChunkShift.Patching.Application;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Application;
using ChunkShift.Patching.Tests.Creation;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.IO;

/// <summary>
/// Create, apply and plan over input streams that return fewer bytes than
/// requested reach exactly the result of the same inputs in a
/// <see cref="MemoryStream"/>, and a destination that runs out of space fails
/// create with its <see cref="IOException"/>.
/// </summary>
/// <remarks>
/// <see cref="Stream.ReadAsync(Memory{byte}, CancellationToken)"/> may return
/// any count from one up to the request before the end, as network, pipe and
/// decompression streams do. A reader that treats a short read as the end of
/// the data, or that drops the bytes after it, produces another patch, another
/// target or a false malformed verdict here.
/// </remarks>
public sealed class ShortReadTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-short-read-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    public static TheoryData<string> ScenarioNames
    {
        get
        {
            var names = new TheoryData<string>();

            foreach (PatchScenario scenario in PatchScenarios.All)
            {
                names.Add(scenario.Name);
            }

            return names;
        }
    }

    /// <summary>
    /// Gets every scenario with the sequential, the overlapped and the
    /// boundary re-chunk check; the overlapped check reads the patch
    /// concurrently with the reconstruction.
    /// </summary>
    public static TheoryData<string, string> ScenarioChecks
    {
        get
        {
            var cases = new TheoryData<string, string>();

            foreach (PatchScenario scenario in PatchScenarios.All)
            {
                cases.Add(scenario.Name, nameof(ChunkingCheck.Sequential));
                cases.Add(scenario.Name, nameof(ChunkingCheck.Overlapped));
                cases.Add(scenario.Name, nameof(ChunkingCheck.Boundary));
            }

            return cases;
        }
    }

    public static TheoryData<string, string> VectorNames
    {
        get
        {
            var names = new TheoryData<string, string>();

            foreach (CspApplyVector vector in CspApplyVectors.All)
            {
                names.Add(vector.Name, nameof(ChunkingCheck.Sequential));
                names.Add(vector.Name, nameof(ChunkingCheck.Overlapped));
                names.Add(vector.Name, nameof(ChunkingCheck.Boundary));
            }

            return names;
        }
    }

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public async Task Create_WithShortReads_WritesTheSamePatch(string scenarioName)
    {
        PatchScenario scenario = PatchScenarios.Find(scenarioName);
        (byte[] baseManifest, byte[] targetManifest, byte[] expected) =
            await CreateBufferedAsync(scenario);

        // The two inputs that need not be seekable are passed as forward-only.
        var baseManifestStream = new ShortReadStream(baseManifest, 0x5EED4001u, seekable: false);
        var baseContentStream = new ShortReadStream(scenario.BaseContent, 0x5EED4002u);
        var targetManifestStream = new ShortReadStream(targetManifest, 0x5EED4003u);
        var targetContentStream = new ShortReadStream(scenario.TargetContent, 0x5EED4004u, seekable: false);
        using var destination = new MemoryStream();

        if (scenario.SelfContained)
        {
            _ = await ChunkPatch.CreateAsync(
                targetManifestStream,
                targetContentStream,
                destination);
        }
        else
        {
            _ = await ChunkPatch.CreateAsync(
                baseManifestStream,
                baseContentStream,
                targetManifestStream,
                targetContentStream,
                destination);

            Assert.True(baseManifestStream.ShortReads > 0);
        }

        Assert.Equal(expected, destination.ToArray());
        Assert.True(targetManifestStream.ShortReads > 0);
        Assert.True(targetContentStream.ShortReads > 0);
    }

    [Theory]
    [MemberData(nameof(ScenarioChecks))]
    public async Task Apply_WithShortReads_ReconstructsTheTarget(string scenarioName, string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        PatchScenario scenario = PatchScenarios.Find(scenarioName);
        (byte[] baseManifest, byte[] targetManifest, byte[] patch) = await CreateBufferedAsync(scenario);
        string destination = Path.Combine(_directory, "target.bin");
        var patchStream = new ShortReadStream(patch, 0x5EED4011u);
        PatchApplyResult result;

        if (scenario.SelfContained)
        {
            result = await CspApplier.ApplyAsync(
                patchStream,
                baseManifest: null,
                baseContent: null,
                destination,
                CspFormat.DefaultMaximumPayloadEntries,
                check,
                CancellationToken.None);
        }
        else
        {
            var baseManifestStream = new ShortReadStream(baseManifest, 0x5EED4012u, seekable: false);
            var baseContentStream = new ShortReadStream(scenario.BaseContent, 0x5EED4013u);

            result = await CspApplier.ApplyAsync(
                patchStream,
                baseManifestStream,
                baseContentStream,
                destination,
                CspFormat.DefaultMaximumPayloadEntries,
                check,
                CancellationToken.None);

            Assert.True(baseManifestStream.ShortReads > 0);

            // Base content is read only for the chunks the target reuses.
            PatchPlan plan = await ChunkPatch.PlanAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(targetManifest, writable: false));
            Assert.Equal(plan.ReusedBytes > 0, baseContentStream.ShortReads > 0);
        }

        Assert.True(result.IsApplied, result.Failures.ToString());
        Assert.Equal(scenario.TargetContent, File.ReadAllBytes(destination));
        Assert.True(patchStream.ShortReads > 0);
    }

    /// <summary>
    /// Every committed vector, valid or not, reaches the same outcome, the
    /// same failure kinds and the same output with short reads of the patch,
    /// the base manifest and the base content.
    /// </summary>
    [Theory]
    [MemberData(nameof(VectorNames))]
    public async Task Vector_WithShortReads_ReachesTheBufferedOutcome(string name, string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        CspApplyVector vector = CspApplyVectors.Find(name);
        byte[] patch = CspApplyVectors.ReadPatch(name);
        byte[]? baseManifest = vector.BaseName is null ? null : CspApplyVectors.ReadBaseManifest(vector);
        byte[]? baseContent = vector.BaseName is null ? null : CspApplyVectors.ReadBaseContent(vector);

        string buffered = await ApplyVectorAsync(
            vector,
            new MemoryStream(patch, writable: false),
            baseManifest is null ? null : new MemoryStream(baseManifest, writable: false),
            baseContent is null ? null : new MemoryStream(baseContent, writable: false),
            Path.Combine(_directory, "buffered"),
            check);
        string shortReads = await ApplyVectorAsync(
            vector,
            new ShortReadStream(patch, 0x5EED4021u),
            baseManifest is null ? null : new ShortReadStream(baseManifest, 0x5EED4022u, seekable: false),
            baseContent is null ? null : new ShortReadStream(baseContent, 0x5EED4023u),
            Path.Combine(_directory, "short"),
            check);

        Assert.Equal(buffered, shortReads);
    }

    [Fact]
    public async Task Plan_WithShortReads_MatchesTheBufferedPlan()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.Inserted);
        (byte[] baseManifest, byte[] targetManifest, _) = await CreateBufferedAsync(scenario);

        PatchPlan buffered = await ChunkPatch.PlanAsync(
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(targetManifest, writable: false));
        var baseStream = new ShortReadStream(baseManifest, 0x5EED4031u, seekable: false);
        var targetStream = new ShortReadStream(targetManifest, 0x5EED4032u, seekable: false);
        PatchPlan shortReads = await ChunkPatch.PlanAsync(baseStream, targetStream);

        Assert.True(buffered.IsValid);
        Assert.Equal(
            (buffered.IsValid, buffered.ReusedChunks, buffered.ReusedBytes, buffered.MissingChunks,
                buffered.MissingBytes, buffered.UniqueMissingChunks, buffered.UniqueMissingBytes),
            (shortReads.IsValid, shortReads.ReusedChunks, shortReads.ReusedBytes, shortReads.MissingChunks,
                shortReads.MissingBytes, shortReads.UniqueMissingChunks, shortReads.UniqueMissingBytes));
        Assert.Equal(buffered.Base.Manifest.ManifestId, shortReads.Base.Manifest.ManifestId);
        Assert.Equal(buffered.Target.Manifest.ManifestId, shortReads.Target.Manifest.ManifestId);
        Assert.True(baseStream.ShortReads > 0);
        Assert.True(targetStream.ShortReads > 0);
    }

    /// <summary>
    /// A destination that fills up at the first write, in the middle of the
    /// patch or at its last byte fails create with that
    /// <see cref="IOException"/>, unwrapped, and create does not dispose any
    /// stream it was given.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1000)]
    [InlineData(-1)]
    public async Task Create_DestinationFull_ThrowsTheIoExceptionAndLeavesTheStreamsOpen(int capacity)
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.EditedChunks);
        (byte[] baseManifest, byte[] targetManifest, byte[] patch) = await CreateBufferedAsync(scenario);
        var destination = new FullDestinationStream(capacity < 0 ? patch.Length - 1 : capacity);
        var inputs = new[]
        {
            new DisposeTrackingStream(new MemoryStream(baseManifest, writable: false)),
            new DisposeTrackingStream(new MemoryStream(scenario.BaseContent, writable: false)),
            new DisposeTrackingStream(new MemoryStream(targetManifest, writable: false)),
            new DisposeTrackingStream(new MemoryStream(scenario.TargetContent, writable: false)),
        };
        var trackedDestination = new DisposeTrackingStream(destination);

        IOException error = await Assert.ThrowsAsync<IOException>(() => ChunkPatch.CreateAsync(
            inputs[0],
            inputs[1],
            inputs[2],
            inputs[3],
            trackedDestination));

        Assert.Equal("No space left on device", error.Message);
        Assert.True(destination.Written < patch.Length);
        Assert.All(inputs, input => Assert.False(input.Disposed));
        Assert.False(trackedDestination.Disposed);
    }

    private static async Task<(byte[] BaseManifest, byte[] TargetManifest, byte[] Patch)> CreateBufferedAsync(
        PatchScenario scenario)
    {
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

        return (baseManifest, targetManifest, patch);
    }

    /// <summary>
    /// Applies one vector into its own directory and renders the outcome:
    /// the exception type, or the failures, or the output bytes.
    /// </summary>
    private static async Task<string> ApplyVectorAsync(
        CspApplyVector vector,
        Stream patch,
        Stream? baseManifest,
        Stream? baseContent,
        string directory,
        ChunkingCheck check)
    {
        Directory.CreateDirectory(directory);
        string destination = Path.Combine(directory, "output.bin");

        try
        {
            PatchApplyResult result = await CspApplier.ApplyAsync(
                patch,
                baseManifest,
                baseContent,
                destination,
                vector.MaximumPayloadEntries,
                check,
                CancellationToken.None);

            return result.IsApplied
                ? "applied:" + Convert.ToHexStringLower(File.ReadAllBytes(destination))
                : "failed:" + result.Failures;
        }
        catch (Exception exception) when (exception is InvalidDataException or NotSupportedException)
        {
            return exception.GetType().Name;
        }
    }
}
