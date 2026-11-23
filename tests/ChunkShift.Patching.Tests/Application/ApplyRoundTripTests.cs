using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Creation;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// End-to-end create-then-apply round trips: a patch the public
/// <see cref="ChunkPatch.CreateAsync(Stream, Stream, Stream, Stream, Stream, CancellationToken)"/>
/// overloads produce reconstructs the exact target bytes.
/// </summary>
public sealed class ApplyRoundTripTests : IDisposable
{
    private const int Mebibyte = 1024 * 1024;

    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-apply-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    public static TheoryData<string, string> ScenarioCases
    {
        get
        {
            var cases = new TheoryData<string, string>();

            foreach (string hashSuite in new[]
            {
                "chunkshift.blake3-256.v1",
                "chunkshift.sha256.v1",
            })
            {
                foreach (PatchScenario scenario in PatchScenarios.All)
                {
                    cases.Add(hashSuite, scenario.Name);
                }
            }

            return cases;
        }
    }

    [Theory]
    [MemberData(nameof(ScenarioCases))]
    public async Task CreatedPatch_AppliesToTheTargetBytes(
        string hashSuite,
        string scenarioName)
    {
        var suite = new HashSuiteId(hashSuite);
        PatchScenario scenario = PatchScenarios.Find(scenarioName);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            suite);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            suite);
        (byte[] patch, PatchInfo info) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        string destination = Path.Combine(
            _directory,
            $"{scenarioName}-{hashSuite}.bin");
        PatchApplyResult result;

        if (scenario.SelfContained)
        {
            // The self-contained creation overload needs no base to apply.
            result = await ChunkPatch.ApplyAsync(
                new MemoryStream(patch, writable: false),
                destination);
        }
        else
        {
            result = await ChunkPatch.ApplyAsync(
                new MemoryStream(patch, writable: false),
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(scenario.BaseContent, writable: false),
                destination);
        }

        Assert.True(result.IsApplied);
        Assert.NotNull(result.Target);
        Assert.Equal(info.TargetManifestId, result.Target!.ManifestId);
        Assert.Equal(suite, result.Target.HashSuite);
        Assert.Equal(scenario.TargetContent, File.ReadAllBytes(destination));
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task RepeatedMissingChunk_IsStoredOnceAndWrittenEveryTime(
        string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);

        // A block longer than the profile's maximum chunk repeats three times,
        // so at least one ChunkId occurs three times in the target manifest.
        byte[] block = CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED2001u);
        byte[] targetContent = [.. block, .. block, .. block];
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            targetContent,
            suite);
        List<ChunkInfo> records =
            await CreationTestSupport.ReadRecordsAsync(targetManifest);

        ChunkId repeated = records
            .GroupBy(static record => record.Id)
            .First(static group => group.Count() == 3)
            .Key;

        using var destination = new MemoryStream();
        PatchInfo info = await ChunkPatch.CreateAsync(
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            destination);

        byte[] patch = destination.ToArray();
        CspReader reader = await CreationTestSupport.OpenAsync(patch);

        // One payload entry serves every occurrence of the repeated ChunkId.
        Assert.Equal(1, reader.PayloadChunkIds.Count(chunkId => chunkId == repeated));
        Assert.Equal(
            records.Select(static record => record.Id).Distinct().Count(),
            reader.PayloadChunkIds.Count);
        Assert.Equal(reader.PayloadChunkIds.Count, info.PayloadEntryCount);

        string output = Path.Combine(_directory, $"repeated-{hashSuite}.bin");
        PatchApplyResult result = await ChunkPatch.ApplyAsync(
            new MemoryStream(patch, writable: false),
            output);

        Assert.True(result.IsApplied);
        Assert.Equal(targetContent, File.ReadAllBytes(output));
    }
}
