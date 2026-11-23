using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Creation;

public sealed class PatchCreationTests
{
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
    public async Task Scenario_ReconstructsTheTargetAndAgreesWithTheReader(
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
        List<ChunkInfo> targetRecords =
            await CreationTestSupport.ReadRecordsAsync(targetManifest);

        (byte[] patch, PatchInfo info) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        // The in-test applier resolves every target record from the base or from
        // the payload and must reproduce the target content byte for byte.
        byte[] reconstructed = await CreationTestSupport.ReconstructAsync(
            patch,
            scenario.SelfContained ? null : baseManifest,
            scenario.SelfContained ? null : scenario.BaseContent);
        Assert.Equal(scenario.TargetContent, reconstructed);

        CspReader reader = await CreationTestSupport.OpenAsync(patch);

        // PatchInfo reports exactly what the reader sees.
        Assert.Equal(reader.TargetManifest.Manifest.ManifestId, info.TargetManifestId);
        Assert.Equal(reader.ExpectedBaseManifestId, info.BaseManifestId);
        Assert.Equal(reader.TargetManifest.Manifest.HashSuite, info.HashSuite);
        Assert.Equal((long)reader.Index.Count, info.PayloadEntryCount);
        Assert.Equal(
            reader.Index.Sum(static entry => (long)entry.StoredLength),
            info.PayloadBytes);
        Assert.Equal(patch.Length, info.PhysicalLength);
        Assert.Equal(
            PatchHashing.Hash(suite, patch.AsSpan(0, patch.Length - CspFormat.TrailerSize)),
            info.FileDigest);

        Assert.Equal(
            scenario.SelfContained,
            reader.ExpectedBaseManifestId is null);

        if (scenarioName == PatchScenarios.Identical)
        {
            // The base supplies every chunk, so the payload stays empty.
            Assert.Empty(reader.Index);
            Assert.True(reader.DependsOnBase);
        }

        if (scenarioName == PatchScenarios.RepeatedBlock)
        {
            // One payload entry serves many occurrences of a repeated chunk.
            Dictionary<ChunkId, int> occurrences = targetRecords
                .GroupBy(static record => record.Id)
                .ToDictionary(static group => group.Key, static group => group.Count());
            Assert.True(targetRecords.Count > reader.Index.Count);
            Assert.Contains(
                reader.PayloadChunkIds,
                chunkId => occurrences[chunkId] > 1);
        }

        if (scenarioName == PatchScenarios.CompressibleText)
        {
            // Repeated text must be stored as zstd frames, not raw copies.
            Assert.Contains(
                reader.Index,
                static entry => entry.Encoding == CspFormat.EncodingZstd);
        }

        if (scenarioName == PatchScenarios.EditedChunks)
        {
            // Small edits inside chunks must recover their base chunks as
            // dictionaries.
            Assert.Contains(
                reader.Index,
                static entry => entry.Encoding == CspFormat.EncodingZstd &&
                    entry.DictionaryCount > 0);
        }
    }

    [Fact]
    public async Task CreatingTheSamePatchTwice_ProducesIdenticalBytes()
    {
        // Non-normative (CSP-V1 section 3.5): the stored bytes of a patch are
        // a physical representation and are not a compatibility contract. This
        // pins only that one build is reproducible for one input.
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.EditedChunks);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);

        (byte[] first, _) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);
        (byte[] second, _) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task ScenarioPatches_AreDumpedWhenTheEnvironmentVariableIsSet()
    {
        string? directory = Environment.GetEnvironmentVariable("CHUNKSHIFT_CSP_DUMP");

        if (string.IsNullOrEmpty(directory))
        {
            // No independent-decoder run was requested.
            return;
        }

        await DumpScenariosAsync(directory);
    }

    /// <summary>
    /// Writes the patches of every scenario under both HashSuites and their
    /// base files to <paramref name="directory"/>, with the file names the
    /// independent decoder consumes.
    /// </summary>
    internal static async Task DumpScenariosAsync(string directory)
    {
        Directory.CreateDirectory(directory);

        foreach (HashSuiteId suite in (HashSuiteId[])[HashSuiteIds.Sha256V1, HashSuiteIds.Blake3256V1])
        {
            string suffix = suite == HashSuiteIds.Sha256V1 ? string.Empty : "-blake3";

            foreach (PatchScenario scenario in PatchScenarios.All)
            {
                await DumpScenarioAsync(directory, scenario.Name + suffix, scenario, suite);
            }
        }
    }

    private static async Task DumpScenarioAsync(
        string directory,
        string name,
        PatchScenario scenario,
        HashSuiteId suite)
    {
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            suite);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            suite);
        (byte[] patch, _) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        File.WriteAllBytes(
            Path.Combine(directory, $"{name}.csp"),
            patch);
        File.WriteAllBytes(
            Path.Combine(directory, $"{name}.base.csm"),
            baseManifest);
        File.WriteAllBytes(
            Path.Combine(directory, $"{name}.base.bin"),
            scenario.BaseContent);
        File.WriteAllText(
            Path.Combine(directory, $"{name}.target.sha256"),
            Convert.ToHexStringLower(
                System.Security.Cryptography.SHA256.HashData(
                    scenario.TargetContent)));
    }
}
