using ChunkShift.Patching.Creation;
using ChunkShift.Patching.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Creation;

/// <summary>
/// Byte oracle of the create executions: every execution writes H0's patch for every creation scenario
/// and every dictionary size, and the patch reconstructs its target.
/// </summary>
public sealed class PatchCreationExecutionBytesTests
{
    private const int Kibibyte = 1024;

    public static TheoryData<string, string> ScenariosByExecution
    {
        get
        {
            var data = new TheoryData<string, string>();

            foreach (PatchScenario scenario in PatchScenarios.All)
            {
                foreach (string execution in CreationExecutions.Names)
                {
                    data.Add(scenario.Name, execution);
                }
            }

            return data;
        }
    }

    public static TheoryData<string, int> ExecutionsByDictionaryChunks
    {
        get
        {
            var data = new TheoryData<string, int>();

            foreach (string execution in CreationExecutions.Names)
            {
                foreach (int chunks in (int[])[1, 2, 4])
                {
                    data.Add(execution, chunks);
                }
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(ScenariosByExecution))]
    public async Task EveryScenario_MakesH0sBytesAndReconstructs(string scenarioName, string executionName)
    {
        PatchScenario scenario = PatchScenarios.Find(scenarioName);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(scenario.BaseContent, scenario.TargetContent);
        byte[]? baseManifestOrNull = scenario.SelfContained ? null : baseManifest;
        byte[]? baseContentOrNull = scenario.SelfContained ? null : scenario.BaseContent;

        byte[] expected = await CreationExecutions.H0Async(
            $"scenario/{scenarioName}",
            () => CreationExecutions.CreateAsync(
                baseManifestOrNull,
                baseContentOrNull,
                targetManifest,
                scenario.TargetContent,
                CspEncoderPolicy.Default,
                CspCreateExecution.Sequential));
        var statistics = new CspCreateStatistics();
        byte[] actual = await CreationExecutions.CreateAsync(
            baseManifestOrNull,
            baseContentOrNull,
            targetManifest,
            scenario.TargetContent,
            CspEncoderPolicy.Default,
            CreationExecutions.Parse(executionName) with { Statistics = statistics });

        Assert.Equal(expected, actual);
        Assert.Equal(
            scenario.TargetContent,
            await CreationTestSupport.ReconstructAsync(actual, baseManifestOrNull, baseContentOrNull));
        AssertNothingLeaked(statistics);
    }

    // The public API runs two encode workers (h2-w2) from two
    // processors on and the sequential pass on one; either makes H0's patch.
    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 2)]
    [InlineData(4, 2)]
    [InlineData(64, 2)]
    public void DefaultExecution_IsTwoWorkersFromTwoProcessorsOtherwiseSequential(int processors, int workers)
    {
        CspCreateExecution execution = CspCreateExecution.ForProcessorCount(processors);

        Assert.Equal(workers, execution.WorkerCount);
        Assert.False(execution.UseBaseCandidateCache);
        Assert.Equal(
            CspCreateExecution.ForProcessorCount(Environment.ProcessorCount),
            CspCreateExecution.Default);
    }

    [Fact]
    public async Task PublicApi_MakesH0sBytes()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.EditedChunks);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(scenario.BaseContent, scenario.TargetContent);

        (byte[] publicPatch, _) = await CreationTestSupport.CreatePatchAsync(scenario, baseManifest, targetManifest);
        byte[] h0 = await CreationExecutions.CreateAsync(
            baseManifest,
            scenario.BaseContent,
            targetManifest,
            scenario.TargetContent,
            CspEncoderPolicy.Default,
            CspCreateExecution.Sequential);

        Assert.Equal(publicPatch, h0);
    }

    [Theory]
    [MemberData(nameof(ExecutionsByDictionaryChunks))]
    public async Task SparseEdits_MakeH0sBytesAtEveryDictionarySize(string executionName, int dictionaryChunks)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(768 * Kibibyte, 48 * Kibibyte, 0x5EED6001u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        CspEncoderPolicy policy = CspEncoderPolicy.Default with { DictionaryChunks = dictionaryChunks };

        byte[] expected = await CreationExecutions.H0Async(
            $"sparse/K{dictionaryChunks}",
            () => CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, targetContent, policy, CspCreateExecution.Sequential));
        var statistics = new CspCreateStatistics();
        byte[] actual = await CreationExecutions.CreateAsync(
            baseManifest,
            baseContent,
            targetManifest,
            targetContent,
            policy,
            CreationExecutions.Parse(executionName) with { Statistics = statistics });

        Assert.Equal(expected, actual);
        CspReader reader = await CreationTestSupport.OpenAsync(actual);
        Assert.Contains(reader.Index, static entry => entry.DictionaryCount > 0);
        Assert.Equal(targetContent, await CreationTestSupport.ReconstructAsync(actual, baseManifest, baseContent));
        Assert.True(statistics.CachePeakRecords <= policy.MaxCandidates + dictionaryChunks - 1);
        AssertNothingLeaked(statistics);
    }

    private static void AssertNothingLeaked(CspCreateStatistics statistics)
    {
        Assert.Equal(0, statistics.ResidualEntries);
        Assert.Equal(0, statistics.ResidualBytes);
        Assert.Equal(0, statistics.OutstandingBuffers);
    }
}
