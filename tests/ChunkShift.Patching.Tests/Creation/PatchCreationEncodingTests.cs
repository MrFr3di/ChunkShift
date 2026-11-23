using ChunkShift.Patching.Creation;
using ChunkShift.Patching.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Creation;

public sealed class PatchCreationEncodingTests
{
    [Fact]
    public async Task DictionaryChunksZero_NoEntryNamesADictionary()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.EditedChunks);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);
        byte[] patch = await CreationTestSupport.CreatePatchWithPolicyAsync(
            scenario,
            baseManifest,
            targetManifest,
            CspEncoderPolicy.Default with { DictionaryChunks = 0 });

        CspReader reader = await CreationTestSupport.OpenAsync(patch);

        Assert.NotEmpty(reader.Index);
        Assert.All(
            reader.Index,
            static entry => Assert.Equal(0, entry.DictionaryCount));

        Assert.Equal(
            scenario.TargetContent,
            await CreationTestSupport.ReconstructAsync(patch, baseManifest, scenario.BaseContent));
    }

    [Fact]
    public async Task LevelZero_NoEntryIsEncoded()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.EditedChunks);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);
        byte[] patch = await CreationTestSupport.CreatePatchWithPolicyAsync(
            scenario,
            baseManifest,
            targetManifest,
            CspEncoderPolicy.Default with { Level = 0 });

        CspReader reader = await CreationTestSupport.OpenAsync(patch);

        Assert.NotEmpty(reader.Index);
        Assert.All(
            reader.Index,
            static entry => Assert.Equal(CspFormat.EncodingRaw, entry.Encoding));

        Assert.Equal(
            scenario.TargetContent,
            await CreationTestSupport.ReconstructAsync(patch, baseManifest, scenario.BaseContent));
    }

    // The builder reuses its dictionary and frame buffers across candidates and
    // chunks; every K must still name the dictionary its frame was encoded
    // against, or the reconstruction fails.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public async Task DictionaryEntries_ReconstructAtEveryDictionarySize(int dictionaryChunks)
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.EditedChunks);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);
        byte[] patch = await CreationTestSupport.CreatePatchWithPolicyAsync(
            scenario,
            baseManifest,
            targetManifest,
            CspEncoderPolicy.Default with { DictionaryChunks = dictionaryChunks });

        CspReader reader = await CreationTestSupport.OpenAsync(patch);

        Assert.Contains(reader.Index, static entry => entry.DictionaryCount > 0);
        Assert.All(
            reader.Index,
            entry => Assert.InRange(entry.DictionaryCount, 0, dictionaryChunks));
        Assert.Equal(
            scenario.TargetContent,
            await CreationTestSupport.ReconstructAsync(patch, baseManifest, scenario.BaseContent));
    }

    [Theory]
    [InlineData(PatchScenarios.Different)]
    [InlineData(PatchScenarios.Inserted)]
    [InlineData(PatchScenarios.XorRegion)]
    [InlineData(PatchScenarios.EditedChunks)]
    [InlineData(PatchScenarios.CompressibleText)]
    [InlineData(PatchScenarios.SelfContainedInserted)]
    public async Task StoredForms_ObeyTheFormatRules(string scenarioName)
    {
        PatchScenario scenario = PatchScenarios.Find(scenarioName);
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

        CspReader reader = await CreationTestSupport.OpenAsync(patch);
        List<ChunkInfo> targetRecords =
            await CreationTestSupport.ReadTargetRecordsAsync(reader);

        Assert.Equal(reader.Index.Count, reader.PayloadChunkIds.Count);
        Assert.NotEmpty(reader.Index);

        for (int ordinal = 0; ordinal < reader.Index.Count; ordinal++)
        {
            CspIndexEntry index = reader.Index[ordinal];
            ChunkInfo record = targetRecords[checked((int)index.FirstTargetIndex)];
            CspEntry entry = await reader.ReadEntryAsync(ordinal);

            Assert.Equal(record.Id, entry.ChunkId);
            Assert.True(
                index.StoredLength <= (uint)record.Length,
                $"Payload entry {ordinal} stores {index.StoredLength} bytes for " +
                $"a {record.Length}-byte chunk.");

            if (entry.Encoding == CspFormat.EncodingRaw)
            {
                // A raw entry's stored bytes ARE the chunk bytes.
                Assert.Equal((uint)record.Length, index.StoredLength);
                Assert.Equal(
                    scenario.TargetContent
                        .AsSpan(checked((int)record.Offset), record.Length)
                        .ToArray(),
                    entry.StoredBytes);
                Assert.Empty(entry.DictionaryChunkIds);
            }
            else
            {
                Assert.Equal(CspFormat.EncodingZstd, entry.Encoding);
            }
        }
    }
}
