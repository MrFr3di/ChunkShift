using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests;

public sealed class PlanTests
{
    private const int Mebibyte = 1024 * 1024;

    [Theory]
    [InlineData("chunkshift.blake3-256.v1", "identical")]
    [InlineData("chunkshift.blake3-256.v1", "inserted")]
    [InlineData("chunkshift.blake3-256.v1", "different")]
    [InlineData("chunkshift.sha256.v1", "identical")]
    [InlineData("chunkshift.sha256.v1", "inserted")]
    [InlineData("chunkshift.sha256.v1", "different")]
    public async Task Plan_MatchesCountsComputedFromManifestRecords(
        string hashSuite,
        string pair)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] baseContent = CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED0001u);
        byte[] targetContent = pair switch
        {
            "identical" => baseContent,
            "inserted" => Insert(
                baseContent,
                Mebibyte / 2,
                CspBytes.CreateXorShiftBytes(4096, 0x5EED0002u)),
            "different" => CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED0003u),
            _ => throw new InvalidOperationException(
                $"Unknown content pair '{pair}'."),
        };

        byte[] baseManifest = await CreateManifestAsync(baseContent, suite);
        byte[] targetManifest = await CreateManifestAsync(targetContent, suite);

        PatchPlan plan = await PlanAsync(baseManifest, targetManifest);
        ExpectedCounts expected =
            await ComputeExpectedCountsAsync(baseManifest, targetManifest);

        Assert.True(plan.IsValid);
        AssertCountsEqual(expected, plan);
        Assert.Equal(
            targetContent.Length,
            plan.ReusedBytes + plan.MissingBytes);
        Assert.Equal(
            plan.Target.Manifest.ChunkCount,
            plan.ReusedChunks + plan.MissingChunks);
        Assert.True(plan.UniqueMissingBytes <= plan.MissingBytes);

        if (pair == "identical")
        {
            Assert.Equal(0, plan.MissingBytes);
            Assert.Equal(targetContent.Length, plan.ReusedBytes);
        }
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task DuplicateTargetChunks_CountEveryOccurrenceAndOneLengthPerDistinctId(
        string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] block = CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED0010u);
        byte[] targetContent = Repeat(block, 8);
        byte[] differentContent = Repeat(
            CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED0011u),
            8);

        byte[] targetManifest = await CreateManifestAsync(targetContent, suite);
        byte[] differentManifest = await CreateManifestAsync(
            differentContent,
            suite);

        List<ChunkInfo> targetRecords = await ReadRecordsAsync(targetManifest);
        int distinctTargetIds = targetRecords
            .Select(static record => record.Id)
            .Distinct()
            .Count();
        long expectedUniqueBytes = targetRecords
            .GroupBy(static record => record.Id)
            .Sum(static group => (long)group.First().Length);

        // Precondition: the repeated block really produces repeated chunks.
        Assert.True(
            targetRecords.Count > distinctTargetIds,
            $"The target has {targetRecords.Count} chunk records and " +
            $"{distinctTargetIds} distinct chunk IDs.");

        // Every occurrence is counted as missing if the base cannot supply it.
        PatchPlan missing = await PlanAsync(differentManifest, targetManifest);

        Assert.True(missing.IsValid);
        Assert.Equal(targetRecords.Count, missing.MissingChunks);
        Assert.Equal(targetContent.Length, missing.MissingBytes);
        Assert.Equal(0, missing.ReusedChunks);
        Assert.Equal(0, missing.ReusedBytes);
        Assert.Equal(distinctTargetIds, missing.UniqueMissingChunks);
        Assert.Equal(expectedUniqueBytes, missing.UniqueMissingBytes);
        Assert.True(missing.UniqueMissingChunks < missing.MissingChunks);

        // Every occurrence is counted as reused if the base supplies it.
        PatchPlan reused = await PlanAsync(targetManifest, targetManifest);

        Assert.True(reused.IsValid);
        Assert.Equal(targetRecords.Count, reused.ReusedChunks);
        Assert.Equal(targetContent.Length, reused.ReusedBytes);
        Assert.Equal(0, reused.MissingChunks);
        Assert.Equal(0, reused.MissingBytes);
        Assert.Equal(0, reused.UniqueMissingChunks);
        Assert.Equal(0, reused.UniqueMissingBytes);
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1", "chunkshift.sha256.v1")]
    [InlineData("chunkshift.sha256.v1", "chunkshift.blake3-256.v1")]
    public async Task DifferentHashSuites_CountEveryTargetRecordAsMissing(
        string baseSuite,
        string targetSuite)
    {
        var baseHashSuite = new HashSuiteId(baseSuite);
        var targetHashSuite = new HashSuiteId(targetSuite);
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED0020u);

        byte[] baseManifest = await CreateManifestAsync(content, baseHashSuite);
        byte[] targetManifest = await CreateManifestAsync(
            content,
            targetHashSuite);

        PatchPlan plan = await PlanAsync(baseManifest, targetManifest);
        List<ChunkInfo> targetRecords = await ReadRecordsAsync(targetManifest);

        Assert.True(plan.IsValid);
        Assert.NotEqual(
            plan.Base.Manifest.HashSuite,
            plan.Target.Manifest.HashSuite);
        Assert.Equal(0, plan.ReusedChunks);
        Assert.Equal(0, plan.ReusedBytes);
        Assert.Equal(targetRecords.Count, plan.MissingChunks);
        Assert.Equal(plan.Target.Manifest.ChunkCount, plan.MissingChunks);
        Assert.Equal(content.Length, plan.MissingBytes);
        Assert.Equal(
            targetRecords
                .Select(static record => record.Id)
                .Distinct()
                .Count(),
            plan.UniqueMissingChunks);
        Assert.Equal(
            targetRecords
                .GroupBy(static record => record.Id)
                .Sum(static group => (long)group.First().Length),
            plan.UniqueMissingBytes);
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task BaseFileDigestMismatch_IsReportedAndCountsAreStillComputed(
        string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED0030u);

        byte[] baseManifest = await CreateManifestAsync(content, suite);
        byte[] targetManifest = await CreateManifestAsync(content, suite);

        // The TRAILER is the last 64 bytes and its FileDigest starts at offset
        // 24, so flipping one byte there leaves the record layout intact.
        baseManifest[^40] ^= 0x01;

        PatchPlan plan = await PlanAsync(baseManifest, targetManifest);
        ExpectedCounts expected =
            await ComputeExpectedCountsAsync(baseManifest, targetManifest);

        Assert.False(plan.IsValid);
        Assert.False(plan.Base.IsValid);
        Assert.True(plan.Target.IsValid);
        Assert.Equal(
            ManifestVerificationFailure.FileDigest,
            plan.Base.Failures);
        AssertCountsEqual(expected, plan);
        Assert.Equal(0, plan.MissingBytes);
        Assert.Equal(content.Length, plan.ReusedBytes);
    }

    [Fact]
    public async Task ForwardOnlyStreams_AreAcceptedAndNeverDisposed()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(128 * 1024, 0x5EED0040u);
        byte[] manifest = await CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);

        using var baseInner = new ForwardOnlyReadStream(manifest);
        using var targetInner = new ForwardOnlyReadStream(manifest);
        using var baseStream = new DisposeTrackingStream(baseInner);
        using var targetStream = new DisposeTrackingStream(targetInner);

        PatchPlan plan = await ChunkPatch.PlanAsync(baseStream, targetStream);

        Assert.True(plan.IsValid);
        Assert.False(baseStream.CanSeek);
        Assert.False(targetStream.CanSeek);
        Assert.False(baseStream.Disposed);
        Assert.False(targetStream.Disposed);
        Assert.True(baseStream.CanRead);
        Assert.True(targetStream.CanRead);
    }

    [Fact]
    public async Task ArgumentErrors_AreThrownByTheCall()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED0041u);
        byte[] manifest = await CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);

        using var other = new MemoryStream(manifest, writable: false);
        using var nonReadable = new WriteOnlyStream(new MemoryStream());

        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.PlanAsync(null!, other);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.PlanAsync(other, null!);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.PlanAsync(nonReadable, other);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.PlanAsync(other, nonReadable);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.PlanAsync(other, other);
        });
    }

    [Fact]
    public async Task PreCancelledToken_ThrowsOperationCanceledException()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED0042u);
        byte[] manifest = await CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);

        using var baseStream = new MemoryStream(manifest, writable: false);
        using var targetStream = new MemoryStream(manifest, writable: false);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkPatch.PlanAsync(
                baseStream,
                targetStream,
                cancellation.Token));
    }

    private static async Task<byte[]> CreateManifestAsync(
        byte[] content,
        HashSuiteId hashSuite)
    {
        using var destination = new MemoryStream();

        await ChunkManifest.CreateAsync(
            new MemoryStream(content, writable: false),
            destination,
            new ManifestCreationOptions { HashSuite = hashSuite },
            CancellationToken.None);

        return destination.ToArray();
    }

    private static async Task<PatchPlan> PlanAsync(
        byte[] baseManifest,
        byte[] targetManifest)
    {
        using var baseStream = new MemoryStream(baseManifest, writable: false);
        using var targetStream =
            new MemoryStream(targetManifest, writable: false);

        return await ChunkPatch.PlanAsync(baseStream, targetStream);
    }

    private static async Task<List<ChunkInfo>> ReadRecordsAsync(byte[] manifest)
    {
        using var stream = new MemoryStream(manifest, writable: false);
        await using ManifestReader reader = await ManifestReader.OpenAsync(stream);

        var records = new List<ChunkInfo>();
        var batch = new ChunkInfo[512];
        int count;
        while ((count = await reader.ReadAsync(batch)) != 0)
        {
            for (int index = 0; index < count; index++)
            {
                records.Add(batch[index]);
            }
        }

        Assert.NotNull(reader.VerificationResult);
        return records;
    }

    private static async Task<ExpectedCounts> ComputeExpectedCountsAsync(
        byte[] baseManifest,
        byte[] targetManifest)
    {
        List<ChunkInfo> baseRecords = await ReadRecordsAsync(baseManifest);
        List<ChunkInfo> targetRecords = await ReadRecordsAsync(targetManifest);

        var baseIds = new HashSet<ChunkId>(
            baseRecords.Select(static record => record.Id));

        long reusedChunks = 0;
        long reusedBytes = 0;
        long missingChunks = 0;
        long missingBytes = 0;
        long uniqueMissingBytes = 0;
        var uniqueMissingIds = new HashSet<ChunkId>();

        foreach (ChunkInfo chunk in targetRecords)
        {
            if (baseIds.Contains(chunk.Id))
            {
                reusedChunks++;
                reusedBytes += chunk.Length;
                continue;
            }

            missingChunks++;
            missingBytes += chunk.Length;

            if (uniqueMissingIds.Add(chunk.Id))
            {
                uniqueMissingBytes += chunk.Length;
            }
        }

        return new ExpectedCounts(
            reusedChunks,
            reusedBytes,
            missingChunks,
            missingBytes,
            uniqueMissingIds.Count,
            uniqueMissingBytes);
    }

    private static void AssertCountsEqual(ExpectedCounts expected, PatchPlan plan)
    {
        Assert.Equal(expected.ReusedChunks, plan.ReusedChunks);
        Assert.Equal(expected.ReusedBytes, plan.ReusedBytes);
        Assert.Equal(expected.MissingChunks, plan.MissingChunks);
        Assert.Equal(expected.MissingBytes, plan.MissingBytes);
        Assert.Equal(expected.UniqueMissingChunks, plan.UniqueMissingChunks);
        Assert.Equal(expected.UniqueMissingBytes, plan.UniqueMissingBytes);
    }

    private static byte[] Insert(byte[] content, int offset, byte[] inserted)
    {
        var result = new byte[content.Length + inserted.Length];
        content.AsSpan(0, offset).CopyTo(result);
        inserted.CopyTo(result, offset);
        content.AsSpan(offset).CopyTo(result.AsSpan(offset + inserted.Length));
        return result;
    }

    private static byte[] Repeat(byte[] block, int count)
    {
        var result = new byte[block.Length * count];

        for (int index = 0; index < count; index++)
        {
            block.CopyTo(result, index * block.Length);
        }

        return result;
    }

    private readonly record struct ExpectedCounts(
        long ReusedChunks,
        long ReusedBytes,
        long MissingChunks,
        long MissingBytes,
        long UniqueMissingChunks,
        long UniqueMissingBytes);
}
