using ChunkShift.Patching.Creation;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Creation;

/// <summary>
/// The create executions (<see cref="CreationExecutions"/>): every
/// execution writes H0's patch bytes, fails as H0 fails, and keeps the cache
/// and the pipeline within their declared bounds.
/// </summary>
public sealed class PatchCreationExecutionTests
{
    private const int Kibibyte = 1024;

    public static TheoryData<string> Executions => CreationExecutions.All();

    // Workers finish in an order unrelated to the target: every entry whose
    // sequence number is even waits, so later entries complete first. The
    // writer must still see first-occurrence order.
    [Theory]
    [InlineData("h2-w2")]
    [InlineData("h2-w4")]
    [InlineData("h2-w8")]
    [InlineData("h3-w2")]
    [InlineData("h3-w4")]
    [InlineData("h3-w8")]
    public async Task CompletionOutOfOrder_WritesFirstOccurrenceOrder(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1024 * Kibibyte, 32 * Kibibyte, 0x5EED6002u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        byte[] expected = await CreationExecutions.H0Async(
            "out-of-order",
            () => CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, targetContent, CspEncoderPolicy.Default, CspCreateExecution.Sequential));

        var statistics = new CspCreateStatistics();
        CspCreateExecution execution = CreationExecutions.Parse(executionName) with
        {
            Statistics = statistics,
            WorkerDelay = static async (sequence, cancellationToken) =>
            {
                if (sequence % 2 == 0)
                {
                    await Task.Delay(20, cancellationToken);
                }
            },
        };

        byte[] actual = await CreationExecutions.CreateAsync(
            baseManifest, baseContent, targetManifest, targetContent, CspEncoderPolicy.Default, execution);

        Assert.Equal(expected, actual);

        CspReader expectedReader = await CreationTestSupport.OpenAsync(expected);
        CspReader actualReader = await CreationTestSupport.OpenAsync(actual);
        Assert.Equal(
            expectedReader.Index.Select(static entry => entry.FirstTargetIndex),
            actualReader.Index.Select(static entry => entry.FirstTargetIndex));
        Assert.Equal(expectedReader.PayloadChunkIds, actualReader.PayloadChunkIds);
        Assert.True(actualReader.Index.Count > 8);

        // The delayed entries made the reorder window hold later entries.
        Assert.True(statistics.ReorderPeakEntries > 1);
        Assert.True(statistics.ReorderPeakEntries <= execution.WorkerCount * execution.WindowEntriesPerWorker);
        AssertNothingLeaked(statistics);
    }

    [Theory]
    [InlineData("h2-w1")]
    [InlineData("h2-w4")]
    [InlineData("h3-w1")]
    [InlineData("h3-w4")]
    [InlineData("h3-w8")]
    public async Task Window_StaysWithinItsEntryAndByteBounds(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(768 * Kibibyte, 16 * Kibibyte, 0x5EED6003u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        byte[] expected = await CreationExecutions.H0Async(
            "window",
            () => CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, targetContent, CspEncoderPolicy.Default, CspCreateExecution.Sequential));
        int longest = (await CreationTestSupport.ReadRecordsAsync(targetManifest)).Max(static record => record.Length);
        int longestBase = (await CreationTestSupport.ReadRecordsAsync(baseManifest)).Max(static record => record.Length);

        foreach (long bytesPerWorker in (long[])[1, 96 * Kibibyte, 4 * 1024 * Kibibyte])
        {
            var statistics = new CspCreateStatistics();
            CspCreateExecution execution = CreationExecutions.Parse(executionName) with
            {
                Statistics = statistics,
                WindowEntriesPerWorker = 2,
                WindowBytesPerWorker = bytesPerWorker,
            };

            byte[] actual = await CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, targetContent, CspEncoderPolicy.Default, execution);

            Assert.Equal(expected, actual);

            long entryBound = execution.WorkerCount * execution.WindowEntriesPerWorker;
            long byteBound = execution.WorkerCount * bytesPerWorker;
            Assert.InRange(statistics.WindowPeakEntries, 1, entryBound);
            Assert.InRange(statistics.ReorderPeakEntries, 1, entryBound);

            // Admission stops at the byte bound; the admitted entry and the
            // base records its window loads may exceed it once.
            long overshoot = longest + ((CspEncoderPolicy.Default.MaxCandidates + CspEncoderPolicy.Default.DictionaryChunks - 1) * (long)longestBase);
            Assert.True(
                statistics.WindowPeakBytes <= byteBound + overshoot,
                $"window peak {statistics.WindowPeakBytes} B over {byteBound} + {overshoot} B");
            Assert.True(statistics.ReorderPeakBytes <= statistics.WindowPeakBytes);

            if (bytesPerWorker == 1)
            {
                // Below one entry, the window admits one entry at a time.
                Assert.Equal(1, statistics.WindowPeakEntries);
            }

            AssertNothingLeaked(statistics);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public async Task Cache_ReusesRecordsAcrossCandidatesAndEntries(int dictionaryChunks)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(2048 * Kibibyte, 24 * Kibibyte, 0x5EED6004u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        CspEncoderPolicy policy = CspEncoderPolicy.Default with { DictionaryChunks = dictionaryChunks };

        var h0Base = new ObservedReadStream(baseContent);
        byte[] expected = await CreationExecutions.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            h0Base,
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            policy,
            CspCreateExecution.Sequential);

        var h1Base = new ObservedReadStream(baseContent);
        var statistics = new CspCreateStatistics();
        byte[] actual = await CreationExecutions.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            h1Base,
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            policy,
            new CspCreateExecution(0, UseBaseCandidateCache: true) { Statistics = statistics });

        Assert.Equal(expected, actual);

        // Each record is read once while it stays in adjacent windows, so
        // most of H0's reads and nearly all of its seeks go away.
        Assert.True(statistics.CacheHits > statistics.CacheLoads);
        Assert.True(h1Base.BytesRead * 2 <= h0Base.BytesRead, $"H1 read {h1Base.BytesRead} B, H0 {h0Base.BytesRead} B");
        Assert.True(h1Base.Seeks * 2 <= h0Base.Seeks, $"H1 seeks {h1Base.Seeks}, H0 {h0Base.Seeks}");
        Assert.True(statistics.CachePeakRecords <= policy.MaxCandidates + dictionaryChunks - 1);
        Assert.Equal(0, statistics.OutstandingBuffers);
    }

    // Workers of H2 share the base stream; H3 workers never touch it. Either
    // way the stream never serves two callers at once.
    [Theory]
    [InlineData("h2-w2")]
    [InlineData("h2-w8")]
    [InlineData("h3-w8")]
    public async Task BaseStream_IsNeverUsedConcurrently(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1024 * Kibibyte, 16 * Kibibyte, 0x5EED6005u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        byte[] expected = await CreationExecutions.H0Async(
            "concurrent",
            () => CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, targetContent, CspEncoderPolicy.Default, CspCreateExecution.Sequential));
        var observed = new ObservedReadStream(baseContent);

        byte[] actual = await CreationExecutions.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            observed,
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            CspEncoderPolicy.Default,
            CreationExecutions.Parse(executionName));

        Assert.Equal(expected, actual);
        Assert.Equal(0, observed.ConcurrentUses);
        Assert.True(observed.Reads > 0);
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task ShortReads_OnEveryInput_MakeH0sBytes(string executionName)
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.XorRegion);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(scenario.BaseContent, scenario.TargetContent);
        byte[] expected = await CreationExecutions.CreateAsync(
            baseManifest, scenario.BaseContent, targetManifest, scenario.TargetContent, CspEncoderPolicy.Default, CspCreateExecution.Sequential);
        var baseContent = new ShortReadStream(scenario.BaseContent, 0x5EED6006u);

        byte[] actual = await CreationExecutions.CreateAsync(
            new ShortReadStream(baseManifest, 0x5EED6007u, seekable: false),
            baseContent,
            new ShortReadStream(targetManifest, 0x5EED6008u),
            new ShortReadStream(scenario.TargetContent, 0x5EED6009u, seekable: false),
            CspEncoderPolicy.Default,
            CreationExecutions.Parse(executionName));

        Assert.Equal(expected, actual);
        Assert.True(baseContent.ShortReads > 0);
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task ChangedByteInAChosenDictionaryChunk_FailsAsH0(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1024 * Kibibyte, 96 * Kibibyte, 0x5EED600Au);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        byte[] patch = await CreationExecutions.CreateAsync(
            baseManifest, baseContent, targetManifest, targetContent, CspEncoderPolicy.Default, CspCreateExecution.Sequential);

        // Corrupt the first base chunk the patch names as a dictionary.
        CspReader reader = await CreationTestSupport.OpenAsync(patch);
        int ordinal = reader.Index.ToList().FindIndex(static entry => entry.DictionaryCount > 0);
        Assert.True(ordinal >= 0);
        CspEntry entry = await reader.ReadEntryAsync(ordinal);
        ChunkInfo record = (await CreationTestSupport.ReadRecordsAsync(baseManifest))
            .First(candidate => candidate.Id == entry.DictionaryChunkIds[0]);
        byte[] corrupted = (byte[])baseContent.Clone();
        corrupted[checked((int)record.Offset)] ^= 0x01;

        await AssertFailsAsH0Async<InvalidDataException>(
            executionName,
            execution => CreationExecutions.CreateAsync(
                baseManifest, corrupted, targetManifest, targetContent, CspEncoderPolicy.Default, execution));
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task ChangedByteInAMissingTargetChunk_FailsAsH0(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1024 * Kibibyte, 64 * Kibibyte, 0x5EED600Bu);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        byte[] changed = (byte[])targetContent.Clone();
        changed[700 * Kibibyte] ^= 0x01;

        await AssertFailsAsH0Async<InvalidDataException>(
            executionName,
            execution => CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, changed, CspEncoderPolicy.Default, execution));
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task ShortAndLongTargets_FailAsH0(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(512 * Kibibyte, 64 * Kibibyte, 0x5EED600Cu);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);

        await AssertFailsAsH0Async<InvalidDataException>(
            executionName,
            execution => CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, targetContent[..(targetContent.Length - 1000)], CspEncoderPolicy.Default, execution));
        await AssertFailsAsH0Async<InvalidDataException>(
            executionName,
            execution => CreationExecutions.CreateAsync(
                baseManifest, baseContent, targetManifest, [.. targetContent, 0x42], CspEncoderPolicy.Default, execution));
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task TruncatedBase_FailsAsH0(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1024 * Kibibyte, 64 * Kibibyte, 0x5EED600Du);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        byte[] truncated = baseContent[..(baseContent.Length / 2)];

        await AssertFailsAsH0Async<InvalidDataException>(
            executionName,
            execution => CreationExecutions.CreateAsync(
                baseManifest, truncated, targetManifest, targetContent, CspEncoderPolicy.Default, execution));
    }

    // Two failures: a dictionary chunk the first entries need is corrupted,
    // and a target chunk far later does not match. H0 meets the dictionary
    // first; so must every execution, however its workers are scheduled.
    [Theory]
    [MemberData(nameof(Executions))]
    public async Task TwoFailures_ReportTheFirstInTargetOrder(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1024 * Kibibyte, 64 * Kibibyte, 0x5EED600Eu);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        byte[] corruptedBase = (byte[])baseContent.Clone();
        corruptedBase[40 * Kibibyte] ^= 0x01;
        byte[] changedTarget = (byte[])targetContent.Clone();
        changedTarget[^100] ^= 0x01;

        Exception h0 = await AssertFailsAsH0Async<InvalidDataException>(
            executionName,
            execution => CreationExecutions.CreateAsync(
                baseManifest, corruptedBase, targetManifest, changedTarget, CspEncoderPolicy.Default, execution),
            workerDelay: static async (sequence, cancellationToken) =>
            {
                // The first entries are slow, so the producer reaches the
                // bad target chunk while they are still encoding.
                if (sequence < 2)
                {
                    await Task.Delay(50, cancellationToken);
                }
            });

        Assert.Contains("base content", h0.Message, StringComparison.Ordinal);
    }

    // The manifest reader returns records in batches of 256 and reads the
    // next section only on the next call. With exactly 256 records, H0
    // chooses record 255, and meets its failing base read, before it reads
    // the manifest's TRAILER. With that entry's worker delayed, the producer
    // reaches the failing TRAILER first; the failure after the last record
    // must still lose to the entry's own.
    [Theory]
    [MemberData(nameof(Executions))]
    public async Task ManifestFailureAtTheBatchBoundary_LosesToTheLastEntrysFailure(string executionName)
    {
        const int Records = 256;
        byte[] source = CspBytes.CreateXorShiftBytes(24 * 1024 * Kibibyte, 0x5EED6015u);
        List<ChunkInfo> sourceRecords = await CreationTestSupport.ReadRecordsAsync(
            await CreationTestSupport.CreateManifestAsync(source, HashSuiteIds.Sha256V1));
        Assert.True(sourceRecords.Count > Records);

        // A prefix that ends on a cut has the same first cuts; changing its
        // last byte keeps them, so both sides have exactly 256 records.
        ChunkInfo last = sourceRecords[Records - 1];
        byte[] baseContent = source[..checked((int)(last.Offset + last.Length))];
        byte[] targetContent = (byte[])baseContent.Clone();
        targetContent[^1] ^= 0x5A;
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        Assert.Equal(Records, (await CreationTestSupport.ReadRecordsAsync(targetManifest)).Count);

        Task<byte[]> Create(CspCreateExecution execution) => CreationExecutions.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            new ObservedReadStream(baseContent, failAtOffset: last.Offset + 10),
            new TailFailingStream(targetManifest, failFromPass: 3),
            new MemoryStream(targetContent, writable: false),
            CspEncoderPolicy.Default,
            execution);

        IOException expected = await Assert.ThrowsAsync<IOException>(
            () => Create(CspCreateExecution.Sequential));
        Assert.Equal("Injected base read failure.", expected.Message);

        var statistics = new CspCreateStatistics();
        IOException actual = await Assert.ThrowsAsync<IOException>(() => Create(
            CreationExecutions.Parse(executionName) with
            {
                Statistics = statistics,
                WorkerDelay = static (_, cancellationToken) => new ValueTask(Task.Delay(100, cancellationToken)),
            }));

        Assert.Equal(expected.Message, actual.Message);
        AssertNothingLeaked(statistics);
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task ThrowingBaseStream_PropagatesItsException(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1024 * Kibibyte, 64 * Kibibyte, 0x5EED600Fu);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        var statistics = new CspCreateStatistics();

        IOException error = await Assert.ThrowsAsync<IOException>(() => CreationExecutions.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            new ObservedReadStream(baseContent, failAtOffset: 300 * Kibibyte),
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            CspEncoderPolicy.Default,
            CreationExecutions.Parse(executionName) with { Statistics = statistics }));

        Assert.Equal("Injected base read failure.", error.Message);
        AssertNothingLeaked(statistics);
    }

    // Six MiB of new content fill more than one 4 MiB PAYL block, so the
    // writer flushes a block, and the disk fills, while entries are added.
    [Theory]
    [MemberData(nameof(Executions))]
    public async Task FullDestination_ThrowsItsIoException(string executionName)
    {
        byte[] baseContent = CspBytes.CreateXorShiftBytes(256 * Kibibyte, 0x5EED6010u);
        byte[] targetContent = CspBytes.CreateXorShiftBytes(6 * 1024 * Kibibyte, 0x5EED6014u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        CspEncoderPolicy policy = CspEncoderPolicy.Default with { Level = 1 };
        byte[] complete = await CreationExecutions.CreateAsync(
            baseManifest, baseContent, targetManifest, targetContent, policy, CspCreateExecution.Sequential);
        var statistics = new CspCreateStatistics();

        IOException error = await Assert.ThrowsAsync<IOException>(() => Patching.Creation.CspPatchBuilder.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(baseContent, writable: false),
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            new FullDestinationStream(complete.Length / 2),
            policy,
            CreationExecutions.Parse(executionName) with { Statistics = statistics },
            CancellationToken.None));

        Assert.Equal("No space left on device", error.Message);
        AssertNothingLeaked(statistics);
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task PreCancelledToken_ThrowsOperationCanceledException(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(256 * Kibibyte, 64 * Kibibyte, 0x5EED6011u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CreationExecutions.CreateAsync(
            baseManifest,
            baseContent,
            targetManifest,
            targetContent,
            CspEncoderPolicy.Default,
            CreationExecutions.Parse(executionName),
            cancellation.Token));
    }

    [Theory]
    [MemberData(nameof(Executions))]
    public async Task CancellationWhileEncoding_ThrowsOperationCanceledException(string executionName)
    {
        (byte[] baseContent, byte[] targetContent) =
            CreationExecutions.SparseEdits(1536 * Kibibyte, 16 * Kibibyte, 0x5EED6012u);
        (byte[] baseManifest, byte[] targetManifest) =
            await CreationExecutions.ManifestsAsync(baseContent, targetContent, HashSuiteIds.Sha256V1);
        using var cancellation = new CancellationTokenSource();
        var statistics = new CspCreateStatistics();
        var targetStream = new CancelAfterReadsStream(targetContent, cancellation, reads: 6);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CreationExecutions.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(baseContent, writable: false),
            new MemoryStream(targetManifest, writable: false),
            targetStream,
            CspEncoderPolicy.Default,
            CreationExecutions.Parse(executionName) with { Statistics = statistics },
            cancellation.Token));

        Assert.True(targetStream.Position < targetContent.Length);
        AssertNothingLeaked(statistics);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(CspCreateExecution.MaximumWorkerCount + 1)]
    public async Task WorkerCountOutOfRange_IsRejected(int workers)
    {
        byte[] content = CspBytes.CreateXorShiftBytes(64 * Kibibyte, 0x5EED6013u);
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(content, HashSuiteIds.Sha256V1);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => CreationExecutions.CreateAsync(
            null, null, manifest, content, CspEncoderPolicy.Default, new CspCreateExecution(workers, false)));
    }

    /// <summary>
    /// Runs the failing create with H0 and with <paramref name="executionName"/>
    /// and requires the same exception type and message from both.
    /// </summary>
    private static async Task<Exception> AssertFailsAsH0Async<TException>(
        string executionName,
        Func<CspCreateExecution, Task> create,
        Func<long, CancellationToken, ValueTask>? workerDelay = null)
        where TException : Exception
    {
        TException expected = await Assert.ThrowsAsync<TException>(() => create(CspCreateExecution.Sequential));
        var statistics = new CspCreateStatistics();
        TException actual = await Assert.ThrowsAsync<TException>(() => create(
            CreationExecutions.Parse(executionName) with { Statistics = statistics, WorkerDelay = workerDelay }));

        Assert.Equal(expected.Message, actual.Message);
        AssertNothingLeaked(statistics);
        return expected;
    }

    private static void AssertNothingLeaked(CspCreateStatistics statistics)
    {
        Assert.Equal(0, statistics.ResidualEntries);
        Assert.Equal(0, statistics.ResidualBytes);
        Assert.Equal(0, statistics.OutstandingBuffers);
    }

    /// <summary>
    /// Seekable read-only stream whose reads of its last 64 bytes (the CSM
    /// TRAILER) throw an <see cref="IOException"/> from its
    /// <paramref name="failFromPass"/>-th pass on, where a pass starts
    /// whenever the position is set to zero.
    /// </summary>
    private sealed class TailFailingStream(byte[] content, int failFromPass)
        : MemoryStream(content, writable: false)
    {
        private int _passes = 1;

        public override long Position
        {
            get => base.Position;
            set
            {
                if (value == 0)
                {
                    _passes++;
                }

                base.Position = value;
            }
        }

        public override int Read(Span<byte> buffer)
        {
            ThrowAtTail(buffer.Length);
            return base.Read(buffer);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ThrowAtTail(count);
            return base.Read(buffer, offset, count);
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ThrowAtTail(buffer.Length);
            return base.ReadAsync(buffer, cancellationToken);
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            ThrowAtTail(count);
            return base.ReadAsync(buffer, offset, count, cancellationToken);
        }

        private void ThrowAtTail(int count)
        {
            if (_passes >= failFromPass && count > 0 && base.Position + count > Length - 64)
            {
                throw new IOException("Injected target manifest failure at its tail.");
            }
        }
    }

    /// <summary>Cancels its token once it has served a number of reads.</summary>
    private sealed class CancelAfterReadsStream(byte[] content, CancellationTokenSource cancellation, int reads)
        : MemoryStream(content, writable: false)
    {
        private int _reads;

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            int read = await base.ReadAsync(buffer, cancellationToken);

            if (++_reads == reads)
            {
                await cancellation.CancelAsync();
            }

            return read;
        }
    }
}
