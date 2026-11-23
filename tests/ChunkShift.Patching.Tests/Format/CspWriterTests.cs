using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Format;

public sealed class CspWriterTests
{
    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task NoBaseNoEntries_MatchesIndependentBytes(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(suite, 64 * 1024);
        byte[] expected = new CspPatchBuilder
        {
            HashSuite = suite,
            TargetManifest = targetManifest,
        }.Build();

        (byte[] actual, CspWriteResult result) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase: null,
            []);

        Assert.Equal(expected, actual);
        Assert.Equal((ulong)actual.Length, result.PhysicalLength);
        Assert.Equal(0UL, result.PayloadEntryCount);
        Assert.Equal(0UL, result.PaylCount);
        Assert.Equal(0UL, result.StoredPayloadBytes);
        Assert.Equal(
            PatchHashing.Hash(suite, actual.AsSpan(0, actual.Length - CspFormat.TrailerSize)),
            result.FileDigest);
        Assert.Equal(
            result.FileDigest,
            Hash256.FromBytes(
                actual.AsSpan(
                    actual.Length - CspFormat.TrailerSize + 24,
                    CspFormat.HashSize)));
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task BaseAndEntries_MatchIndependentBytes(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(suite, 64 * 1024);
        var expectedBase = new ManifestId(
            Hash256.FromBytes(CspBytes.CreateXorShiftBytes(32, 0xBA5E01u)));
        CspPatchEntry[] entries =
        [
            Entry(1, 0, storedLength: 1000),
            Entry(2, 5, CspFormat.EncodingZstd, 512),
            Entry(3, 9, CspFormat.EncodingZstd, 256, 4, 5),
        ];
        byte[] expected = new CspPatchBuilder
        {
            HashSuite = suite,
            TargetManifest = targetManifest,
            ExpectedBase = expectedBase,
        }.AddEntries(entries).Build();

        (byte[] actual, CspWriteResult result) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase,
            entries);

        Assert.Equal(expected, actual);
        Assert.Equal((ulong)entries.Length, result.PayloadEntryCount);
        Assert.Equal(1UL, result.PaylCount);
        Assert.Equal(1000UL + 512 + 256, result.StoredPayloadBytes);
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task FourThousandNinetySevenEntries_SplitAtTheEntryCap(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(suite, 32 * 1024);
        const int entryCount = 4097;
        var entries = new CspPatchEntry[entryCount];

        for (int index = 0; index < entryCount; index++)
        {
            entries[index] = new CspPatchEntry(
                CspBytes.ChunkId((ulong)index + 1),
                (ulong)index,
                CspFormat.EncodingRaw,
                CspBytes.CreateXorShiftBytes(1 + (index % 7), (uint)(0x1000 + index)),
                []);
        }

        byte[] expected = new CspPatchBuilder
        {
            HashSuite = suite,
            TargetManifest = targetManifest,
        }.AddEntries(entries).Build();

        (byte[] actual, CspWriteResult result) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase: null,
            entries);

        Assert.Equal(expected, actual);
        Assert.Equal(2UL, result.PaylCount);
        Assert.Equal((ulong)entryCount, result.PayloadEntryCount);

        IReadOnlyList<CspSectionInfo> sections =
            CspBytes.FindSections(actual, CspFormat.Payload);
        Assert.Equal(2, sections.Count);
        Assert.Equal((uint)4096, CspBytes.ReadPaylEntryCount(actual, sections[0].Offset));
        Assert.Equal(1u, CspBytes.ReadPaylEntryCount(actual, sections[1].Offset));
        Assert.Equal(0UL, CspBytes.ReadPaylFirstEntryOrdinal(actual, sections[0].Offset));
        Assert.Equal(4096UL, CspBytes.ReadPaylFirstEntryOrdinal(actual, sections[1].Offset));

        IReadOnlyList<CspPaylEntryInfo> payloadEntries =
            CspBytes.ReadAllPaylEntries(actual);
        IReadOnlyList<CspPidxEntryInfo> indexEntries = CspBytes.ReadPidxEntries(actual);

        Assert.Equal(entryCount, payloadEntries.Count);
        Assert.Equal(entryCount, indexEntries.Count);

        for (int index = 0; index < entryCount; index++)
        {
            Assert.Equal(entries[index].ChunkId.Value, payloadEntries[index].ChunkId.Value);
            Assert.Equal(
                (ulong)payloadEntries[index].RecordOffset,
                indexEntries[index].PayloadOffset);
            Assert.Equal(
                entries[index].ChunkId.Value,
                Hash256.FromBytes(actual.AsSpan(
                    checked((int)indexEntries[index].PayloadOffset),
                    CspFormat.HashSize)));
        }
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task PaylBlocks_FollowTheBoundedBlockRule(string hashSuite)
    {
        const int blockBytes = 200;
        var suite = new HashSuiteId(hashSuite);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(suite, 16 * 1024);
        CspPatchEntry[] entries =
        [
            Entry(1, 0, storedLength: 60),
            Entry(2, 1, storedLength: 60),
            Entry(3, 2, storedLength: 60),
            Entry(4, 3, storedLength: 60),
            Entry(100, 4, storedLength: 460),
            Entry(101, 5, storedLength: 60),
        ];
        byte[] expected = new CspPatchBuilder
        {
            HashSuite = suite,
            TargetManifest = targetManifest,
            BlockBytes = blockBytes,
        }.AddEntries(entries).Build();

        (byte[] actual, CspWriteResult result) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase: null,
            entries,
            payloadBlockBytes: blockBytes);

        Assert.Equal(expected, actual);
        Assert.Equal(4UL, result.PaylCount);

        IReadOnlyList<CspSectionInfo> sections =
            CspBytes.FindSections(actual, CspFormat.Payload);
        Assert.Equal(4, sections.Count);
        Assert.Equal(2u, CspBytes.ReadPaylEntryCount(actual, sections[0].Offset));
        Assert.Equal(2u, CspBytes.ReadPaylEntryCount(actual, sections[1].Offset));
        Assert.Equal(1u, CspBytes.ReadPaylEntryCount(actual, sections[2].Offset));
        Assert.Equal(1u, CspBytes.ReadPaylEntryCount(actual, sections[3].Offset));
        Assert.Equal(0UL, CspBytes.ReadPaylFirstEntryOrdinal(actual, sections[0].Offset));
        Assert.Equal(2UL, CspBytes.ReadPaylFirstEntryOrdinal(actual, sections[1].Offset));
        Assert.Equal(4UL, CspBytes.ReadPaylFirstEntryOrdinal(actual, sections[2].Offset));
        Assert.Equal(5UL, CspBytes.ReadPaylFirstEntryOrdinal(actual, sections[3].Offset));
    }

    [Fact]
    public async Task BoundedBuffering_BoundsTheLargestDestinationWrite()
    {
        const int blockBytes = 65_536;
        const int storedLength = 16_384;
        byte[] targetManifest = await CspBytes.CreateCsmAsync(
            HashSuiteIds.Sha256V1,
            16 * 1024);
        using var storage = new MemoryStream();
        using var destination = new WriteOnlyStream(storage);
        using var writer = new CspWriter(
            destination,
            HashSuiteIds.Sha256V1,
            payloadBlockBytes: blockBytes);

        await writer.WriteTargetManifestAsync(
            new MemoryStream(targetManifest, writable: false),
            targetManifest.Length,
            CancellationToken.None);

        for (int index = 0; index < 200; index++)
        {
            await AddEntryAsync(
                writer,
                Entry((ulong)index + 1, (ulong)index, storedLength: storedLength));
        }

        _ = await writer.CompleteAsync(CancellationToken.None);

        int bound = CspFormat.SectionHeaderSize
            + CspFormat.PaylPrefixSize
            + blockBytes
            + CspFormat.CrcSize;
        Assert.True(
            destination.MaxWriteLength <= bound,
            $"Largest destination write was {destination.MaxWriteLength} bytes.");
        Assert.False(destination.CanSeek);
    }

    [Fact]
    public void Constructor_RejectsInvalidArguments()
    {
        using var destination = new MemoryStream();
        using var readOnly = new MemoryStream([], writable: false);

        Assert.Throws<ArgumentNullException>(
            () => new CspWriter(null!, HashSuiteIds.Sha256V1));
        Assert.Throws<ArgumentNullException>(
            () => new CspWriter(destination, null!));
        Assert.Throws<ArgumentException>(
            () => new CspWriter(readOnly, HashSuiteIds.Sha256V1));
        Assert.Throws<NotSupportedException>(
            () => new CspWriter(destination, new HashSuiteId("test.unsupported.v1")));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new CspWriter(destination, HashSuiteIds.Sha256V1, payloadBlockBytes: 0));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new CspWriter(destination, HashSuiteIds.Sha256V1, maximumPayloadEntries: 0));
    }

    [Fact]
    public async Task EntryValidation_RejectsDocumentedErrors()
    {
        byte[] stored = CspBytes.CreateXorShiftBytes(16, 0xABCDu);

        await AssertEntryRejectedAsync<ArgumentOutOfRangeException>(
            new CspPayloadEntry(CspBytes.ChunkId(1), 0, 2, ReadOnlyMemory<ChunkId>.Empty),
            stored);

        await AssertEntryRejectedAsync<ArgumentException>(
            new CspPayloadEntry(
                CspBytes.ChunkId(1),
                0,
                CspFormat.EncodingRaw,
                new ChunkId[] { CspBytes.ChunkId(2) }),
            stored);

        await AssertEntryRejectedAsync<ArgumentException>(
            new CspPayloadEntry(
                CspBytes.ChunkId(1),
                0,
                CspFormat.EncodingZstd,
                new ChunkId[]
                {
                    CspBytes.ChunkId(2),
                    CspBytes.ChunkId(3),
                    CspBytes.ChunkId(4),
                    CspBytes.ChunkId(5),
                    CspBytes.ChunkId(6),
                }),
            stored);

        await AssertEntryRejectedAsync<ArgumentException>(
            new CspPayloadEntry(
                CspBytes.ChunkId(1),
                0,
                CspFormat.EncodingRaw,
                ReadOnlyMemory<ChunkId>.Empty),
            storedBytes: []);
    }

    [Fact]
    public async Task FirstTargetIndexes_MustStrictlyIncrease()
    {
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(destination);

        await AddEntryAsync(writer, Entry(1, 5));

        await Assert.ThrowsAsync<ArgumentException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(2, 5)),
                CspBytes.CreateXorShiftBytes(16, 1),
                CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task EntryLimit_RejectsTheEntryAfterTheMaximum()
    {
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(
            destination,
            maximumPayloadEntries: 1);

        await AddEntryAsync(writer, Entry(1, 0));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(2, 1)),
                CspBytes.CreateXorShiftBytes(16, 2),
                CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task CallOrder_BeforeTargetManifest_IsRejected()
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(destination, HashSuiteIds.Sha256V1);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteExpectedBaseAsync(
                new ManifestId(Hash256.FromBytes(CspBytes.CreateXorShiftBytes(32, 1))),
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(1, 0)),
                CspBytes.CreateXorShiftBytes(16, 1),
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.CompleteAsync(CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task CallOrder_AfterTargetManifest_IsRejected()
    {
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(destination);
        var expectedBase = new ManifestId(
            Hash256.FromBytes(CspBytes.CreateXorShiftBytes(32, 0xB10C4u)));

        await writer.WriteExpectedBaseAsync(expectedBase, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteTargetManifestAsync(
                new MemoryStream(CspBytes.CreateXorShiftBytes(4, 7), writable: false),
                4,
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteExpectedBaseAsync(expectedBase, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task CallOrder_BaseAfterPayloadEntry_IsRejected()
    {
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(destination);

        await AddEntryAsync(writer, Entry(1, 0));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteExpectedBaseAsync(
                new ManifestId(Hash256.FromBytes(CspBytes.CreateXorShiftBytes(32, 2))),
                CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task CallOrder_AfterCompletion_IsRejected()
    {
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(destination);

        _ = await writer.CompleteAsync(CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.CompleteAsync(CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(1, 0)),
                CspBytes.CreateXorShiftBytes(16, 1),
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteExpectedBaseAsync(
                new ManifestId(Hash256.FromBytes(CspBytes.CreateXorShiftBytes(32, 3))),
                CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task TargetManifest_RejectsInvalidArguments()
    {
        using var readOnly = new MemoryStream([], writable: false);
        using var nonReadable = new WriteOnlyStream(new MemoryStream());

        await AssertTargetManifestRejectedAsync<ArgumentNullException>(
            null!,
            3);
        await AssertTargetManifestRejectedAsync<ArgumentException>(
            nonReadable,
            3);
        await AssertTargetManifestRejectedAsync<ArgumentOutOfRangeException>(
            readOnly,
            0);
        await AssertTargetManifestRejectedAsync<ArgumentOutOfRangeException>(
            readOnly,
            -1);
    }

    [Fact]
    public async Task TargetManifestShorterThanDeclaredLength_IsInvalidData()
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(destination, HashSuiteIds.Sha256V1);
        using var manifest = new MemoryStream([1, 2, 3, 4], writable: false);

        InvalidDataException error = await Assert.ThrowsAsync<InvalidDataException>(
            () => writer.WriteTargetManifestAsync(
                manifest,
                8,
                CancellationToken.None).AsTask());

        Assert.Contains("declared length", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FailedCall_FaultsTheWriter()
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(destination, HashSuiteIds.Sha256V1);
        using var manifest = new MemoryStream([1, 2, 3], writable: false);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => writer.WriteTargetManifestAsync(
                manifest,
                8,
                CancellationToken.None).AsTask());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteTargetManifestAsync(
                manifest,
                3,
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteExpectedBaseAsync(default, CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(1, 0)),
                CspBytes.CreateXorShiftBytes(16, 1),
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.CompleteAsync(CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task ValidationError_FaultsTheWriter()
    {
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(destination);

        await Assert.ThrowsAsync<ArgumentException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(1, 0)),
                ReadOnlyMemory<byte>.Empty,
                CancellationToken.None).AsTask());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(2, 1)),
                CspBytes.CreateXorShiftBytes(16, 2),
                CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task PreCancelledToken_WritesNothingAndFaultsTheWriter()
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(destination, HashSuiteIds.Sha256V1);
        using var manifest = new MemoryStream([1, 2, 3], writable: false);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => writer.WriteTargetManifestAsync(
                manifest,
                3,
                cancellation.Token).AsTask());

        Assert.Equal(0, destination.Length);
        Assert.Equal(0UL, writer.Offset);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => writer.WriteTargetManifestAsync(
                manifest,
                3,
                CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task PreCancelledTokenOnComplete_WritesNothingForThatCall()
    {
        byte[] targetManifest = CspBytes.CreateXorShiftBytes(64, 0xC0DEu);
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(
            destination,
            targetManifest: targetManifest);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        long before = destination.Length;

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => writer.CompleteAsync(cancellation.Token).AsTask());

        Assert.Equal(before, destination.Length);
        Assert.Equal((ulong)before, writer.Offset);
    }

    [Fact]
    public async Task Writer_NeverDisposesItsStreams()
    {
        byte[] targetManifest = CspBytes.CreateXorShiftBytes(64, 0x0D15C0DEu);
        using var storage = new MemoryStream();
        using var destination = new DisposeTrackingStream(storage);
        using var source = new MemoryStream(targetManifest, writable: false);
        using var manifest = new DisposeTrackingStream(source);

        using (var writer = new CspWriter(destination, HashSuiteIds.Sha256V1))
        {
            await writer.WriteTargetManifestAsync(
                manifest,
                targetManifest.Length,
                CancellationToken.None);
            await AddEntryAsync(writer, Entry(1, 0));
            _ = await writer.CompleteAsync(CancellationToken.None);
        }

        Assert.False(destination.Disposed);
        Assert.False(manifest.Disposed);
        Assert.True(destination.CanWrite);
        Assert.True(manifest.CanRead);
    }

    [Fact]
    public async Task WriteOnlyNonSeekableDestination_ReceivesThePatch()
    {
        var suite = HashSuiteIds.Sha256V1;
        byte[] targetManifest = await CspBytes.CreateCsmAsync(suite, 32 * 1024);
        CspPatchEntry[] entries =
        [
            Entry(1, 0, storedLength: 128),
            Entry(2, 1, CspFormat.EncodingZstd, 64),
        ];
        byte[] expected = new CspPatchBuilder
        {
            HashSuite = suite,
            TargetManifest = targetManifest,
        }.AddEntries(entries).Build();

        using var storage = new MemoryStream();
        using var destination = new WriteOnlyStream(storage);
        using var writer = new CspWriter(destination, suite);

        await writer.WriteTargetManifestAsync(
            new MemoryStream(targetManifest, writable: false),
            targetManifest.Length,
            CancellationToken.None);

        foreach (CspPatchEntry entry in entries)
        {
            await AddEntryAsync(writer, entry);
        }

        _ = await writer.CompleteAsync(CancellationToken.None);

        Assert.False(destination.CanSeek);
        Assert.Equal(expected, storage.ToArray());
        Assert.True(destination.WriteCalls > 0);
    }

    [Fact]
    public async Task DisposedWriter_RejectsCalls()
    {
        using var destination = new MemoryStream();
        byte[] targetManifest = CspBytes.CreateXorShiftBytes(64, 0xD15C05Eu);
        var writer = new CspWriter(destination, HashSuiteIds.Sha256V1);
        writer.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => writer.WriteTargetManifestAsync(
                new MemoryStream(targetManifest, writable: false),
                targetManifest.Length,
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => writer.WriteExpectedBaseAsync(default, CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => writer.AddPayloadEntryAsync(
                ToWriterEntry(Entry(1, 0)),
                CspBytes.CreateXorShiftBytes(16, 1),
                CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => writer.CompleteAsync(CancellationToken.None).AsTask());
    }

    private static async Task<(byte[] Bytes, CspWriteResult Result)> WritePatchAsync(
        HashSuiteId hashSuite,
        byte[] targetManifest,
        ManifestId? expectedBase,
        IEnumerable<CspPatchEntry> entries,
        int payloadBlockBytes = CspWriter.DefaultPayloadBlockBytes)
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(
            destination,
            hashSuite,
            payloadBlockBytes);

        await writer.WriteTargetManifestAsync(
            new MemoryStream(targetManifest, writable: false),
            targetManifest.Length,
            CancellationToken.None);

        if (expectedBase.HasValue)
        {
            await writer.WriteExpectedBaseAsync(expectedBase.Value, CancellationToken.None);
        }

        foreach (CspPatchEntry entry in entries)
        {
            await AddEntryAsync(writer, entry);
        }

        CspWriteResult result = await writer.CompleteAsync(CancellationToken.None);
        return (destination.ToArray(), result);
    }

    /// <summary>
    /// Creates a writer whose target manifest (opaque to the writer) is already
    /// written, so call-order tests start from a valid state.
    /// </summary>
    private static async Task<CspWriter> OpenWriterAsync(
        MemoryStream destination,
        byte[]? targetManifest = null,
        int maximumPayloadEntries = CspFormat.DefaultMaximumPayloadEntries)
    {
        byte[] manifest = targetManifest ?? CspBytes.CreateXorShiftBytes(64, 0x7A11C0DEu);
        var writer = new CspWriter(
            destination,
            HashSuiteIds.Sha256V1,
            CspWriter.DefaultPayloadBlockBytes,
            maximumPayloadEntries);

        await writer.WriteTargetManifestAsync(
            new MemoryStream(manifest, writable: false),
            manifest.Length,
            CancellationToken.None);

        return writer;
    }

    private static async Task AssertEntryRejectedAsync<TException>(
        CspPayloadEntry entry,
        byte[] storedBytes)
        where TException : Exception
    {
        using var destination = new MemoryStream();
        using var writer = await OpenWriterAsync(destination);

        await Assert.ThrowsAsync<TException>(
            () => writer.AddPayloadEntryAsync(
                entry,
                storedBytes,
                CancellationToken.None).AsTask());
    }

    private static async Task AssertTargetManifestRejectedAsync<TException>(
        Stream manifest,
        long length)
        where TException : Exception
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(destination, HashSuiteIds.Sha256V1);

        await Assert.ThrowsAsync<TException>(
            () => writer.WriteTargetManifestAsync(
                manifest,
                length,
                CancellationToken.None).AsTask());

        Assert.Equal(0, destination.Length);
    }

    private static Task AddEntryAsync(CspWriter writer, CspPatchEntry entry) =>
        writer.AddPayloadEntryAsync(
            ToWriterEntry(entry),
            entry.StoredBytes,
            CancellationToken.None).AsTask();

    private static CspPayloadEntry ToWriterEntry(CspPatchEntry entry) =>
        new(
            entry.ChunkId,
            entry.FirstTargetIndex,
            entry.Encoding,
            entry.DictionaryChunkIds);

    private static CspPatchEntry Entry(
        ulong id,
        ulong firstTargetIndex,
        byte encoding = CspFormat.EncodingRaw,
        int storedLength = 16,
        params ulong[] dictionaryIds)
    {
        var dictionary = new ChunkId[dictionaryIds.Length];

        for (int index = 0; index < dictionaryIds.Length; index++)
        {
            dictionary[index] = CspBytes.ChunkId(dictionaryIds[index]);
        }

        return new CspPatchEntry(
            CspBytes.ChunkId(id),
            firstTargetIndex,
            encoding,
            CspBytes.CreateXorShiftBytes(storedLength, 0xE000u + (uint)id),
            dictionary);
    }
}
