using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Format;

public sealed class CspReaderTests
{
    [Theory]
    [InlineData("chunkshift.sha256.v1")]
    [InlineData("chunkshift.blake3-256.v1")]
    public async Task NoEntries_WithBase_OpensAndCarriesTheBase(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(suite, 256 * 1024);
        ManifestId expectedBase = BaseId(0xBA5E01u);
        (byte[] patch, _) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase,
            []);

        CspReader reader = await OpenAsync(patch);

        Assert.Equal(CspVerificationFailure.None, reader.Failures);
        Assert.True(reader.IsValid);
        Assert.Empty(reader.Index);
        Assert.Empty(reader.PayloadChunkIds);
        Assert.True(reader.ExpectedBaseManifestId.HasValue);
        Assert.Equal(expectedBase, reader.ExpectedBaseManifestId!.Value);
        Assert.True(reader.DependsOnBase);
        Assert.Equal(
            await TargetManifestIdAsync(targetManifest),
            reader.TargetManifest.Manifest.ManifestId);
        Assert.Equal(
            CspBytes.FindSection(patch, CspFormat.TargetManifest).Offset +
                CspFormat.SectionHeaderSize,
            reader.TargetManifestOffset);
        Assert.Equal(targetManifest.Length, reader.TargetManifestLength);
        Assert.Equal(targetManifest, ReadAll(reader.OpenTargetManifest()));
    }

    [Theory]
    [InlineData("chunkshift.sha256.v1")]
    [InlineData("chunkshift.blake3-256.v1")]
    public async Task BaseAndEntries_RoundTripEveryField(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] content = CspBytes.CreateXorShiftBytes(1024 * 1024, 0x7A11C0DEu);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(
            suite,
            content.Length,
            0x7A11C0DEu);
        IReadOnlyList<ChunkInfo> records = await ReadRecordsAsync(targetManifest);
        Assert.True(records.Count >= 8, $"The target has only {records.Count} records.");
        ManifestId expectedBase = BaseId(0xBA5E02u);

        var entries = new List<CspPatchEntry>
        {
            new(
                records[0].Id,
                0,
                CspFormat.EncodingRaw,
                Slice(content, records[0]),
                []),
            new(
                records[1].Id,
                1,
                CspFormat.EncodingZstd,
                CspBytes.CreateXorShiftBytes(16, 0xE001u),
                []),
            new(
                records[2].Id,
                2,
                CspFormat.EncodingZstd,
                CspBytes.CreateXorShiftBytes(24, 0xE002u),
                [records[0].Id, records[1].Id]),
        };

        (byte[] patch, _) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase,
            entries);

        CspReader reader = await OpenAsync(patch);

        Assert.Equal(CspVerificationFailure.None, reader.Failures);
        Assert.Equal(expectedBase, reader.ExpectedBaseManifestId!.Value);
        Assert.True(reader.DependsOnBase);
        Assert.Equal(
            await TargetManifestIdAsync(targetManifest),
            reader.TargetManifest.Manifest.ManifestId);
        Assert.Equal(targetManifest, ReadAll(reader.OpenTargetManifest()));

        IReadOnlyList<CspPidxEntryInfo> index = CspBytes.ReadPidxEntries(patch);
        Assert.Equal(entries.Count, reader.Index.Count);
        Assert.Equal(entries.Count, index.Count);
        Assert.Equal(entries.Count, reader.PayloadChunkIds.Count);

        for (int ordinal = 0; ordinal < entries.Count; ordinal++)
        {
            CspIndexEntry actual = reader.Index[ordinal];
            CspPidxEntryInfo expected = index[ordinal];

            Assert.Equal(expected.FirstTargetIndex, actual.FirstTargetIndex);
            Assert.Equal(expected.PayloadOffset, actual.PayloadOffset);
            Assert.Equal(expected.StoredLength, actual.StoredLength);
            Assert.Equal(expected.Encoding, actual.Encoding);
            Assert.Equal(expected.DictionaryCount, actual.DictionaryCount);
            Assert.Equal(entries[ordinal].ChunkId, reader.PayloadChunkIds[ordinal]);

            CspEntry entry = await reader.ReadEntryAsync(ordinal);
            Assert.Equal(entries[ordinal].ChunkId, entry.ChunkId);
            Assert.Equal(entries[ordinal].Encoding, entry.Encoding);
            Assert.Equal(entries[ordinal].DictionaryChunkIds, entry.DictionaryChunkIds);
            Assert.Equal(entries[ordinal].StoredBytes, entry.StoredBytes);
        }
    }

    [Theory]
    [InlineData("chunkshift.sha256.v1")]
    [InlineData("chunkshift.blake3-256.v1")]
    public async Task SelfContainedPatch_DoesNotDependOnABase(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5E1FC0u);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(
            suite,
            content.Length,
            0x5E1FC0u);
        IReadOnlyList<ChunkInfo> records = await ReadRecordsAsync(targetManifest);
        var entries = new List<CspPatchEntry>();

        for (int index = 0; index < records.Count; index++)
        {
            entries.Add(new CspPatchEntry(
                records[index].Id,
                (ulong)index,
                CspFormat.EncodingRaw,
                Slice(content, records[index]),
                []));
        }

        (byte[] patch, _) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase: null,
            entries);

        CspReader reader = await OpenAsync(patch);

        Assert.Equal(CspVerificationFailure.None, reader.Failures);
        Assert.False(reader.ExpectedBaseManifestId.HasValue);
        Assert.False(reader.DependsOnBase);
        Assert.Equal(entries.Count, reader.Index.Count);
        Assert.Equal(entries.Count, reader.PayloadChunkIds.Count);
        Assert.Equal(targetManifest, ReadAll(reader.OpenTargetManifest()));
    }

    [Theory]
    [InlineData("chunkshift.sha256.v1")]
    [InlineData("chunkshift.blake3-256.v1")]
    public async Task FourThousandNinetySevenEntries_SpanTwoPaylSections(string hashSuite)
    {
        const int entryCount = 4097;
        const long sourceLength = 384L * 1024 * 1024;
        var suite = new HashSuiteId(hashSuite);

        byte[] targetManifest = await CreateLargeCsmAsync(suite, sourceLength, 0x4097u);
        IReadOnlyList<ChunkInfo> records = await ReadRecordsAsync(targetManifest);
        Assert.True(
            records.Count >= entryCount,
            $"The target has only {records.Count} records.");
        var entries = new List<CspPatchEntry>(entryCount);

        for (int index = 0; index < entryCount; index++)
        {
            entries.Add(new CspPatchEntry(
                records[index].Id,
                (ulong)index,
                CspFormat.EncodingZstd,
                [0x42],
                []));
        }

        ManifestId expectedBase = BaseId(0x4097u);
        (byte[] patch, CspWriteResult result) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase,
            entries);

        Assert.Equal(2UL, result.PaylCount);
        Assert.Equal(2, CspBytes.FindSections(patch, CspFormat.Payload).Count);

        CspReader reader = await OpenAsync(patch);

        Assert.Equal(CspVerificationFailure.None, reader.Failures);
        Assert.Equal(entryCount, reader.Index.Count);
        Assert.Equal(entryCount, reader.PayloadChunkIds.Count);
        Assert.True(reader.DependsOnBase);
        Assert.Equal(expectedBase, reader.ExpectedBaseManifestId!.Value);

        CspEntry first = await reader.ReadEntryAsync(0);
        Assert.Equal(records[0].Id, first.ChunkId);
        Assert.Equal(CspFormat.EncodingZstd, first.Encoding);
        Assert.Equal([0x42], first.StoredBytes);
        Assert.Empty(first.DictionaryChunkIds);

        CspEntry last = await reader.ReadEntryAsync(entryCount - 1);
        Assert.Equal(records[entryCount - 1].Id, last.ChunkId);
        Assert.Equal([0x42], last.StoredBytes);
    }

    [Fact]
    public async Task PatchAfterJunkBytes_OpensRelativeToTheStartPosition()
    {
        HashSuiteId suite = HashSuiteIds.Sha256V1;
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x1A2Bu);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(
            suite,
            content.Length,
            0x1A2Bu);
        IReadOnlyList<ChunkInfo> records = await ReadRecordsAsync(targetManifest);
        var entries = new List<CspPatchEntry>();

        for (int index = 0; index < records.Count; index++)
        {
            entries.Add(new CspPatchEntry(
                records[index].Id,
                (ulong)index,
                CspFormat.EncodingRaw,
                Slice(content, records[index]),
                []));
        }

        (byte[] patch, _) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase: null,
            entries);

        var storage = new byte[100 + patch.Length];
        patch.CopyTo(storage, 100);
        using var stream = new MemoryStream(storage, writable: false);
        stream.Position = 100;

        CspReader reader = await CspReader.OpenAsync(stream);

        Assert.Equal(CspVerificationFailure.None, reader.Failures);
        Assert.False(reader.DependsOnBase);
        Assert.Equal(
            CspBytes.FindSection(patch, CspFormat.TargetManifest).Offset +
                CspFormat.SectionHeaderSize,
            reader.TargetManifestOffset);
        Assert.Equal(targetManifest, ReadAll(reader.OpenTargetManifest()));

        CspEntry entry = await reader.ReadEntryAsync(0);
        Assert.Equal(entries[0].StoredBytes, entry.StoredBytes);
    }

    [Fact]
    public async Task InvalidStreams_AreRejectedSynchronouslyAndNeverDisposed()
    {
        byte[] patch = await CreateSelfContainedPatchAsync();

        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = CspReader.OpenAsync(null!);
        });

        using var nonReadable = new WriteOnlyStream(new MemoryStream());
        Assert.Throws<ArgumentException>(() =>
        {
            _ = CspReader.OpenAsync(nonReadable);
        });

        using var forwardOnly = new ForwardOnlyReadStream(patch);
        Assert.Throws<ArgumentException>(() =>
        {
            _ = CspReader.OpenAsync(forwardOnly);
        });

        using var inner = new MemoryStream(patch, writable: false);
        using var tracking = new DisposeTrackingStream(inner);
        CspReader reader = await CspReader.OpenAsync(tracking);

        Assert.True(reader.IsValid);
        Assert.False(tracking.Disposed);
        Assert.True(tracking.CanRead);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = CspReader.OpenAsync(tracking, 0);
        });

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = CspReader.OpenAsync(tracking, -1);
        });
    }

    [Fact]
    public async Task PreCancelledToken_ThrowsWithoutOpening()
    {
        byte[] patch = await CreateSelfContainedPatchAsync();
        using var stream = new MemoryStream(patch, writable: false);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => CspReader.OpenAsync(stream, cancellation.Token));
    }

    [Fact]
    public async Task ReadEntryAsync_RejectsOrdinalsOutsideTheIndex()
    {
        byte[] patch = await CreateSelfContainedPatchAsync();
        CspReader reader = await OpenAsync(patch);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = reader.ReadEntryAsync(-1).AsTask();
        });

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = reader.ReadEntryAsync(reader.Index.Count).AsTask();
        });
    }

    private static ManifestId BaseId(uint seed) =>
        new(Hash256.FromBytes(CspBytes.CreateXorShiftBytes(32, seed)));

    private static byte[] Slice(byte[] content, ChunkInfo record) =>
        content.AsSpan(checked((int)record.Offset), record.Length).ToArray();

    private static async Task<CspReader> OpenAsync(byte[] patch)
    {
        var stream = new MemoryStream(patch, writable: false);
        return await CspReader.OpenAsync(stream);
    }

    private static async Task<byte[]> CreateSelfContainedPatchAsync()
    {
        HashSuiteId suite = HashSuiteIds.Sha256V1;
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5A11u);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(
            suite,
            content.Length,
            0x5A11u);
        IReadOnlyList<ChunkInfo> records = await ReadRecordsAsync(targetManifest);
        var entries = new List<CspPatchEntry>();

        for (int index = 0; index < records.Count; index++)
        {
            entries.Add(new CspPatchEntry(
                records[index].Id,
                (ulong)index,
                CspFormat.EncodingRaw,
                Slice(content, records[index]),
                []));
        }

        (byte[] patch, _) = await WritePatchAsync(
            suite,
            targetManifest,
            expectedBase: null,
            entries);

        return patch;
    }

    private static async Task<(byte[] Bytes, CspWriteResult Result)> WritePatchAsync(
        HashSuiteId hashSuite,
        byte[] targetManifest,
        ManifestId? expectedBase,
        IReadOnlyList<CspPatchEntry> entries)
    {
        using var destination = new MemoryStream();
        using var writer = new CspWriter(destination, hashSuite);

        await writer.WriteTargetManifestAsync(
            new MemoryStream(targetManifest, writable: false),
            targetManifest.Length,
            CancellationToken.None);

        if (expectedBase.HasValue)
        {
            await writer.WriteExpectedBaseAsync(
                expectedBase.Value,
                CancellationToken.None);
        }

        foreach (CspPatchEntry entry in entries)
        {
            await writer.AddPayloadEntryAsync(
                new CspPayloadEntry(
                    entry.ChunkId,
                    entry.FirstTargetIndex,
                    entry.Encoding,
                    entry.DictionaryChunkIds),
                entry.StoredBytes,
                CancellationToken.None);
        }

        CspWriteResult result = await writer.CompleteAsync(CancellationToken.None);
        return (destination.ToArray(), result);
    }

    private static async Task<IReadOnlyList<ChunkInfo>> ReadRecordsAsync(
        byte[] targetManifest)
    {
        using var stream = new MemoryStream(targetManifest, writable: false);
        using ManifestReader reader = await ManifestReader.OpenAsync(stream);
        var records = new List<ChunkInfo>();
        var batch = new ChunkInfo[256];

        while (true)
        {
            int count = await reader.ReadAsync(batch);

            if (count == 0)
            {
                break;
            }

            for (int index = 0; index < count; index++)
            {
                records.Add(batch[index]);
            }
        }

        Assert.NotNull(reader.VerificationResult);
        Assert.True(reader.VerificationResult!.IsValid);
        return records;
    }

    private static async Task<ManifestId> TargetManifestIdAsync(byte[] targetManifest)
    {
        using var stream = new MemoryStream(targetManifest, writable: false);
        ManifestVerificationResult result = await ChunkManifest.VerifyManifestAsync(stream);
        Assert.True(result.IsValid);
        return result.Manifest.ManifestId;
    }

    private static async Task<byte[]> CreateLargeCsmAsync(
        HashSuiteId hashSuite,
        long sourceLength,
        uint seed)
    {
        using var source = new GeneratedXorShiftStream(sourceLength, seed);
        using var destination = new MemoryStream();

        await ChunkManifest.CreateAsync(
            source,
            destination,
            new ManifestCreationOptions { HashSuite = hashSuite },
            CancellationToken.None);

        return destination.ToArray();
    }

    private static byte[] ReadAll(Stream stream)
    {
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    /// <summary>
    /// Deterministic forward-only xorshift byte stream, so a multi-hundred-MiB
    /// target can be chunked without materializing it.
    /// </summary>
    private sealed class GeneratedXorShiftStream : Stream
    {
        private long _remaining;
        private uint _state;

        internal GeneratedXorShiftStream(long length, uint seed)
        {
            _remaining = length;
            _state = seed;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadCore(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadCore(buffer.Span));
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        private int ReadCore(Span<byte> destination)
        {
            if (_remaining == 0)
            {
                return 0;
            }

            int count = (int)Math.Min(destination.Length, _remaining);

            for (int index = 0; index < count; index++)
            {
                _state ^= _state << 13;
                _state ^= _state >> 17;
                _state ^= _state << 5;
                destination[index] = (byte)_state;
            }

            _remaining -= count;
            return count;
        }
    }
}
