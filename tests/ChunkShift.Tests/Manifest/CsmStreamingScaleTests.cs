using System.Buffers.Binary;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

[CollectionDefinition("CSM streaming scale", DisableParallelization = true)]
public sealed class CsmStreamingScaleGroup
{
    public const string Name = "CSM streaming scale";
}

[Collection(CsmStreamingScaleGroup.Name)]
public sealed class CsmStreamingScaleTests
{
    [Fact]
    public async Task Generated32MiBSource_WritesWithoutSourceOrManifestMaterialization()
    {
        const long sourceLength = 32L * 1024 * 1024;
        const long allocationCeiling = 16L * 1024 * 1024;

        using var source =
            new GeneratedXorShiftStream(sourceLength, 0x51A6E55u);
        using var destination = new CountingWriteStream();

        ForceFullCollection();
        long before = GC.GetTotalAllocatedBytes(precise: true);

        CsmWriteResult result = await CsmWriter.CreateAsync(
            source,
            destination,
            includeBlockIndex: false);

        long allocated =
            GC.GetTotalAllocatedBytes(precise: true) - before;

        Assert.Equal((ulong)sourceLength, result.ContentLength);
        Assert.Equal(sourceLength, source.BytesRead);
        Assert.Equal(result.PhysicalLength, destination.BytesWritten);
        Assert.False(result.HasBlockIndex);
        Assert.False(source.CanSeek);
        Assert.False(destination.CanSeek);

        Assert.InRange(
            source.MaxRequestedReadLength,
            1,
            1024 * 1024);
        Assert.InRange(
            destination.MaxWriteLength,
            1,
            256 * 1024);

        Assert.True(
            allocated < allocationCeiling,
            $"CSM creation allocated {allocated:N0} bytes for a {sourceLength:N0}-byte generated source.");
    }

    [Fact]
    public async Task ForwardReader_Traverses250kEntriesWithoutManifestMaterialization()
    {
        const int entryCount = 250_000;
        const long allocationCeiling = 4L * 1024 * 1024;

        using var encoded = new MemoryStream();
        await EncodeSyntheticManifestAsync(
            encoded,
            entryCount);

        Assert.True(
            encoded.Length > allocationCeiling,
            "The fixture must be larger than the reader allocation ceiling.");

        encoded.Position = 0;
        using var forwardOnly = new NonSeekableReadStream(encoded);

        ulong observedCount = 0;
        ulong observedLength = 0;
        bool sequenceValid = true;

        ForceFullCollection();
        long before = GC.GetTotalAllocatedBytes(precise: true);

        CsmReadResult result = await CsmReader.ReadAndVerifyAsync(
            forwardOnly,
            (entry, _) =>
            {
                if (entry.Index != observedCount ||
                    entry.Offset != observedLength)
                {
                    sequenceValid = false;
                }

                observedCount++;
                observedLength =
                    checked(observedLength + entry.Length);
                return ValueTask.CompletedTask;
            });

        long allocated =
            GC.GetTotalAllocatedBytes(precise: true) - before;

        Assert.True(result.IsValid);
        Assert.True(sequenceValid);
        Assert.Equal((ulong)entryCount, observedCount);
        Assert.Equal(result.ContentLength, observedLength);
        Assert.False(forwardOnly.CanSeek);
        Assert.InRange(
            forwardOnly.MaxRequestedReadLength,
            1,
            256 * 1024);

        Assert.True(
            allocated < allocationCeiling,
            $"CSM reading allocated {allocated:N0} bytes while traversing a {encoded.Length:N0}-byte manifest.");
    }

    private static async Task EncodeSyntheticManifestAsync(
        Stream destination,
        int entryCount)
    {
        HashSuiteId hashSuite = HashSuiteIds.Default;
        var profileId =
            new ChunkingProfileId("test.streaming-scale.v1");
        ProfileFingerprint fingerprint = new(
            HashSuiteHasher.Hash(
                HashSuiteIds.Sha256V1,
                "test.streaming-scale.profile.v1"u8));

        using CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                destination,
                hashSuite,
                profileId,
                fingerprint,
                includeBlockIndex: false,
                CancellationToken.None);

        var idBytes = new byte[CsmFormat.HashSize];

        for (int index = 0; index < entryCount; index++)
        {
            Array.Clear(idBytes);
            BinaryPrimitives.WriteUInt64LittleEndian(
                idBytes.AsSpan(0, 8),
                checked((ulong)index + 1));
            BinaryPrimitives.WriteUInt64LittleEndian(
                idBytes.AsSpan(8, 8),
                unchecked(
                    (ulong)index
                    * 0x9E3779B97F4A7C15UL));

            await encoder.AppendAsync(
                new ChunkId(Hash256.FromBytes(idBytes)),
                checked((uint)((index % 4096) + 1)),
                CancellationToken.None);
        }

        CsmWriteResult result =
            await encoder.CompleteAsync(CancellationToken.None);

        Assert.Equal((ulong)entryCount, result.ChunkCount);
        Assert.True(result.ChunkBlockCount > 1);
    }

    private static void ForceFullCollection()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private sealed class GeneratedXorShiftStream : Stream
    {
        private long _remaining;
        private uint _state;

        internal GeneratedXorShiftStream(
            long length,
            uint seed)
        {
            _remaining = length;
            _state = seed;
        }

        internal long BytesRead { get; private set; }

        internal int MaxRequestedReadLength { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length =>
            throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count) =>
            ReadCore(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadCore(buffer.Span));
        }

        private int ReadCore(Span<byte> destination)
        {
            MaxRequestedReadLength = Math.Max(
                MaxRequestedReadLength,
                destination.Length);

            if (_remaining == 0)
            {
                return 0;
            }

            int count = checked(
                (int)Math.Min(
                    (long)destination.Length,
                    _remaining));

            for (int index = 0; index < count; index++)
            {
                _state ^= _state << 13;
                _state ^= _state >> 17;
                _state ^= _state << 5;
                destination[index] = (byte)_state;
            }

            _remaining -= count;
            BytesRead += count;
            return count;
        }

        public override void Flush() =>
            throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();
        public override void SetLength(long value) =>
            throw new NotSupportedException();
        public override void Write(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();
    }

    private sealed class CountingWriteStream : Stream
    {
        internal ulong BytesWritten { get; private set; }

        internal int MaxWriteLength { get; private set; }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length =>
            throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(
            byte[] buffer,
            int offset,
            int count) =>
            RecordWrite(count);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RecordWrite(buffer.Length);
            return ValueTask.CompletedTask;
        }

        private void RecordWrite(int count)
        {
            MaxWriteLength = Math.Max(
                MaxWriteLength,
                count);
            BytesWritten = checked(
                BytesWritten + (uint)count);
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(
            CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public override int Read(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();
        public override void SetLength(long value) =>
            throw new NotSupportedException();
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly Stream _inner;

        internal NonSeekableReadStream(Stream inner)
        {
            _inner = inner;
        }

        internal int MaxRequestedReadLength { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length =>
            throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count)
        {
            MaxRequestedReadLength = Math.Max(
                MaxRequestedReadLength,
                count);
            return _inner.Read(buffer, offset, count);
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            MaxRequestedReadLength = Math.Max(
                MaxRequestedReadLength,
                buffer.Length);
            return _inner.ReadAsync(
                buffer,
                cancellationToken);
        }

        public override void Flush() =>
            throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();
        public override void SetLength(long value) =>
            throw new NotSupportedException();
        public override void Write(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();
    }
}
