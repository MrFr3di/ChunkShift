using System.Buffers.Binary;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class CsmWriterTests
{
    [Fact]
    public async Task EmptySource_WritesCompleteForwardOnlyEnvelope()
    {
        using var source = new MemoryStream([], writable: false);
        using var destination = new MemoryStream();

        CsmWriteResult result = await CsmWriter.CreateAsync(source, destination);
        byte[] bytes = destination.ToArray();

        Assert.Equal(0UL, result.ChunkCount);
        Assert.Equal(0UL, result.ContentLength);
        Assert.Equal(0UL, result.ChunkBlockCount);
        Assert.False(result.HasBlockIndex);
        Assert.Equal((ulong)bytes.Length, result.PhysicalLength);

        Assert.Equal("CSM1"u8.ToArray(), bytes.AsSpan(0, 4).ToArray());
        Assert.Equal("CSMT"u8.ToArray(), bytes.AsSpan(bytes.Length - 64, 4).ToArray());

        ulong trailerLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(bytes.Length - 48, 8));
        Assert.Equal((ulong)bytes.Length, trailerLength);

        Hash256 physicalDigest = HashSuiteHasher.Hash(
            HashSuiteIds.Default,
            bytes.AsSpan(0, bytes.Length - CsmFormat.TrailerSize));
        Assert.Equal(result.FileDigest, physicalDigest);

        Hash256 trailerDigest = Hash256.FromBytes(
            bytes.AsSpan(bytes.Length - 40, CsmFormat.HashSize));
        Assert.Equal(result.FileDigest, trailerDigest);
    }

    [Fact]
    public async Task BlockIndex_IsPhysicalOnly_AndDoesNotChangeManifestId()
    {
        byte[] input = CreateXorShiftBytes(2 * 1024 * 1024, 0xC5A5EEDu);

        using var withoutIndex = new MemoryStream();
        using var withIndex = new MemoryStream();

        CsmWriteResult plain = await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            withoutIndex,
            includeBlockIndex: false);

        CsmWriteResult indexed = await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            withIndex,
            includeBlockIndex: true);

        Assert.Equal(plain.ManifestId, indexed.ManifestId);
        Assert.Equal(plain.ChunkCount, indexed.ChunkCount);
        Assert.Equal(plain.ContentLength, indexed.ContentLength);
        Assert.False(plain.HasBlockIndex);
        Assert.True(indexed.HasBlockIndex);
        Assert.NotEqual(plain.PhysicalLength, indexed.PhysicalLength);
        Assert.NotEqual(plain.FileDigest, indexed.FileDigest);
    }

    [Fact]
    public async Task FirstChunkBlock_HasValidCrcAndCanonicalChunkMetadata()
    {
        byte[] input = CreateXorShiftBytes(1024 * 1024, 0x51A6E55u);
        using var destination = new MemoryStream();

        CsmWriteResult result = await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            destination);

        byte[] bytes = destination.ToArray();
        ValidateFirstChunkBlock(bytes, result);
    }

    [Fact]
    public async Task DestinationNeedNotBeSeekable()
    {
        byte[] input = CreateXorShiftBytes(512 * 1024, 0xABCDEF12u);
        using var storage = new MemoryStream();
        using var destination = new NonSeekableWriteStream(storage);

        CsmWriteResult result = await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            destination);

        Assert.Equal((ulong)input.Length, result.ContentLength);
        Assert.Equal((ulong)storage.Length, result.PhysicalLength);
        Assert.False(destination.CanSeek);
    }

    private static void ValidateFirstChunkBlock(
        byte[] bytes,
        CsmWriteResult result)
    {
        int coreOffset = CsmFormat.PreambleSize;
        ulong corePayloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(coreOffset + 8, 8));
        int firstBlockOffset = checked(
            coreOffset
            + CsmFormat.SectionHeaderSize
            + (int)corePayloadLength);

        Assert.Equal(
            CsmFormat.ChunkBlock,
            BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.AsSpan(firstBlockOffset, 4)));

        ulong blockPayloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(firstBlockOffset + 8, 8));
        int blockRecordLength = checked(
            CsmFormat.SectionHeaderSize + (int)blockPayloadLength);
        ReadOnlySpan<byte> record =
            bytes.AsSpan(firstBlockOffset, blockRecordLength);

        uint storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(record[^4..]);
        uint actualCrc = Crc32C.Compute(record[..^4]);
        Assert.Equal(storedCrc, actualCrc);

        uint chunkCount = BinaryPrimitives.ReadUInt32LittleEndian(
            record.Slice(CsmFormat.SectionHeaderSize, 4));
        Assert.InRange(chunkCount, 1u, CsmFormat.MaximumChunksPerBlock);
        Assert.Equal(result.ChunkCount, chunkCount);
    }

    private static byte[] CreateXorShiftBytes(int length, uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int index = 0; index < bytes.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[index] = (byte)state;
        }

        return bytes;
    }

    private sealed class NonSeekableWriteStream : Stream
    {
        private readonly Stream _inner;

        internal NonSeekableWriteStream(Stream inner)
        {
            _inner = inner;
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            _inner.FlushAsync(cancellationToken);

        public override void Write(byte[] buffer, int offset, int count) =>
            _inner.Write(buffer, offset, count);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _inner.WriteAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
