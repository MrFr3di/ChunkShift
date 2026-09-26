using System.Buffers.Binary;
using ChunkShift.Manifest;

namespace ChunkShift.Tests.Manifest;

public sealed class CsmReaderTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WriterOutput_RoundTripsThroughStreamingReader(bool includeBlockIndex)
    {
        byte[] input = CreateXorShiftBytes(2 * 1024 * 1024, 0x10203040u);
        using var encoded = new MemoryStream();

        CsmWriteResult written = await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            encoded,
            includeBlockIndex: includeBlockIndex);

        encoded.Position = 0;
        var entries = new List<CsmChunkEntry>();

        CsmReadResult read = await CsmReader.ReadAndVerifyAsync(
            encoded,
            (entry, _) =>
            {
                entries.Add(entry);
                return ValueTask.CompletedTask;
            });

        Assert.True(read.IsValid);
        Assert.Equal(CsmVerificationFailure.None, read.Failures);
        Assert.Equal(written.ManifestId, read.StoredManifestId);
        Assert.Equal(written.ManifestId, read.ComputedManifestId);
        Assert.Equal(written.FileDigest, read.StoredFileDigest);
        Assert.Equal(written.FileDigest, read.ComputedFileDigest);
        Assert.Equal(written.ChunkCount, read.ChunkCount);
        Assert.Equal(written.ContentLength, read.ContentLength);
        Assert.Equal(written.PhysicalLength, read.PhysicalLength);
        Assert.Equal(written.ChunkBlockCount, read.ChunkBlockCount);
        Assert.Equal(includeBlockIndex, read.HasBlockIndex);
        Assert.Equal(checked((int)read.ChunkCount), entries.Count);

        ulong expectedOffset = 0;
        for (int index = 0; index < entries.Count; index++)
        {
            Assert.Equal((ulong)index, entries[index].Index);
            Assert.Equal(expectedOffset, entries[index].Offset);
            expectedOffset = checked(expectedOffset + entries[index].Length);
        }

        Assert.Equal((ulong)input.Length, expectedOffset);
    }

    [Fact]
    public async Task BadBlockCrc_IsIntegrityFailure_AndBlockIsNotExposed()
    {
        byte[] input = CreateXorShiftBytes(1024 * 1024, 0xA11CE55u);
        using var encoded = new MemoryStream();

        await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            encoded);

        byte[] bytes = encoded.ToArray();
        int firstBlockOffset = FindFirstChunkBlockOffset(bytes);
        int blockRecordLength = GetSectionRecordLength(bytes, firstBlockOffset);
        bytes[firstBlockOffset + blockRecordLength - 1] ^= 0x80;

        int callbacks = 0;
        CsmReadResult result = await CsmReader.ReadAndVerifyAsync(
            new MemoryStream(bytes, writable: false),
            (_, _) =>
            {
                callbacks++;
                return ValueTask.CompletedTask;
            });

        Assert.True(result.Failures.HasFlag(CsmVerificationFailure.BlockCrc));
        Assert.True(result.Failures.HasFlag(CsmVerificationFailure.FileDigest));
        Assert.False(result.Failures.HasFlag(CsmVerificationFailure.ManifestId));
        Assert.Equal(0, callbacks);
    }

    [Fact]
    public async Task BadManifestId_IsLogicalIntegrityFailure_NotParserFailure()
    {
        byte[] input = CreateXorShiftBytes(512 * 1024, 0xBADC0FFEu);
        using var encoded = new MemoryStream();

        await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            encoded);

        byte[] bytes = encoded.ToArray();
        int cendOffset = FindSectionOffset(bytes, CsmFormat.ChunkEnd);
        int manifestIdOffset =
            cendOffset + CsmFormat.SectionHeaderSize + 16;
        bytes[manifestIdOffset] ^= 0x01;

        CsmReadResult result = await CsmReader.ReadAndVerifyAsync(
            new MemoryStream(bytes, writable: false));

        Assert.True(result.Failures.HasFlag(CsmVerificationFailure.ManifestId));
        Assert.True(result.Failures.HasFlag(CsmVerificationFailure.FileDigest));
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task NonSeekableInput_IsAccepted()
    {
        byte[] input = CreateXorShiftBytes(768 * 1024, 0x31415926u);
        using var encoded = new MemoryStream();

        CsmWriteResult written = await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            encoded,
            includeBlockIndex: true);

        using var storage = new MemoryStream(encoded.ToArray(), writable: false);
        using var forwardOnly = new NonSeekableReadStream(storage);

        CsmReadResult read = await CsmReader.ReadAndVerifyAsync(forwardOnly);

        Assert.True(read.IsValid);
        Assert.Equal(written.ManifestId, read.StoredManifestId);
        Assert.False(forwardOnly.CanSeek);
    }

    [Fact]
    public async Task TruncatedTrailer_FailsAsFormatError()
    {
        using var encoded = new MemoryStream();

        await CsmWriter.CreateAsync(
            new MemoryStream("payload"u8.ToArray(), writable: false),
            encoded);

        byte[] bytes = encoded.ToArray();
        Array.Resize(ref bytes, bytes.Length - 1);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => CsmReader.ReadAndVerifyAsync(
                new MemoryStream(bytes, writable: false)));
    }

    [Fact]
    public async Task InvalidPreambleMagic_FailsAsFormatError()
    {
        using var encoded = new MemoryStream();

        await CsmWriter.CreateAsync(
            new MemoryStream("payload"u8.ToArray(), writable: false),
            encoded);

        byte[] bytes = encoded.ToArray();
        bytes[0] = (byte)'X';

        await Assert.ThrowsAsync<InvalidDataException>(
            () => CsmReader.ReadAndVerifyAsync(
                new MemoryStream(bytes, writable: false)));
    }

    private static int FindFirstChunkBlockOffset(byte[] bytes)
    {
        return FindSectionOffset(bytes, CsmFormat.ChunkBlock);
    }

    private static int FindSectionOffset(byte[] bytes, uint sectionType)
    {
        int offset = CsmFormat.PreambleSize;

        while (offset < bytes.Length - CsmFormat.TrailerSize)
        {
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.AsSpan(offset, 4));
            ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
                bytes.AsSpan(offset + 8, 8));

            if (type == sectionType)
            {
                return offset;
            }

            offset = checked(
                offset
                + CsmFormat.SectionHeaderSize
                + (int)payloadLength);
        }

        throw new InvalidOperationException(
            $"Section 0x{sectionType:x8} was not found.");
    }

    private static int GetSectionRecordLength(byte[] bytes, int sectionOffset)
    {
        ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(sectionOffset + 8, 8));
        return checked(CsmFormat.SectionHeaderSize + (int)payloadLength);
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

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly Stream _inner;

        internal NonSeekableReadStream(Stream inner)
        {
            _inner = inner;
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
            _inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(buffer, cancellationToken);

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();
        public override void SetLength(long value) =>
            throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
