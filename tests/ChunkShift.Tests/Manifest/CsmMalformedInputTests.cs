using System.Buffers.Binary;
using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class CsmMalformedInputTests
{
    [Fact]
    public async Task UnsupportedPreambleVersion_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4, 2), 2);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task NonZeroPreambleReserved_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(24, 8), 1);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task UnknownRequiredPhysicalFeature_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(8, 8), 1);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task UnknownOptionalPhysicalFeature_IsAccepted()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16, 8), 1);
        RewritePhysicalDigest(bytes);

        CsmReadResult result = await ReadAsync(bytes);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NonZeroSemanticFeature_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        int coreOffset = CsmFormat.PreambleSize;
        int corePayloadOffset = coreOffset + CsmFormat.SectionHeaderSize;
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(corePayloadOffset, 8),
            1);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task ReservedSectionFlag_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        int coreOffset = CsmFormat.PreambleSize;
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(coreOffset + 4, 4),
            2);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task HugeSeekablePayloadLength_FailsBeforeAllocation()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        int coreOffset = CsmFormat.PreambleSize;
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(coreOffset + 8, 8),
            ulong.MaxValue);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task HugeNonSeekableCblkPayloadLength_FailsBeforeAllocation()
    {
        byte[] bytes = await CreateManifestAsync(128 * 1024);
        int cblkOffset = FindSectionOffset(bytes, CsmFormat.ChunkBlock);
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(cblkOffset + 8, 8),
            ulong.MaxValue);

        using var storage = new MemoryStream(bytes, writable: false);
        using var forwardOnly = new NonSeekableReadStream(storage);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => CsmReader.ReadAndVerifyAsync(forwardOnly));
    }

    [Fact]
    public async Task ChunkBlockPayloadLengthMismatch_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int cblkOffset = FindSectionOffset(bytes, CsmFormat.ChunkBlock);
        ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(cblkOffset + 8, 8));

        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(cblkOffset + 8, 8),
            payloadLength - 1);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task ChunkCountOutsideAllowedRange_IsFormatError()
    {
        byte[] valid = await CreateManifestAsync(512 * 1024);
        int cblkOffset = FindSectionOffset(valid, CsmFormat.ChunkBlock);
        int countOffset = cblkOffset + CsmFormat.SectionHeaderSize;

        foreach (uint invalidCount in
            new[] { 0u, CsmFormat.MaximumChunksPerBlock + 1 })
        {
            byte[] bytes = valid.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(
                bytes.AsSpan(countOffset, 4),
                invalidCount);

            await Assert.ThrowsAsync<InvalidDataException>(
                () => ReadAsync(bytes));
        }
    }

    [Fact]
    public async Task ZeroChunkLength_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int cblkOffset = FindSectionOffset(bytes, CsmFormat.ChunkBlock);
        int payloadOffset = cblkOffset + CsmFormat.SectionHeaderSize;
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(
            bytes.AsSpan(payloadOffset, 4));
        int lengthsOffset = checked(
            payloadOffset
            + CsmFormat.CblkPrefixSize
            + checked((int)count) * CsmFormat.HashSize);

        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(lengthsOffset, 4),
            0);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task WrongCendTotals_AreLogicalMismatchOnly()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int cendOffset = FindSectionOffset(bytes, CsmFormat.ChunkEnd);
        int payloadOffset = cendOffset + CsmFormat.SectionHeaderSize;

        ulong storedLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(payloadOffset + 8, 8));
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(payloadOffset + 8, 8),
            storedLength + 1);

        RewritePhysicalDigest(bytes);

        CsmReadResult result = await ReadAsync(bytes);

        Assert.Equal(
            CsmVerificationFailure.LogicalTotals,
            result.Failures);
    }

    [Fact]
    public async Task WrongFileDigest_IsPhysicalMismatchOnly()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;
        bytes[trailerOffset + 24] ^= 0x01;

        CsmReadResult result = await ReadAsync(bytes);

        Assert.Equal(
            CsmVerificationFailure.FileDigest,
            result.Failures);
    }

    [Fact]
    public async Task UnknownRequiredAuxPhaseSection_IsRejected()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int footOffset = FindSectionOffset(bytes, CsmFormat.Footer);

        byte[] requiredUnknown = BuildSection(
            CsmFormat.FourCc("ZZZZ"u8),
            CsmFormat.RequiredSectionFlag,
            [0x01, 0x02, 0x03]);

        bytes = Insert(bytes, footOffset, requiredUnknown);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task UnknownOptionalAuxPhaseSection_IsSkippedWithoutChangingLogicalIdentity()
    {
        byte[] original = await CreateManifestAsync(512 * 1024);
        CsmReadResult originalResult = await ReadAsync(original);
        int footOffset = FindSectionOffset(original, CsmFormat.Footer);

        byte[] optionalUnknown = BuildSection(
            CsmFormat.FourCc("ZZZZ"u8),
            flags: 0,
            [0x10, 0x20, 0x30, 0x40, 0x50]);

        byte[] mutated = Insert(original, footOffset, optionalUnknown);
        RewriteTrailerAfterInsertion(
            mutated,
            originalFootOffset: footOffset,
            insertedLength: optionalUnknown.Length);

        CsmReadResult mutatedResult = await ReadAsync(mutated);

        Assert.True(mutatedResult.IsValid);
        Assert.Equal(
            originalResult.StoredManifestId,
            mutatedResult.StoredManifestId);
        Assert.NotEqual(
            originalResult.StoredFileDigest,
            mutatedResult.StoredFileDigest);
    }

    [Fact]
    public async Task DuplicateBlockIndex_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(
            2 * 1024 * 1024,
            includeBlockIndex: true);

        int bidxOffset = FindSectionOffset(bytes, CsmFormat.BlockIndex);
        int bidxLength = GetSectionRecordLength(bytes, bidxOffset);
        int footOffset = FindSectionOffset(bytes, CsmFormat.Footer);
        byte[] duplicate = bytes.AsSpan(bidxOffset, bidxLength).ToArray();

        bytes = Insert(bytes, footOffset, duplicate);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task CorruptBlockIndexEntry_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(
            2 * 1024 * 1024,
            includeBlockIndex: true);

        int bidxOffset = FindSectionOffset(bytes, CsmFormat.BlockIndex);
        int firstEntryFileOffset =
            bidxOffset + CsmFormat.SectionHeaderSize + 8 + 8;

        ulong stored = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(firstEntryFileOffset, 8));
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(firstEntryFileOffset, 8),
            stored + 1);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task DuplicateCore_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int coreOffset = CsmFormat.PreambleSize;
        int coreLength = GetSectionRecordLength(bytes, coreOffset);
        byte[] duplicate = bytes.AsSpan(coreOffset, coreLength).ToArray();

        bytes = Insert(bytes, coreOffset + coreLength, duplicate);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task AuxBeforeCend_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int cendOffset = FindSectionOffset(bytes, CsmFormat.ChunkEnd);
        byte[] aux = BuildSection(
            CsmFormat.Aux0,
            flags: 0,
            [0x01]);

        bytes = Insert(bytes, cendOffset, aux);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task BlockIndexBeforeCend_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(
            512 * 1024,
            includeBlockIndex: true);

        int bidxOffset = FindSectionOffset(bytes, CsmFormat.BlockIndex);
        int bidxLength = GetSectionRecordLength(bytes, bidxOffset);
        byte[] bidx = bytes.AsSpan(bidxOffset, bidxLength).ToArray();
        int cendOffset = FindSectionOffset(bytes, CsmFormat.ChunkEnd);

        bytes = Insert(bytes, cendOffset, bidx);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task ChunkBlockAfterCend_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int cblkOffset = FindSectionOffset(bytes, CsmFormat.ChunkBlock);
        int cblkLength = GetSectionRecordLength(bytes, cblkOffset);
        byte[] cblk = bytes.AsSpan(cblkOffset, cblkLength).ToArray();
        int cendOffset = FindSectionOffset(bytes, CsmFormat.ChunkEnd);
        int cendLength = GetSectionRecordLength(bytes, cendOffset);

        bytes = Insert(bytes, cendOffset + cendLength, cblk);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Theory]
    [InlineData("CORE")]
    [InlineData("CBLK")]
    [InlineData("CEND")]
    public async Task KnownLogicalSectionAfterCend_IsRejectedEvenWithoutRequiredFlag(
        string fourCc)
    {
        // CSM-V1 §2: duplicate CORE/CEND and CBLK after CEND MUST
        // be rejected. Clearing REQUIRED and repairing FOOT offset/length and
        // FileDigest makes the mutant otherwise fully valid, so only the
        // position rule can reject it (not the unknown-required-section rule).
        byte[] original = await CreateManifestAsync(512 * 1024);
        uint type = CsmFormat.FourCc(Encoding.ASCII.GetBytes(fourCc));
        int sourceOffset = FindSectionOffset(original, type);
        byte[] copy = original
            .AsSpan(sourceOffset, GetSectionRecordLength(original, sourceOffset))
            .ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(4, 4), 0);

        int footOffset = FindSectionOffset(original, CsmFormat.Footer);
        byte[] mutated = Insert(original, footOffset, copy);
        RewriteTrailerAfterInsertion(
            mutated,
            originalFootOffset: footOffset,
            insertedLength: copy.Length);

        InvalidDataException exception =
            await Assert.ThrowsAsync<InvalidDataException>(
                () => ReadAsync(mutated));

        Assert.Equal(
            $"{fourCc} must not appear after CEND.",
            exception.Message);

        using var storage = new MemoryStream(mutated, writable: false);
        await using ManifestReader reader =
            await ManifestReader.OpenAsync(storage);
        var entries = new ChunkInfo[64];

        await Assert.ThrowsAsync<InvalidDataException>(
            async () =>
            {
                while (await reader.ReadAsync(entries) != 0)
                {
                }
            });
    }

    [Fact]
    public async Task AuxAfterBlockIndex_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(
            512 * 1024,
            includeBlockIndex: true);

        int bidxOffset = FindSectionOffset(bytes, CsmFormat.BlockIndex);
        int bidxLength = GetSectionRecordLength(bytes, bidxOffset);
        byte[] aux = BuildSection(
            CsmFormat.Aux0,
            flags: 0,
            [0x01]);

        bytes = Insert(bytes, bidxOffset + bidxLength, aux);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task BytesAfterTrailer_AreFormatError()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        Array.Resize(ref bytes, bytes.Length + 1);
        bytes[^1] = 0x7f;

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public async Task NonZeroTrailerReserved_IsFormatError()
    {
        byte[] bytes = await CreateManifestAsync(512 * 1024);
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(trailerOffset + 56, 8),
            1);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadAsync(bytes));
    }

    [Fact]
    public void ParserMath_MapsOverflowToInvalidData()
    {
        Assert.Throws<InvalidDataException>(
            () => CsmParserMath.Add(
                ulong.MaxValue,
                1,
                "test field"));

        Assert.Throws<InvalidDataException>(
            () => CsmParserMath.ToInt32(
                (ulong)int.MaxValue + 1,
                "test field"));
    }

    private static async Task<byte[]> CreateManifestAsync(
        int sourceLength,
        bool includeBlockIndex = false)
    {
        byte[] input = CreateXorShiftBytes(sourceLength, 0x7A11C0DEu);
        using var encoded = new MemoryStream();

        await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            encoded,
            includeBlockIndex: includeBlockIndex);

        return encoded.ToArray();
    }

    private static Task<CsmReadResult> ReadAsync(byte[] bytes) =>
        CsmReader.ReadAndVerifyAsync(
            new MemoryStream(bytes, writable: false));

    private static IEnumerable<(int Offset, int Length)> EnumerateSections(
        byte[] bytes)
    {
        int offset = CsmFormat.PreambleSize;
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;

        while (offset < trailerOffset)
        {
            int recordLength = GetSectionRecordLength(bytes, offset);
            yield return (offset, recordLength);
            offset = checked(offset + recordLength);
        }

        Assert.Equal(trailerOffset, offset);
    }

    private static int FindSectionOffset(byte[] bytes, uint sectionType)
    {
        foreach ((int offset, _) in EnumerateSections(bytes))
        {
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.AsSpan(offset, 4));
            if (type == sectionType)
            {
                return offset;
            }
        }

        throw new InvalidOperationException(
            $"Section 0x{sectionType:x8} was not found.");
    }

    private static int GetSectionRecordLength(
        byte[] bytes,
        int sectionOffset)
    {
        ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(sectionOffset + 8, 8));

        return checked(
            CsmFormat.SectionHeaderSize + (int)payloadLength);
    }

    private static byte[] BuildSection(
        uint type,
        uint flags,
        byte[] payload)
    {
        byte[] section =
            new byte[CsmFormat.SectionHeaderSize + payload.Length];

        BinaryPrimitives.WriteUInt32LittleEndian(
            section.AsSpan(0, 4),
            type);
        BinaryPrimitives.WriteUInt32LittleEndian(
            section.AsSpan(4, 4),
            flags);
        BinaryPrimitives.WriteUInt64LittleEndian(
            section.AsSpan(8, 8),
            checked((ulong)payload.Length));
        payload.CopyTo(section.AsSpan(CsmFormat.SectionHeaderSize));

        return section;
    }

    private static byte[] Insert(
        byte[] source,
        int offset,
        byte[] inserted)
    {
        byte[] result = new byte[source.Length + inserted.Length];
        source.AsSpan(0, offset).CopyTo(result);
        inserted.CopyTo(result.AsSpan(offset));
        source.AsSpan(offset).CopyTo(
            result.AsSpan(offset + inserted.Length));
        return result;
    }

    private static void RewriteTrailerAfterInsertion(
        byte[] bytes,
        int originalFootOffset,
        int insertedLength)
    {
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;
        int newFootOffset = checked(originalFootOffset + insertedLength);

        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(trailerOffset + 8, 8),
            checked((ulong)newFootOffset));
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(trailerOffset + 16, 8),
            checked((ulong)bytes.Length));

        RewritePhysicalDigest(bytes);
    }

    private static void RewritePhysicalDigest(byte[] bytes)
    {
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;
        Hash256 digest = HashSuiteHasher.Hash(
            HashSuiteIds.Default,
            bytes.AsSpan(0, trailerOffset));
        digest.CopyTo(
            bytes.AsSpan(trailerOffset + 24, CsmFormat.HashSize));
    }

    private static byte[] CreateXorShiftBytes(
        int length,
        uint seed)
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
        public override void Write(
            byte[] buffer,
            int offset,
            int count) =>
            throw new NotSupportedException();
    }
}
