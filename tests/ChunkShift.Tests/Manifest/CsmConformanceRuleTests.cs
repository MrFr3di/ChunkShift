using System.Buffers.Binary;
using System.Globalization;
using ChunkShift.Manifest;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// One test per explicit MUST / MUST-reject rule of CSM-V1.md that
/// had no direct coverage. Each mutant repairs the CBLK CRC and the physical
/// FileDigest where relevant and asserts the exact rule message, so the test
/// fails if a different, incidental check is what rejects the input.
/// </summary>
public sealed class CsmConformanceRuleTests
{
    private const int CorePrefixHashSuiteIdLength = 48;
    private const int CorePrefixProfileIdLength = 50;
    private const int CorePrefixExtensionBytes = 52;

    // §5: CORE PayloadLength MUST equal 56 + HashSuiteIdLength + ChunkingProfileIdLength + ExtensionBytes.
    [Fact]
    public async Task CorePayloadLength_MustEqualDeclaredFieldLengths()
    {
        byte[] bytes = await CsmBytes.CreateAsync(128 * 1024);
        int coreOffset = CsmFormat.PreambleSize;
        ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(coreOffset + 8, 8));
        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(coreOffset + 8, 8),
            payloadLength + 1);

        await AssertRejectedAsync(
            bytes,
            "CORE PayloadLength does not match its declared identifier lengths.");
    }

    // §5/§13: readers MUST reject non-zero RequiredSemanticFeatures or OptionalSemanticFeatures.
    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    public async Task NonZeroSemanticFeatureField_IsRejected(int corePrefixOffset)
    {
        byte[] bytes = await CsmBytes.CreateAsync(128 * 1024);
        int field = CsmBytes.PayloadOffset(CsmFormat.PreambleSize) + corePrefixOffset;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(field, 8), 1UL << 63);

        await AssertRejectedAsync(
            bytes,
            "CSM v1 candidate requires both semantic feature fields to be zero.");
    }

    // §5: readers MUST reject non-zero ExtensionBytes (the TLV registry is empty).
    [Fact]
    public async Task NonZeroExtensionBytes_IsRejected()
    {
        byte[] bytes = await CsmBytes.CreateAsync(128 * 1024);
        int field = CsmBytes.PayloadOffset(CsmFormat.PreambleSize) + CorePrefixExtensionBytes;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(field, 4), 1);

        await AssertRejectedAsync(
            bytes,
            "CSM v1 candidate does not define CORE extensions.");
    }

    // §5/§13: both identifiers are 1..128 bytes.
    [Theory]
    [InlineData(CorePrefixHashSuiteIdLength, "HashSuiteId", 0)]
    [InlineData(CorePrefixHashSuiteIdLength, "HashSuiteId", 129)]
    [InlineData(CorePrefixProfileIdLength, "ChunkingProfileId", 0)]
    [InlineData(CorePrefixProfileIdLength, "ChunkingProfileId", 129)]
    public async Task IdentifierLengthOutsideBounds_IsRejected(
        int corePrefixOffset,
        string name,
        int length)
    {
        byte[] bytes = await CsmBytes.CreateAsync(128 * 1024);
        int field = CsmBytes.PayloadOffset(CsmFormat.PreambleSize) + corePrefixOffset;
        BinaryPrimitives.WriteUInt16LittleEndian(
            bytes.AsSpan(field, 2),
            checked((ushort)length));

        await AssertRejectedAsync(
            bytes,
            string.Create(
                CultureInfo.InvariantCulture,
                $"{name} must encode to 1..{CsmFormat.MaximumIdentifierBytes} bytes."));
    }

    // §6: FirstChunkIndex / FirstContentOffset MUST equal the preceding totals.
    // The second CBLK is mutated (preceding totals are non-zero) and its CRC is
    // repaired, so the mutant is rejected by the continuity rule alone.
    [Theory]
    [InlineData(8, 1L)]
    [InlineData(8, -1L)]
    [InlineData(16, 1L)]
    [InlineData(16, -1L)]
    public async Task ChunkBlockContinuityFields_MustMatchPrecedingStream(
        int cblkPrefixOffset,
        long delta)
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount: 4097,
            includeBlockIndex: false);
        int secondBlock = CsmBytes.FindSection(bytes, CsmFormat.ChunkBlock, occurrence: 1);
        int field = CsmBytes.PayloadOffset(secondBlock) + cblkPrefixOffset;
        ulong stored = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(field, 8));
        Assert.NotEqual(0UL, stored);

        BinaryPrimitives.WriteUInt64LittleEndian(
            bytes.AsSpan(field, 8),
            unchecked(stored + (ulong)delta));
        CsmBytes.RewriteBlockCrc(bytes, secondBlock);
        CsmBytes.RewritePhysicalDigest(bytes);

        await AssertRejectedAsync(
            bytes,
            "CBLK first index/content offset does not match the preceding logical stream.");
    }

    // §11: every FOOT offset/count MUST match the observed layout.
    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public async Task FooterLayoutField_MustMatchObservedSections(int footPayloadOffset)
    {
        byte[] bytes = await CsmBytes.CreateAsync(
            512 * 1024,
            includeBlockIndex: true);
        int field = CsmBytes.PayloadOffset(
            CsmBytes.FindSection(bytes, CsmFormat.Footer)) + footPayloadOffset;
        ulong stored = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(field, 8));
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(field, 8), stored + 1);
        CsmBytes.RewritePhysicalDigest(bytes);

        await AssertRejectedAsync(
            bytes,
            "FOOT offsets/counts do not match the observed physical section layout.");
    }

    // §11: FOOT Reserved = 0.
    [Fact]
    public async Task FooterReserved_MustBeZero()
    {
        byte[] bytes = await CsmBytes.CreateAsync(512 * 1024);
        int field = CsmBytes.PayloadOffset(
            CsmBytes.FindSection(bytes, CsmFormat.Footer)) + 40;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(field, 8), 1);
        CsmBytes.RewritePhysicalDigest(bytes);

        await AssertRejectedAsync(bytes, "FOOT reserved field must be zero.");
    }

    // §2: duplicate FOOT MUST be rejected. Exactly one fixed TRAILER must follow
    // FOOT, so a second FOOT record is read in the TRAILER position.
    [Fact]
    public async Task DuplicateFooter_IsRejected()
    {
        byte[] bytes = await CsmBytes.CreateAsync(512 * 1024);
        int footOffset = CsmBytes.FindSection(bytes, CsmFormat.Footer);
        int footLength = CsmBytes.GetSectionRecordLength(bytes, footOffset);
        byte[] duplicate = bytes.AsSpan(footOffset, footLength).ToArray();
        byte[] mutated = CsmBytes.Insert(bytes, footOffset + footLength, duplicate);

        await AssertRejectedAsync(mutated, "Invalid CSM trailer magic.");
    }

    // §10/§13: a BIDX beyond the operational validation cap is rejected rather
    // than materialized. The cap is checked before PayloadLength consistency, so
    // only the declared BlockCount needs to exceed it.
    [Fact]
    public async Task BlockIndexBeyondOperationalCap_IsRejected()
    {
        byte[] bytes = await CsmBytes.CreateAsync(
            512 * 1024,
            includeBlockIndex: true);
        int field = CsmBytes.PayloadOffset(
            CsmBytes.FindSection(bytes, CsmFormat.BlockIndex)) + 4;
        BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(field, 4),
            (uint)CsmFormat.MaximumBlockIndexEntries + 1);
        CsmBytes.RewritePhysicalDigest(bytes);

        await AssertRejectedAsync(
            bytes,
            string.Create(
                CultureInfo.InvariantCulture,
                $"BIDX exceeds the operational limit of {CsmFormat.MaximumBlockIndexEntries} entries."));
    }

    private static async Task AssertRejectedAsync(byte[] bytes, string expectedMessage)
    {
        InvalidDataException exception =
            await Assert.ThrowsAsync<InvalidDataException>(
                () => CsmReader.ReadAndVerifyAsync(
                    new MemoryStream(bytes, writable: false)));

        Assert.Equal(expectedMessage, exception.Message);
    }
}
