using System.Buffers.Binary;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class CsmContentVerifierTests
{
    [Fact]
    public async Task OriginalContent_VerifiesAgainstManifest()
    {
        byte[] content = CreateXorShiftBytes(2 * 1024 * 1024, 0xC001D00Du);
        using var manifest = new MemoryStream();

        CsmWriteResult written = await CsmWriter.CreateAsync(
            new MemoryStream(content, writable: false),
            manifest,
            includeBlockIndex: true);

        manifest.Position = 0;

        CsmContentVerificationResult result =
            await CsmContentVerifier.VerifyAsync(
                new MemoryStream(content, writable: false),
                manifest);

        Assert.True(result.IsValid);
        Assert.True(result.Manifest.IsValid);
        Assert.True(result.ProfileMatchesImplementation);
        Assert.True(result.ContentMatches);
        Assert.Equal(written.ManifestId, result.ComputedContentManifestId);
    }

    [Fact]
    public async Task ChangedContent_IsMismatchResult_NotFormatException()
    {
        byte[] content = CreateXorShiftBytes(1024 * 1024, 0xFACEFEEDu);
        using var manifest = new MemoryStream();

        await CsmWriter.CreateAsync(
            new MemoryStream(content, writable: false),
            manifest);

        content[content.Length / 2] ^= 0x80;
        manifest.Position = 0;

        CsmContentVerificationResult result =
            await CsmContentVerifier.VerifyAsync(
                new MemoryStream(content, writable: false),
                manifest);

        Assert.True(result.Manifest.IsValid);
        Assert.True(result.ProfileMatchesImplementation);
        Assert.False(result.ContentMatches);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task CorruptedStoredManifestId_WithCorrectContent_IsNotContentMismatch()
    {
        byte[] content = CreateXorShiftBytes(1024 * 1024, 0x0DDBA11u);
        byte[] manifest = await CreateManifestWithCorruptedStoredManifestIdAsync(content);

        CsmContentVerificationResult result =
            await CsmContentVerifier.VerifyAsync(
                new MemoryStream(content, writable: false),
                new MemoryStream(manifest, writable: false));

        Assert.Equal(
            CsmVerificationFailure.ManifestId,
            result.Manifest.Failures);
        Assert.True(result.ProfileMatchesImplementation);
        Assert.True(result.ContentMatches);
        Assert.Equal(
            result.Manifest.ComputedManifestId,
            result.ComputedContentManifestId);
        Assert.False(result.IsValid);

        ManifestVerificationResult publicResult =
            await ChunkManifest.VerifyAsync(
                new MemoryStream(content, writable: false),
                new MemoryStream(manifest, writable: false));

        Assert.False(publicResult.IsValid);
        Assert.Equal(
            ManifestVerificationFailure.ManifestId,
            publicResult.Failures);
    }

    [Fact]
    public async Task CorruptedStoredManifestId_WithChangedContent_ReportsBothMismatches()
    {
        byte[] content = CreateXorShiftBytes(1024 * 1024, 0x5EEDF00Du);
        byte[] manifest = await CreateManifestWithCorruptedStoredManifestIdAsync(content);
        content[content.Length / 3] ^= 0x01;

        ManifestVerificationResult result =
            await ChunkManifest.VerifyAsync(
                new MemoryStream(content, writable: false),
                new MemoryStream(manifest, writable: false));

        Assert.False(result.IsValid);
        Assert.Equal(
            ManifestVerificationFailure.ManifestId
                | ManifestVerificationFailure.Content,
            result.Failures);
    }

    private static async Task<byte[]> CreateManifestWithCorruptedStoredManifestIdAsync(
        byte[] content)
    {
        using var encoded = new MemoryStream();
        await CsmWriter.CreateAsync(
            new MemoryStream(content, writable: false),
            encoded);
        byte[] bytes = encoded.ToArray();

        // Flip one bit of CEND.ManifestId (payload offset 16) and repair the
        // physical FileDigest so the stored logical identity is the only damage.
        int cendOffset = FindSectionOffset(bytes, CsmFormat.ChunkEnd);
        bytes[cendOffset + CsmFormat.SectionHeaderSize + 16] ^= 0x01;

        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;
        Hash256 digest = HashSuiteHasher.Hash(
            HashSuiteIds.Default,
            bytes.AsSpan(0, trailerOffset));
        digest.CopyTo(
            bytes.AsSpan(trailerOffset + 24, CsmFormat.HashSize));

        return bytes;
    }

    private static int FindSectionOffset(byte[] bytes, uint sectionType)
    {
        int offset = CsmFormat.PreambleSize;
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;

        while (offset < trailerOffset)
        {
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.AsSpan(offset, 4));
            if (type == sectionType)
            {
                return offset;
            }

            ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
                bytes.AsSpan(offset + 8, 8));
            offset = checked(
                offset + CsmFormat.SectionHeaderSize + (int)payloadLength);
        }

        throw new InvalidOperationException(
            $"Section 0x{sectionType:x8} was not found.");
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
}
