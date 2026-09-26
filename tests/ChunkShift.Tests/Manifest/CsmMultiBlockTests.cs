using System.Buffers.Binary;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class CsmMultiBlockTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MoreThan4096Entries_EmitsAndReadsMultipleChunkBlocks(
        bool includeBlockIndex)
    {
        const int entryCount = 4097;
        HashSuiteId hashSuite = HashSuiteIds.Default;
        var profileId = new ChunkingProfileId("test.multiblock.v1");
        ProfileFingerprint fingerprint = new(
            HashSuiteHasher.Hash(
                HashSuiteIds.Sha256V1,
                "test.multiblock.profile.v1"u8));

        using var encoded = new MemoryStream();
        using CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                encoded,
                hashSuite,
                profileId,
                fingerprint,
                includeBlockIndex,
                CancellationToken.None);

        ulong expectedContentLength = 0;
        var idBytes = new byte[CsmFormat.HashSize];

        for (int index = 0; index < entryCount; index++)
        {
            Array.Clear(idBytes);
            BinaryPrimitives.WriteUInt64LittleEndian(
                idBytes.AsSpan(0, 8),
                checked((ulong)index + 1));
            BinaryPrimitives.WriteUInt64LittleEndian(
                idBytes.AsSpan(8, 8),
                0x43534D3100000000UL);
            BinaryPrimitives.WriteUInt64LittleEndian(
                idBytes.AsSpan(16, 8),
                unchecked((ulong)index * 0x9E3779B97F4A7C15UL));
            BinaryPrimitives.WriteUInt64LittleEndian(
                idBytes.AsSpan(24, 8),
                checked((ulong)index ^ 0xA5A5A5A5A5A5A5A5UL));

            uint length = checked((uint)((index % 1024) + 1));
            expectedContentLength =
                checked(expectedContentLength + length);

            await encoder.AppendAsync(
                new ChunkId(Hash256.FromBytes(idBytes)),
                length,
                CancellationToken.None);
        }

        CsmWriteResult written =
            await encoder.CompleteAsync(CancellationToken.None);

        Assert.Equal((ulong)entryCount, written.ChunkCount);
        Assert.Equal(expectedContentLength, written.ContentLength);
        Assert.Equal(2UL, written.ChunkBlockCount);
        Assert.Equal(includeBlockIndex, written.HasBlockIndex);

        encoded.Position = 0;
        ulong observedCount = 0;
        ulong observedOffset = 0;

        CsmReadResult read = await CsmReader.ReadAndVerifyAsync(
            encoded,
            (entry, _) =>
            {
                Assert.Equal(observedCount, entry.Index);
                Assert.Equal(observedOffset, entry.Offset);

                observedCount++;
                observedOffset =
                    checked(observedOffset + entry.Length);
                return ValueTask.CompletedTask;
            });

        Assert.True(read.IsValid);
        Assert.Equal((ulong)entryCount, observedCount);
        Assert.Equal(expectedContentLength, observedOffset);
        Assert.Equal(2UL, read.ChunkBlockCount);
        Assert.Equal(includeBlockIndex, read.HasBlockIndex);
        Assert.Equal(written.ManifestId, read.StoredManifestId);
    }

    [Fact]
    public async Task BlockIndexPresence_DoesNotChangeMultiBlockManifestIdentity()
    {
        CsmWriteResult withoutIndex =
            await EncodeDeterministicSequenceAsync(includeBlockIndex: false);
        CsmWriteResult withIndex =
            await EncodeDeterministicSequenceAsync(includeBlockIndex: true);

        Assert.Equal(withoutIndex.ManifestId, withIndex.ManifestId);
        Assert.Equal(withoutIndex.ChunkCount, withIndex.ChunkCount);
        Assert.Equal(withoutIndex.ContentLength, withIndex.ContentLength);
        Assert.Equal(2UL, withoutIndex.ChunkBlockCount);
        Assert.Equal(2UL, withIndex.ChunkBlockCount);
        Assert.NotEqual(withoutIndex.FileDigest, withIndex.FileDigest);
        Assert.NotEqual(withoutIndex.PhysicalLength, withIndex.PhysicalLength);
    }

    private static async Task<CsmWriteResult> EncodeDeterministicSequenceAsync(
        bool includeBlockIndex)
    {
        const int entryCount = 4097;
        HashSuiteId hashSuite = HashSuiteIds.Default;
        var profileId = new ChunkingProfileId("test.multiblock.v1");
        ProfileFingerprint fingerprint = new(
            HashSuiteHasher.Hash(
                HashSuiteIds.Sha256V1,
                "test.multiblock.profile.v1"u8));

        using var encoded = new MemoryStream();
        using CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                encoded,
                hashSuite,
                profileId,
                fingerprint,
                includeBlockIndex,
                CancellationToken.None);

        var idBytes = new byte[CsmFormat.HashSize];

        for (int index = 0; index < entryCount; index++)
        {
            Array.Clear(idBytes);
            BinaryPrimitives.WriteUInt64LittleEndian(
                idBytes.AsSpan(0, 8),
                checked((ulong)index + 1));

            await encoder.AppendAsync(
                new ChunkId(Hash256.FromBytes(idBytes)),
                checked((uint)((index % 31) + 1)),
                CancellationToken.None);
        }

        return await encoder.CompleteAsync(CancellationToken.None);
    }
}
