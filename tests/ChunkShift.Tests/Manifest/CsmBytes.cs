using System.Buffers.Binary;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// Byte-level helpers for building and mutating CSM v1 representations in tests.
/// </summary>
internal static class CsmBytes
{
    internal static async Task<byte[]> CreateAsync(
        int sourceLength,
        bool includeBlockIndex = false,
        uint seed = 0x7A11C0DEu)
    {
        byte[] input = CreateXorShiftBytes(sourceLength, seed);
        using var encoded = new MemoryStream();

        await CsmWriter.CreateAsync(
            new MemoryStream(input, writable: false),
            encoded,
            includeBlockIndex: includeBlockIndex);

        return encoded.ToArray();
    }

    /// <summary>
    /// Encodes a synthetic manifest with <paramref name="entryCount"/> entries so
    /// multi-CBLK layouts do not require gigabytes of content.
    /// </summary>
    internal static async Task<byte[]> CreateSyntheticAsync(
        int entryCount,
        bool includeBlockIndex)
    {
        var profileId = new ChunkingProfileId("test.csm-bytes.v1");
        ProfileFingerprint fingerprint = new(
            HashSuiteHasher.Hash(
                HashSuiteIds.Sha256V1,
                "test.csm-bytes.profile.v1"u8));

        using var encoded = new MemoryStream();
        using (CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                encoded,
                HashSuiteIds.Default,
                profileId,
                fingerprint,
                includeBlockIndex,
                CancellationToken.None))
        {
            var idBytes = new byte[CsmFormat.HashSize];

            for (int index = 0; index < entryCount; index++)
            {
                Array.Clear(idBytes);
                BinaryPrimitives.WriteUInt64LittleEndian(
                    idBytes.AsSpan(0, 8),
                    checked((ulong)index + 1));

                await encoder.AppendAsync(
                    new ChunkId(Hash256.FromBytes(idBytes)),
                    checked((uint)((index % 97) + 1)),
                    CancellationToken.None);
            }

            _ = await encoder.CompleteAsync(CancellationToken.None);
        }

        return encoded.ToArray();
    }

    internal static IEnumerable<(int Offset, int Length, uint Type)> EnumerateSections(
        byte[] bytes)
    {
        int offset = CsmFormat.PreambleSize;
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;

        while (offset < trailerOffset)
        {
            int recordLength = GetSectionRecordLength(bytes, offset);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.AsSpan(offset, 4));
            yield return (offset, recordLength, type);
            offset = checked(offset + recordLength);
        }

        if (offset != trailerOffset)
        {
            throw new InvalidOperationException(
                "Section walk did not end at the TRAILER.");
        }
    }

    internal static int FindSection(byte[] bytes, uint sectionType, int occurrence = 0)
    {
        int seen = 0;

        foreach ((int offset, _, uint type) in EnumerateSections(bytes))
        {
            if (type == sectionType && seen++ == occurrence)
            {
                return offset;
            }
        }

        throw new InvalidOperationException(
            $"Section 0x{sectionType:x8} occurrence {occurrence} was not found.");
    }

    internal static int PayloadOffset(int sectionOffset) =>
        sectionOffset + CsmFormat.SectionHeaderSize;

    internal static int GetSectionRecordLength(byte[] bytes, int sectionOffset)
    {
        ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(sectionOffset + 8, 8));

        return checked(CsmFormat.SectionHeaderSize + (int)payloadLength);
    }

    internal static byte[] Insert(byte[] source, int offset, byte[] inserted)
    {
        byte[] result = new byte[source.Length + inserted.Length];
        source.AsSpan(0, offset).CopyTo(result);
        inserted.CopyTo(result.AsSpan(offset));
        source.AsSpan(offset).CopyTo(result.AsSpan(offset + inserted.Length));
        return result;
    }

    /// <summary>
    /// Recomputes TRAILER.FileDigest with the default HashSuite so a mutation of
    /// hashed bytes is not rejected merely for its physical digest.
    /// </summary>
    internal static void RewritePhysicalDigest(byte[] bytes)
    {
        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;
        Hash256 digest = HashSuiteHasher.Hash(
            HashSuiteIds.Default,
            bytes.AsSpan(0, trailerOffset));
        digest.CopyTo(bytes.AsSpan(trailerOffset + 24, CsmFormat.HashSize));
    }

    /// <summary>
    /// Recomputes the CRC-32C of the CBLK record at <paramref name="cblkOffset"/>.
    /// </summary>
    internal static void RewriteBlockCrc(byte[] bytes, int cblkOffset)
    {
        int recordLength = GetSectionRecordLength(bytes, cblkOffset);
        int crcOffset = cblkOffset + recordLength - sizeof(uint);
        uint crc = Crc32C.Compute(bytes.AsSpan(cblkOffset, crcOffset - cblkOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(crcOffset, 4), crc);
    }

    internal static byte[] CreateXorShiftBytes(int length, uint seed)
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
