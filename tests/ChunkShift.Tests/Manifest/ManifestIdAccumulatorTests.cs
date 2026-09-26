using System.Buffers.Binary;
using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class ManifestIdAccumulatorTests
{
    [Theory]
    [MemberData(nameof(HashSuites))]
    public void StreamingAccumulator_MatchesCanonicalByteSequence(HashSuiteId hashSuite)
    {
        var profileId = new ChunkingProfileId("fastcdc.test.v1");
        ProfileFingerprint fingerprint = new(HashSuiteHasher.Hash(
            HashSuiteIds.Sha256V1,
            "profile"u8));

        ChunkId first = new(HashSuiteHasher.Hash(hashSuite, "first"u8));
        ChunkId second = new(HashSuiteHasher.Hash(hashSuite, "second"u8));

        using var accumulator =
            new ManifestIdAccumulator(hashSuite, profileId, fingerprint);
        accumulator.Append(first, 5);
        accumulator.Append(second, 6);

        ManifestId actual = accumulator.Complete();

        byte[] expectedBytes = BuildCanonicalBytes(
            hashSuite,
            profileId,
            fingerprint,
            [(first, 5), (second, 6)]);

        ManifestId expected = new(HashSuiteHasher.Hash(hashSuite, expectedBytes));

        Assert.Equal(expected, actual);
        Assert.Equal(2UL, accumulator.ChunkCount);
        Assert.Equal(11UL, accumulator.ContentLength);
    }

    [Fact]
    public void EmptyManifest_BindsZeroFinalTotals()
    {
        HashSuiteId hashSuite = HashSuiteIds.Blake3256V1;
        var profileId = new ChunkingProfileId("fastcdc.test.v1");
        ProfileFingerprint fingerprint = new(HashSuiteHasher.Hash(
            HashSuiteIds.Sha256V1,
            "profile"u8));

        using var accumulator =
            new ManifestIdAccumulator(hashSuite, profileId, fingerprint);

        ManifestId actual = accumulator.Complete();

        byte[] expectedBytes = BuildCanonicalBytes(
            hashSuite,
            profileId,
            fingerprint,
            []);

        Assert.Equal(
            new ManifestId(HashSuiteHasher.Hash(hashSuite, expectedBytes)),
            actual);
    }

    private static byte[] BuildCanonicalBytes(
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint fingerprint,
        IReadOnlyList<(ChunkId Id, int Length)> chunks)
    {
        using var bytes = new MemoryStream();
        bytes.Write("chunkshift.manifest-id.v1\0"u8);
        WriteIdentifier(bytes, hashSuite.Value);
        WriteIdentifier(bytes, profileId.Value);

        Span<byte> hash = stackalloc byte[32];
        fingerprint.Value.CopyTo(hash);
        bytes.Write(hash);

        ulong totalLength = 0;
        Span<byte> lengthBytes = stackalloc byte[4];
        foreach ((ChunkId id, int length) in chunks)
        {
            id.Value.CopyTo(hash);
            bytes.Write(hash);

            BinaryPrimitives.WriteUInt32LittleEndian(lengthBytes, checked((uint)length));
            bytes.Write(lengthBytes);
            totalLength = checked(totalLength + (uint)length);
        }

        Span<byte> totals = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(totals, checked((ulong)chunks.Count));
        BinaryPrimitives.WriteUInt64LittleEndian(totals[8..], totalLength);
        bytes.Write(totals);

        return bytes.ToArray();
    }

    private static void WriteIdentifier(Stream destination, string value)
    {
        byte[] encoded = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(length, checked((ushort)encoded.Length));
        destination.Write(length);
        destination.Write(encoded);
    }

    public static TheoryData<HashSuiteId> HashSuites => new()
    {
        HashSuiteIds.Blake3256V1,
        HashSuiteIds.Sha256V1,
    };
}
