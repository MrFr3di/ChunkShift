using System;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Hashing;

public class HashSuiteHasherTests
{
    [Theory]
    [MemberData(nameof(HashVectors.Blake3OfficialVectorsData), MemberType = typeof(HashVectors))]
    public void Blake3_OfficialVectors_Match(int length, string expected)
    {
        byte[] input = HashVectors.CreateInput(length);

        Hash256 digest = HashSuiteHasher.Hash(HashSuiteIds.Blake3256V1, input);

        Assert.Equal(expected, digest.ToHexLower());
    }

    [Theory]
    [MemberData(nameof(HashVectors.Blake3ChunkShiftScaleVectorsData), MemberType = typeof(HashVectors))]
    public void Blake3_ChunkShiftScaleVectors_Match(int length, string expected)
    {
        byte[] input = HashVectors.CreateInput(length);

        Hash256 digest = HashSuiteHasher.Hash(HashSuiteIds.Blake3256V1, input);

        Assert.Equal(expected, digest.ToHexLower());
    }

    [Theory]
    [MemberData(nameof(HashVectors.Sha256VectorsData), MemberType = typeof(HashVectors))]
    public void Sha256_Vectors_Match(int length, string expected)
    {
        byte[] input = HashVectors.CreateInput(length);

        Hash256 digest = HashSuiteHasher.Hash(HashSuiteIds.Sha256V1, input);

        Assert.Equal(expected, digest.ToHexLower());
    }

    [Fact]
    public void Sha256_EmptyInput_MatchesStandardVector()
    {
        Hash256 digest = HashSuiteHasher.Hash(HashSuiteIds.Sha256V1, ReadOnlySpan<byte>.Empty);

        Assert.Equal(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            digest.ToHexLower());
    }

    [Fact]
    public void UnknownSuite_IsRejected()
    {
        var unknown = new HashSuiteId("chunkshift.unknown.v1");

        Assert.Throws<NotSupportedException>(() => HashSuiteHasher.Hash(unknown, ReadOnlySpan<byte>.Empty));
    }
}
