using System;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Hashing;

public class HashSuiteHasherTests
{
    [Fact]
    public void Blake3_EmptyInput_MatchesOfficialVector()
    {
        Hash256 digest = HashSuiteHasher.Hash(HashSuiteIds.Blake3256V1, ReadOnlySpan<byte>.Empty);

        Assert.Equal(
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            digest.ToHexLower());
    }

    [Theory]
    [InlineData(1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213")]
    [InlineData(63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b")]
    [InlineData(64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98")]
    [InlineData(65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee")]
    [InlineData(1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11")]
    [InlineData(1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7")]
    [InlineData(1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444")]
    [InlineData(2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a")]
    [InlineData(102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085")]
    public void Blake3_OfficialBoundaryVectors_Match(int length, string expected)
    {
        byte[] input = new byte[length];

        for (int i = 0; i < input.Length; i++)
        {
            input[i] = (byte)(i % 251);
        }

        Hash256 digest = HashSuiteHasher.Hash(HashSuiteIds.Blake3256V1, input);

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
