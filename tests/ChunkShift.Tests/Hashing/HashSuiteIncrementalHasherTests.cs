using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Hashing;

public sealed class HashSuiteIncrementalHasherTests
{
    [Theory]
    [MemberData(nameof(HashSuites))]
    public void IncrementalHash_MatchesOneShot(HashSuiteId hashSuite)
    {
        byte[] input = Encoding.UTF8.GetBytes(
            "ChunkShift incremental hashing must preserve HashSuite semantics.");

        using var incremental = HashSuiteIncrementalHasher.Create(hashSuite);
        incremental.Append(input.AsSpan(0, 7));
        incremental.Append(input.AsSpan(7, 19));
        incremental.Append(input.AsSpan(26));

        Hash256 actual = incremental.FinalizeHash();
        Hash256 expected = HashSuiteHasher.Hash(hashSuite, input);

        Assert.Equal(expected, actual);
    }

    public static TheoryData<HashSuiteId> HashSuites => new()
    {
        HashSuiteIds.Blake3256V1,
        HashSuiteIds.Sha256V1,
    };
}
