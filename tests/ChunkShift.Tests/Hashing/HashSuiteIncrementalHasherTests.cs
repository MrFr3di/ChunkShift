using System;
using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Hashing;

public sealed class HashSuiteIncrementalHasherTests
{
    private const uint PseudoRandomSeed = 0x9E3779B9;

    private static readonly HashSuiteId[] Suites =
    [
        HashSuiteIds.Blake3256V1,
        HashSuiteIds.Sha256V1,
    ];

    private static readonly SplitPolicy[] SplitPolicies =
    [
        new("whole-input", static length => [length]),
        new("one-byte", static length => FixedSegments(length, 1)),
        new("fixed-63", static length => FixedSegments(length, 63)),
        new("fixed-64", static length => FixedSegments(length, 64)),
        new("fixed-65", static length => FixedSegments(length, 65)),
        new("fixed-1023", static length => FixedSegments(length, 1023)),
        new("fixed-1024", static length => FixedSegments(length, 1024)),
        new("fixed-1025", static length => FixedSegments(length, 1025)),
        new("prime-257", static length => FixedSegments(length, 257)),
        new("prime-509", static length => FixedSegments(length, 509)),
        new("blake3-chunk-boundary", Blake3ChunkBoundary),
        new("pseudo-random", PseudoRandom),
        new("pseudo-random-with-empty-appends", PseudoRandom, InsertEmptyAppends: true),
    ];

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

    [Theory]
    [MemberData(nameof(SuiteAndPolicyNames))]
    public void IncrementalHash_MatchesIndependentVectorsForEverySegmentation(
        HashSuiteId hashSuite,
        string policyName)
    {
        SplitPolicy policy = SplitPolicies.First(candidate => candidate.Name == policyName);
        IReadOnlyList<(int Length, string Expected)> vectors = HashVectors.VectorsFor(hashSuite);

        foreach ((int length, string expected) in vectors)
        {
            byte[] input = HashVectors.CreateInput(length);

            Hash256 oneShot = HashSuiteHasher.Hash(hashSuite, input);

            using var incremental = HashSuiteIncrementalHasher.Create(hashSuite);
            int offset = 0;

            foreach (int segmentLength in policy.Segments(length))
            {
                if (policy.InsertEmptyAppends && offset > 0)
                {
                    incremental.Append(ReadOnlySpan<byte>.Empty);
                }

                incremental.Append(input.AsSpan(offset, segmentLength));
                offset += segmentLength;
            }

            Hash256 segmented = incremental.FinalizeHash();

            Assert.Equal(length, offset);
            AssertMatchesVector("one-shot", oneShot, expected, hashSuite, policyName, length);
            AssertMatchesVector("segmented", segmented, expected, hashSuite, policyName, length);
        }
    }

    [Theory]
    [MemberData(nameof(HashSuites))]
    public void FinalizeHash_RejectsFurtherAppendAndSecondFinalize(HashSuiteId hashSuite)
    {
        using var incremental = HashSuiteIncrementalHasher.Create(hashSuite);
        incremental.Append("ChunkShift"u8);
        _ = incremental.FinalizeHash();

        Assert.Throws<InvalidOperationException>(() => incremental.Append(" more"u8));
        Assert.Throws<InvalidOperationException>(() => incremental.FinalizeHash());
    }

    public static TheoryData<HashSuiteId> HashSuites
    {
        get
        {
            var data = new TheoryData<HashSuiteId>();

            foreach (HashSuiteId hashSuite in Suites)
            {
                data.Add(hashSuite);
            }

            return data;
        }
    }

    public static TheoryData<HashSuiteId, string> SuiteAndPolicyNames
    {
        get
        {
            var data = new TheoryData<HashSuiteId, string>();

            foreach (HashSuiteId hashSuite in Suites)
            {
                foreach (SplitPolicy policy in SplitPolicies)
                {
                    data.Add(hashSuite, policy.Name);
                }
            }

            return data;
        }
    }

    private static void AssertMatchesVector(
        string source,
        Hash256 actual,
        string expected,
        HashSuiteId hashSuite,
        string policyName,
        int length)
    {
        string actualHex = actual.ToHexLower();

        if (!string.Equals(expected, actualHex, StringComparison.Ordinal))
        {
            Assert.Fail(
                $"Hash suite '{hashSuite.Value}', policy '{policyName}', length {length}: " +
                $"{source} digest {actualHex} does not match the independent vector {expected}.");
        }
    }

    private static IEnumerable<int> FixedSegments(int totalLength, int segmentLength)
    {
        for (int offset = 0; offset < totalLength; offset += segmentLength)
        {
            yield return Math.Min(segmentLength, totalLength - offset);
        }
    }

    private static IEnumerable<int> Blake3ChunkBoundary(int totalLength)
    {
        // Split directly before and after the internal BLAKE3 1024-byte chunk boundary.
        int[] boundaries = [0, 1023, 1024, 1025, totalLength];

        for (int i = 1; i < boundaries.Length; i++)
        {
            int start = Math.Min(boundaries[i - 1], totalLength);
            int end = Math.Min(boundaries[i], totalLength);

            if (end > start)
            {
                yield return end - start;
            }
        }
    }

    private static IEnumerable<int> PseudoRandom(int totalLength)
    {
        uint state = PseudoRandomSeed;
        int remaining = totalLength;

        while (remaining > 0)
        {
            state = XorShift32(state);
            int segmentLength = Math.Min((int)(state % 4096) + 1, remaining);

            yield return segmentLength;
            remaining -= segmentLength;
        }
    }

    private static uint XorShift32(uint state)
    {
        // Marsaglia's xorshift32, written locally so the matrix stays reproducible
        // and does not depend on the System.Random implementation.
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }

    private readonly record struct SplitPolicy(
        string Name,
        Func<int, IEnumerable<int>> Segments,
        bool InsertEmptyAppends = false);
}
