using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using ChunkShift.Chunking;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Chunking;

public class FastCdcKernelTests
{
    private static readonly FastCdcProfile Profile64K = FastCdcProfile.CreateM1Candidate(64 * 1024);

    [Fact]
    public void GearTableDigest_MatchesNormativeDocument()
    {
        byte[] serialized = new byte[256 * sizeof(ulong)];

        for (int i = 0; i < 256; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                serialized.AsSpan(i * sizeof(ulong), sizeof(ulong)),
                FastCdcGearTable.Values[i]);
        }

        string digest = Convert.ToHexString(SHA256.HashData(serialized)).ToLowerInvariant();

        Assert.Equal(FastCdcGearTable.Sha256, digest);
        Assert.Equal("91a3061015ae351cd3701852712bcd6aa4a1ce26c8a231d3969432b00f028f88", digest);
    }

    [Theory]
    [InlineData(64 * 1024, 0x0000d90703537000UL, 0x0000d90f03530000UL)]
    [InlineData(128 * 1024, 0x0000d90707537000UL, 0x0000d90303537000UL)]
    [InlineData(256 * 1024, 0x0000d91707537000UL, 0x0000d90703537000UL)]
    public void CandidateMasks_AreNormative(int target, ulong strict, ulong relaxed)
    {
        FastCdcProfile profile = FastCdcProfile.CreateM1Candidate(target);

        Assert.Equal(target / 4, profile.Minimum);
        Assert.Equal(target, profile.Target);
        Assert.Equal(target * 4, profile.Maximum);
        Assert.Equal(strict, profile.StrictMask);
        Assert.Equal(relaxed, profile.RelaxedMask);
    }

    [Theory]
    [InlineData(64 * 1024, "fastcdc.gear.candidate.v1.m16384.t65536.x262144", "054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0")]
    [InlineData(128 * 1024, "fastcdc.gear.candidate.v1.m32768.t131072.x524288", "74d375951d3cd4d165fdad5866c6de0b7a9231c794f16444930ac5acdd65b3da")]
    [InlineData(256 * 1024, "fastcdc.gear.candidate.v1.m65536.t262144.x1048576", "d8fc289d93f8f8b6308498891831638743cce8dde789417f25cf5f3d8f7fbae4")]
    public void CandidateProfileIdentity_IsDeterministic(
        int target,
        string profileId,
        string fingerprint)
    {
        FastCdcProfile profile = FastCdcProfile.CreateM1Candidate(target);

        Assert.Equal(profileId, profile.CandidateProfileId.Value);
        Assert.Equal(fingerprint, profile.ComputeFingerprint().ToString());
    }

    [Fact]
    public void GearLookup_DoesNotAllocatePerLookup()
    {
        // The first call absorbs one-time runtime work (static initialization,
        // tier-up/OSR of the loop), which on a loaded net8.0 Windows runner was
        // observed at ~8 KB. The minimum of the following runs is what the
        // lookup itself costs: a per-lookup allocation would add at least 24 MB
        // to every run, so it cannot hide behind the minimum.
        _ = MeasureGearLookupAllocations();

        long allocated = long.MaxValue;
        for (int run = 0; run < 3; run++)
        {
            allocated = Math.Min(allocated, MeasureGearLookupAllocations());
        }

        // This is a scaling regression guard, not a promise that the runtime/JIT
        // performs zero incidental thread-local allocation on every architecture.
        Assert.InRange(allocated, 0, 4096);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static long MeasureGearLookupAllocations()
    {
        long before = GC.GetAllocatedBytesForCurrentThread();
        ulong accumulator = 0;

        for (int iteration = 0; iteration < 1_000_000; iteration++)
        {
            accumulator ^= FastCdcGearTable.Get((byte)iteration);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        GC.KeepAlive(accumulator);
        return allocated;
    }

    [Fact]
    public void CandidateProfileId_IsAShortLabelSeparateFromTheFingerprint()
    {
        var baseline = new FastCdcProfile(16 * 1024, 64 * 1024, 256 * 1024);
        var changedMinimum = new FastCdcProfile(8 * 1024, 64 * 1024, 256 * 1024);
        var changedMaximum = new FastCdcProfile(16 * 1024, 64 * 1024, 128 * 1024);

        Assert.NotEqual(baseline.ComputeFingerprint(), changedMinimum.ComputeFingerprint());
        Assert.NotEqual(baseline.ComputeFingerprint(), changedMaximum.ComputeFingerprint());
        Assert.NotEqual(baseline.CandidateProfileId, changedMinimum.CandidateProfileId);
        Assert.NotEqual(baseline.CandidateProfileId, changedMaximum.CandidateProfileId);

        // The ProfileFingerprint is recorded next to the ProfileId in CORE and
        // is the authoritative digest; the ProfileId never embeds it.
        Assert.DoesNotContain(
            baseline.ComputeFingerprint().ToString(),
            baseline.CandidateProfileId.Value,
            StringComparison.Ordinal);
    }

    [Fact]
    public void ScalarReference_MatchesIndependentRandomGoldenVector()
    {
        byte[] input = CreateXorShiftBytes(1024 * 1024, 0x12345678);
        ChunkKernelChunk[] chunks = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(Profile64K),
            HashSuiteIds.Blake3256V1);

        (long Offset, int Length)[] expected =
        [
            (0, 100081),
            (100081, 33106),
            (133187, 69903),
            (203090, 49442),
            (252532, 103705),
            (356237, 144977),
            (501214, 214287),
            (715501, 145480),
            (860981, 50981),
            (911962, 37677),
            (949639, 79457),
            (1029096, 19480),
        ];

        Assert.Equal(expected.Length, chunks.Length);

        for (int i = 0; i < expected.Length; i++)
        {
            Assert.Equal(expected[i].Offset, chunks[i].Offset);
            Assert.Equal(expected[i].Length, chunks[i].Length);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PathologicalRepeatedInput_ForcesMaximumCuts(bool zeros)
    {
        byte[] input = new byte[1024 * 1024];

        if (!zeros)
        {
            byte[] pattern = [1, 2, 3, 4, 5, 6, 7, 8];
            for (int i = 0; i < input.Length; i++)
            {
                input[i] = pattern[i & 7];
            }
        }

        ChunkKernelChunk[] chunks = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(Profile64K),
            HashSuiteIds.Blake3256V1);

        Assert.Equal(4, chunks.Length);
        Assert.All(chunks, chunk => Assert.Equal(256 * 1024, chunk.Length));
    }

    [Theory]
    [InlineData(16383)]
    [InlineData(16384)]
    [InlineData(16385)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(65537)]
    [InlineData(262143)]
    [InlineData(262144)]
    [InlineData(262145)]
    public void ZeroInput_EdgeLengthsNeverExceedMaximum(int length)
    {
        byte[] input = new byte[length];
        ChunkKernelChunk[] chunks = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(Profile64K),
            HashSuiteIds.Blake3256V1);

        Assert.Equal(length, chunks.Sum(static chunk => chunk.Length));
        Assert.All(chunks, chunk => Assert.InRange(chunk.Length, 1, Profile64K.Maximum));

        if (length <= Profile64K.Maximum)
        {
            Assert.Single(chunks);
            Assert.Equal(length, chunks[0].Length);
        }
    }

    [Fact]
    public void ChunkIds_UseSelectedHashSuiteOverExactChunkBytes()
    {
        byte[] input = CreateXorShiftBytes(400 * 1024, 0xD00DFEED);

        ChunkKernelChunk[] blake = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(Profile64K),
            HashSuiteIds.Blake3256V1);

        ChunkKernelChunk[] sha = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(Profile64K),
            HashSuiteIds.Sha256V1);

        Assert.Equal(blake.Select(static x => x.Length), sha.Select(static x => x.Length));

        foreach (ChunkKernelChunk chunk in blake)
        {
            Hash256 expected = HashSuiteHasher.Hash(
                HashSuiteIds.Blake3256V1,
                input.AsSpan(checked((int)chunk.Offset), chunk.Length));
            Assert.Equal(expected, chunk.Id.Value);
        }

        foreach (ChunkKernelChunk chunk in sha)
        {
            Hash256 expected = HashSuiteHasher.Hash(
                HashSuiteIds.Sha256V1,
                input.AsSpan(checked((int)chunk.Offset), chunk.Length));
            Assert.Equal(expected, chunk.Id.Value);
        }
    }

    [Theory]
    [InlineData(63, 256, 1024)]
    [InlineData(64, 255, 1024)]
    [InlineData(64, 300, 1024)]
    [InlineData(64, 256, 1023)]
    [InlineData(256, 256, 1024)]
    [InlineData(64, 1024, 1024)]
    [InlineData(65, 256, 1024)]
    public void InvalidProfiles_AreRejected(int minimum, int target, int maximum)
    {
        Assert.ThrowsAny<ArgumentException>(() => new FastCdcProfile(minimum, target, maximum));
    }

    private static byte[] CreateXorShiftBytes(int length, uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int i = 0; i < bytes.Length; i++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[i] = (byte)state;
        }

        return bytes;
    }
}
