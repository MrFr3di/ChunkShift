using ChunkShift.Chunking;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Chunking;

public sealed class StableFastCdcProfileTests
{
    private const string StableId = "fastcdc.gear.chunkshift.v1.64k";
    private const string StableFingerprint =
        "054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0";

    [Fact]
    public void Stable64KIdentityAndSemantics_AreFrozen()
    {
        FastCdcProfile profile = FastCdcProfile.CreateStable64K();

        Assert.Equal(StableId, FastCdcProfile.Stable64KProfileId.Value);
        Assert.Equal(16 * 1024, profile.Minimum);
        Assert.Equal(64 * 1024, profile.Target);
        Assert.Equal(256 * 1024, profile.Maximum);
        Assert.Equal(0x0000d90703537000UL, profile.StrictMask);
        Assert.Equal(0x0000d90f03530000UL, profile.RelaxedMask);
        Assert.Equal(StableFingerprint, profile.ComputeFingerprint().ToString());
    }

    [Fact]
    public void Stable64KSemantics_MatchTheMeasured64KCandidate()
    {
        FastCdcProfile stable = FastCdcProfile.CreateStable64K();
        FastCdcProfile measured = FastCdcProfile.CreateM1Candidate(64 * 1024);

        Assert.Equal(measured.Minimum, stable.Minimum);
        Assert.Equal(measured.Target, stable.Target);
        Assert.Equal(measured.Maximum, stable.Maximum);
        Assert.Equal(measured.StrictMask, stable.StrictMask);
        Assert.Equal(measured.RelaxedMask, stable.RelaxedMask);
        Assert.Equal(measured.ComputeFingerprint(), stable.ComputeFingerprint());

        byte[] input = CreateXorShiftBytes(2 * 1024 * 1024, 0x08F2EE64u);
        ChunkKernelChunk[] stableChunks = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(stable),
            HashSuiteIds.Blake3256V1);
        ChunkKernelChunk[] measuredChunks = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(measured),
            HashSuiteIds.Blake3256V1);

        Assert.Equal(measuredChunks.Length, stableChunks.Length);
        for (int index = 0; index < stableChunks.Length; index++)
        {
            Assert.Equal(measuredChunks[index].Offset, stableChunks[index].Offset);
            Assert.Equal(measuredChunks[index].Length, stableChunks[index].Length);
            Assert.Equal(measuredChunks[index].Id, stableChunks[index].Id);
        }
    }

    [Fact]
    public void ProductionRegistry_ContainsOnlyTheStable64KProfile()
    {
        ChunkScanConfiguration.ProfileRegistration byDefault =
            ChunkScanConfiguration.ResolveProfileRegistration(null);
        ChunkScanConfiguration.ProfileRegistration explicitStable =
            ChunkScanConfiguration.ResolveProfileRegistration(
                FastCdcProfile.Stable64KProfileId);

        Assert.Equal(StableId, byDefault.Id.Value);
        Assert.Equal(StableFingerprint, byDefault.Fingerprint.ToString());
        Assert.Equal(byDefault.Id, explicitStable.Id);
        Assert.Equal(byDefault.Fingerprint, explicitStable.Fingerprint);

        foreach (int target in new[] { 64 * 1024, 128 * 1024, 256 * 1024 })
        {
            ChunkingProfileId candidateId =
                FastCdcProfile.CreateM1Candidate(target).CandidateProfileId;

            Assert.False(
                ChunkScanConfiguration.TryResolveProfileRegistration(
                    candidateId,
                    out _));
            Assert.Throws<NotSupportedException>(
                () => ChunkScanConfiguration.ResolveProfileRegistration(candidateId));
        }
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
