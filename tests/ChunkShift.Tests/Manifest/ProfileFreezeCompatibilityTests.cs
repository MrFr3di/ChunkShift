using ChunkShift;
using ChunkShift.Chunking;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class ProfileFreezeCompatibilityTests
{
    private static readonly byte[] Content =
        CreateXorShiftBytes(400_000, 0x08F2_C064u);

    [Fact]
    public async Task PreFreeze64KProfileId_IsUnknownManifestOnlyAndUnsupportedForContent()
    {
        FastCdcProfile measured = FastCdcProfile.CreateM1Candidate(64 * 1024);
        ChunkingProfileId oldCandidateId = measured.CandidateProfileId;
        ProfileFingerprint fingerprint = measured.ComputeFingerprint();

        byte[] manifest = await EncodeDefaultChunksAsync(
            oldCandidateId,
            fingerprint);

        ManifestVerificationResult manifestOnly =
            await ChunkManifest.VerifyManifestAsync(Read(manifest));

        Assert.True(manifestOnly.IsValid);
        Assert.Equal(oldCandidateId, manifestOnly.Manifest.ProfileId);
        Assert.Equal(fingerprint, manifestOnly.Manifest.ProfileFingerprint);
        Assert.False(
            ChunkScanConfiguration.TryResolveProfileRegistration(
                oldCandidateId,
                out _));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => ChunkManifest.VerifyAsync(Read(Content), Read(manifest)));
    }

    [Fact]
    public void StableProfileId_ChangesManifestIdentityWithoutChangingTheFingerprint()
    {
        FastCdcProfile measured = FastCdcProfile.CreateM1Candidate(64 * 1024);
        FastCdcProfile stable = FastCdcProfile.CreateStable64K();

        ProfileFingerprint measuredFingerprint = measured.ComputeFingerprint();
        ProfileFingerprint stableFingerprint = stable.ComputeFingerprint();
        Assert.Equal(measuredFingerprint, stableFingerprint);

        ChunkId chunkId = new(
            HashSuiteHasher.Hash(
                HashSuiteIds.Default,
                "same chunk bytes"u8));

        ManifestId oldId;
        using (var oldAccumulator = new ManifestIdAccumulator(
            HashSuiteIds.Default,
            measured.CandidateProfileId,
            measuredFingerprint))
        {
            oldAccumulator.Append(chunkId, 16);
            oldId = oldAccumulator.Complete();
        }

        ManifestId stableId;
        using (var stableAccumulator = new ManifestIdAccumulator(
            HashSuiteIds.Default,
            FastCdcProfile.Stable64KProfileId,
            stableFingerprint))
        {
            stableAccumulator.Append(chunkId, 16);
            stableId = stableAccumulator.Complete();
        }

        Assert.NotEqual(oldId, stableId);
    }

    private static async Task<byte[]> EncodeDefaultChunksAsync(
        ChunkingProfileId profileId,
        ProfileFingerprint fingerprint)
    {
        var chunks = new List<ChunkInfo>();
        await ChunkScanner.ScanAsync(
            Read(Content),
            (chunk, _, _) =>
            {
                chunks.Add(chunk);
                return ValueTask.CompletedTask;
            });

        using var encoded = new MemoryStream();
        using (CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                encoded,
                HashSuiteIds.Default,
                profileId,
                fingerprint,
                includeBlockIndex: false,
                CancellationToken.None))
        {
            foreach (ChunkInfo chunk in chunks)
            {
                await encoder.AppendAsync(
                    chunk.Id,
                    checked((uint)chunk.Length),
                    CancellationToken.None);
            }

            _ = await encoder.CompleteAsync(CancellationToken.None);
        }

        return encoded.ToArray();
    }

    private static MemoryStream Read(byte[] bytes) =>
        new(bytes, writable: false);

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
