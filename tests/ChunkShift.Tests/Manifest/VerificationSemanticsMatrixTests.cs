using ChunkShift.Chunking;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// Pins the CSM v1 verification matrix (CSM-V1 §14): what manifest-only verification
/// (<see cref="ChunkManifest.VerifyManifestAsync"/> and <see cref="ManifestReader"/>)
/// and content verification (<see cref="ChunkManifest.VerifyAsync"/>) report for
/// each kind of input.
/// </summary>
/// <remarks>
/// <code>
/// situation                          manifest-only        VerifyAsync
/// malformed CSM                      InvalidData          InvalidData
/// unknown HashSuite                  NotSupported         NotSupported
/// unknown ProfileId                  accepted             NotSupported
/// known ProfileId, wrong fingerprint ProfileSemantics     ProfileSemantics
/// wrong content                      -                    Content
/// bad CRC / ManifestId / FileDigest  that flag            that flag
/// </code>
/// </remarks>
public sealed class VerificationSemanticsMatrixTests
{
    private const string FixtureDirectory = "Fixtures/CsmV1";

    private static readonly byte[] Content =
        CsmBytes.CreateXorShiftBytes(300_000, 0x6400_0064u);

    [Fact]
    public async Task MalformedCsm_IsInvalidDataOnEveryPath()
    {
        byte[] manifest = await CreateKnownManifestAsync();
        byte[] truncated = manifest.AsSpan(0, manifest.Length - 10).ToArray();

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ChunkManifest.VerifyManifestAsync(Read(truncated)));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => ReadToEndAsync(truncated));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => ChunkManifest.VerifyAsync(Read(Content), Read(truncated)));
    }

    [Fact]
    public async Task UnknownHashSuite_IsNotSupportedOnEveryPath()
    {
        byte[] manifest = Fixture("unsupported-unknown-hash-suite.csm");

        await Assert.ThrowsAsync<NotSupportedException>(
            () => ChunkManifest.VerifyManifestAsync(Read(manifest)));
        await Assert.ThrowsAsync<NotSupportedException>(
            () => ReadToEndAsync(manifest));
        await Assert.ThrowsAsync<NotSupportedException>(
            () => ChunkManifest.VerifyAsync(Read(Content), Read(manifest)));
    }

    [Fact]
    public async Task UnknownProfileId_IsAcceptedManifestOnlyButNotSupportedForContent()
    {
        // The fixtures declare "fixture.csm.synthetic.v1", which no build registers.
        byte[] manifest = Fixture("one-entry-sha256-no-bidx.csm");

        ManifestVerificationResult manifestOnly =
            await ChunkManifest.VerifyManifestAsync(Read(manifest));
        ManifestVerificationResult reader = await ReadToEndAsync(manifest);

        Assert.True(manifestOnly.IsValid);
        Assert.Equal(ManifestVerificationFailure.None, reader.Failures);
        Assert.False(
            ChunkScanConfiguration.TryResolveProfileRegistration(
                manifestOnly.Manifest.ProfileId,
                out _));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => ChunkManifest.VerifyAsync(Read(Content), Read(manifest)));
    }

    [Fact]
    public async Task KnownProfileIdWithWrongFingerprint_IsProfileSemanticsOnEveryPath()
    {
        // Internally consistent CSM (CRCs, ManifestId, FileDigest all match) whose
        // CORE pairs the registered 64 KiB candidate ProfileId with another
        // profile's fingerprint.
        ChunkScanConfiguration.ProfileRegistration registered =
            ChunkScanConfiguration.ResolveProfileRegistration(null);
        ProfileFingerprint other =
            FastCdcProfile.CreateM1Candidate(128 * 1024).ComputeFingerprint();
        Assert.NotEqual(registered.Fingerprint, other);

        byte[] manifest = await EncodeAsync(registered.Id, other);

        ManifestVerificationResult manifestOnly =
            await ChunkManifest.VerifyManifestAsync(Read(manifest));
        ManifestVerificationResult reader = await ReadToEndAsync(manifest);
        ManifestVerificationResult content =
            await ChunkManifest.VerifyAsync(Read(Content), Read(manifest));

        Assert.Equal(ManifestVerificationFailure.ProfileSemantics, manifestOnly.Failures);
        Assert.Equal(ManifestVerificationFailure.ProfileSemantics, reader.Failures);
        Assert.Equal(ManifestVerificationFailure.ProfileSemantics, content.Failures);
    }

    [Fact]
    public async Task KnownProfileIdWithItsOwnFingerprint_IsValidOnEveryPath()
    {
        byte[] manifest = await CreateKnownManifestAsync();

        Assert.True((await ChunkManifest.VerifyManifestAsync(Read(manifest))).IsValid);
        Assert.True((await ReadToEndAsync(manifest)).IsValid);
        Assert.True((await ChunkManifest.VerifyAsync(Read(Content), Read(manifest))).IsValid);
    }

    [Fact]
    public async Task WrongContent_IsContentForContentVerificationOnly()
    {
        byte[] manifest = await CreateKnownManifestAsync();
        byte[] otherContent = (byte[])Content.Clone();
        otherContent[otherContent.Length / 2] ^= 0x01;

        Assert.True((await ChunkManifest.VerifyManifestAsync(Read(manifest))).IsValid);

        ManifestVerificationResult result =
            await ChunkManifest.VerifyAsync(Read(otherContent), Read(manifest));

        Assert.Equal(ManifestVerificationFailure.Content, result.Failures);
    }

    [Fact]
    public async Task BadBlockCrc_IsBlockCrcOnEveryPath()
    {
        byte[] manifest = await CreateKnownManifestAsync();
        int cblk = CsmBytes.FindSection(manifest, CsmFormat.ChunkBlock);
        int crcOffset = cblk + CsmBytes.GetSectionRecordLength(manifest, cblk) - sizeof(uint);
        manifest[crcOffset] ^= 0x01;
        CsmBytes.RewritePhysicalDigest(manifest);

        await AssertSameFailureOnEveryPathAsync(manifest, ManifestVerificationFailure.BlockCrc);
    }

    [Fact]
    public async Task BadStoredManifestId_IsManifestIdOnEveryPath()
    {
        byte[] manifest = await CreateKnownManifestAsync();
        int cend = CsmBytes.FindSection(manifest, CsmFormat.ChunkEnd);
        manifest[CsmBytes.PayloadOffset(cend) + 16] ^= 0x01;
        CsmBytes.RewritePhysicalDigest(manifest);

        await AssertSameFailureOnEveryPathAsync(manifest, ManifestVerificationFailure.ManifestId);
    }

    [Fact]
    public async Task BadFileDigest_IsFileDigestOnEveryPath()
    {
        byte[] manifest = await CreateKnownManifestAsync();
        manifest[manifest.Length - CsmFormat.TrailerSize + 24] ^= 0x01;

        await AssertSameFailureOnEveryPathAsync(manifest, ManifestVerificationFailure.FileDigest);
    }

    private static async Task AssertSameFailureOnEveryPathAsync(
        byte[] manifest,
        ManifestVerificationFailure expected)
    {
        Assert.Equal(
            expected,
            (await ChunkManifest.VerifyManifestAsync(Read(manifest))).Failures);
        Assert.Equal(
            expected,
            (await ReadToEndAsync(manifest)).Failures);
        Assert.Equal(
            expected,
            (await ChunkManifest.VerifyAsync(Read(Content), Read(manifest))).Failures);
    }

    private static async Task<byte[]> CreateKnownManifestAsync()
    {
        using var destination = new MemoryStream();
        _ = await ChunkManifest.CreateAsync(Read(Content), destination);
        return destination.ToArray();
    }

    /// <summary>
    /// Encodes the default-profile chunks of <see cref="Content"/> under an arbitrary
    /// ProfileId/fingerprint pair, producing an otherwise consistent CSM.
    /// </summary>
    private static async Task<byte[]> EncodeAsync(
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

    private static async Task<ManifestVerificationResult> ReadToEndAsync(byte[] manifest)
    {
        await using ManifestReader reader = await ManifestReader.OpenAsync(Read(manifest));
        var batch = new ChunkInfo[64];

        while (await reader.ReadAsync(batch) != 0)
        {
        }

        return reader.VerificationResult!;
    }

    private static MemoryStream Read(byte[] bytes) => new(bytes, writable: false);

    private static byte[] Fixture(string name) =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixtureDirectory, name));
}
