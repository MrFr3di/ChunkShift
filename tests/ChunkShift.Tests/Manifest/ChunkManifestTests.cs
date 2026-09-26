using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class ChunkManifestTests
{
    [Fact]
    public async Task CreateAndVerify_DefaultCandidate_RoundTrips()
    {
        byte[] content = CreateXorShiftBytes(
            2 * 1024 * 1024,
            0xC5A5EEDu);
        using var source =
            new MemoryStream(content, writable: false);
        using var manifest = new MemoryStream();

        ManifestInfo created = await ChunkManifest.CreateAsync(
            source,
            manifest);

        manifest.Position = 0;
        ManifestVerificationResult verified =
            await ChunkManifest.VerifyManifestAsync(manifest);

        Assert.True(verified.IsValid);
        Assert.Equal(
            ManifestVerificationFailure.None,
            verified.Failures);
        Assert.Equal(
            created.ManifestId,
            verified.Manifest.ManifestId);
        Assert.Equal(
            created.FileDigest,
            verified.Manifest.FileDigest);
        Assert.Equal(
            created.ChunkCount,
            verified.Manifest.ChunkCount);
        Assert.Equal(
            created.ContentLength,
            verified.Manifest.ContentLength);
    }

    [Fact]
    public async Task Create_WithSha256AndBlockIndex_PreservesSelectedSemantics()
    {
        byte[] content = CreateXorShiftBytes(
            1024 * 1024,
            0x13579BDFu);
        using var manifest = new MemoryStream();

        ManifestInfo created = await ChunkManifest.CreateAsync(
            new MemoryStream(content, writable: false),
            manifest,
            new ManifestCreationOptions
            {
                HashSuite = HashSuiteIds.Sha256V1,
                IncludeBlockIndex = true,
            });

        Assert.Equal(HashSuiteIds.Sha256V1, created.HashSuite);
        Assert.True(created.HasBlockIndex);

        manifest.Position = 0;
        ManifestVerificationResult verified =
            await ChunkManifest.VerifyManifestAsync(manifest);

        Assert.True(verified.IsValid);
        Assert.Equal(HashSuiteIds.Sha256V1, verified.Manifest.HashSuite);
        Assert.True(verified.Manifest.HasBlockIndex);
    }

    [Fact]
    public async Task VerifyContent_ReportsMismatchWithoutThrowing()
    {
        byte[] content = CreateXorShiftBytes(
            1024 * 1024,
            0x2468ACE0u);
        using var manifest = new MemoryStream();

        _ = await ChunkManifest.CreateAsync(
            new MemoryStream(content, writable: false),
            manifest);

        content[content.Length / 2] ^= 0x80;
        manifest.Position = 0;

        ManifestVerificationResult result =
            await ChunkManifest.VerifyAsync(
                new MemoryStream(content, writable: false),
                manifest);

        Assert.False(result.IsValid);
        Assert.True(
            result.Failures.HasFlag(
                ManifestVerificationFailure.Content));
        Assert.False(
            result.Failures.HasFlag(
                ManifestVerificationFailure.FileDigest));
    }

    [Fact]
    public async Task CallerOwnedStreams_AreNeverDisposed()
    {
        byte[] content = CreateXorShiftBytes(
            256 * 1024,
            0x10293847u);
        var source =
            new TrackingMemoryStream(content, writable: false);
        var manifest = new TrackingMemoryStream();

        try
        {
            _ = await ChunkManifest.CreateAsync(
                source,
                manifest);

            Assert.False(source.WasDisposed);
            Assert.False(manifest.WasDisposed);

            manifest.Position = 0;
            _ = await ChunkManifest.VerifyManifestAsync(manifest);

            Assert.False(source.WasDisposed);
            Assert.False(manifest.WasDisposed);
        }
        finally
        {
            source.Dispose();
            manifest.Dispose();
        }
    }

    [Fact]
    public async Task Create_RejectsAliasedSourceAndDestination()
    {
        using var shared = new MemoryStream(
            CreateXorShiftBytes(64 * 1024, 0xABCDEF01u));

        ArgumentException exception =
            await Assert.ThrowsAsync<ArgumentException>(
                () => ChunkManifest.CreateAsync(
                    shared,
                    shared));

        Assert.Equal("destination", exception.ParamName);
    }

    [Fact]
    public async Task Verify_RejectsAliasedContentAndManifest()
    {
        using var manifest = new MemoryStream();

        _ = await ChunkManifest.CreateAsync(
            new MemoryStream(
                CreateXorShiftBytes(64 * 1024, 0x1234ABCDu),
                writable: false),
            manifest);

        manifest.Position = 0;

        ArgumentException exception =
            await Assert.ThrowsAsync<ArgumentException>(
                () => ChunkManifest.VerifyAsync(
                    manifest,
                    manifest));

        Assert.Equal("manifest", exception.ParamName);
    }

    [Fact]
    public async Task MalformedManifest_UsesInvalidDataException()
    {
        byte[] malformed = "not-a-csm"u8.ToArray();

        await Assert.ThrowsAsync<InvalidDataException>(
            () => ChunkManifest.VerifyManifestAsync(
                new MemoryStream(malformed, writable: false)));
    }

    private static byte[] CreateXorShiftBytes(
        int length,
        uint seed)
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

    private sealed class TrackingMemoryStream : MemoryStream
    {
        internal TrackingMemoryStream()
        {
        }

        internal TrackingMemoryStream(
            byte[] buffer,
            bool writable)
            : base(buffer, writable)
        {
        }

        internal bool WasDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }
}
