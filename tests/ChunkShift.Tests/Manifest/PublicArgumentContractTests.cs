using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// Public manifest operations validate their arguments when called, not when the
/// returned task is awaited, and report the public parameter names.
/// </summary>
public sealed class PublicArgumentContractTests
{
    private const string FixtureDirectory = "Fixtures/CsmV1";

    [Fact]
    public void CreateAsync_RejectsInvalidArgumentsSynchronously()
    {
        using var content = new MemoryStream([1, 2, 3], writable: false);
        using var destination = new MemoryStream();

        AssertParameter<ArgumentNullException>(
            "content",
            () => ChunkManifest.CreateAsync(null!, destination));
        AssertParameter<ArgumentNullException>(
            "destination",
            () => ChunkManifest.CreateAsync(content, null!));
        AssertParameter<ArgumentException>(
            "content",
            () => ChunkManifest.CreateAsync(Unusable(), destination));
        AssertParameter<ArgumentException>(
            "destination",
            () => ChunkManifest.CreateAsync(content, content));
        AssertParameter<ArgumentException>(
            "destination",
            () => ChunkManifest.CreateAsync(content, Unusable()));

        Assert.Equal(0, destination.Length);
        Assert.Equal(0, content.Position);
    }

    [Fact]
    public void CreateAsync_RejectsUnsupportedSelectionsBeforeWriting()
    {
        using var content = new MemoryStream([1, 2, 3], writable: false);
        using var destination = new MemoryStream();

        Assert.Throws<NotSupportedException>(() =>
        {
            _ = ChunkManifest.CreateAsync(
                content,
                destination,
                new ManifestCreationOptions
                {
                    ProfileId = new ChunkingProfileId("unknown.profile.v1"),
                });
        });

        Assert.Throws<NotSupportedException>(() =>
        {
            _ = ChunkManifest.CreateAsync(
                content,
                destination,
                new ManifestCreationOptions
                {
                    HashSuite = new HashSuiteId("chunkshift.unknown-256.v1"),
                });
        });

        Assert.Equal(0, destination.Length);
        Assert.Equal(0, content.Position);
    }

    [Fact]
    public void VerifyManifestAsync_RejectsInvalidArgumentsSynchronously()
    {
        AssertParameter<ArgumentNullException>(
            "manifest",
            () => ChunkManifest.VerifyManifestAsync(null!));
        AssertParameter<ArgumentException>(
            "manifest",
            () => ChunkManifest.VerifyManifestAsync(Unusable()));
    }

    [Fact]
    public void VerifyAsync_RejectsInvalidArgumentsSynchronously()
    {
        using var content = new MemoryStream([1, 2, 3], writable: false);
        using var manifest = new MemoryStream([4, 5, 6], writable: false);

        AssertParameter<ArgumentNullException>(
            "content",
            () => ChunkManifest.VerifyAsync(null!, manifest));
        AssertParameter<ArgumentNullException>(
            "manifest",
            () => ChunkManifest.VerifyAsync(content, null!));
        AssertParameter<ArgumentException>(
            "content",
            () => ChunkManifest.VerifyAsync(Unusable(), manifest));
        AssertParameter<ArgumentException>(
            "manifest",
            () => ChunkManifest.VerifyAsync(content, Unusable()));
        AssertParameter<ArgumentException>(
            "manifest",
            () => ChunkManifest.VerifyAsync(content, content));

        Assert.Equal(0, content.Position);
        Assert.Equal(0, manifest.Position);
    }

    [Fact]
    public void ManifestReaderOpenAsync_RejectsInvalidArgumentsSynchronously()
    {
        AssertParameter<ArgumentNullException>(
            "manifest",
            () => ManifestReader.OpenAsync(null!));
        AssertParameter<ArgumentException>(
            "manifest",
            () => ManifestReader.OpenAsync(Unusable()));
    }

    [Fact]
    public async Task ManifestReaderReadAsync_RejectsInvalidCallsSynchronously()
    {
        ManifestReader reader = await ManifestReader.OpenAsync(
            new MemoryStream(Fixture("one-entry-sha256-no-bidx.csm"), writable: false));

        ArgumentException empty = Assert.Throws<ArgumentException>(() =>
        {
            _ = reader.ReadAsync(Memory<ChunkInfo>.Empty).AsTask();
        });
        Assert.Equal("destination", empty.ParamName);

        await reader.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() =>
        {
            _ = reader.ReadAsync(new ChunkInfo[1]).AsTask();
        });
    }

    [Fact]
    public async Task ManifestReader_ReportsLengthsOutsideTheApiRangeAsUnsupported()
    {
        // Well-formed CSM whose single chunk is 2^31 bytes long: every public path
        // reaches the same NotSupported verdict instead of InvalidData or a
        // truncated ChunkInfo.Length.
        byte[] bytes = Fixture("unsupported-chunk-length-above-int32.csm");

        await Assert.ThrowsAsync<NotSupportedException>(
            () => ChunkManifest.VerifyManifestAsync(new MemoryStream(bytes, writable: false)));

        ManifestReader reader = await ManifestReader.OpenAsync(
            new MemoryStream(bytes, writable: false));

        await Assert.ThrowsAsync<NotSupportedException>(
            async () => await reader.ReadAsync(new ChunkInfo[4]));

        // The failed read leaves the reader unusable, reported at the call site.
        Assert.Throws<InvalidOperationException>(() =>
        {
            _ = reader.ReadAsync(new ChunkInfo[4]).AsTask();
        });

        await reader.DisposeAsync();
    }

    private static void AssertParameter<TException>(
        string parameterName,
        Func<Task> call)
        where TException : ArgumentException
    {
        // Assert.Throws (not ThrowsAsync): the exception must escape the call
        // itself, before any task exists to await.
        TException exception = Assert.Throws<TException>(() =>
        {
            _ = call();
        });

        Assert.IsType<TException>(exception);
        Assert.Equal(parameterName, exception.ParamName);
    }

    /// <summary>A stream that can neither be read nor written.</summary>
    private static MemoryStream Unusable()
    {
        var stream = new MemoryStream();
        stream.Dispose();
        return stream;
    }

    private static byte[] Fixture(string name) =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixtureDirectory, name));
}
