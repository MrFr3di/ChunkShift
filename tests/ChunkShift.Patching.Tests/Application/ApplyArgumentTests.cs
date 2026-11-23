using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Creation;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// Synchronous argument validation and caller-owned streams: apply throws
/// argument errors from the call itself and never disposes a stream.
/// </summary>
public sealed class ApplyArgumentTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-apply-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string Destination => Path.Combine(_directory, "argument.bin");

    [Fact]
    public void Patch_IsRequiredAndMustBeReadableAndSeekable()
    {
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(null!, Destination);
        });

        using var writableOnly = new WriteOnlyStream(new MemoryStream());
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(writableOnly, Destination);
        });

        using var forwardOnly = new ForwardOnlyReadStream([]);
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(forwardOnly, Destination);
        });
    }

    [Fact]
    public void DestinationPath_IsRequired()
    {
        using var patch = new MemoryStream([], writable: false);

        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, null!);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, string.Empty);
        });
    }

    [Fact]
    public void BaseStreams_AreRequiredAndMustHaveTheirCapabilities()
    {
        using var patch = new MemoryStream([], writable: false);
        using var manifest = new MemoryStream([], writable: false);
        using var content = new MemoryStream([], writable: false);

        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, null!, content, Destination);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, manifest, null!, Destination);
        });

        using var writableOnly = new WriteOnlyStream(new MemoryStream());
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, writableOnly, content, Destination);
        });

        using var forwardOnly = new ForwardOnlyReadStream([]);
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, manifest, forwardOnly, Destination);
        });
    }

    [Fact]
    public void SameStreamInstanceInTwoRoles_IsRejected()
    {
        using var patch = new MemoryStream([], writable: false);
        using var other = new MemoryStream([], writable: false);

        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, patch, other, Destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, other, patch, Destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.ApplyAsync(patch, other, other, Destination);
        });
    }

    [Fact]
    public async Task Streams_AreNeverDisposed()
    {
        (PatchScenario scenario, byte[] baseManifest, _, byte[] patch) =
            await CreatePatchAsync();

        using var patchInner = new MemoryStream(patch, writable: false);
        using var manifestInner = new MemoryStream(baseManifest, writable: false);
        using var contentInner = new MemoryStream(scenario.BaseContent, writable: false);
        using var patchStream = new DisposeTrackingStream(patchInner);
        using var manifestStream = new DisposeTrackingStream(manifestInner);
        using var contentStream = new DisposeTrackingStream(contentInner);

        PatchApplyResult applied = await ChunkPatch.ApplyAsync(
            patchStream,
            manifestStream,
            contentStream,
            Path.Combine(_directory, "applied.bin"));

        Assert.True(applied.IsApplied);
        AssertStreamsAlive(patchStream, manifestStream, contentStream);

        // A failure releases nothing either. Corrupting a byte inside PAYL
        // makes the reader reject the patch as malformed.
        CspReader reader = await CreationTestSupport.OpenAsync(patch);
        CspIndexEntry first = reader.Index[0];
        int storedAt = checked(
            (int)first.PayloadOffset +
            CspFormat.PaylEntryHeaderSize +
            (first.DictionaryCount * CspFormat.DictionaryReferenceSize));
        byte[] corrupted = (byte[])patch.Clone();
        corrupted[storedAt] ^= 0xFF;

        using var corruptedInner = new MemoryStream(corrupted, writable: false);
        using var failedManifestInner = new MemoryStream(baseManifest, writable: false);
        using var failedContentInner = new MemoryStream(scenario.BaseContent, writable: false);
        using var corruptedStream = new DisposeTrackingStream(corruptedInner);
        using var failedManifestStream = new DisposeTrackingStream(failedManifestInner);
        using var failedContentStream = new DisposeTrackingStream(failedContentInner);

        await Assert.ThrowsAsync<InvalidDataException>(() => ChunkPatch.ApplyAsync(
            corruptedStream,
            failedManifestStream,
            failedContentStream,
            Path.Combine(_directory, "failed.bin")));

        AssertStreamsAlive(corruptedStream, failedManifestStream, failedContentStream);
    }

    private static async Task<(PatchScenario Scenario, byte[] BaseManifest, byte[] TargetManifest, byte[] Patch)>
        CreatePatchAsync()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.Different);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);
        (byte[] patch, _) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        return (scenario, baseManifest, targetManifest, patch);
    }

    private static void AssertStreamsAlive(params DisposeTrackingStream[] streams)
    {
        foreach (DisposeTrackingStream stream in streams)
        {
            Assert.False(stream.Disposed);
        }
    }
}
