using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Creation;

public sealed class PatchCreationErrorTests
{
    private const int Mebibyte = 1024 * 1024;

    [Theory]
    [InlineData("chunkshift.blake3-256.v1", "chunkshift.sha256.v1")]
    [InlineData("chunkshift.sha256.v1", "chunkshift.blake3-256.v1")]
    public async Task DifferentHashSuites_ThrowArgumentExceptionFromTheTask(
        string baseSuiteName,
        string targetSuiteName)
    {
        byte[] content = CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED3001u);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            content,
            new HashSuiteId(baseSuiteName));
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            content,
            new HashSuiteId(targetSuiteName));
        using var destination = new MemoryStream();

        ArgumentException error = await Assert.ThrowsAsync<ArgumentException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(content, writable: false),
                new MemoryStream(targetManifest, writable: false),
                new MemoryStream(content, writable: false),
                destination));

        Assert.Equal("targetManifest", error.ParamName);
        Assert.Equal(0, destination.Length);
    }

    [Fact]
    public async Task TargetContentShorterThanTheManifest_IsInvalidData()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED3002u);
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);
        byte[] truncated = content[..(content.Length / 2)];
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(manifest, writable: false),
                new MemoryStream(truncated, writable: false),
                destination));
    }

    [Fact]
    public async Task TargetContentLongerThanTheManifest_IsInvalidData()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED3003u);
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);
        byte[] longer = [.. content, 0x42];
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(manifest, writable: false),
                new MemoryStream(longer, writable: false),
                destination));
    }

    [Fact]
    public async Task TargetContentWithAChangedByteInAMissingChunk_IsInvalidData()
    {
        byte[] baseContent = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED3004u);
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED3005u);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            baseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);

        // The content differs from its manifest inside a chunk the base does not
        // supply, so the chunk must be hashed against the manifest's ChunkId.
        byte[] targetContent = (byte[])content.Clone();
        targetContent[1234] ^= 0x01;
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(baseContent, writable: false),
                new MemoryStream(targetManifest, writable: false),
                new MemoryStream(targetContent, writable: false),
                destination));
    }

    [Fact]
    public async Task TargetContentWithAChangedByteInAChunkTheBaseSupplies_IsInvalidData()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED300Au);
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);

        // Base and target manifests are identical, so no chunk is stored; the
        // content must still match the manifest it claims to be.
        byte[] targetContent = (byte[])content.Clone();
        targetContent[^1] ^= 0x01;

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(manifest, writable: false),
                new MemoryStream(content, writable: false),
                new MemoryStream(manifest, writable: false),
                new MemoryStream(targetContent, writable: false),
                new MemoryStream()));
    }

    [Fact]
    public async Task BaseContentWithAChangedByteInAChosenDictionaryChunk_IsInvalidData()
    {
        byte[] baseContent = CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED3006u);
        byte[] targetContent = (byte[])baseContent.Clone();
        targetContent[Mebibyte / 2] ^= 0x5A;
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            baseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            targetContent,
            HashSuiteIds.Sha256V1);

        // The first creation reveals which base chunks the encoder chose as
        // dictionaries; the scenario makes that choice deterministic for one
        // build; patch bytes are not a contract.
        (byte[] patch, _) = await CreationTestSupport.CreatePatchAsync(
            new PatchScenario("dictionary-probe", baseContent, targetContent, false),
            baseManifest,
            targetManifest);
        CspReader reader = await CreationTestSupport.OpenAsync(patch);
        ChunkId? dictionaryChunkId = null;

        for (int ordinal = 0;
            ordinal < reader.Index.Count && dictionaryChunkId is null;
            ordinal++)
        {
            if (reader.Index[ordinal].DictionaryCount == 0)
            {
                continue;
            }

            CspEntry entry = await reader.ReadEntryAsync(ordinal);
            dictionaryChunkId = entry.DictionaryChunkIds[0];
        }

        Assert.NotNull(dictionaryChunkId);

        ChunkInfo dictionaryRecord = (await CreationTestSupport.ReadRecordsAsync(baseManifest))
            .First(record => record.Id == dictionaryChunkId!.Value);
        byte[] corruptedBase = (byte[])baseContent.Clone();
        corruptedBase[checked((int)dictionaryRecord.Offset)] ^= 0x01;
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(corruptedBase, writable: false),
                new MemoryStream(targetManifest, writable: false),
                new MemoryStream(targetContent, writable: false),
                destination));
    }

    [Fact]
    public async Task BaseManifestWithAFlippedFileDigest_IsInvalidData()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(256 * 1024, 0x5EED3007u);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);

        // The TRAILER is the last 64 bytes and its FileDigest starts 40 bytes
        // before the end.
        baseManifest[^40] ^= 0x01;
        using var destination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(content, writable: false),
                new MemoryStream(targetManifest, writable: false),
                new MemoryStream(content, writable: false),
                destination));

        Assert.Equal(0, destination.Length);
    }

    [Fact]
    public async Task ArgumentErrors_AreThrownByTheCall()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED3008u);
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);

        using var readable = new MemoryStream(manifest, writable: false);
        using var baseContent = new MemoryStream(content, writable: false);
        using var targetManifest = new MemoryStream(manifest, writable: false);
        using var targetContent = new MemoryStream(content, writable: false);
        using var destination = new MemoryStream();
        using var nonReadable = new WriteOnlyStream(new MemoryStream());
        using var nonSeekable = new ForwardOnlyReadStream(content);
        using var readOnly = new MemoryStream(content, writable: false);

        // A null argument is rejected synchronously, by the call itself.
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                null!,
                baseContent,
                targetManifest,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                null!,
                targetManifest,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                null!,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                targetManifest,
                null!,
                destination);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                targetManifest,
                targetContent,
                null!);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(null!, targetContent, destination);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(targetManifest, null!, destination);
        });
        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkPatch.CreateAsync(targetManifest, targetContent, null!);
        });

        // Every role needs exactly the capability its documentation lists.
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                nonReadable,
                baseContent,
                targetManifest,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                nonSeekable,
                targetManifest,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                nonSeekable,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                targetManifest,
                nonReadable,
                destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                targetManifest,
                targetContent,
                readOnly);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(nonSeekable, targetContent, destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(targetManifest, nonReadable, destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(targetManifest, targetContent, readOnly);
        });

        // No two roles may share one Stream instance.
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                readable,
                targetManifest,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                targetManifest,
                baseContent,
                destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                targetContent,
                targetContent,
                destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(
                readable,
                baseContent,
                targetManifest,
                targetContent,
                targetManifest);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(targetManifest, targetManifest, destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(targetContent, targetContent, destination);
        });
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkPatch.CreateAsync(targetContent, targetManifest, targetContent);
        });
    }

    [Fact]
    public async Task PreCancelledToken_ThrowsOperationCanceledException()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED3009u);
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(
            content,
            HashSuiteIds.Sha256V1);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        using var destination = new MemoryStream();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(manifest, writable: false),
                new MemoryStream(content, writable: false),
                destination,
                cancellation.Token));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(manifest, writable: false),
                new MemoryStream(content, writable: false),
                new MemoryStream(manifest, writable: false),
                new MemoryStream(content, writable: false),
                destination,
                cancellation.Token));
    }

    [Fact]
    public async Task CancellationDuringTheContentPass_ThrowsOperationCanceledException()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.Different);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);
        using var cancellation = new CancellationTokenSource();
        using var targetContent = new CancelOnReadStream(scenario.TargetContent, cancellation);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(scenario.BaseContent, writable: false),
                new MemoryStream(targetManifest, writable: false),
                targetContent,
                new MemoryStream(),
                cancellation.Token));

        Assert.True(targetContent.Position < scenario.TargetContent.Length);
    }

    [Fact]
    public async Task Streams_AreNeverDisposed()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.Different);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);

        using var baseManifestInner = new MemoryStream(baseManifest, writable: false);
        using var baseContentInner = new MemoryStream(scenario.BaseContent, writable: false);
        using var targetManifestInner = new MemoryStream(targetManifest, writable: false);
        using var targetContentInner =
            new MemoryStream(scenario.TargetContent, writable: false);
        using var destinationInner = new MemoryStream();
        using var baseManifestStream = new DisposeTrackingStream(baseManifestInner);
        using var baseContentStream = new DisposeTrackingStream(baseContentInner);
        using var targetManifestStream = new DisposeTrackingStream(targetManifestInner);
        using var targetContentStream = new DisposeTrackingStream(targetContentInner);
        using var destinationStream = new DisposeTrackingStream(destinationInner);

        _ = await ChunkPatch.CreateAsync(
            baseManifestStream,
            baseContentStream,
            targetManifestStream,
            targetContentStream,
            destinationStream);

        Assert.True(destinationStream.Length > 0);
        AssertStreamsAlive(
            baseManifestStream,
            baseContentStream,
            targetManifestStream,
            targetContentStream,
            destinationStream);

        // A failure path releases nothing either. The first target chunk is not
        // in the base, so its content must hash to the manifest's ChunkId.
        byte[] corruptedTarget = (byte[])scenario.TargetContent.Clone();
        corruptedTarget[0] ^= 0x01;

        using var corruptedInner = new MemoryStream(corruptedTarget, writable: false);
        using var corruptedStream = new DisposeTrackingStream(corruptedInner);
        using var failedDestination = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ChunkPatch.CreateAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(scenario.BaseContent, writable: false),
                new MemoryStream(targetManifest, writable: false),
                corruptedStream,
                failedDestination));

        AssertStreamsAlive(corruptedStream);

        // The self-contained overload releases nothing either.
        using var manifestInner = new MemoryStream(targetManifest, writable: false);
        using var contentInner = new MemoryStream(scenario.TargetContent, writable: false);
        using var selfContainedDestinationInner = new MemoryStream();
        using var manifestStream = new DisposeTrackingStream(manifestInner);
        using var contentStream = new DisposeTrackingStream(contentInner);
        using var selfContainedDestination =
            new DisposeTrackingStream(selfContainedDestinationInner);

        _ = await ChunkPatch.CreateAsync(
            manifestStream,
            contentStream,
            selfContainedDestination);

        Assert.True(selfContainedDestination.Length > 0);
        AssertStreamsAlive(manifestStream, contentStream, selfContainedDestination);
    }

    private static void AssertStreamsAlive(params DisposeTrackingStream[] streams)
    {
        foreach (DisposeTrackingStream stream in streams)
        {
            Assert.False(stream.Disposed);
        }
    }

    /// <summary>Cancels its token after serving the first read.</summary>
    private sealed class CancelOnReadStream(byte[] content, CancellationTokenSource cancellation)
        : MemoryStream(content, writable: false)
    {
        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            int read = await base.ReadAsync(buffer, cancellationToken);
            await cancellation.CancelAsync();
            return read;
        }
    }
}
