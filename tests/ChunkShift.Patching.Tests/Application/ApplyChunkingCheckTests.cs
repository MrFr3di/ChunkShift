using ChunkShift.Patching.Application;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Creation;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// The optional re-chunk verification (CSP-V1 section 9.5): it runs when
/// this build registers the embedded profile, is skipped for an unregistered
/// one, and the internal switch turns it off, overlaps it with the
/// reconstruction or checks only the boundaries without changing a verdict.
/// </summary>
public sealed class ApplyChunkingCheckTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-apply-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    /// <summary>Gets every way of running the re-chunk check.</summary>
    public static TheoryData<string> Checks => new(Enum.GetNames<ChunkingCheck>());

    /// <summary>Gets both hash suites with every way of running the check.</summary>
    public static TheoryData<string, string> SuiteChecks
    {
        get
        {
            var cases = new TheoryData<string, string>();

            foreach (string suite in (string[])["chunkshift.blake3-256.v1", "chunkshift.sha256.v1"])
            {
                foreach (ChunkingCheck check in Enum.GetValues<ChunkingCheck>())
                {
                    cases.Add(suite, check.ToString());
                }
            }

            return cases;
        }
    }

    [Theory]
    [MemberData(nameof(SuiteChecks))]
    public async Task RegisteredProfile_Applies(string hashSuite, string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        var suite = new HashSuiteId(hashSuite);
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.EditedChunks);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            suite);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            suite);
        (byte[] patch, _) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        // Core creates manifests with the registered stable profile, so the
        // re-chunk check really runs when it is enabled.
        CspReader reader = await CreationTestSupport.OpenAsync(patch);
        Assert.Equal(
            "fastcdc.gear.chunkshift.v1.64k",
            reader.TargetManifest.Manifest.ProfileId.Value);

        string destination = Path.Combine(_directory, "target.bin");

        PatchApplyResult result = await CspApplier.ApplyAsync(
            new MemoryStream(patch, writable: false),
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(scenario.BaseContent, writable: false),
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            check,
            CancellationToken.None);

        Assert.True(result.IsApplied, result.Failures.ToString());
        Assert.Equal(scenario.TargetContent, File.ReadAllBytes(destination));
        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Theory]
    [MemberData(nameof(Checks))]
    public async Task UnregisteredProfile_SkipsTheCheckAndApplies(string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        // The committed vectors use a synthetic profile this build does not
        // register, so the check cannot run and must not block apply.
        CspApplyVector vector = CspApplyVectors.Find("valid-base-dependent.csp");
        string destination = Path.Combine(_directory, "unregistered.bin");

        using var patch = new MemoryStream(CspApplyVectors.ReadPatch(vector.Name), writable: false);
        using var baseManifest =
            new MemoryStream(CspApplyVectors.ReadBaseManifest(vector), writable: false);
        using var baseContent =
            new MemoryStream(CspApplyVectors.ReadBaseContent(vector), writable: false);

        PatchApplyResult result = await CspApplier.ApplyAsync(
            patch,
            baseManifest,
            baseContent,
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            check,
            CancellationToken.None);

        Assert.True(result.IsApplied);
        Assert.Equal(
            vector.OutputSha256,
            Convert.ToHexStringLower(
                System.Security.Cryptography.SHA256.HashData(
                    File.ReadAllBytes(destination))));
    }

    [Theory]
    [MemberData(nameof(SuiteChecks))]
    public async Task ManifestNotCutByItsProfile_IsProfileContent(string hashSuite, string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        var suite = new HashSuiteId(hashSuite);
        byte[] content = CspBytes.CreateXorShiftBytes(640 * 1024, 0x5EED6001u);
        byte[] manifest = await RecutManifests.SplitFirstRecordAsync(content, suite);
        byte[] patch = await CreateSelfContainedAsync(manifest, content);
        string destination = Path.Combine(_directory, "recut.bin");
        byte[] existing = [9, 8, 7];
        File.WriteAllBytes(destination, existing);

        PatchApplyResult result = await ApplySelfContainedAsync(patch, destination, check);

        if (check == ChunkingCheck.Off)
        {
            // Every chunk matches its ChunkId: without the check the target
            // is published.
            Assert.True(result.IsApplied, result.Failures.ToString());
            Assert.Equal(content, File.ReadAllBytes(destination));
        }
        else
        {
            Assert.False(result.IsApplied);
            Assert.Equal(PatchApplyFailure.ProfileContent, result.Failures);
            Assert.Equal(existing, File.ReadAllBytes(destination));
        }

        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Theory]
    [MemberData(nameof(Checks))]
    public async Task StableProfileWithAnotherFingerprint_FailsTheSameInEveryMode(string checkName)
    {
        // The boundary check reproduces only the pinned fingerprint. A
        // manifest that names the stable profile with another fingerprint
        // fails the embedded CSM's profile semantics before any re-chunk
        // check runs, so every mode reports the same failure.
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        byte[] content = CspBytes.CreateXorShiftBytes(640 * 1024, 0x5EED6003u);
        byte[] canonical = await CreationTestSupport.CreateManifestAsync(content, HashSuiteIds.Sha256V1);
        List<ChunkInfo> records = await CreationTestSupport.ReadRecordsAsync(canonical);
        var otherFingerprint = new ProfileFingerprint(Hash256.FromBytes(new byte[32]));
        byte[] manifest = await RecutManifests.WriteAsync(
            content,
            [.. records.Select(static record => record.Length)],
            HashSuiteIds.Sha256V1,
            BoundaryChunkingCheck.ProfileId,
            otherFingerprint);
        byte[] patch = await CreateSelfContainedAsync(manifest, content);
        string destination = Path.Combine(_directory, "fingerprint.bin");

        PatchApplyResult result = await ApplySelfContainedAsync(patch, destination, check);

        Assert.False(result.IsApplied);
        Assert.Equal(PatchApplyFailure.ProfileSemantics, result.Failures);
        Assert.Empty(Directory.GetFileSystemEntries(_directory));
    }

    [Theory]
    [InlineData(nameof(ChunkingCheck.Overlapped))]
    [InlineData(nameof(ChunkingCheck.Boundary))]
    public async Task ReconstructionFailure_TakesPrecedenceOverTheCheck(string checkName)
    {
        // The recut manifest would fail the check, but a corrupt payload
        // fails the reconstruction first, and the verdict order reports that failure alone.
        byte[] content = CspBytes.CreateXorShiftBytes(640 * 1024, 0x5EED6002u);
        byte[] manifest = await RecutManifests.SplitFirstRecordAsync(content, HashSuiteIds.Sha256V1);
        byte[] patch = await CreateSelfContainedAsync(manifest, content);
        CspReader reader = await CreationTestSupport.OpenAsync(patch);
        CspIndexEntry last = reader.Index[^1];

        // A raw last entry: flip one stored byte and repair the section CRC
        // and the file digest, so only the payload hash fails.
        Assert.Equal(CspFormat.EncodingRaw, last.Encoding);
        int storedAt = checked((int)last.PayloadOffset + CspFormat.PaylEntryHeaderSize);
        byte[] corrupted = (byte[])patch.Clone();
        corrupted[storedAt] ^= 0x01;
        CspSectionInfo payl = CspBytes.FindSections(corrupted, CspFormat.Payload)
            .Last(section => (ulong)section.Offset < last.PayloadOffset);
        CspBytes.RewriteSectionCrc(corrupted, payl.Offset);
        CspBytes.RewriteFileDigest(corrupted, HashSuiteIds.Sha256V1);

        string destination = Path.Combine(_directory, "precedence.bin");
        PatchApplyResult result = await ApplySelfContainedAsync(
            corrupted,
            destination,
            Enum.Parse<ChunkingCheck>(checkName));

        Assert.Equal(PatchApplyFailure.PayloadChunk, result.Failures);
        Assert.Empty(Directory.GetFileSystemEntries(_directory));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(50)]
    [InlineData(99)]
    public async Task CancellationDuringTheOverlappedCheck_PublishesNothing(int percentOfReads)
    {
        (byte[] patch, byte[] baseManifest, byte[] baseContent) = await CreateLargePatchAsync();
        string destination = Path.Combine(_directory, "cancelled.bin");
        byte[] existing = [1, 2, 3];
        File.WriteAllBytes(destination, existing);

        // The patch is read by both the reconstruction and the concurrent
        // check, so the cancellation lands while both are running: after the
        // reads that open the patch and a share of those that follow.
        int open = ReadsToOpen(patch);
        int apply = await ReadsToApplyAsync(patch, baseManifest, baseContent) - open;
        Assert.True(apply > 2, $"Only {apply} patch reads follow the open.");

        using var cancellation = new CancellationTokenSource();
        using var patchStream = new CancellingAfterReadsStream(
            new MemoryStream(patch, writable: false),
            cancellation,
            open + (apply * percentOfReads / 100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CspApplier.ApplyAsync(
            patchStream,
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(baseContent, writable: false),
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            ChunkingCheck.Overlapped,
            cancellation.Token));

        Assert.Equal(existing, File.ReadAllBytes(destination));
        Assert.Equal([destination], Directory.GetFiles(_directory));
    }

    [Fact]
    public async Task PatchFailureWhileTheOverlappedCheckReads_ThrowsAndPublishesNothing()
    {
        (byte[] patch, byte[] baseManifest, byte[] baseContent) = await CreateLargePatchAsync();
        string destination = Path.Combine(_directory, "failed.bin");

        // Every read after the reader opened the patch fails: the embedded
        // CSM that the check re-reads fails whichever task reaches it first.
        using var patchStream = new CancellingAfterReadsStream(
            new MemoryStream(patch, writable: false),
            cancellation: null,
            ReadsToOpen(patch));

        await Assert.ThrowsAsync<IOException>(() => CspApplier.ApplyAsync(
            patchStream,
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(baseContent, writable: false),
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            ChunkingCheck.Overlapped,
            CancellationToken.None));

        Assert.Empty(Directory.GetFileSystemEntries(_directory));
    }

    [Fact]
    public async Task LargeTarget_OverlappedCheckWaitsOnItsPipeAndApplies()
    {
        // A target of several MiB fills the pipe many times over.
        (byte[] patch, byte[] baseManifest, byte[] baseContent) = await CreateLargePatchAsync();
        string destination = Path.Combine(_directory, "large.bin");

        PatchApplyResult result = await CspApplier.ApplyAsync(
            new MemoryStream(patch, writable: false),
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(baseContent, writable: false),
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            ChunkingCheck.Overlapped,
            CancellationToken.None);

        Assert.True(result.IsApplied, result.Failures.ToString());
        Assert.True(result.Target!.ContentLength > 4 * OverlappedChunkingCheck.PauseBytes);
    }


    [Fact]
    public async Task OverlappedCheck_RespectsANonZeroPatchStart()
    {
        // CspReader offsets are patch-relative while SharedStreamView positions
        // are absolute. Exercise that composition explicitly instead of only
        // testing a patch that begins at stream position zero.
        (byte[] patch, byte[] baseManifest, byte[] baseContent) = await CreateLargePatchAsync();
        const int prefixBytes = 37;
        byte[] wrapped = new byte[prefixBytes + patch.Length];
        Array.Fill<byte>(wrapped, 0xA5, 0, prefixBytes);
        patch.CopyTo(wrapped.AsSpan(prefixBytes));

        using var patchStream = new MemoryStream(wrapped, writable: false)
        {
            Position = prefixBytes,
        };
        string destination = Path.Combine(_directory, "offset.bin");

        PatchApplyResult result = await CspApplier.ApplyAsync(
            patchStream,
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(baseContent, writable: false),
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            ChunkingCheck.Overlapped,
            CancellationToken.None);

        Assert.True(result.IsApplied, result.Failures.ToString());
        Assert.Equal(result.Target!.ContentLength, new FileInfo(destination).Length);
    }

    private static async Task<(byte[] Patch, byte[] BaseManifest, byte[] BaseContent)> CreateLargePatchAsync()
    {
        byte[] baseContent = CspBytes.CreateXorShiftBytes(6 * 1024 * 1024, 0x5EED6101u);
        byte[] targetContent = (byte[])baseContent.Clone();

        for (int offset = 512 * 1024; offset < targetContent.Length; offset += 1024 * 1024)
        {
            targetContent[offset] ^= 0x5A;
        }

        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            baseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            targetContent,
            HashSuiteIds.Sha256V1);
        using var destination = new MemoryStream();
        _ = await ChunkPatch.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(baseContent, writable: false),
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            destination);

        return (destination.ToArray(), baseManifest, baseContent);
    }

    private static async Task<byte[]> CreateSelfContainedAsync(byte[] manifest, byte[] content)
    {
        using var destination = new MemoryStream();
        _ = await ChunkPatch.CreateAsync(
            new MemoryStream(manifest, writable: false),
            new MemoryStream(content, writable: false),
            destination);
        return destination.ToArray();
    }

    private static Task<PatchApplyResult> ApplySelfContainedAsync(
        byte[] patch,
        string destination,
        ChunkingCheck check) =>
        CspApplier.ApplyAsync(
            new MemoryStream(patch, writable: false),
            baseManifest: null,
            baseContent: null,
            destination,
            CspFormat.DefaultMaximumPayloadEntries,
            check,
            CancellationToken.None);

    /// <summary>Counts the patch reads of a complete overlapped apply.</summary>
    private static async Task<int> ReadsToApplyAsync(byte[] patch, byte[] baseManifest, byte[] baseContent)
    {
        string directory = Directory.CreateTempSubdirectory("chunkshift-apply-count-").FullName;

        try
        {
            using var counting = new CancellingAfterReadsStream(
                new MemoryStream(patch, writable: false),
                cancellation: null,
                int.MaxValue);
            PatchApplyResult result = await CspApplier.ApplyAsync(
                counting,
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(baseContent, writable: false),
                Path.Combine(directory, "count.bin"),
                CspFormat.DefaultMaximumPayloadEntries,
                ChunkingCheck.Overlapped,
                CancellationToken.None);
            Assert.True(result.IsApplied);
            return counting.Reads;
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Counts the patch reads <see cref="CspReader.OpenAsync(Stream, CancellationToken)"/> makes.</summary>
    private static int ReadsToOpen(byte[] patch)
    {
        using var counting = new CancellingAfterReadsStream(
            new MemoryStream(patch, writable: false),
            cancellation: null,
            int.MaxValue);
        _ = CspReader.OpenAsync(counting).GetAwaiter().GetResult();
        return counting.Reads;
    }

    /// <summary>
    /// A seekable read stream that, after a given number of reads, either
    /// cancels a token source or, without one, fails every further read with
    /// an <see cref="IOException"/>.
    /// </summary>
    private sealed class CancellingAfterReadsStream(
        Stream inner,
        CancellationTokenSource? cancellation,
        int readsBefore) : Stream
    {
        private int _reads;

        internal int Reads => Volatile.Read(ref _reads);

        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => false;

        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            Count();
            return inner.Read(buffer);
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            Count();
            cancellationToken.ThrowIfCancellationRequested();
            return inner.ReadAsync(buffer, cancellationToken);
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);

        public override void Flush()
        {
        }

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        private void Count()
        {
            if (Interlocked.Increment(ref _reads) <= readsBefore)
            {
                return;
            }

            if (cancellation is null)
            {
                throw new IOException("Injected patch read failure.");
            }

            cancellation.Cancel();
        }
    }
}
