namespace ChunkShift.Tests.Manifest;

/// <summary>
/// Cancellation contract of the public CSM/manifest APIs.
/// </summary>
/// <remarks>
/// Every source and destination here ignores the token it is given, so each
/// test proves that ChunkShift itself observes cancellation instead of relying
/// on the caller's stream to do it. A stream that honors the token would make
/// these tests pass even if ChunkShift never checked it.
/// </remarks>
public sealed class ManifestCancellationTests
{
    private static readonly TimeSpan HangGuard = TimeSpan.FromSeconds(30);

    // Five CBLKs (4096 entries per block) so a mid-read cancellation has
    // several later reads that must not happen.
    private const int MultiBlockEntryCount = 5 * 4096;

    private const int ContentLength = 8 * 1024 * 1024;
    private const int CancelAfterBytes = 64 * 1024;

    [Fact]
    public async Task CreateAsync_PreCanceled_ReadsAndWritesNothing()
    {
        var content = new ProbeStream(
            CsmBytes.CreateXorShiftBytes(ContentLength, 0xC0FFEE01u));
        var destination = new ProbeStream();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkManifest.CreateAsync(
                content,
                destination,
                cancellationToken: new CancellationToken(canceled: true))
                .WaitAsync(HangGuard));

        Assert.Equal(0, content.BytesRead);
        Assert.Equal(0, destination.BytesWritten);
    }

    [Fact]
    public async Task CreateAsync_CanceledWhileReadingContent_StopsBeforeEnd()
    {
        using var cancellation = new CancellationTokenSource();
        var content = new ProbeStream(
            CsmBytes.CreateXorShiftBytes(ContentLength, 0xC0FFEE02u))
        {
            CancelAfterBytes = CancelAfterBytes,
            Cancellation = cancellation,
        };
        var destination = new ProbeStream();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkManifest.CreateAsync(
                content,
                destination,
                cancellationToken: cancellation.Token)
                .WaitAsync(HangGuard));

        Assert.True(content.BytesRead >= CancelAfterBytes);
        Assert.True(content.BytesRead < ContentLength);
    }

    [Fact]
    public async Task CreateAsync_CanceledByDestinationWrite_DoesNotScanContent()
    {
        using var cancellation = new CancellationTokenSource();
        var content = new ProbeStream(
            CsmBytes.CreateXorShiftBytes(ContentLength, 0xC0FFEE03u));
        var destination = new ProbeStream
        {
            CancelAfterBytes = 1,
            Cancellation = cancellation,
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkManifest.CreateAsync(
                content,
                destination,
                cancellationToken: cancellation.Token)
                .WaitAsync(HangGuard));

        // The PREAMBLE/CORE write requested the cancellation; nothing after it
        // may run, so the content is never read and nothing else is written.
        Assert.Equal(0, content.BytesRead);
        Assert.Equal(1, destination.WriteCalls);
    }

    [Fact]
    public async Task VerifyManifestAsync_PreCanceled_ReadsNothing()
    {
        var manifest = new ProbeStream(
            await CsmBytes.CreateSyntheticAsync(
                MultiBlockEntryCount,
                includeBlockIndex: true));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkManifest.VerifyManifestAsync(
                manifest,
                new CancellationToken(canceled: true))
                .WaitAsync(HangGuard));

        Assert.Equal(0, manifest.BytesRead);
    }

    [Fact]
    public async Task VerifyManifestAsync_CanceledMidManifest_StopsBeforeEnd()
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            MultiBlockEntryCount,
            includeBlockIndex: true);
        using var cancellation = new CancellationTokenSource();
        var manifest = new ProbeStream(bytes)
        {
            CancelAfterBytes = CancelAfterBytes,
            Cancellation = cancellation,
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkManifest.VerifyManifestAsync(
                manifest,
                cancellation.Token)
                .WaitAsync(HangGuard));

        Assert.True(manifest.BytesRead >= CancelAfterBytes);
        Assert.True(manifest.BytesRead < bytes.Length);
    }

    [Fact]
    public async Task VerifyAsync_PreCanceled_ReadsNeitherStream()
    {
        (byte[] content, byte[] manifest) = await CreateContentAndManifestAsync(
            0xC0FFEE04u);
        var contentStream = new ProbeStream(content);
        var manifestStream = new ProbeStream(manifest);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkManifest.VerifyAsync(
                contentStream,
                manifestStream,
                new CancellationToken(canceled: true))
                .WaitAsync(HangGuard));

        Assert.Equal(0, contentStream.BytesRead);
        Assert.Equal(0, manifestStream.BytesRead);
    }

    [Fact]
    public async Task VerifyAsync_CanceledWhileScanningContent_StopsBeforeEnd()
    {
        (byte[] content, byte[] manifest) = await CreateContentAndManifestAsync(
            0xC0FFEE05u);
        using var cancellation = new CancellationTokenSource();
        var contentStream = new ProbeStream(content)
        {
            CancelAfterBytes = CancelAfterBytes,
            Cancellation = cancellation,
        };
        var manifestStream = new ProbeStream(manifest);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ChunkManifest.VerifyAsync(
                contentStream,
                manifestStream,
                cancellation.Token)
                .WaitAsync(HangGuard));

        // The manifest is verified before the content scan starts.
        Assert.Equal(manifest.Length, manifestStream.BytesRead);
        Assert.True(contentStream.BytesRead >= CancelAfterBytes);
        Assert.True(contentStream.BytesRead < content.Length);
    }

    [Fact]
    public async Task ManifestReaderOpenAsync_PreCanceled_ReadsNothing()
    {
        var manifest = new ProbeStream(
            await CsmBytes.CreateSyntheticAsync(
                MultiBlockEntryCount,
                includeBlockIndex: false));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ManifestReader.OpenAsync(
                manifest,
                new CancellationToken(canceled: true))
                .WaitAsync(HangGuard));

        Assert.Equal(0, manifest.BytesRead);
    }

    [Fact]
    public async Task ManifestReaderReadAsync_PreCanceled_ConsumesNothingAndStaysUsable()
    {
        var manifest = new ProbeStream(
            await CsmBytes.CreateSyntheticAsync(
                MultiBlockEntryCount,
                includeBlockIndex: false));

        await using ManifestReader reader =
            await ManifestReader.OpenAsync(manifest);

        // Load the first CBLK so the next entries are buffered and a read would
        // need no I/O: cancellation must still win.
        var first = new ChunkInfo[1];
        Assert.Equal(1, await reader.ReadAsync(first));
        long bytesAfterFirstRead = manifest.BytesRead;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => reader.ReadAsync(
                new ChunkInfo[16],
                new CancellationToken(canceled: true))
                .AsTask()
                .WaitAsync(HangGuard));

        Assert.Equal(bytesAfterFirstRead, manifest.BytesRead);

        // Nothing was consumed, so the reader continues exactly where it was.
        var rest = new ChunkInfo[MultiBlockEntryCount];
        int read;
        long expectedIndex = 1;

        while ((read = await reader.ReadAsync(rest)) != 0)
        {
            for (int index = 0; index < read; index++)
            {
                Assert.Equal(expectedIndex++, rest[index].Index);
            }
        }

        Assert.Equal((long)MultiBlockEntryCount, expectedIndex);
        Assert.NotNull(reader.VerificationResult);
        Assert.True(reader.VerificationResult.IsValid);
    }

    [Fact]
    public async Task ManifestReaderReadAsync_CanceledMidManifest_LeavesReaderUnusable()
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            MultiBlockEntryCount,
            includeBlockIndex: true);
        using var cancellation = new CancellationTokenSource();
        var manifest = new ProbeStream(bytes)
        {
            CancelAfterBytes = CancelAfterBytes,
            Cancellation = cancellation,
        };

        await using ManifestReader reader =
            await ManifestReader.OpenAsync(manifest);

        var batch = new ChunkInfo[MultiBlockEntryCount];

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => reader.ReadAsync(batch, cancellation.Token)
                .AsTask()
                .WaitAsync(HangGuard));

        Assert.True(manifest.BytesRead < bytes.Length);
        Assert.False(reader.IsCompleted);
        Assert.Null(reader.VerificationResult);

        // The stream position has advanced past a partially consumed block, so
        // the reader refuses to continue even with a fresh token.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => reader.ReadAsync(batch, CancellationToken.None)
                .AsTask()
                .WaitAsync(HangGuard));
    }

    private static async Task<(byte[] Content, byte[] Manifest)>
        CreateContentAndManifestAsync(uint seed)
    {
        byte[] content = CsmBytes.CreateXorShiftBytes(ContentLength, seed);
        using var manifest = new MemoryStream();

        _ = await ChunkManifest.CreateAsync(
            new MemoryStream(content, writable: false),
            manifest);

        return (content, manifest.ToArray());
    }

    /// <summary>
    /// Forward-only stream that ignores cancellation tokens, counts traffic and
    /// can request cancellation once a byte threshold has been crossed.
    /// </summary>
    private sealed class ProbeStream : Stream
    {
        private readonly byte[] _data;
        private readonly bool _readable;
        private int _position;

        internal ProbeStream(byte[] data)
        {
            _data = data;
            _readable = true;
        }

        internal ProbeStream()
        {
            _data = [];
            _readable = false;
        }

        internal long CancelAfterBytes { get; init; } = long.MaxValue;
        internal CancellationTokenSource? Cancellation { get; init; }
        internal long BytesRead { get; private set; }
        internal long BytesWritten { get; private set; }
        internal int WriteCalls { get; private set; }

        public override bool CanRead => _readable;
        public override bool CanSeek => false;
        public override bool CanWrite => !_readable;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadCore(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ReadCore(buffer.Span));

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken) =>
            Task.FromResult(ReadCore(buffer.AsSpan(offset, count)));

        public override void Write(byte[] buffer, int offset, int count) =>
            WriteCore(count);

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            WriteCore(buffer.Length);
            return ValueTask.CompletedTask;
        }

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            WriteCore(count);
            return Task.CompletedTask;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        private int ReadCore(Span<byte> destination)
        {
            if (!_readable)
            {
                throw new NotSupportedException();
            }

            int count = Math.Min(destination.Length, _data.Length - _position);
            _data.AsSpan(_position, count).CopyTo(destination);
            _position += count;
            BytesRead += count;
            RequestCancellationIfDue(BytesRead);
            return count;
        }

        private void WriteCore(int count)
        {
            if (_readable)
            {
                throw new NotSupportedException();
            }

            WriteCalls++;
            BytesWritten += count;
            RequestCancellationIfDue(BytesWritten);
        }

        private void RequestCancellationIfDue(long transferred)
        {
            if (transferred >= CancelAfterBytes)
            {
                Cancellation?.Cancel();
            }
        }
    }
}
