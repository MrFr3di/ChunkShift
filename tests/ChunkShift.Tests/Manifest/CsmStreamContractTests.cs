namespace ChunkShift.Tests.Manifest;

/// <summary>
/// A manifest stream that violates the <see cref="Stream.ReadAsync(Memory{byte}, CancellationToken)"/>
/// count contract is a caller bug, not malformed CSM data, and must be reported as such.
/// </summary>
public sealed class CsmStreamContractTests
{
    private static readonly TimeSpan HangGuard = TimeSpan.FromSeconds(30);

    public static TheoryData<int> ViolatingCounts => new()
    {
        -1,
        int.MinValue,
        1, // one byte more than requested
    };

    [Theory]
    [MemberData(nameof(ViolatingCounts))]
    public async Task VerifyManifestAsync_ViolatingFirstRead_IsInvalidOperation(
        int excessOverRequest)
    {
        byte[] bytes = await CsmBytes.CreateAsync(64 * 1024);
        using var manifest = new MisreportingStream(
            bytes,
            misreportAtRead: 1,
            excessOverRequest);

        InvalidOperationException exception =
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => ChunkManifest.VerifyManifestAsync(manifest)
                    .WaitAsync(HangGuard));

        Assert.Contains("Stream.ReadAsync", exception.Message, StringComparison.Ordinal);
        Assert.Equal(1, manifest.Reads);
    }

    [Theory]
    [MemberData(nameof(ViolatingCounts))]
    public async Task ManifestReader_ViolatingReadInsideChunkBlock_IsInvalidOperation(
        int excessOverRequest)
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount: 3 * 4096,
            includeBlockIndex: false);

        using var manifest = new MisreportingStream(
            bytes,
            misreportAtRead: int.MaxValue,
            excessOverRequest);

        await using ManifestReader reader =
            await ManifestReader.OpenAsync(manifest).WaitAsync(HangGuard);

        // OpenAsync leaves the first CBLK header and the start of its payload in
        // the reader's read-ahead buffer; the payload is larger than that
        // buffer, so the next stream read fetches the rest of the chunk block.
        int misreportAt = manifest.Reads + 1;
        manifest.MisreportAtRead = misreportAt;

        InvalidOperationException exception =
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => reader.ReadAsync(new ChunkInfo[16])
                    .AsTask()
                    .WaitAsync(HangGuard));

        Assert.Contains("Stream.ReadAsync", exception.Message, StringComparison.Ordinal);
        Assert.Equal(misreportAt, manifest.Reads);
    }

    [Theory]
    [MemberData(nameof(ViolatingCounts))]
    public async Task VerifyManifestAsync_ViolatingEndOfStreamProbe_IsNotReportedAsTrailingBytes(
        int excessOverRequest)
    {
        byte[] bytes = await CsmBytes.CreateAsync(64 * 1024);

        // Serve every CSM byte correctly, then misreport the read that probes
        // for end of stream after the TRAILER.
        using var manifest = new MisreportingStream(
            bytes,
            misreportAtRead: int.MaxValue,
            excessOverRequest,
            misreportAtEndOfStream: true);

        InvalidOperationException exception =
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => ChunkManifest.VerifyManifestAsync(manifest)
                    .WaitAsync(HangGuard));

        Assert.Contains("Stream.ReadAsync", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Serves <c>data</c> faithfully except for one read, which reports a count
    /// outside the Stream contract.
    /// </summary>
    private sealed class MisreportingStream(
        byte[] data,
        int misreportAtRead,
        int excessOverRequest,
        bool misreportAtEndOfStream = false) : Stream
    {
        private int _position;

        internal int MisreportAtRead { get; set; } = misreportAtRead;

        internal int Reads { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            Reads++;

            bool atEnd = _position == data.Length;
            if (Reads == MisreportAtRead || (misreportAtEndOfStream && atEnd))
            {
                return ValueTask.FromResult(
                    excessOverRequest < 0
                        ? excessOverRequest
                        : buffer.Length + excessOverRequest);
            }

            int count = Math.Min(buffer.Length, data.Length - _position);
            data.AsSpan(_position, count).CopyTo(buffer.Span);
            _position += count;
            return ValueTask.FromResult(count);
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
