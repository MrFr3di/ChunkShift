using ChunkShift.Manifest;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// The seekable early rejection of an oversized PayloadLength (CSM-V1
/// §13) must be computed from the bytes the reader consumed, not from the
/// stream's Position, which a caller's adapter may not keep in step with what
/// it returned.
/// </summary>
public sealed class CsmPayloadAvailabilityTests
{
    private const string PayloadExceedsRemaining =
        "CSM section PayloadLength exceeds the known remaining physical bytes.";

    [Fact]
    public async Task PositionReportedAhead_DoesNotRejectAValidManifest()
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount: 4097,
            includeBlockIndex: true);

        // Position is right at the start but then reports twice the bytes
        // returned, so by the second CBLK it points past the end. Trusting it
        // would reject a valid manifest.
        var source = new DriftingPositionStream(
            new MemoryStream(bytes, writable: false),
            PositionDrift.Doubled);

        CsmReadResult result = await CsmReader.ReadAndVerifyAsync(source);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task PositionStuckAtStart_StillRejectsAnOversizedPayloadBeforeReadingIt()
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount: 4097,
            includeBlockIndex: false);

        // Keep the first CBLK header, drop its whole payload.
        int cblk = CsmBytes.FindSection(bytes, CsmFormat.ChunkBlock);
        int cut = CsmBytes.PayloadOffset(cblk);
        var storage = new MemoryStream(bytes.AsSpan(0, cut).ToArray(), writable: false);
        var source = new DriftingPositionStream(storage, PositionDrift.StuckAtStart);

        InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => CsmReader.ReadAndVerifyAsync(source));

        Assert.Equal(PayloadExceedsRemaining, exception.Message);
        Assert.Equal(cut, storage.Position);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StreamStartingMidFile_BoundsPayloadFromItsStartPosition(bool truncate)
    {
        byte[] manifest = await CsmBytes.CreateSyntheticAsync(
            entryCount: 4097,
            includeBlockIndex: true);
        int cblk = CsmBytes.FindSection(manifest, CsmFormat.ChunkBlock);
        int manifestLength = truncate ? CsmBytes.PayloadOffset(cblk) : manifest.Length;

        const int PrefixLength = 1000;
        byte[] container = new byte[PrefixLength + manifestLength];
        manifest.AsSpan(0, manifestLength).CopyTo(container.AsSpan(PrefixLength));
        var source = new MemoryStream(container, writable: false) { Position = PrefixLength };

        if (truncate)
        {
            InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => CsmReader.ReadAndVerifyAsync(source));
            Assert.Equal(PayloadExceedsRemaining, exception.Message);
        }
        else
        {
            CsmReadResult result = await CsmReader.ReadAndVerifyAsync(source);
            Assert.True(result.IsValid);
        }
    }

    private enum PositionDrift
    {
        Doubled,
        StuckAtStart,
    }

    /// <summary>
    /// A seekable adapter whose Position is correct before the first read and
    /// then stops matching the bytes it has returned; reads and Length are
    /// passed through unchanged.
    /// </summary>
    private sealed class DriftingPositionStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _start;
        private readonly PositionDrift _drift;

        internal DriftingPositionStream(Stream inner, PositionDrift drift)
        {
            _inner = inner;
            _start = inner.Position;
            _drift = drift;
        }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _drift == PositionDrift.StuckAtStart
                ? _start
                : _start + (2 * (_inner.Position - _start));
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            _inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(buffer, cancellationToken);

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
