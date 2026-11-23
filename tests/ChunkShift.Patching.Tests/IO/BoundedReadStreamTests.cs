using ChunkShift.Patching.IO;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.IO;

public sealed class BoundedReadStreamTests
{
    [Theory]
    [InlineData(false, 64)]
    [InlineData(true, 512)]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    public async Task Reads_ReturnExactlyTheWindowBytes(bool asynchronous, int bufferLength)
    {
        byte[] inner = CspBytes.CreateXorShiftBytes(4096, 0x1EAFu);
        byte[] expected = inner.AsSpan(1000, 2000).ToArray();
        using var stream = new MemoryStream(inner, writable: false);
        using var view = new BoundedReadStream(stream, 1000, 2000);

        var actual = new List<byte>();
        byte[] buffer = new byte[bufferLength];

        while (true)
        {
            int read = asynchronous
                ? await view.ReadAsync(buffer)
                : view.Read(buffer, 0, buffer.Length);

            if (read == 0)
            {
                break;
            }

            actual.AddRange(buffer.AsSpan(0, read).ToArray());
        }

        Assert.Equal(expected, actual);
        Assert.Equal(2000L, view.Length);
        Assert.Equal(2000L, view.Position);
        Assert.Equal(3000L, stream.Position);
    }

    [Fact]
    public void PositionAndSeek_AreWindowRelative()
    {
        using var stream = new MemoryStream(new byte[4096], writable: false);
        using var view = new BoundedReadStream(stream, 1000, 2000);

        Assert.Equal(2000L, view.Length);
        Assert.Equal(0L, view.Position);
        Assert.Equal(1000L, view.Seek(1000, SeekOrigin.Begin));
        Assert.Equal(1000L, view.Position);
        Assert.Equal(500L, view.Seek(500, SeekOrigin.Begin));
        Assert.Equal(600L, view.Seek(100, SeekOrigin.Current));
        Assert.Equal(1900L, view.Seek(-100, SeekOrigin.End));
        Assert.Equal(0L, view.Seek(-1900, SeekOrigin.Current));
        Assert.Equal(0L, view.Position);

        view.Position = 2000;
        Assert.Equal(2000L, view.Position);

        Assert.Throws<ArgumentOutOfRangeException>(() => view.Position = -1);
        Assert.Throws<ArgumentOutOfRangeException>(() => view.Position = 2001);
        Assert.Throws<ArgumentOutOfRangeException>(() => view.Seek(1, SeekOrigin.End));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => view.Seek(long.MinValue, SeekOrigin.Current));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => view.Seek(2001, SeekOrigin.Begin));
    }

    [Fact]
    public async Task CsmInsideALargerStream_ReadsThroughTheManifestReader()
    {
        byte[] csm = await CspBytes.CreateCsmAsync(HashSuiteIds.Blake3256V1, 512 * 1024);
        byte[] inner = new byte[1000 + csm.Length + 1000];
        inner.AsSpan().Fill(0xA5);
        csm.CopyTo(inner.AsSpan(1000));

        using var stream = new MemoryStream(inner, writable: false);
        using var view = new BoundedReadStream(stream, 1000, csm.Length);
        await using ManifestReader reader = await ManifestReader.OpenAsync(view);

        var batch = new ChunkInfo[16];
        long count = 0;

        while (true)
        {
            int read = await reader.ReadAsync(batch);

            if (read == 0)
            {
                break;
            }

            count += read;
        }

        Assert.True(reader.IsCompleted);
        Assert.NotNull(reader.VerificationResult);
        Assert.True(reader.VerificationResult.IsValid);
        Assert.Equal(csm.Length, reader.VerificationResult.Manifest.PhysicalLength);
        Assert.Equal(reader.VerificationResult.Manifest.ChunkCount, count);
    }

    [Fact]
    public void Constructor_RejectsInvalidInnerStreamsAndBounds()
    {
        using var readable = new MemoryStream([1, 2, 3], writable: false);
        using var nonSeekable = new ForwardOnlyReadStream([1, 2, 3]);
        using var nonReadable = new WriteOnlyStream(new MemoryStream());

        Assert.Throws<ArgumentNullException>(() => new BoundedReadStream(null!, 0, 1));
        Assert.Throws<ArgumentException>(() => new BoundedReadStream(nonReadable, 0, 1));
        Assert.Throws<ArgumentException>(() => new BoundedReadStream(nonSeekable, 0, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedReadStream(readable, -1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedReadStream(readable, 0, -1));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new BoundedReadStream(readable, long.MaxValue, 1));
    }

    [Fact]
    public void Dispose_DoesNotDisposeTheInnerStream()
    {
        using var storage = new MemoryStream(new byte[64], writable: false);
        using var inner = new DisposeTrackingStream(storage);
        var view = new BoundedReadStream(inner, 8, 16);

        view.Dispose();

        Assert.False(inner.Disposed);
        Assert.True(inner.CanRead);
    }

    [Fact]
    public void WritesAreNotSupported()
    {
        using var stream = new MemoryStream(new byte[64], writable: false);
        using var view = new BoundedReadStream(stream, 0, 32);

        Assert.False(view.CanWrite);
        Assert.True(view.CanRead);
        Assert.True(view.CanSeek);
        Assert.Throws<NotSupportedException>(() => view.Write([1], 0, 1));
        Assert.Throws<NotSupportedException>(() => view.SetLength(1));
        view.Flush();
    }

    [Fact]
    public async Task InnerStreamReportingOutsideTheStreamContract_Throws()
    {
        using var stream = new MemoryStream(new byte[64], writable: false);
        using var misreporting = new MisreportingReadStream(stream);
        using var view = new BoundedReadStream(misreporting, 0, 32);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => _ = await view.ReadAsync(new byte[8]));
        Assert.Throws<InvalidOperationException>(() => view.Read(new byte[8], 0, 8));
    }

    private sealed class MisreportingReadStream(Stream inner) : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => true;

        public override bool CanWrite => false;

        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            _ = inner.Read(buffer, offset, count);
            return count + 1;
        }

        public override int Read(Span<byte> buffer)
        {
            _ = inner.Read(buffer);
            return buffer.Length + 1;
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            _ = inner.Read(buffer.Span);
            return ValueTask.FromResult(buffer.Length + 1);
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) =>
            inner.Seek(offset, origin);

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
