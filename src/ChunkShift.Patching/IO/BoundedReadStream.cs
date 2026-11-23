namespace ChunkShift.Patching.IO;

/// <summary>
/// Read-only window over the byte range <c>[offset, offset + length)</c> of a
/// readable, seekable inner stream.
/// </summary>
/// <remarks>
/// Positions, seeks and reads are relative to the window, and the end of the
/// window reads as end of stream. That is how an embedded CSM section is handed
/// to Core's manifest reader, which must see end-of-stream exactly at the end of
/// the section. Every read repositions the inner stream and observes the
/// cancellation token before the inner read. The inner stream is never disposed.
/// </remarks>
internal sealed class BoundedReadStream : Stream
{
    private const string InvalidReadCountMessage =
        "The inner stream returned a byte count outside the Stream contract.";

    private readonly Stream _inner;
    private readonly long _offset;
    private readonly long _length;
    private long _position;

    internal BoundedReadStream(Stream inner, long offset, long length)
    {
        ArgumentNullException.ThrowIfNull(inner);

        if (!inner.CanRead)
        {
            throw new ArgumentException(
                "The bounded window requires a readable inner stream.",
                nameof(inner));
        }

        if (!inner.CanSeek)
        {
            throw new ArgumentException(
                "The bounded window requires a seekable inner stream.",
                nameof(inner));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        if (offset > long.MaxValue - length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                "The bounded window end overflows Int64.");
        }

        _inner = inner;
        _offset = offset;
        _length = length;
    }

    public override bool CanRead => true;

    public override bool CanSeek => true;

    public override bool CanWrite => false;

    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => Seek(value, SeekOrigin.Begin);
    }

    public override int Read(Span<byte> buffer) => ReadCore(buffer);

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        return ReadCore(buffer.AsSpan(offset, count));
    }

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ReadAsyncCore(buffer, cancellationToken);
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        cancellationToken.ThrowIfCancellationRequested();

        return ReadAsyncCore(buffer.AsMemory(offset, count), cancellationToken)
            .AsTask();
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("The bounded window is read-only.");

    public override void SetLength(long value) =>
        throw new NotSupportedException("The bounded window is read-only.");

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => AddPosition(_position, offset),
            SeekOrigin.End => AddPosition(_length, offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };

        if ((ulong)position > (ulong)_length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(offset),
                "The position lies outside the bounded window.");
        }

        _position = position;
        return position;
    }

    private static long AddPosition(long position, long offset)
    {
        try
        {
            return checked(position + offset);
        }
        catch (OverflowException)
        {
            throw new ArgumentOutOfRangeException(
                nameof(offset),
                "The position lies outside the bounded window.");
        }
    }

    private static void ValidateReadCount(int read, int requested)
    {
        if ((uint)read > (uint)requested)
        {
            throw new InvalidOperationException(InvalidReadCountMessage);
        }
    }

    private int ReadCore(Span<byte> buffer)
    {
        int requested = PrepareRead(buffer.Length);

        if (requested == 0)
        {
            return 0;
        }

        int read = _inner.Read(buffer[..requested]);
        ValidateReadCount(read, requested);
        _position = checked(_position + read);
        return read;
    }

    private async ValueTask<int> ReadAsyncCore(
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        int requested = PrepareRead(buffer.Length);

        if (requested == 0)
        {
            return 0;
        }

        int read = await _inner
            .ReadAsync(buffer[..requested], cancellationToken)
            .ConfigureAwait(false);

        ValidateReadCount(read, requested);
        _position = checked(_position + read);
        return read;
    }

    /// <summary>
    /// Positions the inner stream on the current window byte and returns how
    /// many bytes the window still allows the caller to request.
    /// </summary>
    private int PrepareRead(int bufferLength)
    {
        _inner.Position = checked(_offset + _position);

        return (int)Math.Min((long)bufferLength, _length - _position);
    }
}
