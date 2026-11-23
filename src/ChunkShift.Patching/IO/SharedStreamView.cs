namespace ChunkShift.Patching.IO;

/// <summary>
/// Read-only view with a position of its own over a readable, seekable stream
/// that other views of the same gate share.
/// </summary>
/// <remarks>
/// Every read takes the gate, positions the inner stream at the view's
/// position, reads once and releases the gate, so two tasks may read one
/// stream concurrently, each through its own view. The gate is held only for
/// that single read, never while the caller waits for anything else. Seeking
/// only moves the view's position. The inner stream and the gate are never
/// disposed.
/// </remarks>
internal sealed class SharedStreamView : Stream
{
    private const string InvalidReadCountMessage =
        "The inner stream returned a byte count outside the Stream contract.";

    private readonly Stream _inner;
    private readonly SemaphoreSlim _gate;
    private long _position;

    /// <summary>
    /// Creates a view positioned at <paramref name="position"/>. Callers create
    /// every view before any of them is read, because reading the inner
    /// stream's position here would race with another view's read.
    /// </summary>
    internal SharedStreamView(Stream inner, SemaphoreSlim gate, long position)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(gate);

        if (!inner.CanRead || !inner.CanSeek)
        {
            throw new ArgumentException(
                "A shared view requires a readable and seekable inner stream.",
                nameof(inner));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(position);

        _inner = inner;
        _gate = gate;
        _position = position;
    }

    public override bool CanRead => true;

    public override bool CanSeek => true;

    public override bool CanWrite => false;

    public override long Length => _inner.Length;

    public override long Position
    {
        get => _position;
        set => Seek(value, SeekOrigin.Begin);
    }

    public override int Read(Span<byte> buffer)
    {
        _gate.Wait();

        try
        {
            _inner.Position = _position;
            int read = _inner.Read(buffer);
            Advance(read, buffer.Length);
            return read;
        }
        finally
        {
            _gate.Release();
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        return Read(buffer.AsSpan(offset, count));
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            _inner.Position = _position;
            int read = await _inner
                .ReadAsync(buffer, cancellationToken)
                .ConfigureAwait(false);
            Advance(read, buffer.Length);
            return read;
        }
        finally
        {
            _gate.Release();
        }
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("A shared view is read-only.");

    public override void SetLength(long value) =>
        throw new NotSupportedException("A shared view is read-only.");

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        long position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => checked(_position + offset),
            SeekOrigin.End => checked(_inner.Length + offset),
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };

        ArgumentOutOfRangeException.ThrowIfNegative(position, nameof(offset));
        _position = position;
        return position;
    }

    private void Advance(int read, int requested)
    {
        if ((uint)read > (uint)requested)
        {
            throw new InvalidOperationException(InvalidReadCountMessage);
        }

        _position = checked(_position + read);
    }
}
