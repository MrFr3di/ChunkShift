using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Manifest;

internal sealed class CsmInput : IDisposable
{
    // Small sections (PREAMBLE, headers, CORE, CEND, BIDX entries, FOOT,
    // TRAILER) are served from one bounded read-ahead buffer instead of one
    // source read each; payloads at least this large are read straight into
    // the caller's destination. It also backs skips and replaces the former
    // 16 KiB skip buffer. The size is a trade-off: bytes read ahead of a CBLK
    // payload are copied twice, which cost measurable time on free-read
    // sources at 16 KiB but not at 4 KiB, while the small sections of typical
    // manifests still fit one fill.
    // BufferedStream is not used: every source read must still pass
    // ValidateReadCount and observe the token, and the caller's stream must
    // not be wrapped or disposed.
    internal const int ReadAheadSize = 4 * 1024;
    private const string TrailingBytesMessage =
        "Bytes are present after the fixed CSM trailer.";
    private const int MaximumDeferredHashPrefix = 512;

    private readonly Stream _source;
    private readonly long _startPosition = -1;
    private readonly byte[] _readAhead = new byte[ReadAheadSize];
    private int _readAheadStart;
    private int _readAheadEnd;

    // Bytes taken from the source, including read-ahead not yet consumed.
    private ulong _sourceBytesRead;
    private readonly byte[] _deferredPrefix = new byte[MaximumDeferredHashPrefix];
    private int _deferredPrefixLength;
    private HashSuiteIncrementalHasher? _physicalHasher;
    private bool _digestFinalized;
    private bool _disposed;

    internal CsmInput(Stream source)
    {
        ArgumentNullException.ThrowIfNull(source);

        if (!source.CanRead)
        {
            throw new ArgumentException(
                "CSM input stream must be readable.",
                nameof(source));
        }

        _source = source;

        // Remaining bytes are derived from this start plus the bytes this
        // input consumed, not from a later Position read, so a stream whose
        // Position does not track what it returned cannot move the bound.
        if (source.CanSeek)
        {
            try
            {
                _startPosition = source.Position;
            }
            catch (NotSupportedException)
            {
                _startPosition = -1;
            }
        }
    }

    internal ulong Offset { get; private set; }

    internal void EnsurePayloadAvailable(ulong payloadLength)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_startPosition < 0 || !_source.CanSeek)
        {
            return;
        }

        long length;
        try
        {
            length = _source.Length;
        }
        catch (NotSupportedException)
        {
            return;
        }

        // Compare the reported length with everything taken from the source,
        // read-ahead included, so a source that returns more bytes than its
        // Length is caught as soon as it does; the remaining-bytes bound
        // below still counts only what the parser consumed.
        ulong consumedEnd = checked((ulong)_startPosition + Offset);
        ulong readEnd = checked((ulong)_startPosition + _sourceBytesRead);
        if (length < 0 || (ulong)length < readEnd)
        {
            throw new InvalidDataException(
                "CSM stream reported a length shorter than the bytes already read.");
        }

        ulong remaining = (ulong)length - consumedEnd;
        if (payloadLength > remaining)
        {
            throw new InvalidDataException(
                "CSM section PayloadLength exceeds the known remaining physical bytes.");
        }
    }

    internal void SetHashSuite(HashSuiteId hashSuite)
    {
        ThrowIfActive();

        if (_physicalHasher is not null)
        {
            throw new InvalidOperationException(
                "The CSM physical hash suite has already been selected.");
        }

        _physicalHasher = HashSuiteIncrementalHasher.Create(hashSuite);

        if (_deferredPrefixLength != 0)
        {
            _physicalHasher.Append(
                _deferredPrefix.AsSpan(0, _deferredPrefixLength));
            _deferredPrefixLength = 0;
        }
    }

    internal ValueTask ReadExactlyAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        ThrowIfActive();

        return ReadExactlyCoreAsync(
            destination,
            hashed: true,
            cancellationToken);
    }

    internal async ValueTask SkipExactlyAsync(
        ulong length,
        CancellationToken cancellationToken)
    {
        ThrowIfActive();

        ulong remaining = length;
        while (remaining != 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_readAheadStart == _readAheadEnd)
            {
                await FillReadAheadAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            int count = (int)Math.Min(
                (ulong)(_readAheadEnd - _readAheadStart),
                remaining);

            _ = ConsumeReadAhead(count, hashed: true);
            remaining -= (uint)count;
        }
    }

    internal Hash256 FinalizePhysicalDigest()
    {
        ThrowIfActive();

        if (_physicalHasher is null)
        {
            throw new InvalidOperationException(
                "Cannot finalize the CSM physical digest before CORE selects a HashSuite.");
        }

        _digestFinalized = true;
        return _physicalHasher.FinalizeHash();
    }

    internal ValueTask ReadExactlyUnhashedAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_digestFinalized)
        {
            throw new InvalidOperationException(
                "Unhashed CSM reads are permitted only after physical digest finalization.");
        }

        return ReadExactlyCoreAsync(
            destination,
            hashed: false,
            cancellationToken);
    }

    internal async ValueTask EnsureEofAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        if (_readAheadStart != _readAheadEnd)
        {
            throw new InvalidDataException(TrailingBytesMessage);
        }

        int read = await _source
            .ReadAsync(_readAhead.AsMemory(0, 1), cancellationToken)
            .ConfigureAwait(false);

        ValidateReadCount(read, 1);

        if (read != 0)
        {
            throw new InvalidDataException(TrailingBytesMessage);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _physicalHasher?.Dispose();
    }

    /// <summary>
    /// Rejects a count outside 0..requested. Such a count violates the Stream
    /// contract; accepting it would slice past the bytes actually produced or
    /// misreport a broken source as malformed CSM data.
    /// </summary>
    private static void ValidateReadCount(int read, int requested)
    {
        if ((uint)read > (uint)requested)
        {
            throw new InvalidOperationException(
                $"The manifest stream returned {read} bytes for a {requested}-byte read; Stream.ReadAsync must return a count from 0 to the buffer length.");
        }
    }

    /// <summary>
    /// Delivers exactly <paramref name="destination"/>.Length bytes, first from
    /// the read-ahead buffer, then straight from the source when the rest is at
    /// least a buffer long, otherwise by refilling the buffer. Only delivered
    /// bytes are hashed and counted in <see cref="Offset"/>; bytes read ahead
    /// are not consumed until the parser asks for them.
    /// </summary>
    private async ValueTask ReadExactlyCoreAsync(
        Memory<byte> destination,
        bool hashed,
        CancellationToken cancellationToken)
    {
        int completed = 0;
        while (completed < destination.Length)
        {
            // Observe cancellation here rather than relying on the caller's
            // stream: Stream.ReadAsync implementations may ignore the token,
            // and buffered bytes need no stream call at all.
            cancellationToken.ThrowIfCancellationRequested();

            int remaining = destination.Length - completed;

            if (_readAheadStart != _readAheadEnd)
            {
                int count = Math.Min(
                    remaining,
                    _readAheadEnd - _readAheadStart);

                ConsumeReadAhead(count, hashed)
                    .CopyTo(destination.Span.Slice(completed, count));

                completed += count;
                continue;
            }

            if (remaining < _readAhead.Length)
            {
                await FillReadAheadAsync(cancellationToken)
                    .ConfigureAwait(false);
                continue;
            }

            int read = await _source
                .ReadAsync(destination[completed..], cancellationToken)
                .ConfigureAwait(false);

            ValidateReadCount(read, remaining);

            if (read == 0)
            {
                throw new InvalidDataException(
                    $"Unexpected EOF at physical offset {Offset}.");
            }

            _sourceBytesRead = checked(_sourceBytesRead + (uint)read);

            if (hashed)
            {
                AppendPhysical(destination.Span.Slice(completed, read));
            }

            completed += read;
            Offset = checked(Offset + (uint)read);
        }
    }

    /// <summary>Refills the empty read-ahead buffer with at least one byte.</summary>
    private async ValueTask FillReadAheadAsync(
        CancellationToken cancellationToken)
    {
        int read = await _source
            .ReadAsync(_readAhead, cancellationToken)
            .ConfigureAwait(false);

        ValidateReadCount(read, _readAhead.Length);

        if (read == 0)
        {
            throw new InvalidDataException(
                $"Unexpected EOF at physical offset {Offset}.");
        }

        _sourceBytesRead = checked(_sourceBytesRead + (uint)read);
        _readAheadStart = 0;
        _readAheadEnd = read;
    }

    /// <summary>
    /// Consumes <paramref name="count"/> buffered bytes: hashes them if
    /// requested, advances <see cref="Offset"/>, and returns them. The span is
    /// valid until the next refill.
    /// </summary>
    private ReadOnlySpan<byte> ConsumeReadAhead(int count, bool hashed)
    {
        ReadOnlySpan<byte> bytes =
            _readAhead.AsSpan(_readAheadStart, count);

        if (hashed)
        {
            AppendPhysical(bytes);
        }

        _readAheadStart += count;
        Offset = checked(Offset + (uint)count);
        return bytes;
    }

    private void AppendPhysical(ReadOnlySpan<byte> bytes)
    {
        if (_physicalHasher is not null)
        {
            _physicalHasher.Append(bytes);
            return;
        }

        int nextLength = checked(_deferredPrefixLength + bytes.Length);
        if (nextLength > _deferredPrefix.Length)
        {
            throw new InvalidDataException(
                "CSM CORE prefix exceeded the bounded pre-HashSuite staging area.");
        }

        bytes.CopyTo(_deferredPrefix.AsSpan(_deferredPrefixLength));
        _deferredPrefixLength = nextLength;
    }

    private void ThrowIfActive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_digestFinalized)
        {
            throw new InvalidOperationException(
                "The CSM physical digest has already been finalized.");
        }
    }
}
