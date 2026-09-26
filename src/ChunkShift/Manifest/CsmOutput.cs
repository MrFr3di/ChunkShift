using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Manifest;

internal sealed class CsmOutput : IDisposable
{
    private readonly Stream _destination;
    private readonly HashSuiteIncrementalHasher _physicalHasher;
    private bool _digestFinalized;
    private bool _disposed;

    internal CsmOutput(Stream destination, HashSuiteId hashSuite)
    {
        ArgumentNullException.ThrowIfNull(destination);

        if (!destination.CanWrite)
        {
            throw new ArgumentException(
                "CSM destination stream must be writable.",
                nameof(destination));
        }

        _destination = destination;
        _physicalHasher = HashSuiteIncrementalHasher.Create(hashSuite);
    }

    internal ulong Offset { get; private set; }

    internal async ValueTask WriteAsync(
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        ThrowIfWritable();

        if (bytes.IsEmpty)
        {
            return;
        }

        // Observe cancellation here rather than relying on the caller's
        // stream: Stream.WriteAsync implementations may ignore the token.
        cancellationToken.ThrowIfCancellationRequested();

        _physicalHasher.Append(bytes.Span);
        await _destination.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        Offset = checked(Offset + (uint)bytes.Length);
    }

    internal Hash256 FinalizePhysicalDigest()
    {
        ThrowIfWritable();
        _digestFinalized = true;
        return _physicalHasher.FinalizeHash();
    }

    internal async ValueTask WriteTrailerAsync(
        ReadOnlyMemory<byte> trailer,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_digestFinalized)
        {
            throw new InvalidOperationException(
                "The physical digest must be finalized before the CSM trailer is written.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        await _destination.WriteAsync(trailer, cancellationToken).ConfigureAwait(false);
        Offset = checked(Offset + (uint)trailer.Length);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _physicalHasher.Dispose();
    }

    private void ThrowIfWritable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_digestFinalized)
        {
            throw new InvalidOperationException(
                "CSM physical bytes cannot be hashed after digest finalization.");
        }
    }
}
