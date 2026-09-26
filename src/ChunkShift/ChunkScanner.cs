using ChunkShift.Chunking;
using ChunkShift.Primitives;

namespace ChunkShift;

/// <summary>
/// Streams deterministic content chunks from an arbitrary readable <see cref="Stream"/>.
/// </summary>
/// <remarks>
/// <para>
/// The caller retains ownership of the source stream. ChunkShift never disposes it.
/// While a scan is active, the caller and handler must not concurrently read, seek, rewind,
/// replace, or dispose the same stream.
/// </para>
/// <para>
/// Delivery is ordered and non-concurrent. The scanner waits for each handler operation
/// before delivering the next chunk, providing natural backpressure.
/// </para>
/// <para>
/// Cancellation is cooperative. Once cancellation is observed, the scanner starts no new
/// read or callback. An already-running handler is not preempted and must observe the supplied
/// token itself when prompt cancellation is required.
/// </para>
/// <para>
/// A read that returns zero bytes is treated as the end of the source, as the
/// <see cref="Stream"/> contract defines. A stream that returns zero before its real
/// end therefore produces a shorter, internally consistent result for the bytes it did
/// return; ChunkShift cannot detect that contract violation.
/// </para>
/// <para>
/// ChunkShift may read ahead into bounded private buffers. After cancellation, handler failure,
/// or source I/O failure, the underlying stream position is therefore intentionally unspecified
/// relative to the last delivered chunk and the stream is never rewound.
/// </para>
/// </remarks>
public static class ChunkScanner
{
    /// <summary>
    /// Scans <paramref name="source"/> and invokes <paramref name="handler"/> once for every
    /// non-empty content chunk.
    /// </summary>
    /// <param name="source">The readable stream to scan from its current position through EOF.</param>
    /// <param name="handler">The ordered, non-concurrent chunk consumer.</param>
    /// <param name="options">Optional semantic profile and hash-suite selection.</param>
    /// <param name="cancellationToken">A cooperative cancellation token.</param>
    /// <returns>A task that represents the complete scan.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="source"/> or <paramref name="handler"/> is <see langword="null"/>.
    /// Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="source"/> is not readable. Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// An explicitly requested profile or hash suite is not supported by this build.
    /// Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before the scan completes.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="source"/> returned a negative byte count, or more bytes than
    /// requested, from <see cref="Stream.ReadAsync(Memory{byte}, CancellationToken)"/>.
    /// </exception>
    public static Task ScanAsync(
        Stream source,
        ChunkScanHandler handler,
        ChunkScanOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(handler);

        if (!source.CanRead)
        {
            throw new ArgumentException("Source stream must be readable.", nameof(source));
        }

        ChunkingKernelProfile profile =
            ChunkScanConfiguration.ResolveProfile(options?.ProfileId);
        HashSuiteId hashSuite =
            ChunkScanConfiguration.ResolveHashSuite(options?.HashSuite);

        var sink = new PublicChunkSink(handler);
        return ScanCoreAsync(source, profile, hashSuite, sink, cancellationToken);
    }

    private static async Task ScanCoreAsync(
        Stream source,
        ChunkingKernelProfile profile,
        HashSuiteId hashSuite,
        PublicChunkSink sink,
        CancellationToken cancellationToken)
    {
        await ChunkingKernel
            .ScanAsync(source, profile, hashSuite, sink.OnChunkAsync, cancellationToken)
            .ConfigureAwait(false);
    }

    private sealed class PublicChunkSink
    {
        private readonly ChunkScanHandler _handler;
        private long _index;

        internal PublicChunkSink(ChunkScanHandler handler)
        {
            _handler = handler;
        }

        internal ValueTask OnChunkAsync(
            ChunkKernelChunk chunk,
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken)
        {
            var info = new ChunkInfo(_index, chunk.Offset, chunk.Length, chunk.Id);
            _index = checked(_index + 1);
            return _handler(info, content, cancellationToken);
        }
    }
}
