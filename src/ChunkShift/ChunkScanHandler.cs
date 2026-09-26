namespace ChunkShift;

/// <summary>
/// Processes one chunk while its borrowed content buffer is valid.
/// </summary>
/// <param name="chunk">Metadata for the chunk being delivered.</param>
/// <param name="content">
/// Borrowed, read-only chunk bytes. The memory is valid only until the returned
/// <see cref="ValueTask"/> reaches its terminal state.
/// </param>
/// <param name="cancellationToken">The cooperative cancellation token for the scan.</param>
/// <returns>
/// An operation that completes when the consumer has finished using <paramref name="content"/>.
/// </returns>
/// <remarks>
/// The handler must not retain or use <paramref name="content"/> after the returned operation
/// completes unless it first copies the bytes into consumer-owned storage.
/// ChunkShift consumes the returned <see cref="ValueTask"/> exactly once.
/// </remarks>
public delegate ValueTask ChunkScanHandler(
    ChunkInfo chunk,
    ReadOnlyMemory<byte> content,
    CancellationToken cancellationToken);
