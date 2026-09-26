using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Chunking;

internal delegate ValueTask ChunkKernelSink(
    ChunkKernelChunk chunk,
    ReadOnlyMemory<byte> content,
    CancellationToken cancellationToken);

/// <summary>
/// Optional measurement counters for the <c>ChunkingKernel.ScanAsync</c> overload that takes them.
/// Updated once per scanned span, never per byte.
/// </summary>
internal sealed class ChunkingKernelCounters
{
    /// <summary>
    /// Bytes moved inside the kernel buffer: the pending chunk prefix moved to the
    /// front when the buffer end is reached. Bytes read from the source are not counted.
    /// </summary>
    internal long BytesCopied { get; set; }
}

internal static class ChunkingKernel
{
    internal const int IoBufferSize = 64 * 1024;

    internal static ValueTask ScanAsync(
        Stream source,
        ChunkingKernelProfile profile,
        HashSuiteId hashSuite,
        ChunkKernelSink sink,
        CancellationToken cancellationToken = default) =>
        ScanAsync(source, profile, hashSuite, sink, counters: null, cancellationToken);

    internal static async ValueTask ScanAsync(
        Stream source,
        ChunkingKernelProfile profile,
        HashSuiteId hashSuite,
        ChunkKernelSink sink,
        ChunkingKernelCounters? counters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(sink);

        if (!source.CanRead)
        {
            throw new ArgumentException("Source stream must be readable.", nameof(source));
        }

        int chunkCapacity = profile.Maximum;
        if (chunkCapacity <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(profile),
                "Chunking profile maximum must be positive.");
        }

        // One pooled buffer holds the pending chunk followed by bytes read but
        // not yet scanned. Reads land directly after the pending data, so a
        // chunk is hashed and handed to the sink where it was read; only the
        // pending prefix is moved to the front when fewer than one read's worth
        // of space is left (A1-F05). A pending chunk is always shorter than the
        // profile maximum, so a buffer of at least that size always has room.
        // Small profiles get two read buffers' worth, so several chunks share a
        // buffer and reads stay at the full read size instead of shrinking to
        // the space left after each cut.
        int bufferCapacity = Math.Max(chunkCapacity, 2 * IoBufferSize);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferCapacity);
        const int readSize = IoBufferSize;

        try
        {
            var boundaryState = new ChunkBoundaryState(profile);
            int chunkStart = 0;
            int scanned = 0;
            int filled = 0;
            long chunkOffset = 0;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (bufferCapacity - filled < readSize && chunkStart > 0)
                {
                    int pending = filled - chunkStart;
                    buffer.AsSpan(chunkStart, pending).CopyTo(buffer);

                    if (counters is not null)
                    {
                        counters.BytesCopied += pending;
                    }

                    chunkStart = 0;
                    scanned = pending;
                    filled = pending;
                }

                int requested = Math.Min(readSize, bufferCapacity - filled);
                if (requested == 0)
                {
                    // A zero-length read would look like EOF and truncate silently.
                    throw new InvalidOperationException(
                        "Pending chunk filled the kernel buffer without a boundary.");
                }

                int read = await source
                    .ReadAsync(
                        buffer.AsMemory(filled, requested),
                        cancellationToken)
                    .ConfigureAwait(false);

                // A count outside 0..requested violates the Stream contract. A
                // negative count would otherwise loop forever and an oversized
                // one would read past the bytes actually produced.
                if ((uint)read > (uint)requested)
                {
                    throw new InvalidOperationException(
                        $"The source stream returned {read} bytes for a {requested}-byte read; Stream.ReadAsync must return a count from 0 to the buffer length.");
                }

                if (read == 0)
                {
                    break;
                }

                filled += read;

                while (scanned < filled)
                {
                    ChunkBoundaryScanResult result =
                        boundaryState.Scan(buffer.AsSpan(scanned, filled - scanned));
                    scanned += result.Consumed;

                    if (!result.HasBoundary)
                    {
                        continue;
                    }

                    int payloadLength = scanned - chunkStart;
                    if (payloadLength != result.CompletedChunkLength)
                    {
                        throw new InvalidOperationException(
                            "Boundary state and payload accumulation diverged.");
                    }

                    await EmitAsync(
                        buffer,
                        chunkStart,
                        payloadLength,
                        chunkOffset,
                        hashSuite,
                        sink,
                        cancellationToken).ConfigureAwait(false);

                    chunkOffset = checked(chunkOffset + payloadLength);
                    chunkStart = scanned;
                }
            }

            int finalLength = boundaryState.Finish();
            if (finalLength != filled - chunkStart)
            {
                throw new InvalidOperationException(
                    "Boundary state and payload accumulation diverged at EOF.");
            }

            if (finalLength != 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                await EmitAsync(
                    buffer,
                    chunkStart,
                    finalLength,
                    chunkOffset,
                    hashSuite,
                    sink,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static ValueTask EmitAsync(
        byte[] buffer,
        int start,
        int length,
        long offset,
        HashSuiteId hashSuite,
        ChunkKernelSink sink,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Hash256 hash = HashSuiteHasher.Hash(hashSuite, buffer.AsSpan(start, length));
        cancellationToken.ThrowIfCancellationRequested();

        var chunk = new ChunkKernelChunk(offset, length, new ChunkId(hash));
        return sink(chunk, buffer.AsMemory(start, length), cancellationToken);
    }
}
