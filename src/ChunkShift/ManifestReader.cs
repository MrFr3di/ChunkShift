using ChunkShift.Manifest;

namespace ChunkShift;

/// <summary>
/// Reads logical chunk entries from a CSM manifest with bounded buffering.
/// </summary>
/// <remarks>
/// <para>
/// The caller owns the source stream. Disposing the reader never disposes it.
/// While the reader is active, the caller must not concurrently read, seek,
/// rewind, replace, or dispose that same stream.
/// </para>
/// <para>
/// Each CBLK is fully buffered and CRC-validated before any entry from that
/// block is returned. Integrity mismatches are reported through
/// <see cref="VerificationResult"/> rather than format exceptions.
/// </para>
/// <para>
/// Reading is fail-closed: once a CBLK fails its CRC-32C check, no further
/// entries are returned, including entries from later intact blocks. The
/// reader still consumes and validates the rest of the representation, so
/// <see cref="VerificationResult"/> reports the failure and the totals that
/// were observed.
/// </para>
/// <para>
/// Entries are provisional until the end of the representation. Block CRCs
/// are checked before a block's entries are returned, but the logical
/// <c>ManifestId</c>, <c>FileDigest</c> and totals are verified only after the
/// last block, and <see cref="VerificationResult"/> stays null until
/// <see cref="ReadAsync"/> returns zero. Do not act irreversibly on entries
/// until <see cref="VerificationResult"/> reports a valid manifest.
/// </para>
/// <para>
/// Reads are sequential and must not overlap. Cancellation or another
/// exception during a read leaves this reader unusable because the underlying
/// stream position may already have advanced.
/// </para>
/// <para>
/// The reader buffers a bounded amount of the manifest stream ahead of what it
/// has parsed, so until <see cref="ReadAsync"/> returns zero the stream
/// position does not correspond to the entries returned so far. Do not use
/// the stream while the reader is open.
/// </para>
/// </remarks>
public sealed class ManifestReader : IDisposable, IAsyncDisposable
{
    private const int InternalBatchSize = 256;

    private readonly CsmStreamReaderCore _core;
    private readonly CsmChunkEntry[] _buffer =
        new CsmChunkEntry[InternalBatchSize];

    private bool _disposed;
    private bool _faulted;
    private int _readInProgress;

    private ManifestReader(CsmStreamReaderCore core)
    {
        _core = core;
    }

    /// <summary>
    /// Gets whether the complete CSM representation has been consumed and verified.
    /// </summary>
    public bool IsCompleted => _core.IsCompleted;

    /// <summary>
    /// Gets the final verification result after <see cref="ReadAsync"/> returns zero;
    /// otherwise null.
    /// </summary>
    /// <remarks>
    /// Uses the same manifest-only rules as
    /// <see cref="ChunkManifest.VerifyManifestAsync(Stream, CancellationToken)"/>,
    /// including <see cref="ManifestVerificationFailure.ProfileSemantics"/> for a known
    /// ProfileId with a different fingerprint.
    /// </remarks>
    public ManifestVerificationResult? VerificationResult { get; private set; }

    /// <summary>
    /// Opens a forward reader over a caller-owned CSM stream.
    /// </summary>
    /// <param name="manifest">Readable CSM stream owned by the caller.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>A reader positioned before the first logical chunk entry.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="manifest"/> is <see langword="null"/>. Thrown by this call, not by
    /// the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="manifest"/> is not readable. Thrown by this call, not by the
    /// returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The CSM preamble or CORE section is malformed.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The manifest declares a hash suite this build does not support.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before the reader is open.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="manifest"/> returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<ManifestReader> OpenAsync(
        Stream manifest,
        CancellationToken cancellationToken = default)
    {
        StreamArguments.ThrowIfNotReadable(manifest, nameof(manifest));

        return OpenCoreAsync(manifest, cancellationToken);
    }

    /// <summary>
    /// Reads the next ordered logical chunk entries into <paramref name="destination"/>.
    /// Returns zero only after the CSM representation has been fully consumed.
    /// </summary>
    /// <param name="destination">Buffer that receives the next entries; must not be empty.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The number of entries written, or zero at the end of the representation.</returns>
    /// <remarks>
    /// A token that is already cancelled when the call starts throws
    /// <see cref="OperationCanceledException"/> without consuming anything, and
    /// the reader stays usable. Cancellation observed after the read has started
    /// leaves the reader unusable.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">
    /// The reader has been disposed. Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A previous read failed or was cancelled (thrown by this call), another read is
    /// still in progress, or the stream returned a byte count outside the
    /// <see cref="Stream"/> contract.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="destination"/> is empty. Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The CSM representation is malformed.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The manifest contains a chunk length above <see cref="int.MaxValue"/> or a content
    /// length above <see cref="long.MaxValue"/>, which this API cannot represent.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed.
    /// </exception>
    public ValueTask<int> ReadAsync(
        Memory<ChunkInfo> destination,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_faulted)
        {
            throw new InvalidOperationException(
                "The ManifestReader cannot continue after a failed or cancelled read.");
        }

        if (destination.IsEmpty)
        {
            throw new ArgumentException(
                "Destination must contain at least one entry.",
                nameof(destination));
        }

        return ReadCoreAsync(destination, cancellationToken);
    }

    private static async Task<ManifestReader> OpenCoreAsync(
        Stream manifest,
        CancellationToken cancellationToken)
    {
        CsmStreamReaderCore core =
            await CsmStreamReaderCore.OpenAsync(
                manifest,
                cancellationToken).ConfigureAwait(false);

        return new ManifestReader(core);
    }

    private async ValueTask<int> ReadCoreAsync(
        Memory<ChunkInfo> destination,
        CancellationToken cancellationToken)
    {
        // Checked before the read starts, so a token that is already cancelled
        // neither consumes entries nor leaves the reader unusable, even when
        // the next entries are already buffered and need no I/O.
        cancellationToken.ThrowIfCancellationRequested();

        if (Interlocked.Exchange(ref _readInProgress, 1) != 0)
        {
            throw new InvalidOperationException(
                "Concurrent ManifestReader reads are not supported.");
        }

        try
        {
            if (_core.IsCompleted)
            {
                EnsureVerificationResult();
                return 0;
            }

            int written = 0;

            while (written < destination.Length)
            {
                int requested = Math.Min(
                    _buffer.Length,
                    destination.Length - written);

                int count = await _core.ReadAsync(
                    _buffer.AsMemory(0, requested),
                    cancellationToken).ConfigureAwait(false);

                if (count == 0)
                {
                    EnsureVerificationResult();
                    break;
                }

                CopyEntries(
                    _buffer,
                    count,
                    destination.Slice(written, count));

                written += count;
            }

            return written;
        }
        catch
        {
            _faulted = true;
            throw;
        }
        finally
        {
            Volatile.Write(ref _readInProgress, 0);
        }
    }

    /// <summary>
    /// Releases the reader's internal buffers and hashing state. The caller-owned
    /// stream is not disposed.
    /// </summary>
    /// <remarks>
    /// Do not dispose the reader while a <see cref="ReadAsync"/> call is still
    /// pending; await or cancel it first. Disposal is not synchronized with an
    /// in-flight read.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _core.Dispose();
    }

    /// <inheritdoc cref="Dispose" />
    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private void EnsureVerificationResult()
    {
        if (VerificationResult is not null)
        {
            return;
        }

        VerificationResult =
            ManifestResultMapper.ToVerificationResult(
                _core.Result);
    }

    private static void CopyEntries(
        CsmChunkEntry[] source,
        int count,
        Memory<ChunkInfo> destination)
    {
        for (int index = 0; index < count; index++)
        {
            CsmChunkEntry entry = source[index];
            destination.Span[index] =
                new ChunkInfo(
                    CsmParserMath.ToPublicInt64(entry.Index, "chunk index"),
                    CsmParserMath.ToPublicInt64(entry.Offset, "chunk offset"),
                    CsmParserMath.ToPublicInt32(entry.Length, "chunk length"),
                    entry.Id);
        }
    }
}
