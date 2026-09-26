using ChunkShift.Chunking;
using ChunkShift.Manifest;

namespace ChunkShift;

/// <summary>
/// Creates and verifies ChunkShift CSM manifests over caller-owned streams.
/// </summary>
/// <remarks>
/// ChunkShift never disposes streams supplied to these operations. Cancellation,
/// malformed input, or I/O failure may leave stream positions advanced, including
/// past the point where the failure was detected, because manifest reads are
/// buffered ahead; operations do not rewind. When an operation accepts both content and manifest/destination,
/// those roles must use distinct <see cref="Stream"/> instances. Callers must not
/// concurrently read, write, seek, rewind, or dispose a stream while ChunkShift is
/// operating on it. A read returning zero bytes is treated as end of stream; a
/// stream whose <see cref="Stream.ReadAsync(Memory{byte}, CancellationToken)"/>
/// returns a count outside zero to the buffer length causes
/// <see cref="InvalidOperationException"/>.
/// </remarks>
public static class ChunkManifest
{
    /// <summary>
    /// Creates a forward-only CSM manifest for <paramref name="content"/>.
    /// </summary>
    /// <param name="content">Readable source content owned by the caller.</param>
    /// <param name="destination">Writable CSM destination owned by the caller.</param>
    /// <param name="options">Optional semantic/physical manifest settings.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>Information about the emitted logical and physical manifest.</returns>
    /// <remarks>
    /// The manifest is written forward while <paramref name="content"/> is read.
    /// If the operation fails or is cancelled, the bytes already written remain in
    /// <paramref name="destination"/> as an incomplete CSM that fails verification;
    /// ChunkShift does not truncate or roll back a caller-owned destination. To
    /// publish a manifest atomically, write it to a temporary file and move it into
    /// place only after this method completes.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="content"/> or <paramref name="destination"/> is <see langword="null"/>.
    /// Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="content"/> is not readable, <paramref name="destination"/> is not
    /// writable, or both are the same <see cref="Stream"/> instance. Thrown by this call,
    /// not by the returned task.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// <paramref name="options"/> selects a profile or hash suite this build does not
    /// support. Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before the manifest is complete.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A stream returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<ManifestInfo> CreateAsync(
        Stream content,
        Stream destination,
        ManifestCreationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        StreamArguments.ThrowIfNotReadable(content, nameof(content));
        StreamArguments.ThrowIfNotWritable(destination, nameof(destination));
        StreamArguments.ThrowIfSameInstance(content, destination, nameof(destination));

        // Resolved here only to reject unsupported selections at the call site.
        _ = ChunkScanConfiguration.ResolveProfileRegistration(options?.ProfileId);
        _ = ChunkScanConfiguration.ResolveHashSuite(options?.HashSuite);

        return CreateCoreAsync(content, destination, options, cancellationToken);
    }

    /// <summary>
    /// Verifies the structural, block, logical, and physical integrity of a CSM manifest.
    /// </summary>
    /// <param name="manifest">Readable CSM stream owned by the caller.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The manifest description and any integrity mismatches.</returns>
    /// <remarks>
    /// <para>
    /// Integrity mismatches are returned in <see cref="ManifestVerificationResult"/>.
    /// Malformed format, unsupported required semantics, I/O failure, and cancellation
    /// use normal .NET exceptions.
    /// </para>
    /// <para>
    /// The content is not read, so the chunking profile is not needed: a ProfileId this
    /// build does not know is accepted. A known ProfileId whose recorded fingerprint
    /// differs from this build's semantics is reported as
    /// <see cref="ManifestVerificationFailure.ProfileSemantics"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="manifest"/> is <see langword="null"/>. Thrown by this call, not by
    /// the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="manifest"/> is not readable. Thrown by this call, not by the
    /// returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// <paramref name="manifest"/> is not a well-formed CSM representation.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The manifest declares a hash suite this build does not support, or a chunk length
    /// above <see cref="int.MaxValue"/> or a content length above <see cref="long.MaxValue"/>,
    /// which this API cannot represent.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before verification completes.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="manifest"/> returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<ManifestVerificationResult> VerifyManifestAsync(
        Stream manifest,
        CancellationToken cancellationToken = default)
    {
        StreamArguments.ThrowIfNotReadable(manifest, nameof(manifest));

        return VerifyManifestCoreAsync(manifest, cancellationToken);
    }

    /// <summary>
    /// Verifies both a CSM manifest and the supplied source content against its logical identity.
    /// </summary>
    /// <param name="content">Readable source content owned by the caller.</param>
    /// <param name="manifest">Readable CSM stream owned by the caller.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The manifest description and any integrity, profile, or content mismatches.</returns>
    /// <remarks>
    /// <para>
    /// Both streams remain owned by the caller. Content/profile/integrity mismatches
    /// are result flags rather than exceptions.
    /// </para>
    /// <para>
    /// Verifying content means chunking it with the manifest's profile, so a ProfileId
    /// this build does not know throws <see cref="NotSupportedException"/>. A known
    /// ProfileId whose recorded fingerprint differs is reported as
    /// <see cref="ManifestVerificationFailure.ProfileSemantics"/>, and the content is
    /// then not chunked.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="content"/> or <paramref name="manifest"/> is <see langword="null"/>.
    /// Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="content"/> or <paramref name="manifest"/> is not readable, or both
    /// are the same <see cref="Stream"/> instance. Thrown by this call, not by the returned
    /// task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// <paramref name="manifest"/> is not a well-formed CSM representation.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The manifest declares a hash suite or chunking profile this build does not support,
    /// or a chunk length above <see cref="int.MaxValue"/> or a content length above
    /// <see cref="long.MaxValue"/>, which this API cannot represent.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before verification completes.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A stream returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<ManifestVerificationResult> VerifyAsync(
        Stream content,
        Stream manifest,
        CancellationToken cancellationToken = default)
    {
        StreamArguments.ThrowIfNotReadable(content, nameof(content));
        StreamArguments.ThrowIfNotReadable(manifest, nameof(manifest));
        StreamArguments.ThrowIfSameInstance(content, manifest, nameof(manifest));

        return VerifyCoreAsync(content, manifest, cancellationToken);
    }

    private static async Task<ManifestInfo> CreateCoreAsync(
        Stream content,
        Stream destination,
        ManifestCreationOptions? options,
        CancellationToken cancellationToken)
    {
        ChunkScanOptions? scanOptions = options is null
            ? null
            : new ChunkScanOptions
            {
                ProfileId = options.ProfileId,
                HashSuite = options.HashSuite,
            };

        CsmWriteResult result = await CsmWriter.CreateAsync(
            content,
            destination,
            scanOptions,
            options?.IncludeBlockIndex ?? false,
            cancellationToken).ConfigureAwait(false);

        return ManifestResultMapper.FromWriteResult(result);
    }

    private static async Task<ManifestVerificationResult> VerifyManifestCoreAsync(
        Stream manifest,
        CancellationToken cancellationToken)
    {
        CsmReadResult result = await CsmReader.ReadAndVerifyAsync(
            manifest,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return ManifestResultMapper.ToVerificationResult(result);
    }

    private static async Task<ManifestVerificationResult> VerifyCoreAsync(
        Stream content,
        Stream manifest,
        CancellationToken cancellationToken)
    {
        CsmContentVerificationResult result =
            await CsmContentVerifier.VerifyAsync(
                content,
                manifest,
                cancellationToken).ConfigureAwait(false);

        ManifestVerificationFailure failures =
            ManifestResultMapper.MapFailures(result.Manifest.Failures);

        if (!result.ProfileMatchesImplementation)
        {
            failures |= ManifestVerificationFailure.ProfileSemantics;
        }
        else if (!result.ContentMatches)
        {
            failures |= ManifestVerificationFailure.Content;
        }

        return new ManifestVerificationResult(
            ManifestResultMapper.FromReadResult(result.Manifest),
            failures);
    }
}
