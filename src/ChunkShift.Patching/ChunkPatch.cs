using ChunkShift.Patching.Application;
using ChunkShift.Patching.Creation;
using ChunkShift.Patching.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching;

/// <summary>
/// Plans chunk reuse between CSM manifests, produces ChunkShift CSP patches and
/// applies them over caller-owned streams.
/// </summary>
/// <remarks>
/// The operations read and write caller-owned streams, never dispose them, and
/// report integrity mismatches as result values rather than exceptions.
/// </remarks>
public static class ChunkPatch
{
    private const int BatchSize = 512;

    // Operational bound for the two materialized ID sets, from CSP-V1
    // section 8 (MaximumMaterializedManifestRecords). Exceeding it is a limits
    // failure, not malformed input.
    private const long MaximumDistinctChunkIds = 4_194_304;

    private const string BaseLimitMessage =
        "The base manifest has more than 4,194,304 distinct chunk IDs, which " +
        "exceeds the operational limit of CSP-V1 section 8 " +
        "(MaximumMaterializedManifestRecords).";

    private const string TargetLimitMessage =
        "The target manifest has more than 4,194,304 distinct missing chunk IDs, " +
        "which exceeds the operational limit of CSP-V1 section 8 " +
        "(MaximumMaterializedManifestRecords).";

    /// <summary>
    /// Computes the chunk reuse between a base and a target CSM manifest.
    /// </summary>
    /// <param name="baseManifest">Readable base CSM stream owned by the caller.</param>
    /// <param name="targetManifest">Readable target CSM stream owned by the caller.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The reuse counts and the verification results of both manifests.</returns>
    /// <remarks>
    /// <para>
    /// Both manifests are read once, forward only, and neither stream needs to be
    /// seekable. ChunkShift never disposes a caller-owned stream. Cancellation,
    /// malformed input, or I/O failure may leave stream positions advanced, including
    /// past the point where the failure was detected, because manifest reads are
    /// buffered ahead; the call does not rewind.
    /// </para>
    /// <para>
    /// Integrity mismatches in either manifest are returned in
    /// <see cref="PatchPlan.Base"/> and <see cref="PatchPlan.Target"/> rather than
    /// thrown, and the counts are computed even when a manifest is invalid.
    /// </para>
    /// <para>
    /// Chunk IDs are comparable only within one hash suite, and a patch needs one
    /// suite for both manifests. When they declare different hash suites the counts
    /// do not describe a usable patch; compare <c>Base.Manifest.HashSuite</c> with
    /// <c>Target.Manifest.HashSuite</c> before relying on them.
    /// </para>
    /// <para>
    /// The operation keeps one set entry per distinct base chunk and one per distinct
    /// missing target chunk. Each set is bounded by the operational limit of
    /// 4,194,304 distinct chunk IDs; exceeding it throws
    /// <see cref="NotSupportedException"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="baseManifest"/> or <paramref name="targetManifest"/> is
    /// <see langword="null"/>. Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="baseManifest"/> or <paramref name="targetManifest"/> is not
    /// readable, or both are the same <see cref="Stream"/> instance. Thrown by this
    /// call, not by the returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Either manifest is not a well-formed CSM representation.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// A manifest declares a hash suite this build does not support, or either set of
    /// distinct chunk IDs exceeds the operational limit of 4,194,304.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before both manifests are read.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A stream returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<PatchPlan> PlanAsync(
        Stream baseManifest,
        Stream targetManifest,
        CancellationToken cancellationToken = default)
    {
        ThrowIfNotReadable(baseManifest, nameof(baseManifest));
        ThrowIfNotReadable(targetManifest, nameof(targetManifest));

        if (ReferenceEquals(baseManifest, targetManifest))
        {
            throw new ArgumentException(
                "The base and target manifest roles must use distinct Stream instances.",
                nameof(targetManifest));
        }

        return PlanCoreAsync(baseManifest, targetManifest, cancellationToken);
    }

    // CreateAsync and ApplyAsync each have an overload with a base and one
    // without. Their optional tokens do not create an ambiguous call site: the
    // overloads differ in arity, and every other stream operation in the
    // package makes the token optional the same way.
#pragma warning disable RS0026
    /// <summary>
    /// Creates a CSP v1 patch that reconstructs the target content over the base.
    /// </summary>
    /// <param name="baseManifest">Readable base CSM stream owned by the caller.</param>
    /// <param name="baseContent">Readable and seekable base content stream owned by the caller.</param>
    /// <param name="targetManifest">Readable and seekable target CSM stream owned by the caller.</param>
    /// <param name="targetContent">Readable target content stream owned by the caller.</param>
    /// <param name="destination">Writable CSP destination owned by the caller.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>Information about the emitted patch.</returns>
    /// <remarks>
    /// <para>
    /// The target manifest is embedded byte-for-byte as the <c>TCSM</c> section,
    /// and the base manifest's <see cref="ManifestId"/> is always written as the
    /// expected base (<c>BASE</c>), even when every target chunk ends up in the
    /// payload. Both manifests must be well-formed CSM;
    /// a <see cref="ManifestVerificationFailure.ProfileSemantics"/>-only failure
    /// is accepted (CSP-V1 section 3.4), and the two manifests must
    /// declare the same <see cref="HashSuiteId"/>, because chunk IDs are
    /// comparable only within one hash suite.
    /// </para>
    /// <para>
    /// A target chunk the base supplies by <see cref="ChunkId"/> receives no
    /// payload entry; every other distinct target chunk receives one, stored as
    /// the lowest-cost of its raw bytes and one zstd frame, optionally
    /// compressed against the bytes of nearby base chunks used as raw dictionary
    /// content.
    /// </para>
    /// <para>
    /// The base manifest is read once into a materialized locator of at most
    /// 4,194,304 records. The target manifest is copied byte-for-byte and read a
    /// second time in lockstep with <paramref name="targetContent"/>,
    /// every chunk of which is hashed against its <see cref="ChunkId"/>; the base
    /// content is read at the offsets of candidate dictionary chunks. Streams
    /// are never disposed, and only the target manifest and the base content are
    /// repositioned.
    /// </para>
    /// <para>
    /// If the operation fails or is cancelled, the bytes already written remain
    /// in <paramref name="destination"/> as an incomplete patch; ChunkShift does
    /// not truncate or roll back a caller-owned destination. To publish a patch
    /// atomically, write it to a temporary file and move it into place only after
    /// this method completes.
    /// </para>
    /// <para>
    /// Patch bytes are a physical representation, not a contract: another
    /// version may emit different bytes for the same inputs. The reconstructed
    /// target and the manifest identities do not change.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// A stream argument is <see langword="null"/>. Thrown by this call, not by
    /// the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// A stream does not have the capability its role requires, the same
    /// <see cref="Stream"/> instance is passed in two roles, or the base and
    /// target manifests declare different hash suites (<paramref name="targetManifest"/>).
    /// Thrown by this call for the stream arguments, by the returned task for the
    /// hash suites.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Either manifest is not a well-formed CSM representation or fails
    /// verification, the target content does not match the target manifest, or
    /// the base content does not match the base manifest.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// A manifest declares a hash suite this build does not support, the base
    /// manifest has more than 4,194,304 records, or the patch would need more than
    /// 1,048,576 payload entries.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before the patch is complete.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A stream returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<PatchInfo> CreateAsync(
        Stream baseManifest,
        Stream baseContent,
        Stream targetManifest,
        Stream targetContent,
        Stream destination,
        CancellationToken cancellationToken = default)
    {
        ThrowIfNotReadable(baseManifest, nameof(baseManifest));
        ThrowIfNotReadable(baseContent, nameof(baseContent));
        ThrowIfNotSeekable(baseContent, nameof(baseContent));
        ThrowIfNotReadable(targetManifest, nameof(targetManifest));
        ThrowIfNotSeekable(targetManifest, nameof(targetManifest));
        ThrowIfNotReadable(targetContent, nameof(targetContent));
        ThrowIfNotWritable(destination, nameof(destination));

        ThrowIfSameInstance(baseManifest, baseContent, nameof(baseContent));
        ThrowIfSameInstance(baseManifest, targetManifest, nameof(targetManifest));
        ThrowIfSameInstance(baseManifest, targetContent, nameof(targetContent));
        ThrowIfSameInstance(baseManifest, destination, nameof(destination));
        ThrowIfSameInstance(baseContent, targetManifest, nameof(targetManifest));
        ThrowIfSameInstance(baseContent, targetContent, nameof(targetContent));
        ThrowIfSameInstance(baseContent, destination, nameof(destination));
        ThrowIfSameInstance(targetManifest, targetContent, nameof(targetContent));
        ThrowIfSameInstance(targetManifest, destination, nameof(destination));
        ThrowIfSameInstance(targetContent, destination, nameof(destination));

        return CspPatchBuilder.CreateAsync(
            baseManifest,
            baseContent,
            targetManifest,
            targetContent,
            destination,
            CspEncoderPolicy.Default,
            cancellationToken);
    }

    /// <summary>
    /// Creates a self-contained CSP v1 patch that carries every target chunk and
    /// needs no base to apply.
    /// </summary>
    /// <param name="targetManifest">Readable and seekable target CSM stream owned by the caller.</param>
    /// <param name="targetContent">Readable target content stream owned by the caller.</param>
    /// <param name="destination">Writable CSP destination owned by the caller.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>Information about the emitted patch.</returns>
    /// <remarks>
    /// <para>
    /// The target manifest is embedded byte-for-byte as the <c>TCSM</c> section
    /// and must be well-formed CSM; a
    /// <see cref="ManifestVerificationFailure.ProfileSemantics"/>-only failure is
    /// accepted (CSP-V1 section 3.4). Every distinct target chunk
    /// receives a payload entry, stored as the lower-cost of its raw bytes and
    /// one zstd frame without a dictionary, and the emitted patch carries no
    /// <c>BASE</c> section.
    /// </para>
    /// <para>
    /// The target manifest is copied byte-for-byte and read a second time in
    /// lockstep with <paramref name="targetContent"/>, every chunk of which is
    /// hashed against its <see cref="ChunkId"/>. Streams are never disposed, and
    /// only the target manifest is repositioned.
    /// </para>
    /// <para>
    /// If the operation fails or is cancelled, the bytes already written remain
    /// in <paramref name="destination"/> as an incomplete patch; ChunkShift does
    /// not truncate or roll back a caller-owned destination. To publish a patch
    /// atomically, write it to a temporary file and move it into place only after
    /// this method completes.
    /// </para>
    /// <para>
    /// Patch bytes are a physical representation, not a contract: another
    /// version may emit different bytes for the same inputs. The reconstructed
    /// target and the manifest identities do not change.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// A stream argument is <see langword="null"/>. Thrown by this call, not by
    /// the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// A stream does not have the capability its role requires, or the same
    /// <see cref="Stream"/> instance is passed in two roles. Thrown by this call,
    /// not by the returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The manifest is not a well-formed CSM representation or fails
    /// verification, or the target content does not match the target manifest.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The manifest declares a hash suite this build does not support, or the
    /// patch would need more than 1,048,576 payload entries.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before the patch is complete.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A stream returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<PatchInfo> CreateAsync(
        Stream targetManifest,
        Stream targetContent,
        Stream destination,
        CancellationToken cancellationToken = default)
    {
        ThrowIfNotReadable(targetManifest, nameof(targetManifest));
        ThrowIfNotSeekable(targetManifest, nameof(targetManifest));
        ThrowIfNotReadable(targetContent, nameof(targetContent));
        ThrowIfNotWritable(destination, nameof(destination));

        ThrowIfSameInstance(targetManifest, targetContent, nameof(targetContent));
        ThrowIfSameInstance(targetManifest, destination, nameof(destination));
        ThrowIfSameInstance(targetContent, destination, nameof(destination));

        return CspPatchBuilder.CreateAsync(
            baseManifest: null,
            baseContent: null,
            targetManifest,
            targetContent,
            destination,
            CspEncoderPolicy.Default,
            cancellationToken);
    }

    /// <summary>
    /// Applies a CSP v1 patch over a supplied base and replaces
    /// <paramref name="destinationPath"/> with the verified target.
    /// </summary>
    /// <param name="patch">Readable and seekable CSP stream owned by the caller.</param>
    /// <param name="baseManifest">Readable base CSM stream owned by the caller.</param>
    /// <param name="baseContent">Readable and seekable base content stream owned by the caller.</param>
    /// <param name="destinationPath">Destination file path whose existing file is replaced.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The outcome and the embedded target manifest.</returns>
    /// <remarks>
    /// <para>
    /// The embedded target manifest is reconstructed in target order: every
    /// target chunk comes from the patch payload or from the base, and the bytes
    /// of every source are verified against their <see cref="ChunkId"/> and chunk
    /// length before they are written. The destination is replaced only after
    /// full verification: the reconstruction goes to a temporary file next to
    /// the destination, and that file is renamed over
    /// <paramref name="destinationPath"/> only when the recorded target length
    /// and the re-chunk check agree with the embedded manifest. An existing
    /// destination file is replaced; the replacement is not advertised as
    /// crash-durable, because the destination directory is not flushed.
    /// </para>
    /// <para>
    /// A patch that carries no <c>BASE</c> section ignores a supplied base, and
    /// a patch that carries <c>BASE</c> verifies a supplied base even when it
    /// turns out to be self-contained. When the destination is the base file
    /// itself (an in-place update), Windows requires the base stream to allow
    /// deletion (<see cref="FileShare.Delete"/>); otherwise the final
    /// replacement fails with <see cref="IOException"/> or
    /// <see cref="UnauthorizedAccessException"/> after verification, and the
    /// destination is unchanged.
    /// </para>
    /// <para>
    /// A malformed patch or base manifest throws <see cref="InvalidDataException"/>;
    /// input that needs semantics this build does not implement throws
    /// <see cref="NotSupportedException"/>; integrity mismatches and exceeded
    /// operational limits are reported in <see cref="PatchApplyResult.Failures"/>; a stream read or write failure
    /// throws <see cref="IOException"/>. In every outcome other than an
    /// applied result nothing is written at <paramref name="destinationPath"/>
    /// and no temporary file remains.
    /// </para>
    /// <para>
    /// Streams are never disposed, and only the patch and the base content are
    /// repositioned. The operation re-chunks the verified reconstruction with
    /// the embedded manifest's profile when this build registers it.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// A stream argument or <paramref name="destinationPath"/> is
    /// <see langword="null"/>. Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// A stream does not have the capability its role requires, the same
    /// <see cref="Stream"/> instance is passed in two roles, or
    /// <paramref name="destinationPath"/> is empty. Thrown by this call, not by
    /// the returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The patch or the base manifest is not a well-formed representation, or a
    /// payload entry is not exactly one decodable zstd frame of its target chunk.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The patch requires semantics this build does not implement, for example
    /// an unknown hash suite or an unimplemented payload encoding.
    /// </exception>
    /// <exception cref="IOException">
    /// The destination cannot be written, or the final replacement failed
    /// because the destination is locked.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The destination cannot be written, or Windows refused the final
    /// replacement of a destination that is open without delete sharing.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before the verified target is published.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A stream returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<PatchApplyResult> ApplyAsync(
        Stream patch,
        Stream baseManifest,
        Stream baseContent,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        ThrowIfNotReadable(patch, nameof(patch));
        ThrowIfNotSeekable(patch, nameof(patch));
        ThrowIfNotReadable(baseManifest, nameof(baseManifest));
        ThrowIfNotReadable(baseContent, nameof(baseContent));
        ThrowIfNotSeekable(baseContent, nameof(baseContent));
        ArgumentException.ThrowIfNullOrEmpty(destinationPath);

        ThrowIfSameInstance(patch, baseManifest, nameof(baseManifest));
        ThrowIfSameInstance(patch, baseContent, nameof(baseContent));
        ThrowIfSameInstance(baseManifest, baseContent, nameof(baseContent));

        return CspApplier.ApplyAsync(
            patch,
            baseManifest,
            baseContent,
            destinationPath,
            CspFormat.DefaultMaximumPayloadEntries,
            CspApplier.DefaultChunkingCheck,
            cancellationToken);
    }

    /// <summary>
    /// Applies a self-contained CSP v1 patch and replaces
    /// <paramref name="destinationPath"/> with the verified target.
    /// </summary>
    /// <param name="patch">Readable and seekable CSP stream owned by the caller.</param>
    /// <param name="destinationPath">Destination file path whose existing file is replaced.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The outcome and the embedded target manifest.</returns>
    /// <remarks>
    /// <para>
    /// Every target chunk must come from the patch payload. A patch that carries
    /// a <c>BASE</c> section and depends on a base is rejected with
    /// <see cref="PatchApplyFailure.BaseMismatch"/>; a base-dependent patch
    /// without <c>BASE</c> is malformed.
    /// </para>
    /// <para>
    /// The destination is replaced only after full verification: the
    /// reconstruction goes to a temporary file next to the destination, and that
    /// file is renamed over <paramref name="destinationPath"/> only when the
    /// recorded target length and the re-chunk check agree with the embedded
    /// manifest. An existing destination file is replaced; the replacement is
    /// not advertised as crash-durable, because the destination directory is not
    /// flushed.
    /// </para>
    /// <para>
    /// A malformed patch throws <see cref="InvalidDataException"/>; input that
    /// needs semantics this build does not implement throws
    /// <see cref="NotSupportedException"/>; integrity mismatches and exceeded
    /// operational limits are reported in <see cref="PatchApplyResult.Failures"/>; a stream read or write failure
    /// throws <see cref="IOException"/>. In every outcome other than an
    /// applied result nothing is written at <paramref name="destinationPath"/>
    /// and no temporary file remains.
    /// </para>
    /// <para>
    /// Streams are never disposed, and only the patch is repositioned. The
    /// operation re-chunks the verified reconstruction with the embedded
    /// manifest's profile when this build registers it.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="patch"/> or <paramref name="destinationPath"/> is
    /// <see langword="null"/>. Thrown by this call, not by the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="patch"/> is not readable or not seekable, or
    /// <paramref name="destinationPath"/> is empty. Thrown by this call, not by
    /// the returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The patch is not a well-formed representation, or a payload entry is not
    /// exactly one decodable zstd frame of its target chunk.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The patch requires semantics this build does not implement, for example
    /// an unknown hash suite or an unimplemented payload encoding.
    /// </exception>
    /// <exception cref="IOException">
    /// The destination cannot be written, or the final replacement failed
    /// because the destination is locked.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// The destination cannot be written, or Windows refused the final
    /// replacement of a destination that is open without delete sharing.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Cancellation is observed before the verified target is published.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A stream returned a byte count outside the <see cref="Stream"/> contract.
    /// </exception>
    public static Task<PatchApplyResult> ApplyAsync(
        Stream patch,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        ThrowIfNotReadable(patch, nameof(patch));
        ThrowIfNotSeekable(patch, nameof(patch));
        ArgumentException.ThrowIfNullOrEmpty(destinationPath);

        return CspApplier.ApplyAsync(
            patch,
            baseManifest: null,
            baseContent: null,
            destinationPath,
            CspFormat.DefaultMaximumPayloadEntries,
            CspApplier.DefaultChunkingCheck,
            cancellationToken);
    }
#pragma warning restore RS0026

    private static async Task<PatchPlan> PlanCoreAsync(
        Stream baseManifest,
        Stream targetManifest,
        CancellationToken cancellationToken)
    {
        var baseIds = new HashSet<ChunkId>();

        ManifestVerificationResult baseResult;

        await using (ManifestReader baseReader =
            await ManifestReader.OpenAsync(
                baseManifest,
                cancellationToken).ConfigureAwait(false))
        {
            var baseEntries = new ChunkInfo[BatchSize];
            int count;
            while ((count = await baseReader.ReadAsync(
                baseEntries,
                cancellationToken).ConfigureAwait(false)) != 0)
            {
                for (int index = 0; index < count; index++)
                {
                    if (baseIds.Add(baseEntries[index].Id) &&
                        baseIds.Count > MaximumDistinctChunkIds)
                    {
                        throw new NotSupportedException(BaseLimitMessage);
                    }
                }
            }

            baseResult = RequireVerificationResult(baseReader);
        }

        long reusedChunks = 0;
        long reusedBytes = 0;
        long missingChunks = 0;
        long missingBytes = 0;
        long uniqueMissingBytes = 0;

        var uniqueMissingIds = new HashSet<ChunkId>();

        ManifestVerificationResult targetResult;

        await using (ManifestReader targetReader =
            await ManifestReader.OpenAsync(
                targetManifest,
                cancellationToken).ConfigureAwait(false))
        {
            var targetEntries = new ChunkInfo[BatchSize];
            int count;
            while ((count = await targetReader.ReadAsync(
                targetEntries,
                cancellationToken).ConfigureAwait(false)) != 0)
            {
                for (int index = 0; index < count; index++)
                {
                    ChunkInfo chunk = targetEntries[index];

                    if (baseIds.Contains(chunk.Id))
                    {
                        reusedChunks++;
                        reusedBytes += chunk.Length;
                        continue;
                    }

                    missingChunks++;
                    missingBytes += chunk.Length;

                    // Unique missing bytes record one length per distinct
                    // missing ChunkId, matching UniqueMissingPayloadBytes.
                    if (uniqueMissingIds.Add(chunk.Id))
                    {
                        if (uniqueMissingIds.Count > MaximumDistinctChunkIds)
                        {
                            throw new NotSupportedException(TargetLimitMessage);
                        }

                        uniqueMissingBytes += chunk.Length;
                    }
                }
            }

            targetResult = RequireVerificationResult(targetReader);
        }

        return new PatchPlan(
            baseResult,
            targetResult,
            reusedChunks,
            reusedBytes,
            missingChunks,
            missingBytes,
            uniqueMissingIds.Count,
            uniqueMissingBytes);
    }

    private static void ThrowIfNotReadable(Stream? stream, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(stream, parameterName);

        if (!stream.CanRead)
        {
            throw new ArgumentException(
                "The stream must be readable.",
                parameterName);
        }
    }

    private static void ThrowIfNotSeekable(Stream? stream, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(stream, parameterName);

        if (!stream.CanSeek)
        {
            throw new ArgumentException(
                "The stream must be seekable.",
                parameterName);
        }
    }

    private static void ThrowIfNotWritable(Stream? stream, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(stream, parameterName);

        if (!stream.CanWrite)
        {
            throw new ArgumentException(
                "The stream must be writable.",
                parameterName);
        }
    }

    private static void ThrowIfSameInstance(
        Stream first,
        Stream second,
        string secondParameterName)
    {
        if (ReferenceEquals(first, second))
        {
            throw new ArgumentException(
                "Every stream role must use a distinct Stream instance.",
                secondParameterName);
        }
    }

    private static ManifestVerificationResult RequireVerificationResult(
        ManifestReader reader) =>
        reader.VerificationResult
        ?? throw new InvalidOperationException(
            "ManifestReader completed without a verification result.");
}
