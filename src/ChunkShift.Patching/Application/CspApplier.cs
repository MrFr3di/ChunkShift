using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Patching.IO;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Application;

/// <summary>
/// Applies a CSP v1 patch over an optional base to a destination path
/// (docs/architecture/CSP-V1.md section 6; the checks run in its verdict
/// order).
/// </summary>
/// <remarks>
/// <para>
/// The reconstruction is written to a temporary file next to the destination
/// and published only after every check passed. A failure returns the
/// accumulated integrity flags and leaves an existing destination unchanged.
/// </para>
/// <para>
/// Memory is bounded by the payload map, the base locator of at most 4,194,304
/// records, one chunk buffer of the current record length and one dictionary of
/// at most <see cref="CspDictionary.MaximumBytes"/>; the overlapped re-chunk
/// check adds its pipe (<see cref="OverlappedChunkingCheck"/>). Argument
/// validation is the public caller's job. No stream is disposed; only the base
/// content and the temporary file are repositioned.
/// </para>
/// </remarks>
internal static class CspApplier
{
    /// <summary>
    /// The re-chunk check of the public apply methods: boundary-only for the
    /// stable Core profile and overlapped for any other registered profile.
    /// </summary>
    internal const ChunkingCheck DefaultChunkingCheck = ChunkingCheck.Boundary;

    private const int ManifestBatchEntries = 256;

    // CSP-V1 section 8, MaximumMaterializedManifestRecords.
    private const int MaximumBaseRecords = 4_194_304;

    private const string ByteCountMessage =
        "A stream returned a byte count outside the Stream contract.";

    /// <summary>
    /// Applies a patch; <paramref name="baseManifest"/> and
    /// <paramref name="baseContent"/> are <see langword="null"/> when the caller
    /// supplies no base.
    /// </summary>
    internal static async Task<PatchApplyResult> ApplyAsync(
        Stream patch,
        Stream? baseManifest,
        Stream? baseContent,
        string destinationPath,
        int maximumPayloadEntries,
        ChunkingCheck chunkingCheck,
        CancellationToken cancellationToken)
    {
        // The overlapped check reads the embedded CSM while the reconstruction
        // reads payload entries, and both reposition the caller's patch stream.
        // Each then reads through a view of its own, and the views take turns.
        // The boundary check falls back to it for any other profile, which is
        // known only once the patch is open.
        using SemaphoreSlim? patchGate =
            chunkingCheck is ChunkingCheck.Overlapped or ChunkingCheck.Boundary
                ? new SemaphoreSlim(1, 1)
                : null;
        long patchStart = patch.Position;
        Stream patchSource = patchGate is null
            ? patch
            : new SharedStreamView(patch, patchGate, patchStart);
        Stream? checkPatch = patchGate is null
            ? null
            : new SharedStreamView(patch, patchGate, patchStart);
        CspReader reader;

        // Verdict stages 1-3: structure, embedded CSM, patch FileDigest, payload
        // entries against the target, and the base binding the patch reveals.
        try
        {
            reader = await CspReader
                .OpenAsync(patchSource, maximumPayloadEntries, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (CspResourceLimitException)
        {
            return new PatchApplyResult(PatchApplyFailure.ResourceLimit, target: null);
        }

        ManifestInfo target = reader.TargetManifest.Manifest;

        if (reader.Failures != CspVerificationFailure.None)
        {
            return new PatchApplyResult(MapFailures(reader.Failures), target);
        }

        if (chunkingCheck == ChunkingCheck.Boundary && !BoundaryChunkingCheck.AppliesTo(target))
        {
            chunkingCheck = ChunkingCheck.Overlapped;
        }

        BoundaryChunkingCheck? boundary = chunkingCheck == ChunkingCheck.Boundary
            ? new BoundaryChunkingCheck()
            : null;

        var baseLocator = new Dictionary<ChunkId, ChunkInfo>();
        Stream? baseStream = null;

        // Verdict stage 4: base binding. A patch without BASE ignores a supplied
        // base; with BASE, a supplied base is verified
        // even for a self-contained patch.
        if (reader.ExpectedBaseManifestId is ManifestId expectedBase &&
            (reader.DependsOnBase || baseManifest is not null))
        {
            if (baseManifest is null || baseContent is null)
            {
                return new PatchApplyResult(PatchApplyFailure.BaseMismatch, target);
            }

            ManifestVerificationResult baseResult;

            try
            {
                baseResult = await ReadBaseLocatorAsync(
                    baseManifest,
                    baseLocator,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (CspResourceLimitException)
            {
                return new PatchApplyResult(PatchApplyFailure.ResourceLimit, target);
            }

            // The HashSuite is compared before the base
            // manifest's integrity, because ChunkIds of different suites are
            // not comparable.
            if (baseResult.Manifest.HashSuite != target.HashSuite)
            {
                return new PatchApplyResult(PatchApplyFailure.BaseMismatch, target);
            }

            // A ProfileSemantics-only base failure is
            // accepted (CSP-V1 section 3.4).
            if ((baseResult.Failures & ~ManifestVerificationFailure.ProfileSemantics) != 0)
            {
                return new PatchApplyResult(PatchApplyFailure.BaseManifest, target);
            }

            if (baseResult.Manifest.ManifestId != expectedBase)
            {
                return new PatchApplyResult(PatchApplyFailure.BaseMismatch, target);
            }

            baseStream = baseContent;
        }

        // No file is created before the patch and the base binding are
        // past every check that needs no output.
        await using PendingFile pending = PendingFile.Create(destinationPath);
        Stream output = pending.Stream;

        // Disposed before the pending file: whatever ends the apply, the check
        // is cancelled and awaited first.
        await using OverlappedChunkingCheck? overlapped = chunkingCheck != ChunkingCheck.Overlapped
            ? null
            : OverlappedChunkingCheck.Start(
                (content, token) => CheckChunkingAsync(
                    content,
                    new BoundedReadStream(
                        checkPatch!,
                        checked(patchStart + reader.TargetManifestOffset),
                        reader.TargetManifestLength),
                    token),
                cancellationToken);

        PatchApplyFailure failure = await ResolveTargetAsync(
            reader,
            output,
            baseLocator,
            baseStream,
            overlapped,
            boundary,
            cancellationToken).ConfigureAwait(false);

        if (failure != PatchApplyFailure.None)
        {
            return new PatchApplyResult(failure, target);
        }

        // Verdict stage 6.
        if (output.Length != target.ContentLength)
        {
            return new PatchApplyResult(PatchApplyFailure.ContentLength, target);
        }

        // Verdict stage 6, then the re-chunk check (CSP-V1 section 6,
        // rule 24): reported only after the reconstruction and its length
        // passed, whichever way it ran.
        bool profileMatches = chunkingCheck switch
        {
            ChunkingCheck.Off => true,
            ChunkingCheck.Sequential => await VerifyChunkingAsync(
                reader,
                output,
                cancellationToken).ConfigureAwait(false),
            ChunkingCheck.Overlapped => await CompleteOverlappedAsync(
                overlapped!,
                pending,
                cancellationToken).ConfigureAwait(false),
            ChunkingCheck.Boundary => boundary!.Complete(),
            _ => throw new ArgumentOutOfRangeException(nameof(chunkingCheck)),
        };

        if (!profileMatches)
        {
            return new PatchApplyResult(PatchApplyFailure.ProfileContent, target);
        }

        await pending.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new PatchApplyResult(PatchApplyFailure.None, target);
    }

    /// <summary>
    /// Verdict stage 5: resolves every target record in order, writing the verified
    /// bytes to <paramref name="output"/> and, when a check runs with the
    /// reconstruction, to <paramref name="overlapped"/> or
    /// <paramref name="boundary"/>, stopping at the first failure. A boundary
    /// mismatch does not stop it: the verdict order reports it only after the
    /// reconstruction and the length passed.
    /// </summary>
    private static async Task<PatchApplyFailure> ResolveTargetAsync(
        CspReader reader,
        Stream output,
        Dictionary<ChunkId, ChunkInfo> baseLocator,
        Stream? baseStream,
        OverlappedChunkingCheck? overlapped,
        BoundaryChunkingCheck? boundary,
        CancellationToken cancellationToken)
    {
        HashSuiteId hashSuite = reader.TargetManifest.Manifest.HashSuite;
        var payloadOrdinals = new Dictionary<ChunkId, int>(reader.PayloadChunkIds.Count);

        for (int ordinal = 0; ordinal < reader.PayloadChunkIds.Count; ordinal++)
        {
            // Reader failures already excluded duplicates; a repeated identity
            // keeps its first payload ordinal.
            _ = payloadOrdinals.TryAdd(reader.PayloadChunkIds[ordinal], ordinal);
        }

        var resolvedChunks = new Dictionary<ChunkId, (long Offset, int Length)>();
        byte[] chunkBuffer = [];
        byte[] dictionaryBuffer = [];
        long writeOffset = 0;

        using var decoder = new CspPayloadDecoder();

        await using (ManifestReader targetReader = await ManifestReader
            .OpenAsync(reader.OpenTargetManifest(), cancellationToken)
            .ConfigureAwait(false))
        {
            var batch = new ChunkInfo[ManifestBatchEntries];
            int count;

            while ((count = await targetReader
                .ReadAsync(batch, cancellationToken)
                .ConfigureAwait(false)) != 0)
            {
                for (int index = 0; index < count; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ChunkInfo record = batch[index];
                    Memory<byte> chunk;

                    if (payloadOrdinals.TryGetValue(record.Id, out int ordinal))
                    {
                        if (resolvedChunks.TryGetValue(
                            record.Id,
                            out (long Offset, int Length) resolved))
                        {
                            // A repeated target chunk replays the bytes verified
                            // at its first occurrence instead of decoding again.
                            if (chunkBuffer.Length < resolved.Length)
                            {
                                chunkBuffer = new byte[resolved.Length];
                            }

                            chunk = chunkBuffer.AsMemory(0, resolved.Length);
                            await ReadExactlyAtAsync(
                                output,
                                resolved.Offset,
                                chunk,
                                cancellationToken).ConfigureAwait(false);
                        }
                        else
                        {
                            if (chunkBuffer.Length < record.Length)
                            {
                                chunkBuffer = new byte[record.Length];
                            }

                            chunk = chunkBuffer.AsMemory(0, record.Length);

                            CspEntry entry = await reader
                                .ReadEntryAsync(ordinal, cancellationToken)
                                .ConfigureAwait(false);
                            Memory<byte> dictionary = default;

                            if (entry.Encoding == CspFormat.EncodingZstd &&
                                entry.DictionaryChunkIds.Length > 0)
                            {
                                if (baseStream is null ||
                                    !TryGetDictionaryLength(
                                        entry.DictionaryChunkIds,
                                        baseLocator,
                                        out int dictionaryLength))
                                {
                                    return PatchApplyFailure.DictionaryChunk;
                                }

                                if (dictionaryBuffer.Length < dictionaryLength)
                                {
                                    dictionaryBuffer = new byte[dictionaryLength];
                                }

                                dictionary = dictionaryBuffer.AsMemory(0, dictionaryLength);

                                if (!await TryFillDictionaryAsync(
                                    entry.DictionaryChunkIds,
                                    baseLocator,
                                    baseStream,
                                    dictionary,
                                    hashSuite,
                                    cancellationToken).ConfigureAwait(false))
                                {
                                    return PatchApplyFailure.DictionaryChunk;
                                }

                                if (!CspDictionary.IsUsable(dictionary.Span))
                                {
                                    return PatchApplyFailure.DictionaryChunk;
                                }
                            }

                            // Rule 18: a raw entry stores exactly the target
                            // length. The reader checks the entry against the
                            // first occurrence of its ChunkId; this keeps the
                            // decoder's input contract for the current record.
                            if (entry.Encoding == CspFormat.EncodingRaw &&
                                entry.StoredBytes.Length != record.Length)
                            {
                                return PatchApplyFailure.PayloadChunk;
                            }

                            decoder.Decode(
                                entry.Encoding,
                                entry.StoredBytes,
                                dictionary.Span,
                                chunk.Span);

                            if (PatchHashing.Hash(hashSuite, chunk.Span) != record.Id.Value)
                            {
                                return PatchApplyFailure.PayloadChunk;
                            }

                            resolvedChunks.Add(record.Id, (writeOffset, record.Length));
                        }
                    }
                    else
                    {
                        if (chunkBuffer.Length < record.Length)
                        {
                            chunkBuffer = new byte[record.Length];
                        }

                        chunk = chunkBuffer.AsMemory(0, record.Length);

                        if (baseStream is null)
                        {
                            return PatchApplyFailure.MissingPayload;
                        }

                        if (!baseLocator.TryGetValue(record.Id, out ChunkInfo located))
                        {
                            return PatchApplyFailure.MissingPayload;
                        }

                        if (located.Length != record.Length ||
                            !await TryReadExactlyAtAsync(
                                baseStream,
                                located.Offset,
                                chunk,
                                cancellationToken).ConfigureAwait(false))
                        {
                            return PatchApplyFailure.BaseChunk;
                        }

                        if (PatchHashing.Hash(hashSuite, chunk.Span) != record.Id.Value)
                        {
                            return PatchApplyFailure.BaseChunk;
                        }
                    }

                    output.Position = writeOffset;
                    await output
                        .WriteAsync(chunk, cancellationToken)
                        .ConfigureAwait(false);

                    if (overlapped is not null)
                    {
                        await overlapped
                            .WriteAsync(chunk, cancellationToken)
                            .ConfigureAwait(false);
                    }

                    boundary?.Append(chunk.Span);

                    writeOffset = checked(writeOffset + chunk.Length);
                }
            }
        }

        return PatchApplyFailure.None;
    }

    /// <summary>
    /// Computes the concatenated length of the named dictionary chunks and
    /// rejects the dictionary when a chunk is absent from the base or the
    /// concatenation would exceed the CSP bound. Bounding the length before the
    /// read keeps the buffer within <see cref="CspDictionary.MaximumBytes"/>.
    /// </summary>
    private static bool TryGetDictionaryLength(
        ChunkId[] dictionaryChunkIds,
        Dictionary<ChunkId, ChunkInfo> baseLocator,
        out int length)
    {
        long total = 0;

        foreach (ChunkId chunkId in dictionaryChunkIds)
        {
            if (!baseLocator.TryGetValue(chunkId, out ChunkInfo located))
            {
                length = 0;
                return false;
            }

            total += located.Length;

            if (total > CspDictionary.MaximumBytes)
            {
                length = 0;
                return false;
            }
        }

        length = (int)total;
        return true;
    }

    /// <summary>
    /// Reads the named base chunks into <paramref name="dictionary"/> in listed
    /// order, verifying each by <see cref="ChunkId"/> (rule 28).
    /// </summary>
    private static async ValueTask<bool> TryFillDictionaryAsync(
        ChunkId[] dictionaryChunkIds,
        Dictionary<ChunkId, ChunkInfo> baseLocator,
        Stream baseContent,
        Memory<byte> dictionary,
        HashSuiteId hashSuite,
        CancellationToken cancellationToken)
    {
        int offset = 0;

        foreach (ChunkId chunkId in dictionaryChunkIds)
        {
            ChunkInfo located = baseLocator[chunkId];
            Memory<byte> bytes = dictionary.Slice(offset, located.Length);

            if (!await TryReadExactlyAtAsync(
                baseContent,
                located.Offset,
                bytes,
                cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            if (PatchHashing.Hash(hashSuite, bytes.Span) != chunkId.Value)
            {
                return false;
            }

            offset += located.Length;
        }

        return true;
    }

    /// <summary>
    /// Ends the overlapped check's content and flushes the temporary file to
    /// disk, which publication needs anyway, while the check works
    /// through the rest of the pipe. The rename still waits for the outcome.
    /// </summary>
    private static async Task<bool> CompleteOverlappedAsync(
        OverlappedChunkingCheck overlapped,
        PendingFile pending,
        CancellationToken cancellationToken)
    {
        await overlapped.EndContentAsync().ConfigureAwait(false);
        await pending.FlushToDiskAsync(cancellationToken).ConfigureAwait(false);
        return await overlapped.CompleteAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Re-reads the temporary file for the sequential re-chunk check.
    /// </summary>
    private static Task<bool> VerifyChunkingAsync(
        CspReader reader,
        Stream output,
        CancellationToken cancellationToken)
    {
        output.Position = 0;

        return CheckChunkingAsync(output, reader.OpenTargetManifest(), cancellationToken);
    }

    /// <summary>
    /// Re-chunks the reconstruction with the embedded manifest's profile and
    /// requires it to reproduce that manifest (CSP-V1 section 9.5).
    /// An unregistered profile cannot run the check and does not block apply.
    /// </summary>
    private static async Task<bool> CheckChunkingAsync(
        Stream content,
        Stream manifest,
        CancellationToken cancellationToken)
    {
        try
        {
            ManifestVerificationResult verification = await ChunkManifest
                .VerifyAsync(content, manifest, cancellationToken)
                .ConfigureAwait(false);

            return (verification.Failures &
                (ManifestVerificationFailure.Content |
                 ManifestVerificationFailure.ProfileSemantics)) == 0;
        }
        catch (NotSupportedException)
        {
            return true;
        }
    }

    /// <summary>
    /// Reads the base manifest into the locator, first occurrence wins
    /// (CSP-V1 section 3.3).
    /// </summary>
    private static async Task<ManifestVerificationResult> ReadBaseLocatorAsync(
        Stream baseManifest,
        Dictionary<ChunkId, ChunkInfo> locator,
        CancellationToken cancellationToken)
    {
        await using ManifestReader reader = await ManifestReader
            .OpenAsync(baseManifest, cancellationToken)
            .ConfigureAwait(false);

        var batch = new ChunkInfo[ManifestBatchEntries];
        int count;

        while ((count = await reader
            .ReadAsync(batch, cancellationToken)
            .ConfigureAwait(false)) != 0)
        {
            for (int index = 0; index < count; index++)
            {
                ChunkInfo record = batch[index];

                if (locator.TryAdd(record.Id, record) &&
                    locator.Count > MaximumBaseRecords)
                {
                    throw new CspResourceLimitException(
                        "The base manifest has more than 4,194,304 distinct chunk " +
                        "records, which exceeds the operational limit of " +
                        "CSP-V1 section 8 " +
                        "(MaximumMaterializedManifestRecords).");
                }
            }
        }

        return reader.VerificationResult
            ?? throw new InvalidOperationException(
                "ManifestReader completed without a verification result.");
    }

    /// <summary>
    /// Maps the reader's verification flags onto the public apply failures.
    /// </summary>
    private static PatchApplyFailure MapFailures(CspVerificationFailure failures)
    {
        PatchApplyFailure result = PatchApplyFailure.None;

        if ((failures & CspVerificationFailure.FileDigest) != 0)
        {
            result |= PatchApplyFailure.PatchFileDigest;
        }

        if ((failures & CspVerificationFailure.EmbeddedManifest) != 0)
        {
            result |= PatchApplyFailure.EmbeddedManifest;
        }

        if ((failures & CspVerificationFailure.ProfileSemantics) != 0)
        {
            result |= PatchApplyFailure.ProfileSemantics;
        }

        if ((failures & CspVerificationFailure.DuplicatePayload) != 0)
        {
            result |= PatchApplyFailure.DuplicatePayload;
        }

        if ((failures & CspVerificationFailure.PayloadNotInTarget) != 0)
        {
            result |= PatchApplyFailure.PayloadNotInTarget;
        }

        if ((failures & CspVerificationFailure.PayloadLength) != 0)
        {
            result |= PatchApplyFailure.PayloadLength;
        }

        return result;
    }

    /// <summary>
    /// Reads exactly <paramref name="destination"/>.Length bytes at
    /// <paramref name="offset"/>; a premature end is an internal invariant
    /// violation.
    /// </summary>
    private static async ValueTask ReadExactlyAtAsync(
        Stream source,
        long offset,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        if (!await TryReadExactlyAtAsync(
            source,
            offset,
            destination,
            cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "The temporary file ended before a verified chunk length.");
        }
    }

    /// <summary>
    /// Reads exactly <paramref name="destination"/>.Length bytes at
    /// <paramref name="offset"/> and reports whether the source supplied them.
    /// </summary>
    private static async ValueTask<bool> TryReadExactlyAtAsync(
        Stream source,
        long offset,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        source.Position = offset;
        int written = 0;

        while (written < destination.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = await source
                .ReadAsync(destination[written..], cancellationToken)
                .ConfigureAwait(false);

            if ((uint)read > (uint)(destination.Length - written))
            {
                throw new InvalidOperationException(ByteCountMessage);
            }

            if (read == 0)
            {
                return false;
            }

            written += read;
        }

        return true;
    }
}
