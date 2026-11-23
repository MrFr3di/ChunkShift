using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Creation;

/// <summary>
/// Creates a CSP v1 patch for one target manifest and content pair, optionally
/// over a base (docs/architecture/CSP-V1.md sections 4 and 5).
/// </summary>
/// <remarks>
/// <para>
/// Memory is bounded by CSP section 8: the base records and the base identity
/// set by <c>MaximumMaterializedManifestRecords</c>, the emitted-identity set by
/// <c>MaximumPayloadEntries</c>, and the per-chunk work by one target chunk and
/// one dictionary of at most <see cref="CspDictionary.MaximumBytes"/> per
/// candidate. The target manifest is verified, embedded byte-for-byte as
/// <c>TCSM</c> and re-read in lockstep with the target content, so the patch is
/// written forward-only.
/// </para>
/// <para>
/// How the payload pass runs is a <see cref="CspCreateExecution"/>:
/// sequentially, optionally
/// through a cache of at most one candidate window of base chunks, or with
/// bounded encode workers whose entries are written in first-occurrence
/// order. Every execution writes the same patch bytes; the workers add at
/// most their window of entries and one encoder each.
/// </para>
/// <para>
/// Argument validation is the public caller's job. No stream is disposed; only
/// the target manifest (back to where it was found) and the base content (for
/// dictionary chunks) are repositioned.
/// </para>
/// </remarks>
internal static partial class CspPatchBuilder
{
    private const int ManifestBatchEntries = 256;

    // CSP-V1 section 8, MaximumMaterializedManifestRecords.
    private const int MaximumBaseRecords = 4_194_304;

    private const string ByteCountMessage =
        "A stream returned a byte count outside the Stream contract.";

    /// <summary>
    /// Creates a patch with <see cref="CspCreateExecution.Default"/>; with
    /// <paramref name="baseManifest"/> and <paramref name="baseContent"/> both
    /// <see langword="null"/> it is self-contained.
    /// </summary>
    internal static Task<PatchInfo> CreateAsync(
        Stream? baseManifest,
        Stream? baseContent,
        Stream targetManifest,
        Stream targetContent,
        Stream destination,
        CspEncoderPolicy policy,
        CancellationToken cancellationToken) =>
        CreateAsync(
            baseManifest,
            baseContent,
            targetManifest,
            targetContent,
            destination,
            policy,
            CspCreateExecution.Default,
            cancellationToken);

    /// <summary>
    /// Creates a patch with an explicit <paramref name="execution"/>. Every
    /// execution writes the same patch bytes as
    /// <see cref="CspCreateExecution.Sequential"/>.
    /// </summary>
    internal static async Task<PatchInfo> CreateAsync(
        Stream? baseManifest,
        Stream? baseContent,
        Stream targetManifest,
        Stream targetContent,
        Stream destination,
        CspEncoderPolicy policy,
        CspCreateExecution execution,
        CancellationToken cancellationToken)
    {
        ValidatePolicy(policy);
        ValidateExecution(execution);
        var baseRecords = new List<BaseRecord>();
        var baseIds = new HashSet<ChunkId>();
        ManifestInfo? baseInfo = null;

        if (baseManifest is not null)
        {
            baseInfo = await ReadManifestAsync(
                baseManifest,
                "base",
                chunk =>
                {
                    if (baseRecords.Count >= MaximumBaseRecords)
                    {
                        throw new NotSupportedException(
                            "The base manifest has more than 4,194,304 records " +
                            "(CSP-V1 section 8, MaximumMaterializedManifestRecords).");
                    }

                    baseRecords.Add(new BaseRecord(chunk.Offset, chunk.Length, chunk.Id));
                    _ = baseIds.Add(chunk.Id);
                },
                cancellationToken).ConfigureAwait(false);
        }

        long targetStart = targetManifest.Position;
        ManifestInfo target = await ReadManifestAsync(
            targetManifest,
            "target",
            onRecord: null,
            cancellationToken).ConfigureAwait(false);

        if (baseInfo is not null && baseInfo.HashSuite != target.HashSuite)
        {
            throw new ArgumentException(
                "The base and target manifests must declare the same HashSuiteId; " +
                "ChunkId values are comparable only within one hash suite.",
                nameof(targetManifest));
        }

        using var writer = new CspWriter(destination, target.HashSuite);

        // The Core reader rejects bytes after the TRAILER, so the manifest runs
        // from its start to the end of the stream.
        targetManifest.Position = targetStart;
        await writer.WriteTargetManifestAsync(
            targetManifest,
            checked(targetManifest.Length - targetStart),
            cancellationToken).ConfigureAwait(false);

        // A patch created with a base always carries BASE, even when every
        // target chunk ends up in the payload.
        if (baseInfo is not null)
        {
            await writer.WriteExpectedBaseAsync(
                baseInfo.ManifestId,
                cancellationToken).ConfigureAwait(false);
        }

        targetManifest.Position = targetStart;

        if (execution.WorkerCount == 0)
        {
            await WritePayloadAsync(
                writer,
                baseRecords,
                baseIds,
                baseContent,
                targetManifest,
                targetContent,
                target.HashSuite,
                policy,
                execution,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await WritePayloadInParallelAsync(
                writer,
                baseRecords,
                baseIds,
                baseContent,
                targetManifest,
                targetContent,
                target.HashSuite,
                policy,
                execution,
                cancellationToken).ConfigureAwait(false);
        }

        CspWriteResult result = await writer
            .CompleteAsync(cancellationToken)
            .ConfigureAwait(false);

        return new PatchInfo(
            target.ManifestId,
            baseInfo?.ManifestId,
            target.HashSuite,
            result.FileDigest,
            checked((long)result.PhysicalLength),
            checked((long)result.PayloadEntryCount),
            checked((long)result.StoredPayloadBytes));
    }

    /// <summary>
    /// Reads a manifest to its end and requires a valid verification result; a
    /// <see cref="ManifestVerificationFailure.ProfileSemantics"/>-only failure is
    /// accepted (CSP-V1 section 3.4).
    /// </summary>
    private static async Task<ManifestInfo> ReadManifestAsync(
        Stream manifest,
        string role,
        Action<ChunkInfo>? onRecord,
        CancellationToken cancellationToken)
    {
        await using ManifestReader reader = await ManifestReader
            .OpenAsync(manifest, cancellationToken)
            .ConfigureAwait(false);

        var batch = new ChunkInfo[ManifestBatchEntries];
        int count;

        while ((count = await reader
            .ReadAsync(batch, cancellationToken)
            .ConfigureAwait(false)) != 0)
        {
            if (onRecord is not null)
            {
                for (int index = 0; index < count; index++)
                {
                    onRecord(batch[index]);
                }
            }
        }

        ManifestVerificationResult result = reader.VerificationResult
            ?? throw new InvalidOperationException(
                "ManifestReader completed without a verification result.");

        ManifestVerificationFailure failures =
            result.Failures & ~ManifestVerificationFailure.ProfileSemantics;

        if (failures != ManifestVerificationFailure.None)
        {
            throw new InvalidDataException(
                $"The {role} manifest is not valid: {failures}.");
        }

        return result.Manifest;
    }

    /// <summary>
    /// Verifies every target record against its <see cref="ChunkId"/> and emits
    /// one payload entry per distinct identity the base does not hold, in target
    /// first-occurrence order, one entry at a time.
    /// </summary>
    private static async Task WritePayloadAsync(
        CspWriter writer,
        List<BaseRecord> baseRecords,
        HashSet<ChunkId> baseIds,
        Stream? baseContent,
        Stream targetManifest,
        Stream targetContent,
        HashSuiteId hashSuite,
        CspEncoderPolicy policy,
        CspCreateExecution execution,
        CancellationToken cancellationToken)
    {
        // Level zero is raw-only: no encoder is created and the stored forms
        // are never compared with the raw bytes.
        using CspPayloadEncoder? encoder = CreateEncoder(policy);

        var entryBuffers = new EntryBuffers();
        CreateBufferPool? pool = null;
        BaseCandidateCache? cache = null;
        BaseChunkSource? source = null;

        if (baseContent is not null && UsesDictionaries(policy))
        {
            if (execution.UseBaseCandidateCache)
            {
                pool = new CreateBufferPool(policy.MaxCandidates + policy.DictionaryChunks + 8);
                cache = new BaseCandidateCache(baseRecords, baseContent, policy, pool, window: null, execution.Statistics);
            }
            else
            {
                source = new StreamBaseChunkSource(baseRecords, baseContent, gate: null);
            }
        }

        try
        {
            await ReadTargetEntriesAsync(
                baseIds,
                targetManifest,
                targetContent,
                hashSuite,
                new TargetChunkBuffer(pool: null),
                progress: null,
                async (chunk, bytes, _) =>
                {
                    EntryChoice choice;

                    if (cache is null)
                    {
                        choice = await ChooseEntryAsync(
                            encoder,
                            baseRecords,
                            source,
                            chunk.Offset,
                            bytes,
                            hashSuite,
                            policy,
                            entryBuffers,
                            cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        // The window is released before the entry is written:
                        // the chosen dictionary was verified from the entry
                        // buffers, which hold a copy.
                        using BaseWindow window = await cache
                            .PrepareAsync(chunk.Offset, cancellationToken)
                            .ConfigureAwait(false);
                        choice = await ChooseEntryAsync(
                            encoder,
                            baseRecords,
                            window,
                            chunk.Offset,
                            bytes,
                            hashSuite,
                            policy,
                            entryBuffers,
                            cancellationToken).ConfigureAwait(false);
                    }

                    // The writer copies or writes the stored bytes before it
                    // returns, so the next chunk may reuse the entry buffers.
                    await writer.AddPayloadEntryAsync(
                        new CspPayloadEntry(
                            chunk.Id,
                            checked((ulong)chunk.Index),
                            choice.Encoding,
                            choice.DictionaryChunkIds),
                        choice.Stored,
                        cancellationToken).ConfigureAwait(false);
                },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            cache?.Dispose();

            if (pool is not null)
            {
                execution.Statistics?.RecordOutstandingBuffers(pool.Outstanding);
            }
        }
    }

    /// <summary>
    /// Reads the target manifest and content in lockstep, verifies every record
    /// against its <see cref="ChunkId"/> and calls <paramref name="onEntry"/> for
    /// each distinct identity the base does not hold, in target first-occurrence
    /// order, then requires the content to end with the manifest. The bytes
    /// passed to <paramref name="onEntry"/> live in <paramref name="buffer"/>
    /// and are valid until it returns unless it detaches them.
    /// </summary>
    private static async Task ReadTargetEntriesAsync(
        HashSet<ChunkId> baseIds,
        Stream targetManifest,
        Stream targetContent,
        HashSuiteId hashSuite,
        TargetChunkBuffer buffer,
        TargetProgress? progress,
        Func<ChunkInfo, ReadOnlyMemory<byte>, TargetChunkBuffer, ValueTask> onEntry,
        CancellationToken cancellationToken)
    {
        var emitted = new HashSet<ChunkId>();

        await using ManifestReader reader = await ManifestReader
            .OpenAsync(targetManifest, cancellationToken)
            .ConfigureAwait(false);

        var batch = new ChunkInfo[ManifestBatchEntries];
        int count;

        while ((count = await reader
            .ReadAsync(batch, cancellationToken)
            .ConfigureAwait(false)) != 0)
        {
            for (int index = 0; index < count; index++)
            {
                ChunkInfo chunk = batch[index];

                if (progress is not null)
                {
                    progress.Index = chunk.Index;
                }

                Memory<byte> bytes = buffer.Get(chunk.Length);
                await ReadExactlyAsync(
                    targetContent,
                    bytes,
                    "The target content ended before the target manifest's declared length.",
                    cancellationToken).ConfigureAwait(false);

                // Every record is checked, including those the base or an
                // earlier entry supplies: the patch must describe the caller's
                // content, not only the chunks it happens to store.
                if (PatchHashing.Hash(hashSuite, bytes.Span) != chunk.Id.Value)
                {
                    throw new InvalidDataException(
                        "The target content does not match the target manifest: " +
                        $"record {chunk.Index} does not hash to its ChunkId.");
                }

                if (baseIds.Contains(chunk.Id) || !emitted.Add(chunk.Id))
                {
                    Advance(progress, chunk);
                    continue;
                }

                if (emitted.Count > CspFormat.DefaultMaximumPayloadEntries)
                {
                    throw new NotSupportedException(
                        "The patch needs more than 1,048,576 payload entries " +
                        "(CSP-V1 section 8, MaximumPayloadEntries).");
                }

                await onEntry(chunk, bytes, buffer).ConfigureAwait(false);
                Advance(progress, chunk);
            }
        }

        if (progress is not null)
        {
            progress.Index = long.MaxValue;
        }

        byte[] probe = new byte[1];
        int trailing = await targetContent
            .ReadAsync(probe, cancellationToken)
            .ConfigureAwait(false);

        if ((uint)trailing > 1u)
        {
            throw new InvalidOperationException(ByteCountMessage);
        }

        if (trailing != 0)
        {
            throw new InvalidDataException(
                "The target content is longer than the target manifest describes.");
        }
    }

    // Once a record is handled, a later failure (the next manifest batch, the
    // next record) comes after it in target order, even when it happens
    // before that record's entry is encoded.
    private static void Advance(TargetProgress? progress, ChunkInfo chunk)
    {
        if (progress is not null)
        {
            progress.Index = chunk.Index + 1;
        }
    }

    private static CspPayloadEncoder? CreateEncoder(CspEncoderPolicy policy) =>
        policy.Level == 0
            ? null
            : new CspPayloadEncoder(
                policy.Level,
                policy.DictionaryLoad,
                policy.DictionaryHashLog,
                policy.DictionaryChainLog);

    /// <summary>Gets whether any entry may try a dictionary, and so read the base.</summary>
    private static bool UsesDictionaries(CspEncoderPolicy policy) =>
        policy.Level != 0 && policy.DictionaryChunks != 0;

    /// <summary>
    /// Chooses one stored form for a target chunk: raw, plain zstd or zstd
    /// over each dictionary candidate in turn, keeping the smallest cost and
    /// the earliest candidate on a tie. The chosen dictionary chunks are
    /// verified against their ChunkIds before they are referenced.
    /// </summary>
    private static async Task<EntryChoice> ChooseEntryAsync(
        CspPayloadEncoder? encoder,
        List<BaseRecord> baseRecords,
        BaseChunkSource? baseChunks,
        long targetOffset,
        ReadOnlyMemory<byte> bytes,
        HashSuiteId hashSuite,
        CspEncoderPolicy policy,
        EntryBuffers buffers,
        CancellationToken cancellationToken)
    {
        var best = new EntryChoice(CspFormat.EncodingRaw, bytes, []);

        if (encoder is null)
        {
            return best;
        }

        int bestCost = bytes.Length;
        ReadOnlySpan<byte> frame = encoder.EncodeZstd(bytes.Span, ReadOnlySpan<byte>.Empty);

        if (frame.Length < bestCost)
        {
            best = new EntryChoice(CspFormat.EncodingZstd, buffers.KeepFrame(frame), []);
            bestCost = frame.Length;
        }

        if (policy.DictionaryChunks == 0 || baseChunks is null)
        {
            return best;
        }

        buffers.EnsureDictionaries();
        bool haveDictionary = false;
        int bestStart = 0;
        int bestCount = 0;

        foreach (int start in FindCandidateStarts(baseRecords, targetOffset, policy))
        {
            if (!TryMeasureCandidate(baseRecords, start, policy, out int count, out int length))
            {
                continue;
            }

            Memory<byte> dictionary = buffers.Candidate.AsMemory(0, length);
            await baseChunks
                .ReadAsync(start, count, dictionary, cancellationToken)
                .ConfigureAwait(false);

            if (!CspDictionary.IsUsable(dictionary.Span))
            {
                continue;
            }

            ReadOnlySpan<byte> dictionaryFrame = encoder.EncodeZstd(bytes.Span, dictionary.Span);
            int cost = dictionaryFrame.Length + (count * CspFormat.DictionaryReferenceSize);

            if (cost < bestCost)
            {
                bestCost = cost;
                best = new EntryChoice(CspFormat.EncodingZstd, buffers.KeepFrame(dictionaryFrame), []);
                buffers.KeepCandidateAsBest();
                haveDictionary = true;
                bestStart = start;
                bestCount = count;
            }
        }

        if (!haveDictionary)
        {
            return best;
        }

        var dictionaryIds = new ChunkId[bestCount];
        int verified = 0;

        for (int index = 0; index < bestCount; index++)
        {
            BaseRecord record = baseRecords[bestStart + index];

            if (PatchHashing.Hash(hashSuite, buffers.Best.AsSpan(verified, record.Length))
                != record.ChunkId.Value)
            {
                throw new InvalidDataException(
                    "The base content does not match the base manifest: a dictionary " +
                    "chunk does not hash to its ChunkId.");
            }

            dictionaryIds[index] = record.ChunkId;
            verified += record.Length;
        }

        return best with { DictionaryChunkIds = dictionaryIds };
    }

    /// <summary>
    /// Measures the candidate that starts at base record <paramref name="start"/>:
    /// up to <see cref="CspEncoderPolicy.DictionaryChunks"/> records, and
    /// <see langword="false"/> when they exceed the CSP dictionary bound, in which
    /// case the candidate is skipped before any of it is read.
    /// </summary>
    internal static bool TryMeasureCandidate(
        List<BaseRecord> records,
        int start,
        CspEncoderPolicy policy,
        out int count,
        out int length)
    {
        count = Math.Min(policy.DictionaryChunks, records.Count - start);
        long total = 0;

        for (int index = start; index < start + count; index++)
        {
            total += records[index].Length;
        }

        length = total > CspDictionary.MaximumBytes ? 0 : (int)total;
        return total <= CspDictionary.MaximumBytes;
    }

    /// <summary>
    /// Returns up to <see cref="CspEncoderPolicy.MaxCandidates"/> base record
    /// indices whose offsets lie within <see cref="CspEncoderPolicy.SearchRadius"/>
    /// of <paramref name="targetOffset"/>, nearest first and lower index first on
    /// a tie.
    /// </summary>
    internal static List<int> FindCandidateStarts(
        List<BaseRecord> records,
        long targetOffset,
        CspEncoderPolicy policy)
    {
        var starts = new List<int>(policy.MaxCandidates);
        int windowStart = FirstAtOrAbove(records, targetOffset - policy.SearchRadius);
        int windowEnd = FirstAtOrAbove(records, targetOffset + policy.SearchRadius + 1);
        int right = FirstAtOrAbove(records, targetOffset);
        int left = right - 1;

        while (starts.Count < policy.MaxCandidates &&
            (left >= windowStart || right < windowEnd))
        {
            bool takeLeft = left >= windowStart &&
                (right >= windowEnd ||
                 targetOffset - records[left].Offset <= records[right].Offset - targetOffset);

            starts.Add(takeLeft ? left-- : right++);
        }

        return starts;
    }

    /// <summary>Returns the first index whose offset is at least <paramref name="value"/>.</summary>
    private static int FirstAtOrAbove(List<BaseRecord> records, long value)
    {
        int low = 0;
        int high = records.Count;

        while (low < high)
        {
            int middle = (low + high) >>> 1;

            if (records[middle].Offset < value)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }

        return low;
    }

    private static async Task ReadExactlyAsync(
        Stream source,
        Memory<byte> destination,
        string endMessage,
        CancellationToken cancellationToken)
    {
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
                throw new InvalidDataException(endMessage);
            }

            written += read;
        }
    }

    private static void ValidatePolicy(CspEncoderPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentOutOfRangeException.ThrowIfLessThan(policy.Level, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(policy.Level, 22);
        ArgumentOutOfRangeException.ThrowIfNegative(policy.DictionaryChunks);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            policy.DictionaryChunks,
            CspFormat.MaximumDictionaryCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(policy.MaxCandidates);
        ArgumentOutOfRangeException.ThrowIfNegative(policy.SearchRadius);

        if (!Enum.IsDefined(policy.DictionaryLoad))
        {
            throw new ArgumentOutOfRangeException(nameof(policy), "Unknown dictionary load mode.");
        }

        ValidateTableLog(policy.DictionaryHashLog);
        ValidateTableLog(policy.DictionaryChainLog);
    }

    private static void ValidateExecution(CspCreateExecution execution)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentOutOfRangeException.ThrowIfNegative(execution.WorkerCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            execution.WorkerCount,
            CspCreateExecution.MaximumWorkerCount);
    }

    // Zero means zstd's choice; otherwise zstd's 64-bit bounds of hashLog and
    // chainLog (6..30).
    private static void ValidateTableLog(int value)
    {
        if (value != 0)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 6);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 30);
        }
    }

    /// <summary>
    /// Buffers <see cref="ChooseEntryAsync"/> reuses across candidates and
    /// chunks: the dictionary being tried, the best dictionary so far (each at
    /// most <see cref="CspDictionary.MaximumBytes"/>) and a copy of the best
    /// frame so far.
    /// </summary>
    private sealed class EntryBuffers
    {
        private byte[] _frame = [];

        internal byte[] Candidate { get; private set; } = [];

        internal byte[] Best { get; private set; } = [];

        /// <summary>
        /// Allocates the exhaustive chooser's scratch and selected dictionary.
        /// </summary>
        internal void EnsureDictionaries()
        {
            if (Candidate.Length == 0)
            {
                Candidate = new byte[CspDictionary.MaximumBytes];
                Best = new byte[CspDictionary.MaximumBytes];
            }
        }

        internal void KeepCandidateAsBest() => (Candidate, Best) = (Best, Candidate);

        /// <summary>Copies <paramref name="frame"/> out of the encoder's buffer.</summary>
        internal ReadOnlyMemory<byte> KeepFrame(ReadOnlySpan<byte> frame)
        {
            if (_frame.Length < frame.Length)
            {
                _frame = new byte[Math.Max(frame.Length, _frame.Length * 2)];
            }

            frame.CopyTo(_frame);
            return _frame.AsMemory(0, frame.Length);
        }
    }

    /// <summary>One base manifest record: its logical offset, length and identity.</summary>
    internal readonly record struct BaseRecord(long Offset, int Length, ChunkId ChunkId);

    /// <summary>The stored form chosen for one target chunk.</summary>
    private readonly record struct EntryChoice(
        byte Encoding,
        ReadOnlyMemory<byte> Stored,
        ChunkId[] DictionaryChunkIds);
}
