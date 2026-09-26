namespace ChunkShift.Chunking;

internal readonly record struct ChunkBoundaryScanResult(
    int Consumed,
    int CompletedChunkLength)
{
    internal bool HasBoundary => CompletedChunkLength != 0;
}

/// <summary>
/// Incremental, payload-agnostic boundary state shared by streaming consumers.
/// </summary>
internal struct ChunkBoundaryState
{
    private readonly ChunkingKernelProfile _profile;
    private int _chunkLength;
    private ulong _gearHash;

    internal ChunkBoundaryState(ChunkingKernelProfile profile)
    {
        if (profile.Maximum <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(profile),
                "Chunking profile maximum must be positive.");
        }

        if (profile.Kind != ChunkingKernelKind.Fixed &&
            profile.Kind != ChunkingKernelKind.FastCdcGearV1)
        {
            throw new InvalidOperationException(
                $"Unsupported chunking kernel '{profile.Kind}'.");
        }

        _profile = profile;
        _chunkLength = 0;
        _gearHash = 0;
    }

    internal int PendingChunkLength => _chunkLength;

    /// <summary>
    /// Consumes as much of <paramref name="source"/> as possible until the next boundary.
    /// A FastCDC predicate may complete the pending chunk before source[0], in which case
    /// Consumed is zero and the caller must retry the same source after handling the boundary.
    /// </summary>
    internal ChunkBoundaryScanResult Scan(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return default;
        }

        if (_profile.Kind == ChunkingKernelKind.Fixed)
        {
            int consumed = Math.Min(_profile.Target - _chunkLength, source.Length);
            _chunkLength += consumed;

            if (_chunkLength == _profile.Target)
            {
                int completed = _chunkLength;
                _chunkLength = 0;
                return new ChunkBoundaryScanResult(consumed, completed);
            }

            return new ChunkBoundaryScanResult(consumed, 0);
        }

        return ScanFastCdc(source);
    }

    /// <summary>
    /// FastCDC boundary scan with the same predicate and cut convention as
    /// <see cref="FastCdcScalar.FindCut"/>. The state lives in locals for the
    /// whole call (this struct is hoisted into an async state machine, where
    /// field access per byte is a load/store through a reference), the unhashed
    /// prefix [0, Minimum) is skipped without a per-byte loop, and the strict and
    /// relaxed ranges run as separate loops with bounds computed once, so the
    /// per-byte work is one gear step and one mask test.
    /// </summary>
    private ChunkBoundaryScanResult ScanFastCdc(ReadOnlySpan<byte> source)
    {
        FastCdcProfile fastCdc = _profile.FastCdc;
        int chunkLength = _chunkLength;
        ulong gearHash = _gearHash;
        int index = 0;

        if (chunkLength < fastCdc.Minimum)
        {
            // Minimum < Maximum, so the prefix never completes a chunk.
            int skipped = Math.Min(fastCdc.Minimum - chunkLength, source.Length);
            chunkLength += skipped;
            index = skipped;
        }

        if (chunkLength < fastCdc.Target)
        {
            // Bytes at chunk-relative positions [chunkLength, Target) use the strict mask.
            int end = index + Math.Min(fastCdc.Target - chunkLength, source.Length - index);
            ulong strictMask = fastCdc.StrictMask;

            for (int i = index; i < end; i++)
            {
                gearHash = unchecked((gearHash << 1) + FastCdcGearTable.Get(source[i]));

                if ((gearHash & strictMask) == 0)
                {
                    // The candidate participates in the predicate for the previous
                    // chunk but belongs to the next chunk by the v1 cut convention.
                    return CompleteAt(i, chunkLength + (i - index));
                }
            }

            chunkLength += end - index;
            index = end;
        }

        if (chunkLength >= fastCdc.Target)
        {
            // Bytes at positions [Target, Maximum) use the relaxed mask; a chunk
            // that reaches Maximum without a cut is forced.
            int end = index + Math.Min(fastCdc.Maximum - chunkLength, source.Length - index);
            ulong relaxedMask = fastCdc.RelaxedMask;

            for (int i = index; i < end; i++)
            {
                gearHash = unchecked((gearHash << 1) + FastCdcGearTable.Get(source[i]));

                if ((gearHash & relaxedMask) == 0)
                {
                    return CompleteAt(i, chunkLength + (i - index));
                }
            }

            chunkLength += end - index;
            index = end;

            if (chunkLength == fastCdc.Maximum)
            {
                return CompleteAt(index, chunkLength);
            }
        }

        _chunkLength = chunkLength;
        _gearHash = gearHash;
        return new ChunkBoundaryScanResult(index, 0);
    }

    private ChunkBoundaryScanResult CompleteAt(int consumed, int completed)
    {
        _chunkLength = 0;
        _gearHash = 0;
        return new ChunkBoundaryScanResult(consumed, completed);
    }

    internal int Finish()
    {
        int completed = _chunkLength;
        _chunkLength = 0;
        _gearHash = 0;
        return completed;
    }
}
