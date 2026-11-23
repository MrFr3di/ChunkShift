namespace ChunkShift.Patching.Creation;

/// <summary>
/// Counters of one or more creates, for tests. Every member is
/// updated atomically, so workers may report concurrently.
/// </summary>
internal sealed class CspCreateStatistics
{
    private long _cacheLoads;
    private long _cacheHits;
    private long _cachePeakRecords;
    private long _cachePeakBytes;
    private long _windowPeakEntries;
    private long _windowPeakBytes;
    private long _reorderPeakEntries;
    private long _reorderPeakBytes;
    private long _residualEntries;
    private long _residualBytes;
    private long _outstandingBuffers;

    /// <summary>Gets the base records the cache read from the base content.</summary>
    internal long CacheLoads => Volatile.Read(ref _cacheLoads);

    /// <summary>Gets the base records a candidate window found already cached.</summary>
    internal long CacheHits => Volatile.Read(ref _cacheHits);

    /// <summary>Gets the most records the cache held at once.</summary>
    internal long CachePeakRecords => Volatile.Read(ref _cachePeakRecords);

    /// <summary>Gets the most record bytes the cache held at once.</summary>
    internal long CachePeakBytes => Volatile.Read(ref _cachePeakBytes);

    /// <summary>Gets the most entries the pipeline had in flight at once.</summary>
    internal long WindowPeakEntries => Volatile.Read(ref _windowPeakEntries);

    /// <summary>Gets the most bytes the pipeline had in flight at once.</summary>
    internal long WindowPeakBytes => Volatile.Read(ref _windowPeakBytes);

    /// <summary>Gets the most encoded entries that waited for the writer at once.</summary>
    internal long ReorderPeakEntries => Volatile.Read(ref _reorderPeakEntries);

    /// <summary>Gets the most stored bytes that waited for the writer at once.</summary>
    internal long ReorderPeakBytes => Volatile.Read(ref _reorderPeakBytes);

    /// <summary>
    /// Gets the entries still charged to the pipeline's window when the last
    /// create finished; zero unless an entry was lost.
    /// </summary>
    internal long ResidualEntries => Volatile.Read(ref _residualEntries);

    /// <summary>Gets the bytes still charged to the pipeline's window when the last create finished.</summary>
    internal long ResidualBytes => Volatile.Read(ref _residualBytes);

    /// <summary>
    /// Gets the pooled buffers not returned when the last create finished;
    /// zero unless a buffer's owner lost it.
    /// </summary>
    internal long OutstandingBuffers => Volatile.Read(ref _outstandingBuffers);

    internal void AddCacheLoad() => Interlocked.Increment(ref _cacheLoads);

    internal void AddCacheHit() => Interlocked.Increment(ref _cacheHits);

    internal void ObserveCache(long records, long bytes)
    {
        Raise(ref _cachePeakRecords, records);
        Raise(ref _cachePeakBytes, bytes);
    }

    internal void ObserveWindow(long entries, long bytes)
    {
        Raise(ref _windowPeakEntries, entries);
        Raise(ref _windowPeakBytes, bytes);
    }

    internal void ObserveReorder(long entries, long bytes)
    {
        Raise(ref _reorderPeakEntries, entries);
        Raise(ref _reorderPeakBytes, bytes);
    }

    internal void RecordResidual(long entries, long bytes)
    {
        Volatile.Write(ref _residualEntries, entries);
        Volatile.Write(ref _residualBytes, bytes);
    }

    internal void RecordOutstandingBuffers(long buffers) =>
        Volatile.Write(ref _outstandingBuffers, buffers);

    private static void Raise(ref long peak, long value)
    {
        long current = Volatile.Read(ref peak);

        while (value > current)
        {
            long previous = Interlocked.CompareExchange(ref peak, value, current);

            if (previous == current)
            {
                return;
            }

            current = previous;
        }
    }
}
