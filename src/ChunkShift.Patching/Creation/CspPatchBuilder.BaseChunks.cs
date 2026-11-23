using System.Buffers;
using ChunkShift.Patching.Encoding;

namespace ChunkShift.Patching.Creation;

/// <summary>
/// Where <see cref="ChooseEntryAsync"/> gets the bytes of a dictionary
/// candidate: straight from the base content or from the bounded base-chunk
/// cache.
/// </summary>
internal static partial class CspPatchBuilder
{
    private const string BaseEndMessage =
        "The base content ended before the base manifest's declared length.";

    /// <summary>Copies the bytes of consecutive base records into one dictionary buffer.</summary>
    private abstract class BaseChunkSource
    {
        /// <summary>
        /// Fills <paramref name="destination"/> with base records
        /// <paramref name="start"/> to <paramref name="start"/> + <paramref name="count"/> − 1,
        /// whose lengths sum to its length.
        /// </summary>
        internal abstract ValueTask ReadAsync(
            int start,
            int count,
            Memory<byte> destination,
            CancellationToken cancellationToken);
    }

    /// <summary>
    /// Reads every record of a candidate from the base content with a
    /// <c>Position</c> assignment and a read. With a gate, the
    /// assignment and the read of one record are one critical section, so
    /// workers never move or read the stream at the same time.
    /// </summary>
    private sealed class StreamBaseChunkSource(
        List<BaseRecord> records,
        Stream baseContent,
        SemaphoreSlim? gate) : BaseChunkSource
    {
        internal override async ValueTask ReadAsync(
            int start,
            int count,
            Memory<byte> destination,
            CancellationToken cancellationToken)
        {
            int offset = 0;

            for (int index = start; index < start + count; index++)
            {
                BaseRecord record = records[index];
                Memory<byte> slice = destination.Slice(offset, record.Length);

                if (gate is null)
                {
                    baseContent.Position = record.Offset;
                    await ReadExactlyAsync(baseContent, slice, BaseEndMessage, cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    await gate.WaitAsync(cancellationToken).ConfigureAwait(false);

                    try
                    {
                        baseContent.Position = record.Offset;
                        await ReadExactlyAsync(baseContent, slice, BaseEndMessage, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    finally
                    {
                        _ = gate.Release();
                    }
                }

                offset += record.Length;
            }
        }
    }

    /// <summary>
    /// The buffer the target pass reads each record into. Without a pool it is
    /// one array that grows to the longest record; with a
    /// pool, the pipeline detaches the bytes of an entry, which then belong to
    /// that entry, and the next record gets a fresh pooled array.
    /// </summary>
    private sealed class TargetChunkBuffer(CreateBufferPool? pool)
    {
        private byte[] _array = [];

        internal Memory<byte> Get(int length)
        {
            if (_array.Length < length)
            {
                if (pool is null)
                {
                    _array = new byte[length];
                }
                else
                {
                    Release();
                    _array = pool.Rent(length);
                }
            }

            return _array.AsMemory(0, length);
        }

        /// <summary>Hands the current array to the caller, who must return it to the pool.</summary>
        internal byte[] Detach()
        {
            byte[] array = _array;
            _array = [];
            return array;
        }

        internal void Release()
        {
            if (pool is not null && _array.Length != 0)
            {
                pool.Return(_array);
            }

            _array = [];
        }
    }

    /// <summary>
    /// The arrays of one create: cached base chunks, and in the pipeline the
    /// target bytes of entries in flight and their stored bytes. Private to the
    /// create, so nothing it retains outlives it, and it counts the arrays not
    /// yet returned.
    /// </summary>
    private sealed class CreateBufferPool(int arraysPerBucket)
    {
        private readonly ArrayPool<byte> _pool =
            ArrayPool<byte>.Create(CspDictionary.MaximumBytes, arraysPerBucket);

        private long _outstanding;

        internal long Outstanding => Volatile.Read(ref _outstanding);

        internal byte[] Rent(int length)
        {
            _ = Interlocked.Increment(ref _outstanding);
            return _pool.Rent(length);
        }

        internal void Return(byte[] array)
        {
            _ = Interlocked.Decrement(ref _outstanding);
            _pool.Return(array);
        }
    }

    /// <summary>The target record the pipeline's producer is at, for failure ordering.</summary>
    private sealed class TargetProgress
    {
        private long _index;

        internal long Index
        {
            get => Volatile.Read(ref _index);
            set => Volatile.Write(ref _index, value);
        }
    }

    /// <summary>
    /// Bounded sliding cache of base chunks keyed by base record index.
    /// It holds at most one candidate window, <c>MaxCandidates + K − 1</c>
    /// records: before the records of the next entry are loaded, every record
    /// that entry does not need is evicted. Records are loaded only when a
    /// candidate the uncached pass would read needs them, in its first-read
    /// order, so a truncated or failing base fails on the same record. Not
    /// thread-safe: one caller prepares windows; the windows it hands out may
    /// be read and released on other threads.
    /// </summary>
    private sealed class BaseCandidateCache(
        List<BaseRecord> records,
        Stream baseContent,
        CspEncoderPolicy policy,
        CreateBufferPool pool,
        PipelineWindow? window,
        CspCreateStatistics? statistics) : IDisposable
    {
        private readonly Dictionary<int, CachedBaseChunk> _cached = [];
        private readonly List<int> _needed = [];
        private readonly HashSet<int> _neededSet = [];
        private readonly List<int> _evicted = [];

        // Where the base content is after the cache's last read, or -1 when
        // that is not known; a record that starts there needs no seek.
        private long _position = -1;
        private long _cachedBytes;

        /// <summary>
        /// Loads the records the candidates of an entry at
        /// <paramref name="targetOffset"/> need and returns a window that
        /// references them until it is disposed.
        /// </summary>
        internal async ValueTask<BaseWindow> PrepareAsync(
            long targetOffset,
            CancellationToken cancellationToken)
        {
            _needed.Clear();
            _neededSet.Clear();
            int first = int.MaxValue;
            int last = -1;

            foreach (int start in FindCandidateStarts(records, targetOffset, policy))
            {
                if (!TryMeasureCandidate(records, start, policy, out int count, out _))
                {
                    continue;
                }

                for (int index = start; index < start + count; index++)
                {
                    if (_neededSet.Add(index))
                    {
                        _needed.Add(index);
                        first = Math.Min(first, index);
                        last = Math.Max(last, index);
                    }
                }
            }

            foreach (int index in _cached.Keys)
            {
                if (!_neededSet.Contains(index))
                {
                    _evicted.Add(index);
                }
            }

            foreach (int index in _evicted)
            {
                Evict(index);
            }

            _evicted.Clear();

            var baseWindow = new BaseWindow(
                first,
                new CachedBaseChunk?[_needed.Count == 0 ? 0 : last - first + 1]);

            try
            {
                foreach (int index in _needed)
                {
                    if (_cached.TryGetValue(index, out CachedBaseChunk? chunk))
                    {
                        statistics?.AddCacheHit();
                    }
                    else
                    {
                        chunk = await LoadAsync(index, cancellationToken).ConfigureAwait(false);
                        _cached.Add(index, chunk);
                        _cachedBytes += chunk.Length;
                        statistics?.AddCacheLoad();
                        statistics?.ObserveCache(_cached.Count, _cachedBytes);
                    }

                    baseWindow.Add(index, chunk);
                }
            }
            catch
            {
                baseWindow.Dispose();
                throw;
            }

            return baseWindow;
        }

        /// <summary>Evicts every record; windows still in use keep theirs alive.</summary>
        public void Dispose()
        {
            _evicted.AddRange(_cached.Keys);

            foreach (int index in _evicted)
            {
                Evict(index);
            }

            _evicted.Clear();
        }

        private async ValueTask<CachedBaseChunk> LoadAsync(int index, CancellationToken cancellationToken)
        {
            BaseRecord record = records[index];
            byte[] bytes = pool.Rent(record.Length);

            try
            {
                if (_position != record.Offset)
                {
                    baseContent.Position = record.Offset;
                }

                _position = -1;
                await ReadExactlyAsync(
                    baseContent,
                    bytes.AsMemory(0, record.Length),
                    BaseEndMessage,
                    cancellationToken).ConfigureAwait(false);
                _position = record.Offset + record.Length;
            }
            catch
            {
                pool.Return(bytes);
                throw;
            }

            return new CachedBaseChunk(bytes, record.Length, pool);
        }

        private void Evict(int index)
        {
            CachedBaseChunk chunk = _cached[index];
            _ = _cached.Remove(index);
            _cachedBytes -= chunk.Length;
            chunk.Evict(window);
        }
    }

    /// <summary>
    /// One cached base record. Its bytes never change while it lives; it is
    /// freed when the cache has evicted it and no window references it.
    /// </summary>
    private sealed class CachedBaseChunk(byte[] bytes, int length, CreateBufferPool pool)
    {
        // The cache's own reference.
        private int _references = 1;
        private PipelineWindow? _pinnedIn;

        internal int Length => length;

        internal ReadOnlySpan<byte> Span => bytes.AsSpan(0, length);

        internal void AddReference() => _ = Interlocked.Increment(ref _references);

        /// <summary>
        /// Drops the cache's reference. In the pipeline, bytes that only
        /// in-flight entries still reference count against the window until
        /// the last of them lets go.
        /// </summary>
        internal void Evict(PipelineWindow? window)
        {
            if (window is not null)
            {
                Volatile.Write(ref _pinnedIn, window);
                window.Charge(length);
            }

            Release();
        }

        internal void Release()
        {
            if (Interlocked.Decrement(ref _references) == 0)
            {
                Volatile.Read(ref _pinnedIn)?.Charge(-length);
                pool.Return(bytes);
            }
        }
    }

    /// <summary>
    /// The cached records one entry's candidates read, by base record index;
    /// the dictionary source of a cached pass. Disposing it releases them.
    /// </summary>
    private sealed class BaseWindow(int first, CachedBaseChunk?[] chunks) : BaseChunkSource, IDisposable
    {
        private bool _disposed;

        internal void Add(int index, CachedBaseChunk chunk)
        {
            chunk.AddReference();
            chunks[index - first] = chunk;
        }

        internal override ValueTask ReadAsync(
            int start,
            int count,
            Memory<byte> destination,
            CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Span<byte> span = destination.Span;
            int offset = 0;

            for (int index = start; index < start + count; index++)
            {
                CachedBaseChunk chunk = chunks[index - first]
                    ?? throw new InvalidOperationException("A candidate needs a base record its window did not load.");
                chunk.Span.CopyTo(span[offset..]);
                offset += chunk.Length;
            }

            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            for (int index = 0; index < chunks.Length; index++)
            {
                chunks[index]?.Release();
                chunks[index] = null;
            }
        }
    }
}
