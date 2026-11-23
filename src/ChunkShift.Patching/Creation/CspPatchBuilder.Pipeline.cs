using System.Runtime.ExceptionServices;
using System.Threading.Channels;
using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Creation;

/// <summary>
/// The ordered encode pipeline of a parallel create: one producer reads
/// and verifies the target exactly as the sequential pass does, W workers
/// choose each entry's stored form with encoders of their own, and the caller's
/// flow writes the entries strictly in first-occurrence order.
/// </summary>
internal static partial class CspPatchBuilder
{
    private static async Task WritePayloadInParallelAsync(
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
        int workerCount = execution.WorkerCount;
        int windowEntries = checked(workerCount * execution.WindowEntriesPerWorker);
        CspCreateStatistics? statistics = execution.Statistics;
        bool readsBase = baseContent is not null && UsesDictionaries(policy);

        var pool = new CreateBufferPool(windowEntries + policy.MaxCandidates + policy.DictionaryChunks + 8);
        var window = new PipelineWindow(
            windowEntries,
            checked(workerCount * execution.WindowBytesPerWorker),
            statistics);
        var reorder = new ReorderWindow(statistics);
        var progress = new TargetProgress();
        var workers = new WorkerState[workerCount];
        var channel = Channel.CreateBounded<WorkItem>(new BoundedChannelOptions(windowEntries)
        {
            SingleWriter = true,
            SingleReader = false,
            FullMode = BoundedChannelFullMode.Wait,
        });

        // Cancelled on the caller's request, on the first failure and when the
        // writer stops: the producer never has work before any of those.
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var failure = new PipelineFailure(stop, workers, window);

        for (int index = 0; index < workers.Length; index++)
        {
            workers[index] = new WorkerState(cancellationToken);
        }

        // With the cache, only the producer reads the base. Without it, the
        // workers share the stream, one seek and read at a time.
        BaseCandidateCache? cache = readsBase && execution.UseBaseCandidateCache
            ? new BaseCandidateCache(baseRecords, baseContent!, policy, pool, window, statistics)
            : null;
        using SemaphoreSlim? gate = readsBase && cache is null ? new SemaphoreSlim(1, 1) : null;
        BaseChunkSource? shared = gate is null
            ? null
            : new StreamBaseChunkSource(baseRecords, baseContent!, gate);

        var context = new PipelineContext(
            baseRecords,
            hashSuite,
            policy,
            execution,
            pool,
            window,
            reorder,
            failure,
            shared);

        Task producer = Task.Run(() => ProduceAsync(
            context,
            baseIds,
            targetManifest,
            targetContent,
            cache,
            progress,
            channel.Writer,
            stop.Token), CancellationToken.None);
        var tasks = new Task[workerCount + 1];
        tasks[0] = producer;

        for (int index = 0; index < workerCount; index++)
        {
            WorkerState state = workers[index];
            tasks[index + 1] = Task.Run(
                () => WorkAsync(context, state, channel.Reader),
                CancellationToken.None);
        }

        bool stopped = false;

        try
        {
            stopped = await ConsumeAsync(writer, reorder, window, pool, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            // Everything still in flight comes after the last written entry.
            failure.StopAll();
            await Task.WhenAll(tasks).ConfigureAwait(false);

            while (channel.Reader.TryRead(out WorkItem? item))
            {
                ReleaseItem(item, context);
                window.Release(1, 0);
            }

            reorder.ReleaseAll(window, pool);
            cache?.Dispose();

            foreach (WorkerState state in workers)
            {
                state.Dispose();
            }

            statistics?.RecordResidual(window.Entries, window.Bytes);
            statistics?.RecordOutstandingBuffers(pool.Outstanding);
        }

        cancellationToken.ThrowIfCancellationRequested();
        failure.ThrowIfRecorded();

        if (stopped)
        {
            throw new InvalidOperationException("The create pipeline stopped without a failure.");
        }
    }

    /// <summary>
    /// Writes the encoded entries in sequence order until the producer's last
    /// one, or until an entry did not complete; returns whether it stopped
    /// early. A writer failure propagates at once, as in the sequential pass.
    /// </summary>
    private static async Task<bool> ConsumeAsync(
        CspWriter writer,
        ReorderWindow reorder,
        PipelineWindow window,
        CreateBufferPool pool,
        CancellationToken cancellationToken)
    {
        for (long sequence = 0; ; sequence++)
        {
            EntryOutcome? outcome = await reorder
                .TakeAsync(sequence, cancellationToken)
                .ConfigureAwait(false);

            if (outcome is null)
            {
                return false;
            }

            if (ReferenceEquals(outcome, EntryOutcome.Aborted))
            {
                // Not an entry: the real one is still queued or posted and is
                // released with them.
                return true;
            }

            try
            {
                if (!outcome.Completed)
                {
                    return true;
                }

                // The writer copies or writes the stored bytes before it
                // returns, so the buffer goes back to the pool afterwards.
                await writer.AddPayloadEntryAsync(
                    new CspPayloadEntry(
                        outcome.ChunkId,
                        checked((ulong)outcome.Position),
                        outcome.Encoding,
                        outcome.DictionaryChunkIds),
                    outcome.Stored,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                outcome.Release(pool);
                window.Release(1, outcome.Length);
            }
        }
    }

    /// <summary>
    /// Reads and verifies the target, admits each entry into the window, loads
    /// its candidates' base records into the cache, if any, and queues it. Never throws: a failure
    /// is recorded at the target record it happened at.
    /// </summary>
    private static async Task ProduceAsync(
        PipelineContext context,
        HashSet<ChunkId> baseIds,
        Stream targetManifest,
        Stream targetContent,
        BaseCandidateCache? cache,
        TargetProgress progress,
        ChannelWriter<WorkItem> queue,
        CancellationToken stop)
    {
        var buffer = new TargetChunkBuffer(context.Pool);
        long sequence = 0;

        try
        {
            await ReadTargetEntriesAsync(
                baseIds,
                targetManifest,
                targetContent,
                context.HashSuite,
                buffer,
                progress,
                async (chunk, _, target) =>
                {
                    await context.Window.WaitAsync(stop).ConfigureAwait(false);

                    BaseWindow? baseWindow = cache is null
                        ? null
                        : await cache.PrepareAsync(chunk.Offset, stop).ConfigureAwait(false);
                    var item = new WorkItem(sequence, chunk, target.Detach(), baseWindow);
                    context.Window.Admit(chunk.Length);

                    try
                    {
                        await queue.WriteAsync(item, stop).ConfigureAwait(false);
                    }
                    catch
                    {
                        ReleaseItem(item, context);
                        context.Window.Release(1, 0);
                        throw;
                    }

                    sequence++;
                },
                stop).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            // Stopped by the caller, by a failure before this record or by the
            // writer; none of them needs this record.
        }
        catch (Exception exception)
        {
            context.Failure.Record(progress.Index, exception);
        }
        finally
        {
            buffer.Release();
            _ = queue.TryComplete();
            context.Reorder.CompleteProduction(sequence);
        }
    }

    /// <summary>
    /// One encode worker: its own encoder and entry buffers, one entry at a
    /// time. Never throws: every item it takes posts exactly one outcome.
    /// </summary>
    private static async Task WorkAsync(
        PipelineContext context,
        WorkerState state,
        ChannelReader<WorkItem> queue)
    {
        try
        {
            using CspPayloadEncoder? encoder = CreateEncoder(context.Policy);
            var buffers = new EntryBuffers();

            // The producer always completes the queue, so waiting needs no token.
            while (await queue.WaitToReadAsync(CancellationToken.None).ConfigureAwait(false))
            {
                while (queue.TryRead(out WorkItem? item))
                {
                    context.Reorder.Post(
                        item.Sequence,
                        await EncodeAsync(context, state, encoder, buffers, item).ConfigureAwait(false));
                }
            }
        }
        catch (Exception exception)
        {
            // A worker that cannot run (its encoder could not be created)
            // fails the create before any entry, as the sequential pass would,
            // and the writer stops instead of waiting for its entries.
            context.Failure.Record(long.MinValue, exception);
            context.Reorder.Abort();
        }
    }

    private static async Task<EntryOutcome> EncodeAsync(
        PipelineContext context,
        WorkerState state,
        CspPayloadEncoder? encoder,
        EntryBuffers buffers,
        WorkItem item)
    {
        long position = item.Chunk.Index;

        if (!context.Failure.TryBegin(state, position))
        {
            ReleaseItem(item, context);
            return EntryOutcome.NotCompleted(position);
        }

        try
        {
            CancellationToken cancellationToken = state.Token;
            cancellationToken.ThrowIfCancellationRequested();

            if (context.Execution.WorkerDelay is { } delay)
            {
                await delay(item.Sequence, cancellationToken).ConfigureAwait(false);
            }

            int length = item.Chunk.Length;
            EntryChoice choice = await ChooseEntryAsync(
                encoder,
                context.BaseRecords,
                (BaseChunkSource?)item.BaseWindow ?? context.SharedBase,
                item.Chunk.Offset,
                item.Target.AsMemory(0, length),
                context.HashSuite,
                context.Policy,
                buffers,
                cancellationToken).ConfigureAwait(false);

            item.BaseWindow?.Dispose();

            byte[] stored;

            if (choice.Encoding == CspFormat.EncodingRaw)
            {
                // The raw form is the target bytes themselves: the entry keeps them.
                stored = item.Target;
            }
            else
            {
                stored = context.Pool.Rent(choice.Stored.Length);
                choice.Stored.CopyTo(stored);
                context.Pool.Return(item.Target);
                context.Window.Charge(choice.Stored.Length - (long)length);
            }

            return new EntryOutcome(
                position,
                item.Chunk.Id,
                choice.Encoding,
                choice.DictionaryChunkIds,
                stored,
                choice.Stored.Length);
        }
        catch (OperationCanceledException) when (state.Token.IsCancellationRequested)
        {
            // Cancelled by the caller or by a failure before this entry.
            ReleaseItem(item, context);
            return EntryOutcome.NotCompleted(position);
        }
        catch (Exception exception)
        {
            ReleaseItem(item, context);
            context.Failure.Record(position, exception);
            return EntryOutcome.NotCompleted(position);
        }
        finally
        {
            context.Failure.End(state);
        }
    }

    /// <summary>
    /// Returns a work item's target bytes and releases its base window; its
    /// window entry stays charged until its outcome is taken or dropped.
    /// </summary>
    private static void ReleaseItem(WorkItem item, PipelineContext context)
    {
        item.BaseWindow?.Dispose();
        context.Pool.Return(item.Target);
        context.Window.Charge(-(long)item.Chunk.Length);
    }

    private sealed record PipelineContext(
        List<BaseRecord> BaseRecords,
        HashSuiteId HashSuite,
        CspEncoderPolicy Policy,
        CspCreateExecution Execution,
        CreateBufferPool Pool,
        PipelineWindow Window,
        ReorderWindow Reorder,
        PipelineFailure Failure,
        BaseChunkSource? SharedBase);

    /// <summary>One distinct missing target chunk; it owns its target bytes.</summary>
    private sealed record WorkItem(long Sequence, ChunkInfo Chunk, byte[] Target, BaseWindow? BaseWindow);

    /// <summary>
    /// The result of one work item: an encoded entry that owns its stored
    /// bytes, or an entry that did not complete (failed or cancelled).
    /// </summary>
    private sealed class EntryOutcome
    {
        private byte[]? _buffer;

        internal EntryOutcome(
            long position,
            ChunkId chunkId,
            byte encoding,
            ChunkId[] dictionaryChunkIds,
            byte[]? buffer,
            int length)
        {
            Position = position;
            ChunkId = chunkId;
            Encoding = encoding;
            DictionaryChunkIds = dictionaryChunkIds;
            Completed = buffer is not null;
            Length = buffer is null ? 0 : length;
            _buffer = buffer;
        }

        internal long Position { get; }

        internal bool Completed { get; }

        internal ChunkId ChunkId { get; }

        internal byte Encoding { get; }

        internal ChunkId[] DictionaryChunkIds { get; }

        /// <summary>Gets the stored length, which stays charged to the window until the outcome is released.</summary>
        internal int Length { get; }

        internal ReadOnlyMemory<byte> Stored =>
            _buffer is null ? ReadOnlyMemory<byte>.Empty : _buffer.AsMemory(0, Length);

        /// <summary>Gets the stand-in the reorder window returns once a worker has stopped.</summary>
        internal static EntryOutcome Aborted { get; } = NotCompleted(long.MinValue);

        internal static EntryOutcome NotCompleted(long position) =>
            new(position, default, 0, [], null, 0);

        internal void Release(CreateBufferPool pool)
        {
            if (_buffer is not null)
            {
                pool.Return(_buffer);
                _buffer = null;
            }
        }
    }

    /// <summary>A worker's cancellation and the target position of the entry it encodes.</summary>
    private sealed class WorkerState(CancellationToken cancellationToken) : IDisposable
    {
        private readonly CancellationTokenSource _cancellation =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        internal const long Idle = long.MinValue;

        internal long Position { get; set; } = Idle;

        internal CancellationToken Token => _cancellation.Token;

        internal void Cancel() => _cancellation.Cancel();

        public void Dispose() => _cancellation.Dispose();
    }

    /// <summary>
    /// The first failure in target order. Recording a failure stops the
    /// producer and cancels every worker whose entry comes after it; entries
    /// before it finish, because one of them may fail first in target order,
    /// and that is the failure the sequential pass reports.
    /// </summary>
    private sealed class PipelineFailure(
        CancellationTokenSource stop,
        WorkerState[] workers,
        PipelineWindow window)
    {
        private readonly Lock _lock = new();
        private readonly List<WorkerState> _cancel = [];
        private long _position = long.MaxValue;
        private ExceptionDispatchInfo? _failure;

        /// <summary>Starts an entry unless a failure before it was recorded.</summary>
        internal bool TryBegin(WorkerState state, long position)
        {
            lock (_lock)
            {
                if (_failure is not null && position > _position)
                {
                    return false;
                }

                state.Position = position;
                return true;
            }
        }

        internal void End(WorkerState state)
        {
            lock (_lock)
            {
                state.Position = WorkerState.Idle;
            }
        }

        internal void Record(long position, Exception exception)
        {
            List<WorkerState> cancel;

            lock (_lock)
            {
                if (_failure is not null && position >= _position)
                {
                    return;
                }

                _position = position;
                _failure = ExceptionDispatchInfo.Capture(exception);
                _cancel.Clear();

                foreach (WorkerState state in workers)
                {
                    if (state.Position > position)
                    {
                        _cancel.Add(state);
                    }
                }

                cancel = [.. _cancel];
            }

            // Cancellation callbacks run outside the lock.
            stop.Cancel();

            foreach (WorkerState state in cancel)
            {
                state.Cancel();
            }

            window.Wake();
        }

        /// <summary>Stops the producer and every worker once nothing more will be written.</summary>
        internal void StopAll()
        {
            stop.Cancel();

            foreach (WorkerState state in workers)
            {
                state.Cancel();
            }

            window.Wake();
        }

        internal void ThrowIfRecorded()
        {
            ExceptionDispatchInfo? failure;

            lock (_lock)
            {
                failure = _failure;
            }

            failure?.Throw();
        }
    }

    /// <summary>
    /// The pipeline's admission bound: entries in flight (queued, encoding,
    /// or encoded and not yet written) and their bytes. The producer waits
    /// while both are not below their limits and something is in flight.
    /// </summary>
    private sealed class PipelineWindow(int maximumEntries, long maximumBytes, CspCreateStatistics? statistics)
    {
        private readonly Lock _lock = new();
        private long _entries;
        private long _bytes;
        private TaskCompletionSource? _waiter;

        internal long Entries
        {
            get
            {
                lock (_lock)
                {
                    return _entries;
                }
            }
        }

        internal long Bytes
        {
            get
            {
                lock (_lock)
                {
                    return _bytes;
                }
            }
        }

        internal async ValueTask WaitAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                TaskCompletionSource waiter;

                lock (_lock)
                {
                    if (_entries == 0 || (_entries < maximumEntries && _bytes < maximumBytes))
                    {
                        return;
                    }

                    waiter = _waiter ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                }

                await waiter.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        internal void Admit(long bytes)
        {
            lock (_lock)
            {
                _entries++;
                _bytes += bytes;
                statistics?.ObserveWindow(_entries, _bytes);
            }
        }

        /// <summary>Adds (or, when negative, removes) bytes of entries in flight.</summary>
        internal void Charge(long bytes)
        {
            if (bytes > 0)
            {
                lock (_lock)
                {
                    _bytes += bytes;
                    statistics?.ObserveWindow(_entries, _bytes);
                }
            }
            else if (bytes < 0)
            {
                Release(0, -bytes);
            }
        }

        internal void Release(long entries, long bytes)
        {
            TaskCompletionSource? waiter;

            lock (_lock)
            {
                _entries -= entries;
                _bytes -= bytes;
                waiter = _waiter;
                _waiter = null;
            }

            waiter?.TrySetResult();
        }

        internal void Wake() => Release(0, 0);
    }

    /// <summary>
    /// Encoded entries waiting for the writer, by sequence number. Its size is
    /// bounded by the pipeline window, and its peak is recorded in the statistics.
    /// </summary>
    private sealed class ReorderWindow(CspCreateStatistics? statistics)
    {
        private readonly Lock _lock = new();
        private readonly Dictionary<long, EntryOutcome> _outcomes = [];
        private long _bytes;
        private long _produced = -1;
        private long _awaited = -1;
        private bool _aborted;
        private TaskCompletionSource? _waiter;

        internal void Post(long sequence, EntryOutcome outcome)
        {
            TaskCompletionSource? waiter = null;

            lock (_lock)
            {
                _outcomes.Add(sequence, outcome);
                _bytes += outcome.Length;
                statistics?.ObserveReorder(_outcomes.Count, _bytes);

                if (sequence == _awaited)
                {
                    waiter = _waiter;
                    _waiter = null;
                }
            }

            waiter?.TrySetResult();
        }

        /// <summary>Records that the producer queued <paramref name="count"/> entries in all.</summary>
        internal void CompleteProduction(long count)
        {
            TaskCompletionSource? waiter;

            lock (_lock)
            {
                _produced = count;
                waiter = _waiter;
                _waiter = null;
            }

            waiter?.TrySetResult();
        }

        /// <summary>
        /// Makes every entry the writer still waits for read as not completed,
        /// because a worker stopped and may never post it.
        /// </summary>
        internal void Abort()
        {
            TaskCompletionSource? waiter;

            lock (_lock)
            {
                _aborted = true;
                waiter = _waiter;
                _waiter = null;
            }

            waiter?.TrySetResult();
        }

        /// <summary>
        /// Returns the outcome of entry <paramref name="sequence"/>, or
        /// <see langword="null"/> once the producer is done and queued no such entry.
        /// </summary>
        internal async ValueTask<EntryOutcome?> TakeAsync(long sequence, CancellationToken cancellationToken)
        {
            while (true)
            {
                TaskCompletionSource waiter;

                lock (_lock)
                {
                    if (_outcomes.Remove(sequence, out EntryOutcome? outcome))
                    {
                        _bytes -= outcome.Length;
                        return outcome;
                    }

                    if (_produced >= 0 && sequence >= _produced)
                    {
                        return null;
                    }

                    if (_aborted)
                    {
                        return EntryOutcome.Aborted;
                    }

                    _awaited = sequence;
                    waiter = _waiter ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                }

                await waiter.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        internal void ReleaseAll(PipelineWindow window, CreateBufferPool pool)
        {
            lock (_lock)
            {
                foreach (EntryOutcome outcome in _outcomes.Values)
                {
                    outcome.Release(pool);
                    window.Release(1, outcome.Length);
                }

                _outcomes.Clear();
                _bytes = 0;
            }
        }
    }
}
