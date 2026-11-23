using System.IO.Pipelines;

namespace ChunkShift.Patching.Application;

/// <summary>
/// Runs a re-chunk check concurrently with the reconstruction it checks
/// (<see cref="ChunkingCheck.Overlapped"/>).
/// </summary>
/// <remarks>
/// <para>
/// The reconstruction hands every verified chunk to <see cref="WriteAsync"/>
/// in target order, the order it writes them to the temporary file. The chunks
/// pass through a <see cref="Pipe"/> whose reader side is the content stream of
/// the check, which runs on the thread pool from <see cref="Start"/> on. The
/// check therefore sees exactly the bytes of the temporary file without reading
/// it back.
/// </para>
/// <para>
/// Memory: the writer waits while <see cref="PauseBytes"/> or more bytes are
/// unread, so the pipe holds at most <see cref="PauseBytes"/> plus the chunk
/// being written, in segments of <see cref="SegmentBytes"/>.
/// </para>
/// <para>
/// A check that ends before the content does (an unregistered profile, a
/// profile fingerprint mismatch, a failure) completes the pipe's reader;
/// later chunks are then dropped instead of blocking the reconstruction.
/// <see cref="CompleteAsync"/> ends the content and returns the check's
/// outcome. Disposal without it (a reconstruction failure, an exception,
/// cancellation) cancels the check and waits for it, so the check never
/// outlives the apply call; its outcome is then discarded, because the
/// reconstruction's own failure takes precedence (CSP-V1 section 6).
/// </para>
/// </remarks>
internal sealed class OverlappedChunkingCheck : IAsyncDisposable
{
    /// <summary>Unread bytes at which the writer waits for the check.</summary>
    internal const int PauseBytes = 1024 * 1024;

    /// <summary>Unread bytes at which a waiting writer resumes.</summary>
    internal const int ResumeBytes = PauseBytes / 2;

    /// <summary>Size of the pooled segments the pipe buffers in.</summary>
    internal const int SegmentBytes = 64 * 1024;

    private readonly Pipe _pipe;
    private readonly CancellationTokenSource _cancellation;
    private readonly Task<bool> _check;
    private bool _accepting = true;
    private bool _contentEnded;

    private OverlappedChunkingCheck(
        Func<Stream, CancellationToken, Task<bool>> check,
        CancellationToken cancellationToken)
    {
        _pipe = new Pipe(new PipeOptions(
            pauseWriterThreshold: PauseBytes,
            resumeWriterThreshold: ResumeBytes,
            minimumSegmentSize: SegmentBytes,
            useSynchronizationContext: false));
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        CancellationToken checkToken = _cancellation.Token;
        _check = Task.Run(() => RunAsync(check, checkToken), CancellationToken.None);
    }

    /// <summary>
    /// Starts <paramref name="check"/> over the content this instance will be
    /// fed. The check returns whether the content passed.
    /// </summary>
    internal static OverlappedChunkingCheck Start(
        Func<Stream, CancellationToken, Task<bool>> check,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(check);

        return new OverlappedChunkingCheck(check, cancellationToken);
    }

    /// <summary>
    /// Copies the next verified chunk into the pipe, waiting while the check
    /// has <see cref="PauseBytes"/> or more unread. The caller may reuse
    /// <paramref name="chunk"/> as soon as the call returns.
    /// </summary>
    internal async ValueTask WriteAsync(
        ReadOnlyMemory<byte> chunk,
        CancellationToken cancellationToken)
    {
        if (!_accepting)
        {
            return;
        }

        FlushResult result = await _pipe.Writer
            .WriteAsync(chunk, cancellationToken)
            .ConfigureAwait(false);

        if (result.IsCompleted)
        {
            // The check stopped reading; it needs no more content.
            _accepting = false;
        }
    }

    /// <summary>
    /// Ends the content after the last chunk. The check then finishes on its
    /// own while the caller does other work; <see cref="CompleteAsync"/>
    /// returns its outcome.
    /// </summary>
    internal ValueTask EndContentAsync() => EndContentAsync(error: null);

    /// <summary>
    /// Ends the content if <see cref="EndContentAsync()"/> did not, and returns
    /// whether the check passed. An exception of the check is rethrown here.
    /// </summary>
    internal async Task<bool> CompleteAsync()
    {
        await EndContentAsync(error: null).ConfigureAwait(false);
        return await _check.ConfigureAwait(false);
    }

    /// <summary>
    /// Cancels a check that is still running, waits for it and releases the
    /// pipe. Its outcome and exception are discarded.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (!_check.IsCompleted)
        {
            await _cancellation.CancelAsync().ConfigureAwait(false);
        }

        // A check that is not cancelled in time must not see a clean end of
        // an incomplete reconstruction.
        await EndContentAsync(
            new OperationCanceledException("The reconstruction ended before its last chunk."))
            .ConfigureAwait(false);

        try
        {
            _ = await _check.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Superseded: disposal without CompleteAsync means the apply
            // already has an outcome of its own.
        }

        _cancellation.Dispose();
    }

    private async ValueTask EndContentAsync(Exception? error)
    {
        if (_contentEnded)
        {
            return;
        }

        _contentEnded = true;
        await _pipe.Writer.CompleteAsync(error).ConfigureAwait(false);
    }

    private async Task<bool> RunAsync(
        Func<Stream, CancellationToken, Task<bool>> check,
        CancellationToken cancellationToken)
    {
        // Disposing the stream completes the pipe's reader, which releases a
        // waiting writer and turns later writes into no-ops.
        Stream content = _pipe.Reader.AsStream();

        await using (content.ConfigureAwait(false))
        {
            return await check(content, cancellationToken).ConfigureAwait(false);
        }
    }
}
