using ChunkShift.Patching.Application;
using ChunkShift.Patching.Tests.Format;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// The pipe between the reconstruction and the overlapped re-chunk check
/// (<see cref="ChunkingCheck.Overlapped"/>): order, memory bound, early and failing
/// checks, cancellation and disposal.
/// </summary>
public sealed class OverlappedChunkingCheckTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task Content_ReachesTheCheckInWriteOrder()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(3 * 1024 * 1024 + 17, 0x5EED7001u);
        byte[]? seen = null;

        await using OverlappedChunkingCheck check = OverlappedChunkingCheck.Start(
            async (stream, token) =>
            {
                using var copy = new MemoryStream();
                await stream.CopyToAsync(copy, token);
                seen = copy.ToArray();
                return true;
            },
            CancellationToken.None);

        // Chunk sizes vary around the stable profile's range; the caller
        // reuses one buffer, as the reconstruction does.
        byte[] buffer = new byte[256 * 1024];
        int offset = 0;
        int step = 0;

        while (offset < content.Length)
        {
            int length = Math.Min(content.Length - offset, 16 * 1024 + (step++ * 37_987 % (240 * 1024)));
            content.AsSpan(offset, length).CopyTo(buffer);
            await check.WriteAsync(buffer.AsMemory(0, length), CancellationToken.None);
            buffer.AsSpan(0, length).Clear();
            offset += length;
        }

        Assert.True(await check.CompleteAsync().WaitAsync(Timeout));
        Assert.Equal(content, seen);
    }

    [Fact]
    public async Task Writer_WaitsWhileThePauseBoundIsUnread()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        long consumed = 0;

        await using OverlappedChunkingCheck check = OverlappedChunkingCheck.Start(
            async (stream, token) =>
            {
                await release.Task.WaitAsync(token);
                byte[] buffer = new byte[64 * 1024];
                int read;

                while ((read = await stream.ReadAsync(buffer, token)) != 0)
                {
                    consumed += read;
                }

                return true;
            },
            CancellationToken.None);

        byte[] chunk = new byte[64 * 1024];
        long written = 0;
        ValueTask pending = default;

        // The check reads nothing yet, so a write eventually stays pending,
        // and not later than the pause bound plus the chunk being written.
        for (int index = 0; index < 1024; index++)
        {
            pending = check.WriteAsync(chunk, CancellationToken.None);
            written += chunk.Length;

            if (!pending.IsCompleted)
            {
                break;
            }
        }

        Assert.False(pending.IsCompleted);
        Assert.True(
            written <= OverlappedChunkingCheck.PauseBytes + chunk.Length,
            $"{written} bytes were accepted before the writer waited.");
        Assert.True(written >= OverlappedChunkingCheck.PauseBytes);

        release.SetResult();
        await pending.AsTask().WaitAsync(Timeout);
        Assert.True(await check.CompleteAsync().WaitAsync(Timeout));
        Assert.Equal(written, consumed);
    }

    [Fact]
    public async Task CheckEndingBeforeTheContent_DoesNotBlockTheWriter()
    {
        // An unregistered profile or a fingerprint mismatch ends the check
        // after the manifest, before it reads any content.
        await using OverlappedChunkingCheck check = OverlappedChunkingCheck.Start(
            static (_, _) => Task.FromResult(false),
            CancellationToken.None);

        byte[] chunk = new byte[256 * 1024];

        for (int index = 0; index < 64; index++)
        {
            await check.WriteAsync(chunk, CancellationToken.None).AsTask().WaitAsync(Timeout);
        }

        Assert.False(await check.CompleteAsync().WaitAsync(Timeout));
    }

    [Fact]
    public async Task ExceptionInsideTheCheck_IsRethrownByCompleteAndDoesNotBlockTheWriter()
    {
        await using OverlappedChunkingCheck check = OverlappedChunkingCheck.Start(
            static async (stream, token) =>
            {
                byte[] buffer = new byte[1024];
                _ = await stream.ReadAsync(buffer, token);
                throw new InvalidDataException("Injected check failure.");
            },
            CancellationToken.None);

        byte[] chunk = new byte[256 * 1024];

        for (int index = 0; index < 64; index++)
        {
            await check.WriteAsync(chunk, CancellationToken.None).AsTask().WaitAsync(Timeout);
        }

        InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(
            () => check.CompleteAsync().WaitAsync(Timeout));
        Assert.Equal("Injected check failure.", exception.Message);
    }

    [Fact]
    public async Task Dispose_WithoutComplete_CancelsTheCheckAndWaitsForIt()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool cancelled = false;
        bool finished = false;

        OverlappedChunkingCheck check = OverlappedChunkingCheck.Start(
            async (stream, token) =>
            {
                try
                {
                    started.SetResult();
                    byte[] buffer = new byte[1024];

                    while (await stream.ReadAsync(buffer, token) != 0)
                    {
                    }

                    return true;
                }
                catch (OperationCanceledException)
                {
                    cancelled = true;
                    throw;
                }
                finally
                {
                    finished = true;
                }
            },
            CancellationToken.None);

        await check.WriteAsync(new byte[4096], CancellationToken.None);
        await started.Task.WaitAsync(Timeout);

        // A reconstruction failure disposes the check without completing it.
        await check.DisposeAsync().AsTask().WaitAsync(Timeout);

        Assert.True(finished);
        Assert.True(cancelled);
    }

    [Fact]
    public async Task CallerCancellation_ReachesTheCheck()
    {
        using var cancellation = new CancellationTokenSource();

        await using OverlappedChunkingCheck check = OverlappedChunkingCheck.Start(
            static async (stream, token) =>
            {
                byte[] buffer = new byte[1024];

                while (await stream.ReadAsync(buffer, token) != 0)
                {
                }

                return true;
            },
            cancellation.Token);

        await check.WriteAsync(new byte[4096], CancellationToken.None);
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => check.CompleteAsync().WaitAsync(Timeout));
    }
}
