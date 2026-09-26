using System.Threading.Tasks.Sources;
using ChunkShift.Chunking;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Tests;

public class ChunkScannerTests
{
    // Bounds waits that would otherwise hang the test run (and the CI runner)
    // if cancellation or callback sequencing regressed.
    private static readonly TimeSpan HangGuard = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task DefaultScan_MatchesCanonicalKernelAndReconstructsInput()
    {
        byte[] input = CreateXorShiftBytes(1024 * 1024, 0x51A6E55u);
        FastCdcProfile profile = FastCdcProfile.CreateM1Candidate(64 * 1024);
        ChunkKernelChunk[] expected = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(profile),
            HashSuiteIds.Default);

        var actual = new List<ObservedChunk>();
        using var reconstructed = new MemoryStream();

        await ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            (chunk, content, _) =>
            {
                actual.Add(new ObservedChunk(
                    chunk.Index,
                    chunk.Offset,
                    chunk.Length,
                    chunk.Id));
                reconstructed.Write(content.Span);
                return ValueTask.CompletedTask;
            });

        Assert.Equal(expected.Length, actual.Count);
        for (int index = 0; index < expected.Length; index++)
        {
            Assert.Equal(index, actual[index].Index);
            Assert.Equal(expected[index].Offset, actual[index].Offset);
            Assert.Equal(expected[index].Length, actual[index].Length);
            Assert.Equal(expected[index].Id, actual[index].Id);
        }

        Assert.Equal(input, reconstructed.ToArray());
    }

    [Fact]
    public async Task OneByteReads_ProduceSameChunksAsContiguousInput()
    {
        byte[] input = CreateXorShiftBytes(384 * 1024, 0xA11CE55u);
        FastCdcProfile profile = FastCdcProfile.CreateM1Candidate(64 * 1024);
        ChunkKernelChunk[] expected = ChunkingReference.Chunk(
            input,
            ChunkingKernelProfile.FastCdcGear(profile),
            HashSuiteIds.Blake3256V1);

        var actual = new List<ObservedChunk>();

        await ChunkScanner.ScanAsync(
            new SegmentedReadStream(input, [1]),
            (chunk, _, _) =>
            {
                actual.Add(new ObservedChunk(
                    chunk.Index,
                    chunk.Offset,
                    chunk.Length,
                    chunk.Id));
                return ValueTask.CompletedTask;
            });

        Assert.Equal(expected.Length, actual.Count);
        for (int index = 0; index < expected.Length; index++)
        {
            Assert.Equal(expected[index].Offset, actual[index].Offset);
            Assert.Equal(expected[index].Length, actual[index].Length);
            Assert.Equal(expected[index].Id, actual[index].Id);
        }
    }

    [Fact]
    public async Task Offset_IsRelativeToBeginningOfScan()
    {
        byte[] input = CreateXorShiftBytes(512 * 1024, 0xD15EA5Eu);
        const int initialPosition = 12345;

        using var source = new MemoryStream(input, writable: false)
        {
            Position = initialPosition,
        };

        ChunkInfo? first = null;
        await ChunkScanner.ScanAsync(
            source,
            (chunk, _, _) =>
            {
                first ??= chunk;
                return ValueTask.CompletedTask;
            });

        Assert.NotNull(first);
        Assert.Equal(0, first.Value.Index);
        Assert.Equal(0, first.Value.Offset);

        Hash256 expectedHash = HashSuiteHasher.Hash(
            HashSuiteIds.Default,
            input.AsSpan(initialPosition, first.Value.Length));
        Assert.Equal(new ChunkId(expectedHash), first.Value.Id);
    }

    [Fact]
    public async Task ExplicitSha256_UsesSelectedHashSuite()
    {
        byte[] input = CreateXorShiftBytes(512 * 1024, 0x5A256u);
        ChunkInfo? first = null;
        byte[]? firstBytes = null;

        await ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            (chunk, content, _) =>
            {
                if (first is null)
                {
                    first = chunk;
                    firstBytes = content.ToArray();
                }

                return ValueTask.CompletedTask;
            },
            new ChunkScanOptions
            {
                HashSuite = HashSuiteIds.Sha256V1,
            });

        Assert.NotNull(first);
        Assert.NotNull(firstBytes);
        Assert.Equal(
            new ChunkId(HashSuiteHasher.Hash(HashSuiteIds.Sha256V1, firstBytes)),
            first.Value.Id);
    }

    [Fact]
    public async Task BorrowedContent_RemainsStableUntilAsyncHandlerCompletes()
    {
        byte[] input = CreateXorShiftBytes(768 * 1024, 0xB0FF3u);
        int callbackCount = 0;

        await ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            async (_, content, cancellationToken) =>
            {
                byte[] snapshot = content.ToArray();
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                Assert.Equal(snapshot, content.ToArray());
                callbackCount++;
            });

        Assert.True(callbackCount > 1);
    }

    [Fact]
    public async Task Callbacks_AreOrderedAndNeverConcurrent()
    {
        byte[] input = CreateXorShiftBytes(2 * 1024 * 1024, 0xC011AB1Eu);
        int active = 0;
        int maximumActive = 0;
        long expectedIndex = 0;

        await ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            async (chunk, _, cancellationToken) =>
            {
                int now = Interlocked.Increment(ref active);
                maximumActive = Math.Max(maximumActive, now);

                Assert.Equal(expectedIndex, chunk.Index);
                expectedIndex++;

                await Task.Delay(1, cancellationToken);
                Interlocked.Decrement(ref active);
            });

        Assert.Equal(1, maximumActive);
        Assert.True(expectedIndex > 1);
    }

    [Fact]
    public async Task CancellationDuringHandler_StopsBeforeNextCallback()
    {
        byte[] input = new byte[1024 * 1024];
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;

        Task scan = ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            async (_, _, cancellationToken) =>
            {
                calls++;
                entered.TrySetResult(true);
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            },
            cancellationToken: cancellation.Token);

        await entered.Task.WaitAsync(HangGuard);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => scan.WaitAsync(HangGuard));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task CancellationAfterFirstChunk_DoesNotReadToEnd()
    {
        byte[] input = CreateXorShiftBytes(8 * 1024 * 1024, 0xCA11CE42u);
        using var source = new MemoryStream(input, writable: false);
        using var cancellation = new CancellationTokenSource();

        long firstChunkEnd = 0;
        long sourcePositionAtCancellation = 0;

        Task scan = ChunkScanner.ScanAsync(
            source,
            (chunk, _, cancellationToken) =>
            {
                firstChunkEnd = chunk.Offset + chunk.Length;
                sourcePositionAtCancellation = source.Position;
                cancellation.Cancel();
                return ValueTask.FromCanceled(cancellationToken);
            },
            cancellationToken: cancellation.Token);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scan);

        Assert.True(firstChunkEnd > 0);
        Assert.True(sourcePositionAtCancellation >= firstChunkEnd);
        Assert.True(sourcePositionAtCancellation < input.LongLength);
    }

    [Fact]
    public async Task HandlerFailure_PropagatesAndDoesNotDisposeSource()
    {
        byte[] input = CreateXorShiftBytes(512 * 1024, 0xBAD5EEDu);
        using var source = new MemoryStream(input, writable: false);
        var expected = new InvalidOperationException("consumer failed");

        InvalidOperationException actual = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ChunkScanner.ScanAsync(
                source,
                (_, _, _) => ValueTask.FromException(expected)));

        Assert.Same(expected, actual);
        Assert.True(source.CanRead);
    }

    [Fact]
    public async Task EmptySource_EmitsNoCallbacks()
    {
        int calls = 0;

        await ChunkScanner.ScanAsync(
            new MemoryStream([], writable: false),
            (_, _, _) =>
            {
                calls++;
                return ValueTask.CompletedTask;
            });

        Assert.Equal(0, calls);
    }

    [Fact]
    public void ExplicitStableProfileResolution_HasNoPerCallAllocationGrowth()
    {
        ChunkingProfileId id = FastCdcProfile.Stable64KProfileId;

        _ = ChunkScanConfiguration.ResolveProfile(id);

        long before = GC.GetAllocatedBytesForCurrentThread();

        for (int iteration = 0; iteration < 10_000; iteration++)
        {
            _ = ChunkScanConfiguration.ResolveProfile(id);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        // Tiered JIT/runtime bookkeeping can contribute a few KiB on some
        // architectures even after the warm-up call. The regression guarded
        // here was ~14-44 KiB per ResolveProfile call, so a small whole-loop
        // budget detects per-call growth without making the test runtime-specific.
        Assert.True(
            allocated <= 16 * 1024,
            $"Explicit profile resolution allocated {allocated} bytes across 10,000 calls.");
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public void ExplicitHashSuiteResolution_IsCanonicalAndAllocationFree(string value)
    {
        // A caller-constructed instance is equal by ordinal value, and resolution
        // hands back the canonical instance used by the hash dispatch.
        var requested = new HashSuiteId(value);
        HashSuiteId canonical = ChunkScanConfiguration.ResolveHashSuite(requested);

        Assert.NotSame(requested, canonical);
        Assert.Equal(requested, canonical);
        Assert.True(
            ReferenceEquals(canonical, HashSuiteIds.Blake3256V1) ||
            ReferenceEquals(canonical, HashSuiteIds.Sha256V1));

        long before = GC.GetAllocatedBytesForCurrentThread();

        for (int iteration = 0; iteration < 10_000; iteration++)
        {
            _ = ChunkScanConfiguration.ResolveHashSuite(requested);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(
            allocated <= 16 * 1024,
            $"Explicit hash-suite resolution allocated {allocated} bytes across 10,000 calls.");
    }

    [Fact]
    public void InvalidArgumentsAndUnsupportedSemantics_FailBeforeReading()
    {
        ChunkScanHandler handler = static (_, _, _) => ValueTask.CompletedTask;

        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkScanner.ScanAsync(null!, handler);
        });

        Assert.Throws<ArgumentNullException>(() =>
        {
            _ = ChunkScanner.ScanAsync(Stream.Null, null!);
        });

        using var unreadable = new MemoryStream();
        unreadable.Dispose();
        Assert.Throws<ArgumentException>(() =>
        {
            _ = ChunkScanner.ScanAsync(unreadable, handler);
        });

        Assert.Throws<NotSupportedException>(() =>
        {
            _ = ChunkScanner.ScanAsync(
                Stream.Null,
                handler,
                new ChunkScanOptions
                {
                    ProfileId = new ChunkingProfileId("unknown.profile.v1"),
                });
        });

        Assert.Throws<NotSupportedException>(() =>
        {
            _ = ChunkScanner.ScanAsync(
                Stream.Null,
                handler,
                new ChunkScanOptions
                {
                    HashSuite = new HashSuiteId("chunkshift.unknown-256.v1"),
                });
        });

    }

    [Fact]
    public async Task NullSelections_UseTheDefaults()
    {
        // With reference-type identifiers there is no invalid default instance:
        // null is the only "not selected" state and means the default.
        byte[] data = new byte[300_000];
        new Random(7).NextBytes(data);

        var implicitIds = new List<ChunkId>();
        await ChunkScanner.ScanAsync(
            new MemoryStream(data),
            (chunk, _, _) =>
            {
                implicitIds.Add(chunk.Id);
                return ValueTask.CompletedTask;
            });

        var explicitNullIds = new List<ChunkId>();
        await ChunkScanner.ScanAsync(
            new MemoryStream(data),
            (chunk, _, _) =>
            {
                explicitNullIds.Add(chunk.Id);
                return ValueTask.CompletedTask;
            },
            new ChunkScanOptions { ProfileId = null, HashSuite = null });

        var explicitDefaultIds = new List<ChunkId>();
        await ChunkScanner.ScanAsync(
            new MemoryStream(data),
            (chunk, _, _) =>
            {
                explicitDefaultIds.Add(chunk.Id);
                return ValueTask.CompletedTask;
            },
            new ChunkScanOptions { HashSuite = HashSuiteIds.Default });

        Assert.NotEmpty(implicitIds);
        Assert.Equal(implicitIds, explicitNullIds);
        Assert.Equal(implicitIds, explicitDefaultIds);
    }

    [Fact]
    public async Task HandlerValueTask_IsConsumedExactlyOnce()
    {
        var completion = new SingleConsumptionValueTaskSource();

        await ChunkScanner.ScanAsync(
            new MemoryStream(new byte[] { 0x42 }, writable: false),
            (_, _, _) => completion.CreateValueTask());

        Assert.Equal(1, completion.GetResultCalls);
    }

    [Fact]
    public async Task Cancellation_DoesNotPreemptHandlerThatIgnoresToken()
    {
        byte[] input = CreateXorShiftBytes(1024 * 1024, 0x1A2B3C4Du);
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;

        Task scan = ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            async (_, _, _) =>
            {
                calls++;
                entered.TrySetResult(true);
                await release.Task;
            },
            cancellationToken: cancellation.Token);

        await entered.Task.WaitAsync(HangGuard);
        cancellation.Cancel();

        Assert.False(scan.IsCompleted);

        release.TrySetResult(true);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => scan.WaitAsync(HangGuard));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task BorrowedContent_IsReusedAfterCallbackCompletes()
    {
        byte[] input = CreateXorShiftBytes(2 * 1024 * 1024, 0xB0A0D123u);
        FastCdcProfile fastCdc = FastCdcProfile.CreateStable64K();
        ReadOnlyMemory<byte> retained = default;
        byte[]? firstSnapshot = null;
        long firstEnd = 0;
        long reusedBy = -1;
        int calls = 0;

        await ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            (chunk, content, _) =>
            {
                if (calls == 0)
                {
                    retained = content;
                    firstSnapshot = content.ToArray();
                    firstEnd = chunk.Offset + chunk.Length;
                }
                else if (reusedBy < 0 && !retained.Span.SequenceEqual(firstSnapshot))
                {
                    reusedBy = chunk.Offset + chunk.Length;
                }

                calls++;
                return ValueTask.CompletedTask;
            },
            new ChunkScanOptions { ProfileId = FastCdcProfile.Stable64KProfileId });

        // The kernel keeps one bounded buffer, so the first chunk's memory is
        // overwritten once the scan has moved about one buffer further; a copy
        // per chunk or an unbounded buffer would never overwrite it.
        Assert.True(calls > 1);
        Assert.InRange(reusedBy, firstEnd + 1, firstEnd + (2L * fastCdc.Maximum));
    }

    [Fact]
    public async Task GeneratedNonSeekableSource_IsProcessedWithoutFullMaterialization()
    {
        const long sourceLength = 32L * 1024 * 1024;
        using var source = new GeneratedXorShiftStream(sourceLength, 0x51A6E55u);
        long covered = 0;
        int callbacks = 0;

        ChunkingProfileId profileId = FastCdcProfile.Stable64KProfileId;

        await ChunkScanner.ScanAsync(
            source,
            (chunk, content, _) =>
            {
                Assert.Equal(covered, chunk.Offset);
                Assert.Equal(chunk.Length, content.Length);

                covered += chunk.Length;
                callbacks++;
                return ValueTask.CompletedTask;
            },
            new ChunkScanOptions { ProfileId = profileId });

        Assert.Equal(sourceLength, covered);
        Assert.Equal(sourceLength, source.BytesRead);
        Assert.True(callbacks > 1);
        Assert.False(source.CanSeek);

        // The source is generated on demand and never stores the complete payload.
        // Reads are bounded by the kernel's fixed I/O buffer. Referencing the
        // constant keeps the test independent of its exact value while failing on
        // any regression that requests larger reads (a 1 MiB bound let a 16x
        // regression pass).
        Assert.InRange(source.MaxRequestedReadLength, 1, ChunkingKernel.IoBufferSize);
    }

    private static byte[] CreateXorShiftBytes(int length, uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int index = 0; index < bytes.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[index] = (byte)state;
        }

        return bytes;
    }

    private readonly record struct ObservedChunk(
        long Index,
        long Offset,
        int Length,
        ChunkId Id);

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(1)]
    public async Task SourceViolatingReadCountContract_IsRejectedInsteadOfLoopingOrOverreading(
        int excessOverRequest)
    {
        // excessOverRequest < 0 makes the stream report a negative count (which
        // previously spun forever); > 0 reports one byte more than requested.
        using var source = new MisreportingReadStream(excessOverRequest);

        InvalidOperationException exception =
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => ChunkScanner
                    .ScanAsync(source, (_, _, _) => ValueTask.CompletedTask)
                    .WaitAsync(HangGuard));

        Assert.Contains("Stream.ReadAsync", exception.Message, StringComparison.Ordinal);
        Assert.Equal(1, source.Reads);
    }

    private sealed class MisreportingReadStream(int excessOverRequest) : Stream
    {
        internal int Reads { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            Reads++;
            return ValueTask.FromResult(
                excessOverRequest < 0
                    ? excessOverRequest
                    : buffer.Length + excessOverRequest);
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class SingleConsumptionValueTaskSource : IValueTaskSource
    {
        private int _getResultCalls;

        internal int GetResultCalls => Volatile.Read(ref _getResultCalls);

        internal ValueTask CreateValueTask() => new(this, token: 0);

        public void GetResult(short token)
        {
            if (token != 0)
            {
                throw new InvalidOperationException("Unexpected ValueTask token.");
            }

            if (Interlocked.Increment(ref _getResultCalls) != 1)
            {
                throw new InvalidOperationException(
                    "ChunkShift consumed the handler ValueTask more than once.");
            }
        }

        public ValueTaskSourceStatus GetStatus(short token)
        {
            if (token != 0)
            {
                throw new InvalidOperationException("Unexpected ValueTask token.");
            }

            return ValueTaskSourceStatus.Succeeded;
        }

        public void OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            throw new InvalidOperationException(
                "The test ValueTask source is already complete.");
        }
    }

    private sealed class GeneratedXorShiftStream : Stream
    {
        private long _remaining;
        private uint _state;

        internal GeneratedXorShiftStream(long length, uint seed)
        {
            _remaining = length;
            _state = seed;
        }

        internal long BytesRead { get; private set; }

        internal int MaxRequestedReadLength { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadCore(buffer.AsSpan(offset, count));
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadCore(buffer.Span));
        }

        private int ReadCore(Span<byte> destination)
        {
            MaxRequestedReadLength = Math.Max(
                MaxRequestedReadLength,
                destination.Length);

            if (_remaining == 0)
            {
                return 0;
            }

            int count = (int)Math.Min((long)destination.Length, _remaining);

            for (int index = 0; index < count; index++)
            {
                _state ^= _state << 13;
                _state ^= _state >> 17;
                _state ^= _state << 5;
                destination[index] = (byte)_state;
            }

            _remaining -= count;
            BytesRead += count;
            return count;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class SegmentedReadStream : Stream
    {
        private readonly byte[] _data;
        private readonly int[] _segments;
        private int _position;
        private int _segmentIndex;

        internal SegmentedReadStream(byte[] data, int[] segments)
        {
            _data = data;
            _segments = segments;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadCore(buffer.AsSpan(offset, count));
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ReadCore(buffer.Span));
        }

        private int ReadCore(Span<byte> destination)
        {
            if (_position == _data.Length)
            {
                return 0;
            }

            int requested = _segments[_segmentIndex++ % _segments.Length];
            int count = Math.Min(
                requested,
                Math.Min(destination.Length, _data.Length - _position));

            _data.AsSpan(_position, count).CopyTo(destination);
            _position += count;
            return count;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
