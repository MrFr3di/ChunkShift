using ChunkShift.Patching.Creation;
using ChunkShift.Primitives;
using CreationBuilder = ChunkShift.Patching.Creation.CspPatchBuilder;

namespace ChunkShift.Patching.Tests.Creation;

/// <summary>
/// The create executions under test and the create helpers the execution
/// tests share. Names: <c>h0</c> is the sequential pass (the byte oracle),
/// <c>h1</c> the sequential pass with the base-chunk cache, <c>h2-wN</c> the
/// ordered pipeline with N encode workers sharing the base stream and
/// <c>h3-wN</c> the pipeline with the cache.
/// </summary>
internal static class CreationExecutions
{
    internal const string H0 = "h0";

    internal static IReadOnlyList<string> Names { get; } =
        ["h0", "h1", "h2-w1", "h2-w2", "h2-w4", "h2-w8", "h3-w1", "h3-w2", "h3-w4", "h3-w8"];

    internal static CspCreateExecution Parse(string name) => name switch
    {
        "h0" => CspCreateExecution.Sequential,
        "h1" => new CspCreateExecution(0, UseBaseCandidateCache: true),
        _ when name.StartsWith("h2-w", StringComparison.Ordinal) =>
            new CspCreateExecution(int.Parse(name.AsSpan(4), System.Globalization.CultureInfo.InvariantCulture), false),
        _ when name.StartsWith("h3-w", StringComparison.Ordinal) =>
            new CspCreateExecution(int.Parse(name.AsSpan(4), System.Globalization.CultureInfo.InvariantCulture), true),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown execution."),
    };

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Lazy<Task<byte[]>>> Oracles = new();

    /// <summary>
    /// Returns the H0 patch of one test input, created once per test run: the
    /// oracle every other execution is compared with.
    /// </summary>
    internal static Task<byte[]> H0Async(string key, Func<Task<byte[]>> create) =>
        Oracles.GetOrAdd(key, _ => new Lazy<Task<byte[]>>(create)).Value;

    internal static TheoryData<string> All()
    {
        var data = new TheoryData<string>();

        foreach (string name in Names)
        {
            data.Add(name);
        }

        return data;
    }

    /// <summary>Creates a patch through the internal builder and returns its bytes.</summary>
    internal static async Task<byte[]> CreateAsync(
        byte[]? baseManifest,
        byte[]? baseContent,
        byte[] targetManifest,
        byte[] targetContent,
        CspEncoderPolicy policy,
        CspCreateExecution execution,
        CancellationToken cancellationToken = default)
    {
        using var destination = new MemoryStream();
        _ = await CreationBuilder.CreateAsync(
            baseManifest is null ? null : new MemoryStream(baseManifest, writable: false),
            baseContent is null ? null : new MemoryStream(baseContent, writable: false),
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(targetContent, writable: false),
            destination,
            policy,
            execution,
            cancellationToken);

        return destination.ToArray();
    }

    /// <summary>Creates a patch with explicit streams, so a test can observe or break them.</summary>
    internal static async Task<byte[]> CreateAsync(
        Stream? baseManifest,
        Stream? baseContent,
        Stream targetManifest,
        Stream targetContent,
        CspEncoderPolicy policy,
        CspCreateExecution execution,
        CancellationToken cancellationToken = default)
    {
        using var destination = new MemoryStream();
        _ = await CreationBuilder.CreateAsync(
            baseManifest,
            baseContent,
            targetManifest,
            targetContent,
            destination,
            policy,
            execution,
            cancellationToken);

        return destination.ToArray();
    }

    /// <summary>The manifests of a scenario, created once per hash suite.</summary>
    internal static async Task<(byte[] BaseManifest, byte[] TargetManifest)> ManifestsAsync(
        byte[] baseContent,
        byte[] targetContent,
        HashSuiteId? hashSuite = null)
    {
        HashSuiteId suite = hashSuite ?? HashSuiteIds.Blake3256V1;
        return (
            await CreationTestSupport.CreateManifestAsync(baseContent, suite),
            await CreationTestSupport.CreateManifestAsync(targetContent, suite));
    }

    /// <summary>
    /// A base of random bytes and a target with one changed byte every
    /// <paramref name="stride"/> bytes: every target chunk is missing and its
    /// neighbours' candidate windows overlap its own.
    /// </summary>
    internal static (byte[] BaseContent, byte[] TargetContent) SparseEdits(
        int length,
        int stride,
        uint seed)
    {
        byte[] baseContent = Format.CspBytes.CreateXorShiftBytes(length, seed);
        byte[] targetContent = (byte[])baseContent.Clone();

        for (int offset = stride / 2; offset < length; offset += stride)
        {
            targetContent[offset] ^= 0x5A;
        }

        return (baseContent, targetContent);
    }
}

/// <summary>
/// Seekable read-only stream over a byte array that counts the reads, bytes and
/// repositionings it serves and fails if two callers use it at once.
/// </summary>
internal sealed class ObservedReadStream : Stream
{
    private readonly byte[] _data;
    private long _position;
    private int _busy;

    internal ObservedReadStream(byte[] data, long? failAtOffset = null)
    {
        _data = data;
        FailAtOffset = failAtOffset;
    }

    /// <summary>Gets the offset whose read throws an <see cref="IOException"/>, if any.</summary>
    internal long? FailAtOffset { get; }

    internal long Reads { get; private set; }

    internal long BytesRead { get; private set; }

    internal long Seeks { get; private set; }

    internal int ConcurrentUses { get; private set; }

    public override bool CanRead => true;

    public override bool CanSeek => true;

    public override bool CanWrite => false;

    public override long Length => _data.Length;

    public override long Position
    {
        get => _position;
        set
        {
            Enter();

            try
            {
                ArgumentOutOfRangeException.ThrowIfNegative(value);
                Seeks++;
                _position = value;
            }
            finally
            {
                Exit();
            }
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        Enter();

        try
        {
            // Widen the window in which a second caller would be seen.
            Thread.SpinWait(50);

            if (FailAtOffset is long failure &&
                _position <= failure &&
                failure < _position + buffer.Length)
            {
                throw new IOException("Injected base read failure.");
            }

            int count = (int)Math.Clamp(_data.Length - _position, 0, buffer.Length);
            _data.AsSpan((int)_position, count).CopyTo(buffer);
            _position += count;
            Reads++;
            BytesRead += count;
            return count;
        }
        finally
        {
            Exit();
        }
    }

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin)
    {
        long position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _data.Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        Position = position;
        return position;
    }

    public override void Flush()
    {
    }

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    private void Enter()
    {
        if (Interlocked.Exchange(ref _busy, 1) != 0)
        {
            ConcurrentUses++;
            throw new InvalidOperationException("The base stream was used by two callers at once.");
        }
    }

    private void Exit() => Volatile.Write(ref _busy, 0);
}
