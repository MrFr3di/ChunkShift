using ChunkShift.Chunking;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Chunking;

public class ChunkingKernelStreamTests
{
    [Fact]
    public async Task FastCdc_OneByteReadsMatchContiguousReference()
    {
        byte[] input = CreateXorShiftBytes(320 * 1024, 0xA11CE55u);
        FastCdcProfile fastCdc = FastCdcProfile.CreateM1Candidate(64 * 1024);
        ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(fastCdc);

        ChunkKernelChunk[] expected = ChunkingReference.Chunk(
            input,
            profile,
            HashSuiteIds.Blake3256V1);

        CollectedScan actual = await ScanAsync(
            new SegmentedReadStream(input, [1]),
            profile,
            HashSuiteIds.Blake3256V1);

        Assert.Equal(expected, actual.Chunks);
        Assert.Equal(input, actual.Reconstructed);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(65536)]
    public async Task FastCdc_OddFinalWindowTestsItsLastPosition(int segment)
    {
        // The last position of an odd final window is a boundary candidate
        // (FASTCDC-V1 §4). fastcdc-rs 5.0.0 v2020's two-byte loop
        // never tests it and returns one 16387-byte chunk for this input;
        // v2016 and the independent Python reference agree with the split
        // below (tools/conformance/fastcdc_reference.py).
        byte[] input = new byte[16 * 1024 + 3];
        input[^3] = 2;
        input[^2] = 255;
        input[^1] = 65;
        ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(FastCdcProfile.CreateM1Candidate(64 * 1024));

        ChunkKernelChunk[] expected = ChunkingReference.Chunk(input, profile, HashSuiteIds.Blake3256V1);
        CollectedScan actual = await ScanAsync(new SegmentedReadStream(input, [segment]), profile, HashSuiteIds.Blake3256V1);

        Assert.Equal([(0L, 16386), (16386L, 1)], expected.Select(static chunk => (chunk.Offset, chunk.Length)));
        Assert.Equal(expected, actual.Chunks);
    }

    [Fact]
    public async Task FastCdc_RandomShortReadsMatchContiguousReference()
    {
        byte[] input = CreateXorShiftBytes(1024 * 1024, 0xC0FFEE42u);
        FastCdcProfile fastCdc = FastCdcProfile.CreateM1Candidate(128 * 1024);
        ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(fastCdc);

        ChunkKernelChunk[] expected = ChunkingReference.Chunk(
            input,
            profile,
            HashSuiteIds.Sha256V1);

        CollectedScan actual = await ScanAsync(
            new SegmentedReadStream(input, [3, 8191, 1, 17, 4096, 127, 65535, 2, 257]),
            profile,
            HashSuiteIds.Sha256V1);

        Assert.Equal(expected, actual.Chunks);
        Assert.Equal(input, actual.Reconstructed);
    }

    [Fact]
    public async Task FastCdc_ReadBoundariesAroundCutsDoNotChangeOutput()
    {
        byte[] input = CreateXorShiftBytes(1024 * 1024, 0x12345678u);
        FastCdcProfile fastCdc = FastCdcProfile.CreateM1Candidate(64 * 1024);
        ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(fastCdc);

        ChunkKernelChunk[] expected = ChunkingReference.Chunk(
            input,
            profile,
            HashSuiteIds.Blake3256V1);

        int[] aroundCuts = expected
            .Take(Math.Min(expected.Length, 8))
            .SelectMany(static chunk => new[]
            {
                Math.Max(1, chunk.Length - 1),
                1,
                1,
            })
            .ToArray();

        CollectedScan actual = await ScanAsync(
            new SegmentedReadStream(input, aroundCuts),
            profile,
            HashSuiteIds.Blake3256V1);

        Assert.Equal(expected, actual.Chunks);
        Assert.Equal(input, actual.Reconstructed);
    }

    [Fact]
    public async Task FixedKernel_ShortReadsMatchContiguousReference()
    {
        byte[] input = CreateXorShiftBytes((256 * 1024) + 17, 0x55AA55AAu);
        ChunkingKernelProfile profile = ChunkingKernelProfile.Fixed(64 * 1024);

        ChunkKernelChunk[] expected = ChunkingReference.Chunk(
            input,
            profile,
            HashSuiteIds.Blake3256V1);

        CollectedScan actual = await ScanAsync(
            new SegmentedReadStream(input, [1, 31, 4095, 2, 65535]),
            profile,
            HashSuiteIds.Blake3256V1);

        Assert.Equal(expected, actual.Chunks);
        Assert.Equal(input, actual.Reconstructed);
        Assert.Equal([65536, 65536, 65536, 65536, 17], actual.Chunks.Select(static c => c.Length));
    }

    public static TheoryData<string> BufferEdgeCaseProfiles => new()
    {
        "fixed-1", "fixed-1000", "fixed-4096", "fixed-100000", "fixed-300000",
        "fastcdc-zero-64k", "fastcdc-zero-256k",
        "fastcdc-t256-x1024", "fastcdc-t4k-x16k", "fastcdc-t16k-x64k", "fastcdc-t32k-x128k",
    };

    [Theory]
    [MemberData(nameof(BufferEdgeCaseProfiles))]
    public async Task BufferEdgeCasesMatchContiguousReference(string name)
    {
        // Fixed sizes that do not divide the 64 KiB read size, zero input that
        // forces FastCDC cuts at Maximum, and small FastCDC profiles whose
        // chunks share the minimum-size kernel buffer exercise every place where
        // the pending chunk meets the end of the single kernel buffer.
        (ChunkingKernelProfile profile, byte[] input) = CreateEdgeCase(name);

        ChunkKernelChunk[] expected = ChunkingReference.Chunk(input, profile, HashSuiteIds.Sha256V1);

        foreach (int[] segmentation in new[] { new[] { int.MaxValue }, new[] { 1, 31, 4095, 2, 65535, 70001 } })
        {
            CollectedScan actual = await ScanAsync(
                new SegmentedReadStream(input, segmentation),
                profile,
                HashSuiteIds.Sha256V1);

            Assert.Equal(expected, actual.Chunks);
            Assert.Equal(input, actual.Reconstructed);
        }
    }

    [Theory]
    [MemberData(nameof(BufferEdgeCaseProfiles))]
    public async Task ReadsStayAtTheFullReadSize(string name)
    {
        (ChunkingKernelProfile profile, byte[] input) = CreateEdgeCase(name);
        var source = new SegmentedReadStream(input, [int.MaxValue]);

        _ = await ScanAsync(source, profile, HashSuiteIds.Sha256V1);

        // The two-buffer kernel issued one full read per 64 KiB (plus the EOF
        // read). Reads may shrink only where the space left before the buffer
        // end is short: fixed sizes that do not divide the read size, and the
        // occasional compaction point of content-defined chunks. Small profiles
        // must not fall back to one read per chunk.
        int fullReads = (input.Length / ChunkingKernel.IoBufferSize) + 2;
        double allowance = name is "fixed-100000" or "fixed-300000" ? 1.5 : 1.05;
        Assert.InRange(source.Reads, 1, (int)(fullReads * allowance) + 1);
        Assert.All(source.RequestedLengths, requested => Assert.InRange(requested, 1, ChunkingKernel.IoBufferSize));
    }

    private static (ChunkingKernelProfile Profile, byte[] Input) CreateEdgeCase(string name)
    {
        byte[] random = CreateXorShiftBytes((3 * 1024 * 1024) + 7, 0x0DDBA11u);

        return name switch
        {
            "fixed-1" => (ChunkingKernelProfile.Fixed(1), CreateXorShiftBytes(4099, 0x0DDBA11u)),
            "fixed-1000" => (ChunkingKernelProfile.Fixed(1000), random),
            "fixed-4096" => (ChunkingKernelProfile.Fixed(4096), random),
            "fixed-100000" => (ChunkingKernelProfile.Fixed(100_000), random),
            "fixed-300000" => (ChunkingKernelProfile.Fixed(300_000), random),
            "fastcdc-zero-64k" => ZeroFastCdc(64 * 1024),
            "fastcdc-zero-256k" => ZeroFastCdc(256 * 1024),
            "fastcdc-t256-x1024" => (ChunkingKernelProfile.FastCdcGear(new FastCdcProfile(64, 256, 1024)), random),
            "fastcdc-t4k-x16k" => (ChunkingKernelProfile.FastCdcGear(new FastCdcProfile(1024, 4096, 16384)), random),
            "fastcdc-t16k-x64k" => (ChunkingKernelProfile.FastCdcGear(new FastCdcProfile(4096, 16384, 65536)), random),
            "fastcdc-t32k-x128k" => (ChunkingKernelProfile.FastCdcGear(FastCdcProfile.CreateM1Candidate(32 * 1024)), random),
            _ => throw new ArgumentException($"Unknown edge case '{name}'.", nameof(name)),
        };

        static (ChunkingKernelProfile, byte[]) ZeroFastCdc(int target)
        {
            ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(FastCdcProfile.CreateM1Candidate(target));
            return (profile, new byte[(3 * profile.Maximum) + 12345]);
        }
    }

    [Fact]
    public async Task FastCdc_ScalarAndStreamingAgreeAcrossProfilesSuitesSeedsAndSegmentation()
    {
        int[] targets = [64 * 1024, 128 * 1024, 256 * 1024];
        HashSuiteId[] hashSuites = [HashSuiteIds.Blake3256V1, HashSuiteIds.Sha256V1];
        uint[] seeds = [0x12345678u, 0xA11CE55u, 0xC0FFEE42u];
        int[][] segmentations =
        [
            [1],
            [3, 17, 257, 4095, 65535, 2, 8191],
        ];

        foreach (int target in targets)
        {
            ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(
                FastCdcProfile.CreateM1Candidate(target));

            foreach (HashSuiteId hashSuite in hashSuites)
            {
                foreach (uint seed in seeds)
                {
                    byte[] input = CreateXorShiftBytes(2 * 1024 * 1024, seed);
                    ChunkKernelChunk[] expected = ChunkingReference.Chunk(input, profile, hashSuite);

                    foreach (int[] segmentation in segmentations)
                    {
                        CollectedScan actual = await ScanAsync(
                            new SegmentedReadStream(input, segmentation),
                            profile,
                            hashSuite);

                        Assert.Equal(expected, actual.Chunks);
                        Assert.Equal(input, actual.Reconstructed);
                    }
                }
            }
        }
    }

    [Fact]
    public async Task FastCdc_PerturbationsAroundReferenceCutsRemainScalarStreamingEquivalent()
    {
        byte[] baseline = CreateXorShiftBytes(1024 * 1024, 0x13579BDFu);
        ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(
            FastCdcProfile.CreateM1Candidate(64 * 1024));

        ChunkKernelChunk[] baselineChunks = ChunkingReference.Chunk(
            baseline,
            profile,
            HashSuiteIds.Blake3256V1);

        long[] cutOffsets = baselineChunks
            .Take(Math.Min(4, baselineChunks.Length - 1))
            .Select(static chunk => chunk.Offset + chunk.Length)
            .ToArray();

        foreach (long cutOffset in cutOffsets)
        {
            foreach (int delta in new[] { -1, 0, 1 })
            {
                int position = checked((int)cutOffset + delta);
                if ((uint)position >= (uint)baseline.Length)
                {
                    continue;
                }

                byte[] mutated = (byte[])baseline.Clone();
                mutated[position] ^= 0x5A;

                ChunkKernelChunk[] expected = ChunkingReference.Chunk(
                    mutated,
                    profile,
                    HashSuiteIds.Blake3256V1);

                CollectedScan actual = await ScanAsync(
                    new SegmentedReadStream(mutated, [1, 31, 4095, 2, 65535, 7, 257]),
                    profile,
                    HashSuiteIds.Blake3256V1);

                Assert.Equal(expected, actual.Chunks);
                Assert.Equal(mutated, actual.Reconstructed);
            }
        }
    }

    [Fact]
    public async Task EmptyStream_EmitsNoChunks()
    {
        ChunkingKernelProfile profile = ChunkingKernelProfile.FastCdcGear(
            FastCdcProfile.CreateM1Candidate(64 * 1024));

        CollectedScan actual = await ScanAsync(
            new SegmentedReadStream([], [1]),
            profile,
            HashSuiteIds.Blake3256V1);

        Assert.Empty(actual.Chunks);
        Assert.Empty(actual.Reconstructed);
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(false, 8191)]
    [InlineData(true, 1)]
    [InlineData(true, 8191)]
    public async Task Counters_ReportOnlyPendingPrefixMoves(bool fastCdc, int readLength)
    {
        byte[] input = CreateXorShiftBytes(512 * 1024 + 37, 0xB17E5C0Du);
        ChunkingKernelProfile profile = fastCdc
            ? ChunkingKernelProfile.FastCdcGear(FastCdcProfile.CreateM1Candidate(64 * 1024))
            : ChunkingKernelProfile.Fixed(64 * 1024);
        var counters = new ChunkingKernelCounters();

        await ChunkingKernel.ScanAsync(
            new SegmentedReadStream(input, [readLength]),
            profile,
            HashSuiteIds.Blake3256V1,
            static (_, _, _) => ValueTask.CompletedTask,
            counters);

        // Single-buffer topology: reads land after the pending chunk,
        // and only the pending prefix is moved when the buffer end is reached.
        // A moved prefix is emitted before the next move, so no byte moves
        // twice; the two-buffer topology copied every byte (1.0 per input byte).
        // Short reads only change where the moves happen.
        Assert.InRange(counters.BytesCopied, 0, input.Length / 2);
    }

    private static async Task<CollectedScan> ScanAsync(
        Stream source,
        ChunkingKernelProfile profile,
        HashSuiteId hashSuite)
    {
        var chunks = new List<ChunkKernelChunk>();
        using var reconstructed = new MemoryStream();

        await ChunkingKernel.ScanAsync(
            source,
            profile,
            hashSuite,
            (chunk, content, _) =>
            {
                chunks.Add(chunk);
                reconstructed.Write(content.Span);
                return ValueTask.CompletedTask;
            });

        return new CollectedScan(chunks.ToArray(), reconstructed.ToArray());
    }

    private static byte[] CreateXorShiftBytes(int length, uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int i = 0; i < bytes.Length; i++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[i] = (byte)state;
        }

        return bytes;
    }

    private sealed record CollectedScan(
        ChunkKernelChunk[] Chunks,
        byte[] Reconstructed);

    private sealed class SegmentedReadStream : Stream
    {
        private readonly byte[] _data;
        private readonly int[] _segments;
        private int _position;
        private int _segmentIndex;

        public SegmentedReadStream(byte[] data, int[] segments)
        {
            _data = data;
            _segments = segments.Length == 0 ? [1] : segments;
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

        internal int Reads { get; private set; }

        internal List<int> RequestedLengths { get; } = [];

        private int ReadCore(Span<byte> destination)
        {
            Reads++;
            RequestedLengths.Add(destination.Length);

            if (_position == _data.Length)
            {
                return 0;
            }

            int requested = _segments[_segmentIndex++ % _segments.Length];
            int count = Math.Min(requested, Math.Min(destination.Length, _data.Length - _position));
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
