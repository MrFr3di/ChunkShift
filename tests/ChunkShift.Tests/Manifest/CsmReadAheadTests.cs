using System.Text.Json;
using ChunkShift.Manifest;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// The CSM reader serves small sections from a bounded read-ahead buffer and
/// reads large CBLK payloads straight into place. How the source splits its
/// bytes across reads must never change a verdict, an identity or an error.
/// </summary>
public sealed class CsmReadAheadTests
{
    private const string FixtureDirectory = "Fixtures/CsmV1";

    // Whole requests, single bytes, and an irregular split that lands inside
    // headers and across the read-ahead boundary.
    private static readonly int[][] Shapes =
    [
        [int.MaxValue],
        [1],
        [7, 16, 1, 4093, 3, 16384, 9],
    ];

    public static TheoryData<string> VectorNames()
    {
        var names = new TheoryData<string>();

        using JsonDocument document = JsonDocument.Parse(
            File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixtureDirectory, "vectors.json")));

        foreach (JsonProperty vector in document.RootElement.GetProperty("vectors").EnumerateObject())
        {
            names.Add(vector.Name);
        }

        return names;
    }

    [Theory]
    [MemberData(nameof(VectorNames))]
    public async Task EveryVector_HasTheSameOutcomeForEveryReadShape(string name)
    {
        byte[] bytes = File.ReadAllBytes(
            Path.Combine(AppContext.BaseDirectory, FixtureDirectory, name));

        await AssertSameOutcomeForEveryShapeAsync(bytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MultiBlockManifest_HasTheSameOutcomeForEveryReadShape(bool includeBlockIndex)
    {
        // Full CBLK payloads are larger than the read-ahead buffer, so this
        // exercises the direct-read path between buffered headers.
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount: (3 * 4096) + 17,
            includeBlockIndex);

        string outcome = await AssertSameOutcomeForEveryShapeAsync(bytes);
        Assert.StartsWith("valid=True", outcome, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BytesAfterTheTrailer_AreRejectedWhetherBufferedOrNot(bool multiBlock)
    {
        byte[] valid = multiBlock
            ? await CsmBytes.CreateSyntheticAsync(entryCount: 2 * 4096, includeBlockIndex: true)
            : await CsmBytes.CreateAsync(64 * 1024);
        byte[] bytes = [.. valid, 0];

        // With whole requests the extra byte arrives in the same read as the
        // TRAILER; with single bytes it arrives in the end-of-stream probe.
        foreach (int[] shape in Shapes)
        {
            InvalidDataException exception =
                await Assert.ThrowsAsync<InvalidDataException>(
                    () => ChunkManifest.VerifyManifestAsync(new ShapedReadStream(bytes, shape)));

            Assert.Contains("after the fixed CSM trailer", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task SmallManifest_IsReadWithOneReadAndTheEndOfStreamProbe()
    {
        byte[] bytes = File.ReadAllBytes(
            Path.Combine(AppContext.BaseDirectory, FixtureDirectory, "valid-small-sha256-bidx.csm"));
        var source = new ShapedReadStream(bytes, [int.MaxValue]);

        // The premise: the whole representation fits in one read-ahead fill.
        Assert.True(bytes.Length < CsmInput.ReadAheadSize);

        ManifestVerificationResult result = await ChunkManifest.VerifyManifestAsync(source);

        Assert.True(result.IsValid);
        Assert.Equal(2, source.Reads);
    }

    [Fact]
    public async Task ReadAhead_StaysBoundedForLargeManifests()
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount: 8 * 4096,
            includeBlockIndex: true);
        var source = new ShapedReadStream(bytes, [int.MaxValue]);

        ManifestVerificationResult result = await ChunkManifest.VerifyManifestAsync(source);

        Assert.True(result.IsValid);

        // Every request is a read-ahead fill (exactly the buffer), the one-byte
        // end-of-stream probe, or a CBLK payload remainder read into place,
        // which is at least a buffer long and at most one maximal CBLK record.
        const int maximumCblkRecord = CsmFormat.SectionHeaderSize + CsmFormat.CblkPrefixSize
            + ((int)CsmFormat.MaximumChunksPerBlock * (CsmFormat.HashSize + sizeof(uint))) + sizeof(uint);
        Assert.All(
            source.RequestedReadLengths,
            requested => Assert.True(
                requested == CsmInput.ReadAheadSize
                || requested == 1
                || requested is > CsmInput.ReadAheadSize and <= maximumCblkRecord,
                $"Unexpected {requested}-byte read request."));
        Assert.Equal(1, source.RequestedReadLengths.Count(static requested => requested == 1));

        // Two reads per full CBLK (payload remainder, then a refill that also
        // carries the next header) plus a few for the prefix and tail.
        Assert.InRange(source.Reads, 8, (2 * 8) + 4);
    }

    [Fact]
    public async Task SeekableSourceReturningMoreThanItsLength_IsRejected()
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(entryCount: 2 * 4096, includeBlockIndex: false);

        // Reports a length that ends inside the first read-ahead fill but
        // serves every byte; the reader must notice before trusting the rest.
        using var source = new UnderReportingLengthStream(bytes, reportedLength: 1024);

        InvalidDataException exception =
            await Assert.ThrowsAsync<InvalidDataException>(
                () => ChunkManifest.VerifyManifestAsync(source));

        Assert.Contains("length shorter than the bytes already read", exception.Message, StringComparison.Ordinal);
    }

    private static async Task<string> AssertSameOutcomeForEveryShapeAsync(byte[] bytes)
    {
        // The baseline is forward-only too: a seekable source adds the
        // known-length check on section payloads, which can reject earlier with
        // a different message; CsmIndependentVectorTests covers that path.
        string expected = await OutcomeAsync(new ShapedReadStream(bytes, Shapes[0]));

        foreach (int[] shape in Shapes[1..])
        {
            Assert.Equal(expected, await OutcomeAsync(new ShapedReadStream(bytes, shape)));
        }

        return expected;
    }

    private static async Task<string> OutcomeAsync(Stream source)
    {
        try
        {
            ManifestVerificationResult result = await ChunkManifest.VerifyManifestAsync(source);
            ManifestInfo manifest = result.Manifest;

            return FormattableString.Invariant(
                $"valid={result.IsValid} failures={result.Failures} id={manifest.ManifestId} digest={manifest.FileDigest.ToHexLower()} chunks={manifest.ChunkCount} bytes={manifest.PhysicalLength}");
        }
        catch (Exception exception) when (exception is InvalidDataException or NotSupportedException)
        {
            return $"{exception.GetType().Name}: {exception.Message}";
        }
    }

    /// <summary>Forward-only stream that caps each read at the next shape entry.</summary>
    private sealed class ShapedReadStream(byte[] data, int[] shape) : Stream
    {
        private int _position;

        internal int Reads { get; private set; }

        internal List<int> RequestedReadLengths { get; } = [];

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
            ReadCore(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ReadCore(buffer.Span));

        public override void Flush() => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private int ReadCore(Span<byte> destination)
        {
            RequestedReadLengths.Add(destination.Length);
            int limit = shape[Reads++ % shape.Length];
            int count = Math.Min(Math.Min(limit, destination.Length), data.Length - _position);
            data.AsSpan(_position, count).CopyTo(destination);
            _position += count;
            return count;
        }
    }

    /// <summary>Seekable stream whose Length is smaller than the bytes it serves.</summary>
    private sealed class UnderReportingLengthStream(byte[] data, long reportedLength) : MemoryStream(data, writable: false)
    {
        public override long Length => reportedLength;
    }
}
