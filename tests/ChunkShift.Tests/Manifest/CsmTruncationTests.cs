using System.Globalization;
using ChunkShift.Manifest;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// Truncation matrix over every structural boundary of a CSM representation,
/// for seekable, forward-only and one-byte-per-read sources.
/// </summary>
/// <remarks>
/// CSM-V1 §13: on an unknown-length forward-only stream the reader
/// consumes exactly PayloadLength bytes and treats premature EOF as truncation.
/// A seekable source may reject earlier because a declared PayloadLength
/// exceeds the known remaining bytes. Either way the error must name the
/// truncation, and a forward-only EOF must be reported at the exact cut.
/// </remarks>
public sealed class CsmTruncationTests
{
    private const string PayloadExceedsRemaining =
        "CSM section PayloadLength exceeds the known remaining physical bytes.";

    private const string Seekable = "seekable";
    private const string ForwardOnly = "forward-only";
    private const string ForwardOnlyOneByteReads = "forward-only-1-byte-reads";

    [Theory]
    [InlineData(Seekable, false)]
    [InlineData(Seekable, true)]
    [InlineData(ForwardOnly, false)]
    [InlineData(ForwardOnly, true)]
    [InlineData(ForwardOnlyOneByteReads, false)]
    [InlineData(ForwardOnlyOneByteReads, true)]
    public async Task EveryStructuralCut_IsReportedAsTruncation(
        string kind,
        bool includeBlockIndex)
    {
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount: 4097,
            includeBlockIndex);

        // The untruncated representation must itself be valid through the same
        // source kind, otherwise the matrix would prove nothing.
        CsmReadResult complete = await CsmReader.ReadAndVerifyAsync(
            Open(bytes, kind));
        Assert.True(complete.IsValid);

        int[] cuts = GetStructuralCuts(bytes);
        Assert.True(cuts.Length > 20);

        foreach (int cut in cuts)
        {
            byte[] truncated = bytes.AsSpan(0, cut).ToArray();

            InvalidDataException exception =
                await Assert.ThrowsAsync<InvalidDataException>(
                    () => CsmReader.ReadAndVerifyAsync(Open(truncated, kind)));

            string eofAtCut = string.Create(
                CultureInfo.InvariantCulture,
                $"Unexpected EOF at physical offset {cut}.");

            if (kind == Seekable)
            {
                Assert.True(
                    exception.Message == eofAtCut ||
                    exception.Message == PayloadExceedsRemaining,
                    $"cut {cut}: unexpected message '{exception.Message}'");
            }
            else
            {
                Assert.True(
                    exception.Message == eofAtCut,
                    $"cut {cut}: expected '{eofAtCut}' but got '{exception.Message}'");
            }
        }
    }

    private static Stream Open(byte[] bytes, string kind)
    {
        var storage = new MemoryStream(bytes, writable: false);

        return kind switch
        {
            Seekable => storage,
            ForwardOnly => new ForwardOnlyStream(storage, int.MaxValue),
            ForwardOnlyOneByteReads => new ForwardOnlyStream(storage, 1),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
    }

    private static int[] GetStructuralCuts(byte[] bytes)
    {
        var cuts = new List<int>
        {
            0,
            1,
            CsmFormat.PreambleSize - 1,
            CsmFormat.PreambleSize,
        };

        foreach ((int offset, int length, _) in CsmBytes.EnumerateSections(bytes))
        {
            // Section missing entirely, partial header, header complete with the
            // payload missing, partial payload and one byte short of complete.
            cuts.Add(offset);
            cuts.Add(offset + 1);
            cuts.Add(offset + CsmFormat.SectionHeaderSize - 1);
            cuts.Add(offset + CsmFormat.SectionHeaderSize);
            cuts.Add(offset + CsmFormat.SectionHeaderSize + ((length - CsmFormat.SectionHeaderSize) / 2));
            cuts.Add(offset + length - 1);
        }

        int trailerOffset = bytes.Length - CsmFormat.TrailerSize;
        cuts.Add(trailerOffset);
        cuts.Add(trailerOffset + 1);
        cuts.Add(trailerOffset + (CsmFormat.TrailerSize / 2));
        cuts.Add(bytes.Length - 1);

        return cuts
            .Where(cut => cut >= 0 && cut < bytes.Length)
            .Distinct()
            .Order()
            .ToArray();
    }

    private sealed class ForwardOnlyStream : Stream
    {
        private readonly Stream _inner;
        private readonly int _maximumReadLength;

        internal ForwardOnlyStream(Stream inner, int maximumReadLength)
        {
            _inner = inner;
            _maximumReadLength = maximumReadLength;
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

        public override int Read(byte[] buffer, int offset, int count) =>
            _inner.Read(buffer, offset, Math.Min(count, _maximumReadLength));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(
                buffer[..Math.Min(buffer.Length, _maximumReadLength)],
                cancellationToken);

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
