using System.Buffers.Binary;
using ChunkShift.Patching.Encoding;

namespace ChunkShift.Patching.Tests.Encoding;

/// <summary>
/// The RFC 8878 frame-envelope rules CSP adds to encoding 1
/// (docs/architecture/CSP-V1.md section 5.2, rules 29 and 30).
/// Every frame here is assembled from explicit RFC field values; the validator
/// is never asked to bless bytes a real compressor produced.
/// </summary>
public sealed class ZstdFrameEnvelopeTests
{
    [Fact]
    public void ValidSingleSegmentFrame_IsAccepted()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();

        ZstdFrameEnvelope.Validate(frame, 200);
    }

    [Fact]
    public void ValidWindowDescriptorOfExactlyOneMiB_IsAccepted()
    {
        // Exponent 10, Mantissa 0: windowLog 20, window 1 MiB, the CSP maximum.
        // The 2-byte content size field stores value - 256.
        byte[] frame = new ZstdFrameBuilder
        {
            SingleSegment = false,
            WindowDescriptor = 10 << 3,
            ContentSizeFlag = 1,
            ContentSize = 256,
        }.Build();

        ZstdFrameEnvelope.Validate(frame, 256);
    }

    [Fact]
    public void MissingContentSize_IsRejected()
    {
        // A multi-segment frame with Frame_Content_Size_Flag 0 has no content
        // size field at all (rule 30).
        byte[] frame = new ZstdFrameBuilder
        {
            SingleSegment = false,
            WindowDescriptor = 10 << 3,
            ContentSize = 100,
        }.Build();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(frame, 100));
    }

    [Fact]
    public void WrongContentSize_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(frame, 201));
    }

    [Fact]
    public void NonZeroDictionaryId_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
            DictionaryIdFlag = 1,
            DictionaryId = 7,
        }.Build();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(frame, 200));
    }

    [Fact]
    public void ZeroDictionaryIdField_IsAccepted()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
            DictionaryIdFlag = 2,
            DictionaryId = 0,
        }.Build();

        ZstdFrameEnvelope.Validate(frame, 200);
    }

    [Fact]
    public void WindowAboveOneMiB_IsRejected()
    {
        // Exponent 11: windowLog 21, window 2 MiB.
        byte[] frame = new ZstdFrameBuilder
        {
            SingleSegment = false,
            WindowDescriptor = 11 << 3,
            ContentSizeFlag = 1,
            ContentSize = 256,
        }.Build();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(frame, 256));
    }

    [Fact]
    public void ReservedDescriptorBit_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
            ReservedDescriptorBit = true,
        }.Build();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(frame, 200));
    }

    [Fact]
    public void ReservedBlockType_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
            Blocks = { (3, 1) },
        }.Build();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(frame, 200));
    }

    [Fact]
    public void BlockOverrun_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
            Blocks = { (0, 100) },
        }.Build();

        // Drop half of the raw block's content: the block header claims more
        // bytes than the stored bytes still hold.
        byte[] truncated = frame.AsSpan(0, frame.Length - 50).ToArray();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(truncated, 200));
    }

    [Fact]
    public void TruncatedFrame_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();

        byte[] truncated = frame.AsSpan(0, frame.Length - 1).ToArray();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(truncated, 200));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    public void FewerThanFiveBytes_AreRejected(int length)
    {
        Assert.Throws<InvalidDataException>(
            () => ZstdFrameEnvelope.Validate(new byte[length], 0));
    }

    [Fact]
    public void MagicWithoutTheDescriptorByte_IsRejected()
    {
        Assert.Throws<InvalidDataException>(
            () => ZstdFrameEnvelope.Validate([0x28, 0xB5, 0x2F, 0xFD], 0));
    }

    [Fact]
    public void SecondFrame_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();
        byte[] second = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();

        byte[] stored = [.. frame, .. second];

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(stored, 200));
    }

    [Fact]
    public void LeadingSkippableFrame_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();
        byte[] stored = [.. SkippableFrame(4), .. frame];

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(stored, 200));
    }

    [Fact]
    public void TrailingSkippableFrame_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();
        byte[] stored = [.. frame, .. SkippableFrame(4)];

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(stored, 200));
    }

    [Fact]
    public void TrailingBytes_AreRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
        }.Build();
        byte[] stored = [.. frame, 0x00];

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(stored, 200));
    }

    [Fact]
    public void ContentChecksumWithItsFourBytes_IsAccepted()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
            ContentChecksum = true,
        }.Build();

        ZstdFrameEnvelope.Validate(frame, 200);
    }

    [Fact]
    public void ContentChecksumWithoutItsFourBytes_IsRejected()
    {
        byte[] frame = new ZstdFrameBuilder
        {
            ContentSize = 200,
            ContentChecksum = true,
            WriteChecksumBytes = false,
        }.Build();

        Assert.Throws<InvalidDataException>(() => ZstdFrameEnvelope.Validate(frame, 200));
    }

    private static byte[] SkippableFrame(int payloadLength)
    {
        byte[] frame = new byte[8 + payloadLength];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, 0x184D2A50);
        BinaryPrimitives.WriteUInt32LittleEndian(
            frame.AsSpan(sizeof(uint)),
            (uint)payloadLength);
        return frame;
    }

    /// <summary>
    /// Assembles one frame from explicit RFC 8878 fields. The default frame is
    /// a valid single-segment frame whose one RLE block closes the frame.
    /// </summary>
    private sealed class ZstdFrameBuilder
    {
        internal bool SingleSegment { get; set; } = true;

        internal int ContentSizeFlag { get; set; }

        internal bool ReservedDescriptorBit { get; set; }

        internal bool ContentChecksum { get; set; }

        internal int DictionaryIdFlag { get; set; }

        internal ulong DictionaryId { get; set; }

        internal byte WindowDescriptor { get; set; }

        internal ulong ContentSize { get; set; } = 200;

        internal List<(uint Type, uint Size)> Blocks { get; } = [(1, 1)];

        internal bool WriteChecksumBytes { get; set; } = true;

        internal byte[] Build()
        {
            var frame = new List<byte> { 0x28, 0xB5, 0x2F, 0xFD };

            frame.Add((byte)(
                (ContentSizeFlag << 6)
                | (SingleSegment ? 0x20 : 0)
                | (ReservedDescriptorBit ? 0x08 : 0)
                | (ContentChecksum ? 0x04 : 0)
                | DictionaryIdFlag));

            if (!SingleSegment)
            {
                frame.Add(WindowDescriptor);
            }

            int dictionaryIdSize = DictionaryIdFlag switch
            {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };

            for (int index = 0; index < dictionaryIdSize; index++)
            {
                frame.Add((byte)(DictionaryId >> (8 * index)));
            }

            int contentSizeSize = (SingleSegment ? new[] { 1, 2, 4, 8 } : new[] { 0, 2, 4, 8 })
                [ContentSizeFlag];
            ulong encodedContentSize = ContentSizeFlag == 1
                ? ContentSize - 256
                : ContentSize;

            for (int index = 0; index < contentSizeSize; index++)
            {
                frame.Add((byte)(encodedContentSize >> (8 * index)));
            }

            for (int index = 0; index < Blocks.Count; index++)
            {
                (uint type, uint size) = Blocks[index];
                uint header = (size << 3)
                    | (type << 1)
                    | (index == Blocks.Count - 1 ? 1u : 0u);

                frame.Add((byte)header);
                frame.Add((byte)(header >> 8));
                frame.Add((byte)(header >> 16));

                int contentSize = type == 1 ? 1 : (int)size;

                for (int content = 0; content < contentSize; content++)
                {
                    frame.Add(0);
                }
            }

            if (ContentChecksum && WriteChecksumBytes)
            {
                frame.AddRange([0x12, 0x34, 0x56, 0x78]);
            }

            return [.. frame];
        }
    }
}
