using System.Buffers.Binary;

namespace ChunkShift.Patching.Encoding;

/// <summary>
/// RFC 8878 frame-envelope validation for CSP payload encoding 1
/// (docs/architecture/CSP-V1.md sections 5.2 and 7, rules 29 and 30).
/// </summary>
/// <remarks>
/// <para>
/// The stored bytes must be exactly one standard zstd frame: the frame magic
/// and header of RFC 8878, one or more data blocks ending at the stored bytes,
/// and nothing else. Skippable frames, a second frame and trailing bytes are
/// rejected, as are a reserved descriptor bit, a reserved block type, a
/// truncated header or block, an absent or mismatching
/// <c>Frame_Content_Size</c>, a non-zero <c>Dictionary_ID</c> and a window
/// above <see cref="MaximumWindowBytes"/>.
/// </para>
/// <para>
/// This is envelope validation only. Block headers are walked to prove the
/// stored bytes end with the frame, but compressed block contents are never
/// interpreted and no declared size drives an allocation. Every rejection is
/// <see cref="InvalidDataException"/>, whether it breaks rule 29 or rule 30.
/// </para>
/// </remarks>
internal static class ZstdFrameEnvelope
{
    /// <summary>Maximum window (and single-segment content size) CSP allows.</summary>
    internal const int MaximumWindowBytes = 1 << 20;

    /// <summary>ASCII <c>28 B5 2F FD</c>, the little-endian frame magic.</summary>
    private const uint FrameMagic = 0xFD2FB528;

    private const int DescriptorOffset = 4;
    private const int BlockHeaderSize = 3;
    private const int ContentChecksumSize = 4;
    private const int ReservedDescriptorBit = 0x08;
    private const int SingleSegmentBit = 0x20;
    private const int ContentChecksumBit = 0x04;
    private const int DictionaryIdFlagMask = 0x03;
    private const int ContentSizeFlagShift = 6;
    private const uint BlockTypeMask = 0x03;
    private const uint BlockSizeShift = 3;
    private const uint LastBlockBit = 0x01;
    private const uint ReservedBlockType = 3;

    private static readonly int[] DictionaryIdSizes = [0, 1, 2, 4];
    private static readonly int[] SingleSegmentContentSizes = [1, 2, 4, 8];
    private static readonly int[] MultiSegmentContentSizes = [0, 2, 4, 8];

    /// <summary>
    /// Throws <see cref="InvalidDataException"/> unless <paramref name="stored"/>
    /// is exactly one zstd frame whose declared content size is
    /// <paramref name="chunkLength"/> and that satisfies CSP section 5.2.
    /// </summary>
    /// <param name="stored">The stored bytes of one encoding-1 payload entry.</param>
    /// <param name="chunkLength">Target chunk length the frame must declare.</param>
    internal static void Validate(ReadOnlySpan<byte> stored, int chunkLength)
    {
        if (stored.Length < DescriptorOffset + 1 ||
            BinaryPrimitives.ReadUInt32LittleEndian(stored) != FrameMagic)
        {
            throw Malformed("The stored bytes are not exactly one zstd frame.");
        }

        byte descriptor = stored[DescriptorOffset];

        if ((descriptor & ReservedDescriptorBit) != 0)
        {
            throw Malformed("The zstd frame descriptor reserved bit is set.");
        }

        bool singleSegment = (descriptor & SingleSegmentBit) != 0;
        bool contentChecksum = (descriptor & ContentChecksumBit) != 0;
        int contentSizeFlag = descriptor >> ContentSizeFlagShift;
        int dictionaryIdFlag = descriptor & DictionaryIdFlagMask;

        int position = DescriptorOffset + 1;
        ulong window = 0;

        if (!singleSegment)
        {
            if (position >= stored.Length)
            {
                throw Malformed("The zstd frame header is truncated.");
            }

            byte windowDescriptor = stored[position];
            position++;

            int windowLog = 10 + (windowDescriptor >> 3);
            ulong windowBase = 1UL << windowLog;
            window = windowBase + ((windowBase >> 3) * (ulong)(windowDescriptor & 0x07));
        }

        int dictionaryIdSize = DictionaryIdSizes[dictionaryIdFlag];

        if (position > stored.Length - dictionaryIdSize)
        {
            throw Malformed("The zstd frame header is truncated.");
        }

        ulong dictionaryId = 0;

        for (int index = 0; index < dictionaryIdSize; index++)
        {
            dictionaryId |= (ulong)stored[position + index] << (8 * index);
        }

        position += dictionaryIdSize;

        int contentSizeSize = singleSegment
            ? SingleSegmentContentSizes[contentSizeFlag]
            : MultiSegmentContentSizes[contentSizeFlag];

        if (contentSizeSize == 0)
        {
            throw Malformed("The zstd frame does not declare Frame_Content_Size.");
        }

        if (position > stored.Length - contentSizeSize)
        {
            throw Malformed("The zstd frame header is truncated.");
        }

        ulong contentSize = 0;

        for (int index = 0; index < contentSizeSize; index++)
        {
            contentSize |= (ulong)stored[position + index] << (8 * index);
        }

        position += contentSizeSize;

        if (contentSizeSize == 2)
        {
            contentSize += 256;
        }

        if (dictionaryId != 0)
        {
            throw Malformed("The zstd frame declares a non-zero Dictionary_ID.");
        }

        if (contentSize != (ulong)chunkLength)
        {
            throw Malformed(
                "The zstd frame Frame_Content_Size differs from the target chunk length.");
        }

        if (singleSegment)
        {
            window = contentSize;
        }

        if (window > MaximumWindowBytes)
        {
            throw Malformed("The zstd frame window exceeds 1 MiB.");
        }

        position = WalkBlocks(stored, position);

        if (contentChecksum)
        {
            if (position > stored.Length - ContentChecksumSize)
            {
                throw Malformed("The zstd frame content checksum is truncated.");
            }

            position += ContentChecksumSize;
        }

        if (position != stored.Length)
        {
            throw Malformed(
                "The stored bytes carry a second frame, a skippable frame or trailing bytes.");
        }
    }

    /// <summary>
    /// Walks the data-block headers and returns the offset just after the last
    /// block, throwing when a block is reserved, truncated or overruns the
    /// stored bytes.
    /// </summary>
    private static int WalkBlocks(ReadOnlySpan<byte> stored, int position)
    {
        while (true)
        {
            if (position > stored.Length - BlockHeaderSize)
            {
                throw Malformed("The zstd frame is truncated before its last block.");
            }

            uint header = (uint)stored[position]
                | ((uint)stored[position + 1] << 8)
                | ((uint)stored[position + 2] << 16);
            position += BlockHeaderSize;

            bool lastBlock = (header & LastBlockBit) != 0;
            uint blockType = (header >> 1) & BlockTypeMask;
            uint blockSize = header >> (int)BlockSizeShift;

            if (blockType == ReservedBlockType)
            {
                throw Malformed("The zstd frame carries a reserved block type.");
            }

            // Raw and compressed blocks carry Block_Size content bytes; an RLE
            // block carries exactly one, whatever size it decodes to.
            ulong contentSize = blockType == 1 ? 1UL : blockSize;

            if (contentSize > (ulong)(stored.Length - position))
            {
                throw Malformed("A zstd block overruns the stored bytes.");
            }

            position = checked(position + (int)contentSize);

            if (lastBlock)
            {
                return position;
            }
        }
    }

    private static InvalidDataException Malformed(string message) => new(message);
}
