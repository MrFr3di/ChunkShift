using System.Buffers.Binary;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Format;

/// <summary>
/// One payload entry the writer encodes into a CSP v1 <c>PAYL</c> block.
/// </summary>
/// <param name="ChunkId">Target chunk identity the stored bytes reproduce.</param>
/// <param name="FirstTargetIndex">Index of the first target-manifest record with this identity.</param>
/// <param name="Encoding">Payload encoding: 0 raw, 1 one zstd frame.</param>
/// <param name="DictionaryChunkIds">Base chunks used as raw dictionary content, in listed order.</param>
internal readonly record struct CspPayloadEntry(
    ChunkId ChunkId,
    ulong FirstTargetIndex,
    byte Encoding,
    ReadOnlyMemory<ChunkId> DictionaryChunkIds);

/// <summary>
/// Totals of one completed CSP v1 patch.
/// </summary>
/// <param name="FileDigest">Physical digest over every byte before the TRAILER.</param>
/// <param name="PhysicalLength">Complete patch length including the TRAILER.</param>
/// <param name="PayloadEntryCount">Number of payload entries written.</param>
/// <param name="PaylCount">Number of <c>PAYL</c> sections written.</param>
/// <param name="StoredPayloadBytes">Sum of every entry's stored byte length.</param>
internal readonly record struct CspWriteResult(
    Hash256 FileDigest,
    ulong PhysicalLength,
    ulong PayloadEntryCount,
    ulong PaylCount,
    ulong StoredPayloadBytes);

/// <summary>
/// Forward-only CSP v1 writer.
/// </summary>
/// <remarks>
/// <para>
/// The writer emits the physical order of CSP-V1 section 4.1 without
/// ever seeking or reading its destination, hashes every byte before the
/// TRAILER into <see cref="CspWriteResult.FileDigest"/> and buffers at most one
/// <c>PAYL</c> block plus the payload index (section 8). It
/// validates entry shape and call order; the semantic rules against the
/// embedded target manifest are the caller's responsibility.
/// </para>
/// <para>
/// The destination and the embedded target manifest stream stay owned by the
/// caller and are never disposed. Any exception from a call, cancellation
/// included, faults the writer: every later call throws
/// <see cref="InvalidOperationException"/> until it is disposed.
/// </para>
/// </remarks>
internal sealed class CspWriter : IDisposable
{
    internal const int DefaultPayloadBlockBytes = 4 * 1024 * 1024;

    // Bounded pieces for the embedded TCSM copy, mirroring the CSM encoder's
    // write granularity. The writer never materializes the whole manifest.
    private const int ManifestCopyBytes = 81_920;
    private const int PidxBatchEntries = 1024;
    private const int BlockEntriesOffset =
        CspFormat.SectionHeaderSize + CspFormat.PaylPrefixSize;
    private const int PidxEntriesOffset =
        CspFormat.SectionHeaderSize + CspFormat.PidxPrefixSize;
    private const int BaseSectionBytes =
        CspFormat.SectionHeaderSize + CspFormat.BasePayloadSize;
    private const int FootSectionBytes =
        CspFormat.SectionHeaderSize + CspFormat.FootPayloadSize;
    private const int SectionScratchBytes =
        CspFormat.SectionHeaderSize
        + CspFormat.PaylPrefixSize
        + CspFormat.PaylEntryHeaderSize
        + (CspFormat.DictionaryReferenceSize * CspFormat.MaximumDictionaryCount);
    private const int MaximumPayloadBlockBytes =
        int.MaxValue - CspFormat.SectionHeaderSize - CspFormat.PaylPrefixSize - CspFormat.CrcSize;

    // Field offsets inside a PAYL entry record (CSP-V1 section 4.6).
    private const int EntryStoredLengthOffset = 32;
    private const int EntryEncodingOffset = 36;
    private const int EntryDictionaryCountOffset = 37;
    private const int EntryReservedOffset = 38;
    private const int EntryDictionaryOffset = CspFormat.PaylEntryHeaderSize;

    // Field offsets inside a PIDX entry record (CSP-V1 section 4.7).
    private const int IndexPayloadOffsetOffset = 8;
    private const int IndexStoredLengthOffset = 16;
    private const int IndexEncodingOffset = 20;
    private const int IndexDictionaryCountOffset = 21;
    private const int IndexReservedOffset = 22;

    private readonly Stream _destination;
    private readonly IncrementalPatchHash _hasher;
    private readonly int _payloadBlockBytes;
    private readonly int _maximumPayloadEntries;
    private readonly byte[] _blockBuffer;
    private readonly byte[] _sectionScratch;

    private PidxRecord[] _index = new PidxRecord[64];
    private int _indexCount;
    private int _blockEntryCount;
    private long _blockEntryBytes;
    private ulong _blockFirstEntryOrdinal;
    private ulong _payloadEntryCount;
    private ulong _paylCount;
    private ulong _storedPayloadBytes;
    private ulong _lastFirstTargetIndex;
    private ulong _tcsSectionOffset;
    private ulong _baseSectionOffset;
    private ulong _pidxSectionOffset;
    private ulong _footSectionOffset;
    private ulong _firstPaylSectionOffset;
    private bool _tcsWritten;
    private bool _baseWritten;
    private bool _completed;
    private bool _faulted;
    private bool _disposed;

    internal CspWriter(
        Stream destination,
        HashSuiteId hashSuite,
        int payloadBlockBytes = DefaultPayloadBlockBytes,
        int maximumPayloadEntries = CspFormat.DefaultMaximumPayloadEntries)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(hashSuite);

        if (!destination.CanWrite)
        {
            throw new ArgumentException(
                "CSP destination stream must be writable.",
                nameof(destination));
        }

        if (!PatchHashing.IsSupported(hashSuite))
        {
            throw new NotSupportedException($"Unsupported HashSuiteId '{hashSuite}'.");
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(payloadBlockBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumPayloadEntries);

        if (payloadBlockBytes > MaximumPayloadBlockBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payloadBlockBytes),
                $"Payload block bytes must not exceed {MaximumPayloadBlockBytes}.");
        }

        _destination = destination;
        _hasher = PatchHashing.CreateIncremental(hashSuite);
        _payloadBlockBytes = payloadBlockBytes;
        _maximumPayloadEntries = maximumPayloadEntries;
        _blockBuffer = new byte[checked(BlockEntriesOffset + payloadBlockBytes + CspFormat.CrcSize)];
        _sectionScratch = new byte[SectionScratchBytes];
    }

    /// <summary>Gets the number of bytes written to the destination so far.</summary>
    internal ulong Offset { get; private set; }

    /// <summary>
    /// Writes the fixed PREAMBLE and the embedded target CSM as the <c>TCSM</c>
    /// section. Must be the first call and is permitted exactly once.
    /// </summary>
    internal async ValueTask WriteTargetManifestAsync(
        Stream manifest,
        long length,
        CancellationToken cancellationToken)
    {
        try
        {
            ThrowIfUnavailable();

            if (_tcsWritten)
            {
                throw new InvalidOperationException(
                    "The target manifest can be written only once and before every other section.");
            }

            ArgumentNullException.ThrowIfNull(manifest);

            if (!manifest.CanRead)
            {
                throw new ArgumentException(
                    "The target manifest stream must be readable.",
                    nameof(manifest));
            }

            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
            cancellationToken.ThrowIfCancellationRequested();

            PreparePreamble();
            await WriteHashedAsync(
                _sectionScratch.AsMemory(0, CspFormat.PreambleSize),
                cancellationToken).ConfigureAwait(false);

            _tcsSectionOffset = Offset;
            PrepareTargetManifestHeader(checked((ulong)length));
            await WriteHashedAsync(
                _sectionScratch.AsMemory(0, CspFormat.SectionHeaderSize),
                cancellationToken).ConfigureAwait(false);

            byte[] copyBuffer = new byte[ManifestCopyBytes];
            long remaining = length;

            while (remaining > 0)
            {
                int requested = (int)Math.Min((long)copyBuffer.Length, remaining);
                int read = await manifest
                    .ReadAsync(copyBuffer.AsMemory(0, requested), cancellationToken)
                    .ConfigureAwait(false);

                if ((uint)read > (uint)requested)
                {
                    throw new InvalidOperationException(
                        "The target manifest stream returned a byte count outside the Stream contract.");
                }

                if (read == 0)
                {
                    throw new InvalidDataException(
                        "The target manifest ended before its declared length.");
                }

                await WriteHashedAsync(
                    copyBuffer.AsMemory(0, read),
                    cancellationToken).ConfigureAwait(false);

                remaining -= read;
            }

            _tcsWritten = true;
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    /// <summary>
    /// Writes the optional <c>BASE</c> section with the expected base
    /// <see cref="ManifestId"/>. Permitted at most once, after the target
    /// manifest and before the first payload entry.
    /// </summary>
    internal async ValueTask WriteExpectedBaseAsync(
        ManifestId expectedBase,
        CancellationToken cancellationToken)
    {
        try
        {
            ThrowIfUnavailable();

            if (!_tcsWritten)
            {
                throw new InvalidOperationException(
                    "The target manifest must be written before the expected base.");
            }

            if (_baseWritten)
            {
                throw new InvalidOperationException(
                    "The expected base can be written at most once.");
            }

            if (_payloadEntryCount != 0)
            {
                throw new InvalidOperationException(
                    "The expected base must be written before the first payload entry.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            PrepareBaseSection(expectedBase);
            _baseSectionOffset = Offset;
            await WriteHashedAsync(
                _sectionScratch.AsMemory(0, BaseSectionBytes),
                cancellationToken).ConfigureAwait(false);

            _baseWritten = true;
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    /// <summary>
    /// Adds one payload entry. Entries are appended in target first-occurrence
    /// order and grouped into <c>PAYL</c> blocks of at most
    /// <see cref="CspFormat.MaximumEntriesPerPayl"/> entries and roughly
    /// <c>payloadBlockBytes</c> entry bytes.
    /// </summary>
    internal async ValueTask AddPayloadEntryAsync(
        CspPayloadEntry entry,
        ReadOnlyMemory<byte> storedBytes,
        CancellationToken cancellationToken)
    {
        try
        {
            ThrowIfUnavailable();

            if (!_tcsWritten)
            {
                throw new InvalidOperationException(
                    "The target manifest must be written before any payload entry.");
            }

            ValidateEntry(entry, storedBytes);
            cancellationToken.ThrowIfCancellationRequested();

            long entryBytes = checked(
                (long)GetEntryMetadataSize(entry) + storedBytes.Length);

            if (_blockEntryCount >= (int)CspFormat.MaximumEntriesPerPayl ||
                (_blockEntryCount > 0 &&
                 checked(_blockEntryBytes + entryBytes) > _payloadBlockBytes))
            {
                await FlushBlockAsync(cancellationToken).ConfigureAwait(false);
            }

            uint storedLength = checked((uint)storedBytes.Length);

            if (entryBytes > _payloadBlockBytes)
            {
                ulong payloadOffset = await WriteStandaloneEntryAsync(
                    entry,
                    storedBytes,
                    storedLength,
                    cancellationToken).ConfigureAwait(false);

                RecordAcceptedEntry(entry, storedLength, payloadOffset);
                return;
            }

            if (_blockEntryCount == 0)
            {
                _blockFirstEntryOrdinal = _payloadEntryCount;
            }

            AppendEntryToBlock(entry, storedBytes.Span);
            _blockEntryCount++;
            _blockEntryBytes = checked(_blockEntryBytes + entryBytes);

            RecordAcceptedEntry(entry, storedLength, payloadOffset: 0);
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    /// <summary>
    /// Writes the last payload block, the <c>PIDX</c> index, the <c>FOOT</c>
    /// section and the fixed TRAILER, and returns the patch totals. Permitted
    /// exactly once, after the target manifest.
    /// </summary>
    internal async ValueTask<CspWriteResult> CompleteAsync(CancellationToken cancellationToken)
    {
        try
        {
            ThrowIfUnavailable();

            if (!_tcsWritten)
            {
                throw new InvalidOperationException(
                    "The target manifest must be written before the patch is completed.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            await FlushBlockAsync(cancellationToken).ConfigureAwait(false);
            await WritePayloadIndexAsync(cancellationToken).ConfigureAwait(false);
            await WriteFooterAsync(cancellationToken).ConfigureAwait(false);

            Hash256 fileDigest = _hasher.FinalizeHash();
            ulong physicalLength = checked(Offset + CspFormat.TrailerSize);

            PrepareTrailer(fileDigest, physicalLength);
            await WriteTrailerAsync(
                _sectionScratch.AsMemory(0, CspFormat.TrailerSize),
                cancellationToken).ConfigureAwait(false);

            if (Offset != physicalLength)
            {
                throw new InvalidOperationException(
                    "CSP physical-length bookkeeping diverged.");
            }

            _completed = true;

            return new CspWriteResult(
                fileDigest,
                physicalLength,
                _payloadEntryCount,
                _paylCount,
                _storedPayloadBytes);
        }
        catch
        {
            _faulted = true;
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _hasher.Dispose();
    }

    private static int GetEntryMetadataSize(CspPayloadEntry entry) =>
        CspFormat.PaylEntryHeaderSize
        + checked(entry.DictionaryChunkIds.Length * CspFormat.DictionaryReferenceSize);

    private static void WriteSectionHeader(
        Span<byte> destination,
        uint type,
        uint flags,
        ulong payloadLength)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination, type);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], flags);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], payloadLength);
    }

    private static void WritePaylPrefix(
        Span<byte> destination,
        uint entryCount,
        ulong firstEntryOrdinal)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination, entryCount);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], firstEntryOrdinal);
    }

    private static void WriteEntryMetadata(
        Span<byte> destination,
        CspPayloadEntry entry,
        uint storedLength)
    {
        entry.ChunkId.Value.CopyTo(destination);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination[EntryStoredLengthOffset..],
            storedLength);
        destination[EntryEncodingOffset] = entry.Encoding;
        destination[EntryDictionaryCountOffset] =
            checked((byte)entry.DictionaryChunkIds.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(
            destination[EntryReservedOffset..],
            0);

        ReadOnlySpan<ChunkId> dictionaries = entry.DictionaryChunkIds.Span;

        for (int index = 0; index < dictionaries.Length; index++)
        {
            dictionaries[index].Value.CopyTo(
                destination.Slice(
                    EntryDictionaryOffset
                    + (index * CspFormat.DictionaryReferenceSize)));
        }
    }

    private static void WriteIndexEntry(Span<byte> destination, in PidxRecord record)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(
            destination,
            record.FirstTargetIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(
            destination[IndexPayloadOffsetOffset..],
            record.PayloadOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination[IndexStoredLengthOffset..],
            record.StoredLength);
        destination[IndexEncodingOffset] = record.Encoding;
        destination[IndexDictionaryCountOffset] = record.DictionaryCount;
        BinaryPrimitives.WriteUInt16LittleEndian(
            destination[IndexReservedOffset..],
            0);
    }

    private void PreparePreamble()
    {
        Span<byte> preamble = _sectionScratch.AsSpan(0, CspFormat.PreambleSize);
        CspFormat.PreambleMagic.CopyTo(preamble);
        BinaryPrimitives.WriteUInt16LittleEndian(
            preamble[4..],
            CspFormat.FormatMajor);
        BinaryPrimitives.WriteUInt16LittleEndian(
            preamble[6..],
            CspFormat.PreambleSize);
        BinaryPrimitives.WriteUInt64LittleEndian(preamble[8..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(preamble[16..], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(preamble[24..], 0);
    }

    private void PrepareTargetManifestHeader(ulong length)
    {
        WriteSectionHeader(
            _sectionScratch.AsSpan(0, CspFormat.SectionHeaderSize),
            CspFormat.TargetManifest,
            CspFormat.RequiredSectionFlag,
            length);
    }

    private void PrepareBaseSection(ManifestId expectedBase)
    {
        Span<byte> section = _sectionScratch.AsSpan(0, BaseSectionBytes);
        WriteSectionHeader(
            section,
            CspFormat.Base,
            0,
            CspFormat.BasePayloadSize);
        expectedBase.Value.CopyTo(section[CspFormat.SectionHeaderSize..]);
    }

    /// <summary>
    /// Encodes the open block into the block buffer and returns the record
    /// length, the section offset and the first entry's absolute offset.
    /// </summary>
    private (int RecordLength, ulong SectionOffset, ulong PayloadOffset) PrepareBlockRecord()
    {
        int entryBytes = checked((int)_blockEntryBytes);
        int payloadLength = checked(
            CspFormat.PaylPrefixSize + entryBytes + CspFormat.CrcSize);
        int recordLength = checked(CspFormat.SectionHeaderSize + payloadLength);
        ulong sectionOffset = Offset;
        ulong payloadOffset = checked(
            sectionOffset
            + (ulong)(CspFormat.SectionHeaderSize + CspFormat.PaylPrefixSize));

        Span<byte> record = _blockBuffer.AsSpan(0, recordLength);
        WriteSectionHeader(
            record,
            CspFormat.Payload,
            CspFormat.RequiredSectionFlag,
            checked((ulong)payloadLength));
        WritePaylPrefix(
            record[CspFormat.SectionHeaderSize..],
            checked((uint)_blockEntryCount),
            _blockFirstEntryOrdinal);
        BinaryPrimitives.WriteUInt32LittleEndian(
            record[(recordLength - CspFormat.CrcSize)..],
            Crc32C.Compute(record[..(recordLength - CspFormat.CrcSize)]));

        return (recordLength, sectionOffset, payloadOffset);
    }

    /// <summary>
    /// Records the absolute offset of every entry in the block just encoded.
    /// The index records of that block are the last
    /// <see cref="_blockEntryCount"/> entries of <see cref="_index"/>.
    /// </summary>
    private void PatchBlockOffsets(ulong payloadOffset)
    {
        Span<PidxRecord> block = _index.AsSpan(
            _indexCount - _blockEntryCount,
            _blockEntryCount);
        ulong entryOffset = payloadOffset;

        for (int index = 0; index < block.Length; index++)
        {
            ref PidxRecord record = ref block[index];
            record.PayloadOffset = entryOffset;
            entryOffset = checked(
                entryOffset
                + (ulong)(CspFormat.PaylEntryHeaderSize
                    + (record.DictionaryCount * CspFormat.DictionaryReferenceSize))
                + record.StoredLength);
        }
    }

    private void AppendEntryToBlock(CspPayloadEntry entry, ReadOnlySpan<byte> storedBytes)
    {
        int metadataSize = GetEntryMetadataSize(entry);
        Span<byte> destination = _blockBuffer.AsSpan(
            checked(BlockEntriesOffset + (int)_blockEntryBytes),
            checked(metadataSize + storedBytes.Length));

        WriteEntryMetadata(destination, entry, checked((uint)storedBytes.Length));
        storedBytes.CopyTo(destination[metadataSize..]);
    }

    private void AppendIndexRecord(
        CspPayloadEntry entry,
        uint storedLength,
        ulong payloadOffset)
    {
        if (_indexCount == _index.Length)
        {
            Array.Resize(ref _index, checked(_index.Length * 2));
        }

        _index[_indexCount] = new PidxRecord(
            entry.FirstTargetIndex,
            payloadOffset,
            storedLength,
            entry.Encoding,
            checked((byte)entry.DictionaryChunkIds.Length));
        _indexCount++;
    }

    private void RecordAcceptedEntry(
        CspPayloadEntry entry,
        uint storedLength,
        ulong payloadOffset)
    {
        _payloadEntryCount = checked(_payloadEntryCount + 1);
        _storedPayloadBytes = checked(_storedPayloadBytes + storedLength);
        _lastFirstTargetIndex = entry.FirstTargetIndex;
        AppendIndexRecord(entry, storedLength, payloadOffset);
    }

    private void ValidateEntry(CspPayloadEntry entry, ReadOnlyMemory<byte> storedBytes)
    {
        if (entry.Encoding != CspFormat.EncodingRaw &&
            entry.Encoding != CspFormat.EncodingZstd)
        {
            throw new ArgumentOutOfRangeException(
                nameof(entry),
                entry.Encoding,
                "CSP payload encoding must be 0 (raw) or 1 (zstd).");
        }

        if (entry.DictionaryChunkIds.Length > CspFormat.MaximumDictionaryCount)
        {
            throw new ArgumentException(
                $"A CSP payload entry names at most {CspFormat.MaximumDictionaryCount} dictionary chunks.",
                nameof(entry));
        }

        if (entry.Encoding == CspFormat.EncodingRaw &&
            !entry.DictionaryChunkIds.IsEmpty)
        {
            throw new ArgumentException(
                "A raw CSP payload entry cannot name dictionary chunks.",
                nameof(entry));
        }

        if (storedBytes.IsEmpty)
        {
            throw new ArgumentException(
                "A CSP payload entry must store at least one byte.",
                nameof(storedBytes));
        }

        if (_payloadEntryCount != 0 &&
            entry.FirstTargetIndex <= _lastFirstTargetIndex)
        {
            throw new ArgumentException(
                "CSP payload entry FirstTargetIndex values must strictly increase.",
                nameof(entry));
        }

        if (_payloadEntryCount >= (ulong)_maximumPayloadEntries)
        {
            throw new InvalidOperationException(
                $"The CSP writer already holds the maximum of {_maximumPayloadEntries} payload entries.");
        }
    }

    private async ValueTask FlushBlockAsync(CancellationToken cancellationToken)
    {
        if (_blockEntryCount == 0)
        {
            return;
        }

        (int recordLength, ulong sectionOffset, ulong payloadOffset) =
            PrepareBlockRecord();

        PatchBlockOffsets(payloadOffset);

        if (_firstPaylSectionOffset == 0)
        {
            _firstPaylSectionOffset = sectionOffset;
        }

        _paylCount = checked(_paylCount + 1);

        await WriteHashedAsync(
            _blockBuffer.AsMemory(0, recordLength),
            cancellationToken).ConfigureAwait(false);

        _blockEntryCount = 0;
        _blockEntryBytes = 0;
        _blockFirstEntryOrdinal = 0;
    }

    private async ValueTask<ulong> WriteStandaloneEntryAsync(
        CspPayloadEntry entry,
        ReadOnlyMemory<byte> storedBytes,
        uint storedLength,
        CancellationToken cancellationToken)
    {
        ulong sectionOffset = Offset;
        ulong payloadOffset = checked(
            sectionOffset
            + (ulong)(CspFormat.SectionHeaderSize + CspFormat.PaylPrefixSize));
        int headLength = PrepareStandaloneEntryHead(entry, storedLength);
        uint crc = Crc32C.Finalize(
            Crc32C.Append(
                Crc32C.Append(
                    Crc32C.Start(),
                    _sectionScratch.AsSpan(0, headLength)),
                storedBytes.Span));

        await WriteHashedAsync(
            _sectionScratch.AsMemory(0, headLength),
            cancellationToken).ConfigureAwait(false);

        if (!storedBytes.IsEmpty)
        {
            await WriteHashedAsync(storedBytes, cancellationToken).ConfigureAwait(false);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(
            _sectionScratch.AsSpan(0, CspFormat.CrcSize),
            crc);
        await WriteHashedAsync(
            _sectionScratch.AsMemory(0, CspFormat.CrcSize),
            cancellationToken).ConfigureAwait(false);

        if (_firstPaylSectionOffset == 0)
        {
            _firstPaylSectionOffset = sectionOffset;
        }

        _paylCount = checked(_paylCount + 1);

        return payloadOffset;
    }

    private int PrepareStandaloneEntryHead(CspPayloadEntry entry, uint storedLength)
    {
        int metadataSize = GetEntryMetadataSize(entry);
        int headLength = checked(
            CspFormat.SectionHeaderSize
            + CspFormat.PaylPrefixSize
            + metadataSize);
        ulong entryBytes = checked((ulong)metadataSize + storedLength);
        ulong payloadLength = checked(
            (ulong)CspFormat.PaylPrefixSize
            + entryBytes
            + (ulong)CspFormat.CrcSize);

        Span<byte> head = _sectionScratch.AsSpan(0, headLength);
        WriteSectionHeader(
            head,
            CspFormat.Payload,
            CspFormat.RequiredSectionFlag,
            payloadLength);
        WritePaylPrefix(
            head[CspFormat.SectionHeaderSize..],
            1,
            _payloadEntryCount);
        WriteEntryMetadata(
            head[(CspFormat.SectionHeaderSize + CspFormat.PaylPrefixSize)..],
            entry,
            storedLength);

        return headLength;
    }

    private async ValueTask WritePayloadIndexAsync(CancellationToken cancellationToken)
    {
        ulong entryCount = checked((ulong)_indexCount);
        ulong payloadLength = checked(
            (ulong)CspFormat.PidxPrefixSize
            + (entryCount * (ulong)CspFormat.PidxEntrySize)
            + (ulong)CspFormat.CrcSize);

        int batchEntries = Math.Min(_indexCount, PidxBatchEntries);
        byte[] buffer = new byte[
            PidxEntriesOffset
            + (batchEntries * CspFormat.PidxEntrySize)
            + CspFormat.CrcSize];

        _pidxSectionOffset = Offset;
        WriteSectionHeader(
            buffer.AsSpan(0, CspFormat.SectionHeaderSize),
            CspFormat.PayloadIndex,
            CspFormat.RequiredSectionFlag,
            payloadLength);
        BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(CspFormat.SectionHeaderSize, sizeof(uint)),
            CspFormat.IndexVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(CspFormat.SectionHeaderSize + sizeof(uint), sizeof(uint)),
            checked((uint)_indexCount));

        uint crc = Crc32C.Start();
        crc = Crc32C.Append(crc, buffer.AsSpan(0, PidxEntriesOffset));
        await WriteHashedAsync(
            buffer.AsMemory(0, PidxEntriesOffset),
            cancellationToken).ConfigureAwait(false);

        for (int start = 0; start < _indexCount; start += PidxBatchEntries)
        {
            int count = Math.Min(PidxBatchEntries, _indexCount - start);
            int batchLength = checked(count * CspFormat.PidxEntrySize);

            FillIndexBatch(buffer, start, count);
            crc = Crc32C.Append(
                crc,
                buffer.AsSpan(PidxEntriesOffset, batchLength));

            await WriteHashedAsync(
                buffer.AsMemory(PidxEntriesOffset, batchLength),
                cancellationToken).ConfigureAwait(false);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(
            buffer,
            Crc32C.Finalize(crc));
        await WriteHashedAsync(
            buffer.AsMemory(0, CspFormat.CrcSize),
            cancellationToken).ConfigureAwait(false);
    }

    private void FillIndexBatch(byte[] buffer, int start, int count)
    {
        for (int index = 0; index < count; index++)
        {
            WriteIndexEntry(
                buffer.AsSpan(
                    PidxEntriesOffset + (index * CspFormat.PidxEntrySize),
                    CspFormat.PidxEntrySize),
                _index[start + index]);
        }
    }

    private async ValueTask WriteFooterAsync(CancellationToken cancellationToken)
    {
        _footSectionOffset = Offset;
        PrepareFooter();
        await WriteHashedAsync(
            _sectionScratch.AsMemory(0, FootSectionBytes),
            cancellationToken).ConfigureAwait(false);
    }

    private void PrepareFooter()
    {
        Span<byte> section = _sectionScratch.AsSpan(0, FootSectionBytes);
        WriteSectionHeader(
            section,
            CspFormat.Footer,
            CspFormat.RequiredSectionFlag,
            CspFormat.FootPayloadSize);

        Span<byte> payload = section[CspFormat.SectionHeaderSize..];
        BinaryPrimitives.WriteUInt64LittleEndian(payload, _tcsSectionOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[8..], _baseSectionOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[16..], _pidxSectionOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[24..], _firstPaylSectionOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[32..], _paylCount);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[40..], _payloadEntryCount);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[48..], 0);
    }

    private void PrepareTrailer(Hash256 fileDigest, ulong physicalLength)
    {
        Span<byte> trailer = _sectionScratch.AsSpan(0, CspFormat.TrailerSize);
        CspFormat.TrailerMagic.CopyTo(trailer);
        BinaryPrimitives.WriteUInt16LittleEndian(trailer[4..], CspFormat.FormatMajor);
        BinaryPrimitives.WriteUInt16LittleEndian(trailer[6..], CspFormat.TrailerSize);
        BinaryPrimitives.WriteUInt64LittleEndian(trailer[8..], _footSectionOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(trailer[16..], physicalLength);
        fileDigest.CopyTo(trailer[24..]);
        BinaryPrimitives.WriteUInt64LittleEndian(trailer[56..], 0);
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_faulted)
        {
            throw new InvalidOperationException(
                "The CSP writer is faulted after an earlier failed call.");
        }

        if (_completed)
        {
            throw new InvalidOperationException(
                "The CSP writer has already completed the patch.");
        }
    }

    private async ValueTask WriteHashedAsync(
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _hasher.Append(bytes.Span);
        await _destination.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        Offset = checked(Offset + (ulong)bytes.Length);
    }

    private async ValueTask WriteTrailerAsync(
        ReadOnlyMemory<byte> trailer,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _destination.WriteAsync(trailer, cancellationToken).ConfigureAwait(false);
        Offset = checked(Offset + (ulong)trailer.Length);
    }

    private struct PidxRecord
    {
        internal PidxRecord(
            ulong firstTargetIndex,
            ulong payloadOffset,
            uint storedLength,
            byte encoding,
            byte dictionaryCount)
        {
            FirstTargetIndex = firstTargetIndex;
            PayloadOffset = payloadOffset;
            StoredLength = storedLength;
            Encoding = encoding;
            DictionaryCount = dictionaryCount;
        }

        internal ulong FirstTargetIndex;
        internal ulong PayloadOffset;
        internal uint StoredLength;
        internal byte Encoding;
        internal byte DictionaryCount;
    }
}
