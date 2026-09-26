using System.Buffers.Binary;
using System.Text;
using ChunkShift.Primitives;

namespace ChunkShift.Manifest;

/// <summary>
/// Forward-only encoder for an already canonical logical chunk sequence.
/// It does not perform chunking or payload hashing; callers feed finalized
/// (ChunkId, Length) records from the canonical ingestion kernel.
/// </summary>
internal sealed class CsmEncoderSession : IDisposable
{
    private const int MaximumCblkRecordSize =
        CsmFormat.SectionHeaderSize
        + CsmFormat.CblkPrefixSize
        + (int)CsmFormat.MaximumChunksPerBlock * (CsmFormat.HashSize + sizeof(uint))
        + sizeof(uint);

    private readonly CsmOutput _output;
    private readonly ManifestIdAccumulator _manifestId;
    private readonly HashSuiteId _hashSuite;
    private readonly ChunkingProfileId _profileId;
    private readonly ProfileFingerprint _profileFingerprint;
    private readonly bool _includeBlockIndex;
    private readonly ChunkId[] _blockIds =
        new ChunkId[CsmFormat.MaximumChunksPerBlock];
    private readonly uint[] _blockLengths =
        new uint[CsmFormat.MaximumChunksPerBlock];
    private readonly byte[] _blockRecord = new byte[MaximumCblkRecordSize];
    private readonly List<BlockIndexEntry>? _blockIndex;

    private int _blockCount;
    private ulong _blockFirstChunkIndex;
    private ulong _blockFirstContentOffset;
    private ulong _totalChunkCount;
    private ulong _totalContentLength;
    private ulong _coreOffset;
    private ulong _firstCblkOffset;
    private ulong _cblkCount;
    private ulong _cendOffset;
    private bool _completed;
    private bool _disposed;

    private CsmEncoderSession(
        Stream destination,
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint profileFingerprint,
        bool includeBlockIndex)
    {
        _output = new CsmOutput(destination, hashSuite);
        _manifestId = new ManifestIdAccumulator(
            hashSuite,
            profileId,
            profileFingerprint);
        _hashSuite = hashSuite;
        _profileId = profileId;
        _profileFingerprint = profileFingerprint;
        _includeBlockIndex = includeBlockIndex;
        _blockIndex = includeBlockIndex ? new List<BlockIndexEntry>() : null;
    }

    internal ulong ChunkCount => _totalChunkCount;

    internal ulong ContentLength => _totalContentLength;

    internal static async Task<CsmEncoderSession> CreateAsync(
        Stream destination,
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint profileFingerprint,
        bool includeBlockIndex,
        CancellationToken cancellationToken)
    {
        var session = new CsmEncoderSession(
            destination,
            hashSuite,
            profileId,
            profileFingerprint,
            includeBlockIndex);

        try
        {
            await session.WritePreambleAndCoreAsync(cancellationToken)
                .ConfigureAwait(false);
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    internal async ValueTask AppendAsync(
        ChunkId chunkId,
        uint length,
        CancellationToken cancellationToken)
    {
        ThrowIfActive();

        if (length == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                "CSM chunk lengths must be positive.");
        }

        if (_blockCount == 0)
        {
            _blockFirstChunkIndex = _totalChunkCount;
            _blockFirstContentOffset = _totalContentLength;
        }

        _manifestId.Append(chunkId, length);
        _blockIds[_blockCount] = chunkId;
        _blockLengths[_blockCount] = length;
        _blockCount++;

        _totalChunkCount = checked(_totalChunkCount + 1);
        _totalContentLength = checked(_totalContentLength + length);

        if (_blockCount == CsmFormat.MaximumChunksPerBlock)
        {
            await FlushBlockAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    internal async Task<CsmWriteResult> CompleteAsync(
        CancellationToken cancellationToken)
    {
        ThrowIfActive();

        if (_blockCount != 0)
        {
            await FlushBlockAsync(cancellationToken).ConfigureAwait(false);
        }

        ManifestId manifestId = _manifestId.Complete();
        if (_manifestId.ChunkCount != _totalChunkCount ||
            _manifestId.ContentLength != _totalContentLength)
        {
            throw new InvalidOperationException(
                "Manifest identity totals diverged from CSM encoder totals.");
        }

        _cendOffset = _output.Offset;
        byte[] cend = BuildCendSection(
            _totalChunkCount,
            _totalContentLength,
            manifestId);
        await _output.WriteAsync(cend, cancellationToken).ConfigureAwait(false);

        ulong bidxOffset = 0;
        if (_includeBlockIndex)
        {
            bidxOffset = _output.Offset;
            byte[] bidx = BuildBlockIndexSection(_blockIndex!);
            await _output.WriteAsync(bidx, cancellationToken).ConfigureAwait(false);
        }

        ulong footOffset = _output.Offset;
        byte[] footer = BuildFooterSection(
            _coreOffset,
            _cendOffset,
            bidxOffset,
            _firstCblkOffset,
            _cblkCount);
        await _output.WriteAsync(footer, cancellationToken).ConfigureAwait(false);

        Hash256 fileDigest = _output.FinalizePhysicalDigest();
        ulong physicalLength = checked(
            _output.Offset + CsmFormat.TrailerSize);
        byte[] trailer = BuildTrailer(
            footOffset,
            physicalLength,
            fileDigest);
        await _output.WriteTrailerAsync(trailer, cancellationToken)
            .ConfigureAwait(false);

        if (_output.Offset != physicalLength)
        {
            throw new InvalidOperationException(
                "CSM physical-length bookkeeping diverged.");
        }

        _completed = true;

        return new CsmWriteResult(
            _hashSuite,
            _profileId,
            _profileFingerprint,
            manifestId,
            fileDigest,
            _totalChunkCount,
            _totalContentLength,
            physicalLength,
            _cblkCount,
            _includeBlockIndex);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _manifestId.Dispose();
        _output.Dispose();
    }

    private async Task WritePreambleAndCoreAsync(
        CancellationToken cancellationToken)
    {
        byte[] preamble = new byte[CsmFormat.PreambleSize];
        CsmFormat.PreambleMagic.CopyTo(preamble);
        BinaryPrimitives.WriteUInt16LittleEndian(
            preamble.AsSpan(4),
            CsmFormat.FormatMajor);
        BinaryPrimitives.WriteUInt16LittleEndian(
            preamble.AsSpan(6),
            CsmFormat.PreambleSize);

        await _output.WriteAsync(preamble, cancellationToken)
            .ConfigureAwait(false);

        _coreOffset = _output.Offset;
        byte[] core = BuildCoreSection(
            _hashSuite,
            _profileId,
            _profileFingerprint);

        await _output.WriteAsync(core, cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask FlushBlockAsync(
        CancellationToken cancellationToken)
    {
        if (_blockCount == 0)
        {
            return;
        }

        ulong sectionOffset = _output.Offset;
        if (_cblkCount == 0)
        {
            _firstCblkOffset = sectionOffset;
        }

        int recordLength = EncodeChunkBlock(
            _blockRecord,
            _blockIds,
            _blockLengths,
            _blockCount,
            _blockFirstChunkIndex,
            _blockFirstContentOffset);

        if (_includeBlockIndex)
        {
            if (_blockIndex!.Count == CsmFormat.MaximumBlockIndexEntries)
            {
                throw new InvalidOperationException(
                    $"BIDX generation exceeds the operational limit of {CsmFormat.MaximumBlockIndexEntries} entries.");
            }

            _blockIndex.Add(
                new BlockIndexEntry(
                    _blockFirstContentOffset,
                    sectionOffset));
        }

        await _output
            .WriteAsync(
                _blockRecord.AsMemory(0, recordLength),
                cancellationToken)
            .ConfigureAwait(false);

        _cblkCount = checked(_cblkCount + 1);
        _blockCount = 0;
    }

    private void ThrowIfActive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_completed)
        {
            throw new InvalidOperationException(
                "The CSM encoder session has already been completed.");
        }
    }

    private static byte[] BuildCoreSection(
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint profileFingerprint)
    {
        byte[] hashId = Encoding.UTF8.GetBytes(hashSuite.Value);
        byte[] profileIdBytes = Encoding.UTF8.GetBytes(profileId.Value);

        ValidateIdentifierLength(hashId.Length, nameof(hashSuite));
        ValidateIdentifierLength(profileIdBytes.Length, nameof(profileId));

        int payloadLength = checked(
            CsmFormat.CorePrefixSize
            + hashId.Length
            + profileIdBytes.Length);
        byte[] section =
            new byte[CsmFormat.SectionHeaderSize + payloadLength];

        WriteSectionHeader(
            section,
            CsmFormat.Core,
            CsmFormat.RequiredSectionFlag,
            checked((ulong)payloadLength));

        Span<byte> payload =
            section.AsSpan(CsmFormat.SectionHeaderSize);
        profileFingerprint.Value.CopyTo(
            payload.Slice(16, CsmFormat.HashSize));
        BinaryPrimitives.WriteUInt16LittleEndian(
            payload.Slice(48),
            checked((ushort)hashId.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(
            payload.Slice(50),
            checked((ushort)profileIdBytes.Length));

        hashId.CopyTo(payload.Slice(CsmFormat.CorePrefixSize));
        profileIdBytes.CopyTo(
            payload.Slice(
                CsmFormat.CorePrefixSize + hashId.Length));

        return section;
    }

    private static int EncodeChunkBlock(
        byte[] destination,
        ChunkId[] ids,
        uint[] lengths,
        int count,
        ulong firstChunkIndex,
        ulong firstContentOffset)
    {
        if (count is <= 0 or > (int)CsmFormat.MaximumChunksPerBlock)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        int payloadLength = checked(
            CsmFormat.CblkPrefixSize
            + count * CsmFormat.HashSize
            + count * sizeof(uint)
            + sizeof(uint));
        int recordLength = checked(
            CsmFormat.SectionHeaderSize + payloadLength);

        Span<byte> record = destination.AsSpan(0, recordLength);
        record.Clear();

        WriteSectionHeader(
            record,
            CsmFormat.ChunkBlock,
            CsmFormat.RequiredSectionFlag,
            checked((ulong)payloadLength));

        Span<byte> payload =
            record[CsmFormat.SectionHeaderSize..];
        BinaryPrimitives.WriteUInt32LittleEndian(
            payload,
            checked((uint)count));
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload.Slice(8),
            firstChunkIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload.Slice(16),
            firstContentOffset);

        int idsOffset = CsmFormat.CblkPrefixSize;
        int lengthsOffset = checked(
            idsOffset + count * CsmFormat.HashSize);

        for (int index = 0; index < count; index++)
        {
            ids[index].Value.CopyTo(
                payload.Slice(
                    idsOffset + index * CsmFormat.HashSize,
                    CsmFormat.HashSize));

            BinaryPrimitives.WriteUInt32LittleEndian(
                payload.Slice(
                    lengthsOffset + index * sizeof(uint)),
                lengths[index]);
        }

        int crcOffset = recordLength - sizeof(uint);
        uint crc = Crc32C.Compute(record[..crcOffset]);
        BinaryPrimitives.WriteUInt32LittleEndian(
            record.Slice(crcOffset, sizeof(uint)),
            crc);

        return recordLength;
    }

    private static byte[] BuildCendSection(
        ulong totalChunkCount,
        ulong totalContentLength,
        ManifestId manifestId)
    {
        byte[] section =
            new byte[
                CsmFormat.SectionHeaderSize
                + CsmFormat.CendPayloadSize];

        WriteSectionHeader(
            section,
            CsmFormat.ChunkEnd,
            CsmFormat.RequiredSectionFlag,
            CsmFormat.CendPayloadSize);

        Span<byte> payload =
            section.AsSpan(CsmFormat.SectionHeaderSize);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload,
            totalChunkCount);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload.Slice(8),
            totalContentLength);
        manifestId.Value.CopyTo(
            payload.Slice(16, CsmFormat.HashSize));

        return section;
    }

    private static byte[] BuildBlockIndexSection(
        IReadOnlyList<BlockIndexEntry> entries)
    {
        int payloadLength = checked(8 + entries.Count * 16);
        byte[] section =
            new byte[
                CsmFormat.SectionHeaderSize
                + payloadLength];

        WriteSectionHeader(
            section,
            CsmFormat.BlockIndex,
            flags: 0,
            checked((ulong)payloadLength));

        Span<byte> payload =
            section.AsSpan(CsmFormat.SectionHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(payload, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(
            payload.Slice(4),
            checked((uint)entries.Count));

        for (int index = 0; index < entries.Count; index++)
        {
            int offset = 8 + index * 16;
            BinaryPrimitives.WriteUInt64LittleEndian(
                payload.Slice(offset),
                entries[index].FirstContentOffset);
            BinaryPrimitives.WriteUInt64LittleEndian(
                payload.Slice(offset + 8),
                entries[index].CblkSectionFileOffset);
        }

        return section;
    }

    private static byte[] BuildFooterSection(
        ulong coreOffset,
        ulong cendOffset,
        ulong bidxOffset,
        ulong firstCblkOffset,
        ulong cblkCount)
    {
        byte[] section =
            new byte[
                CsmFormat.SectionHeaderSize
                + CsmFormat.FootPayloadSize];

        WriteSectionHeader(
            section,
            CsmFormat.Footer,
            CsmFormat.RequiredSectionFlag,
            CsmFormat.FootPayloadSize);

        Span<byte> payload =
            section.AsSpan(CsmFormat.SectionHeaderSize);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload,
            coreOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload.Slice(8),
            cendOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload.Slice(16),
            bidxOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload.Slice(24),
            firstCblkOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(
            payload.Slice(32),
            cblkCount);

        return section;
    }

    private static byte[] BuildTrailer(
        ulong footOffset,
        ulong physicalLength,
        Hash256 fileDigest)
    {
        byte[] trailer = new byte[CsmFormat.TrailerSize];
        CsmFormat.TrailerMagic.CopyTo(trailer);

        BinaryPrimitives.WriteUInt16LittleEndian(
            trailer.AsSpan(4),
            CsmFormat.FormatMajor);
        BinaryPrimitives.WriteUInt16LittleEndian(
            trailer.AsSpan(6),
            CsmFormat.TrailerSize);
        BinaryPrimitives.WriteUInt64LittleEndian(
            trailer.AsSpan(8),
            footOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(
            trailer.AsSpan(16),
            physicalLength);
        fileDigest.CopyTo(
            trailer.AsSpan(24, CsmFormat.HashSize));

        return trailer;
    }

    private static void WriteSectionHeader(
        Span<byte> destination,
        uint type,
        uint flags,
        ulong payloadLength)
    {
        if (destination.Length < CsmFormat.SectionHeaderSize)
        {
            throw new ArgumentException(
                "Destination is smaller than a CSM section header.",
                nameof(destination));
        }

        BinaryPrimitives.WriteUInt32LittleEndian(
            destination,
            type);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination.Slice(4),
            flags);
        BinaryPrimitives.WriteUInt64LittleEndian(
            destination.Slice(8),
            payloadLength);
    }

    private static void ValidateIdentifierLength(
        int length,
        string parameterName)
    {
        if (length is <= 0 or > CsmFormat.MaximumIdentifierBytes)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                $"CSM identifiers must encode to 1..{CsmFormat.MaximumIdentifierBytes} UTF-8 bytes.");
        }
    }

    private readonly record struct BlockIndexEntry(
        ulong FirstContentOffset,
        ulong CblkSectionFileOffset);
}
