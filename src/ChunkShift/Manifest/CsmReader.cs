using System.Buffers.Binary;
using System.Text;
using ChunkShift.Chunking;
using ChunkShift.Primitives;

namespace ChunkShift.Manifest;

internal delegate ValueTask CsmChunkEntryHandler(
    CsmChunkEntry entry,
    CancellationToken cancellationToken);

internal readonly record struct CsmChunkEntry(
    ulong Index,
    ulong Offset,
    uint Length,
    ChunkId Id);

[Flags]
internal enum CsmVerificationFailure
{
    None = 0,
    BlockCrc = 1 << 0,
    LogicalTotals = 1 << 1,
    ManifestId = 1 << 2,
    FileDigest = 1 << 3,
}

internal readonly record struct CsmReadResult(
    HashSuiteId HashSuite,
    ChunkingProfileId ProfileId,
    ProfileFingerprint ProfileFingerprint,
    ManifestId StoredManifestId,
    ManifestId ComputedManifestId,
    Hash256 StoredFileDigest,
    Hash256 ComputedFileDigest,
    ulong ChunkCount,
    ulong ContentLength,
    ulong PhysicalLength,
    ulong ChunkBlockCount,
    bool HasBlockIndex,
    CsmVerificationFailure Failures)
{
    internal bool IsValid => Failures == CsmVerificationFailure.None;
}

internal static class CsmReader
{
    private const int BatchSize = 256;

    internal static async Task<CsmReadResult> ReadAndVerifyAsync(
        Stream manifest,
        CsmChunkEntryHandler? handler = null,
        CancellationToken cancellationToken = default)
    {
        using CsmStreamReaderCore reader =
            await CsmStreamReaderCore.OpenAsync(
                manifest,
                cancellationToken).ConfigureAwait(false);

        var batch = new CsmChunkEntry[BatchSize];

        while (true)
        {
            int count = await reader
                .ReadAsync(batch, cancellationToken)
                .ConfigureAwait(false);

            if (count == 0)
            {
                return reader.Result;
            }

            if (handler is null)
            {
                continue;
            }

            for (int index = 0; index < count; index++)
            {
                await handler(batch[index], cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }
}

/// <summary>
/// Single forward CSM parser shared by one-shot verification and ManifestReader.
/// A CBLK is buffered and CRC-validated before any entry becomes visible.
/// </summary>
internal sealed class CsmStreamReaderCore : IDisposable
{
    private const int MaximumCblkPayloadSize =
        CsmFormat.CblkPrefixSize
        + (int)CsmFormat.MaximumChunksPerBlock
            * (CsmFormat.HashSize + sizeof(uint))
        + sizeof(uint);

    private static readonly UTF8Encoding StrictUtf8 =
        new(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

    private readonly CsmInput _input;
    private readonly byte[] _headerBytes =
        new byte[CsmFormat.SectionHeaderSize];
    private readonly byte[] _blockBuffer =
        new byte[
            CsmFormat.SectionHeaderSize
            + MaximumCblkPayloadSize];
    private readonly List<BlockIndexEntry> _observedBlocks = [];
    private readonly ManifestIdAccumulator _manifestId;

    private readonly HashSuiteId _hashSuite;
    private readonly ChunkingProfileId _profileId;
    private readonly ProfileFingerprint _profileFingerprint;
    private readonly ulong _coreOffset;

    private ulong _observedChunkCount;
    private ulong _observedContentLength;
    private ulong _cblkCount;
    private ulong _firstCblkOffset;
    private ulong _cendOffset;
    private ulong _bidxOffset;
    private bool _seenBidx;
    private bool _blockIndexTrackingOverflow;
    private CsmVerificationFailure _failures;
    private ManifestId _storedManifestId;
    private ManifestId _computedManifestId;

    private int _activeBlockCount;
    private int _activeBlockIndex;
    private int _activeIdsOffset;
    private int _activeLengthsOffset;
    private ulong _activeFirstIndex;
    private ulong _activeEntryOffset;
    private bool _suppressEntries;

    private bool _completed;
    private bool _disposed;
    private CsmReadResult _result;

    private CsmStreamReaderCore(
        CsmInput input,
        CoreMetadata core,
        ulong coreOffset)
    {
        _input = input;
        _hashSuite = core.HashSuite;
        _profileId = core.ProfileId;
        _profileFingerprint = core.ProfileFingerprint;
        _coreOffset = coreOffset;
        _manifestId = new ManifestIdAccumulator(
            core.HashSuite,
            core.ProfileId,
            core.ProfileFingerprint);
    }

    internal bool IsCompleted => _completed;

    internal CsmReadResult Result
    {
        get
        {
            if (!_completed)
            {
                throw new InvalidOperationException(
                    "CSM verification is not complete.");
            }

            return _result;
        }
    }

    internal static async Task<CsmStreamReaderCore> OpenAsync(
        Stream manifest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        var input = new CsmInput(manifest);

        try
        {
            await ReadAndValidatePreambleAsync(
                input,
                cancellationToken).ConfigureAwait(false);

            ulong coreOffset = input.Offset;
            var headerBytes =
                new byte[CsmFormat.SectionHeaderSize];

            SectionHeader coreHeader =
                await ReadSectionHeaderAsync(
                    input,
                    headerBytes,
                    cancellationToken).ConfigureAwait(false);

            if (coreHeader.Type != CsmFormat.Core)
            {
                throw new InvalidDataException(
                    "CORE must immediately follow PREAMBLE.");
            }

            CoreMetadata core = await ReadCoreAsync(
                input,
                coreHeader,
                cancellationToken).ConfigureAwait(false);

            input.SetHashSuite(core.HashSuite);

            return new CsmStreamReaderCore(
                input,
                core,
                coreOffset);
        }
        catch
        {
            input.Dispose();
            throw;
        }
    }

    internal async ValueTask<int> ReadAsync(
        Memory<CsmChunkEntry> destination,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (destination.IsEmpty)
        {
            throw new ArgumentException(
                "Destination must contain at least one entry.",
                nameof(destination));
        }

        if (_completed)
        {
            return 0;
        }

        int written = 0;

        while (written < destination.Length)
        {
            if (_activeBlockIndex < _activeBlockCount)
            {
                written += CopyActiveEntries(
                    destination[written..]);
                continue;
            }

            if (_suppressEntries)
            {
                await DrainToCompletionAsync(cancellationToken)
                    .ConfigureAwait(false);
                return written;
            }

            bool blockReady = await LoadNextLogicalSectionAsync(
                cancellationToken).ConfigureAwait(false);

            if (!blockReady)
            {
                if (_suppressEntries && !_completed)
                {
                    await DrainToCompletionAsync(
                        cancellationToken).ConfigureAwait(false);
                }

                return written;
            }
        }

        return written;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _manifestId.Dispose();
        _input.Dispose();
    }

    private int CopyActiveEntries(
        Memory<CsmChunkEntry> destination)
    {
        int available =
            _activeBlockCount - _activeBlockIndex;
        int count = Math.Min(
            available,
            destination.Length);

        for (int relative = 0; relative < count; relative++)
        {
            int index = _activeBlockIndex + relative;

            ChunkId id = new(
                Hash256.FromBytes(
                    _blockBuffer.AsSpan(
                        _activeIdsOffset
                            + index * CsmFormat.HashSize,
                        CsmFormat.HashSize)));

            uint length =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    _blockBuffer.AsSpan(
                        _activeLengthsOffset
                            + index * sizeof(uint),
                        sizeof(uint)));

            destination.Span[relative] =
                new CsmChunkEntry(
                    CsmParserMath.Add(
                        _activeFirstIndex,
                        (uint)index,
                        "chunk index"),
                    _activeEntryOffset,
                    length,
                    id);

            _activeEntryOffset = CsmParserMath.Add(
                _activeEntryOffset,
                length,
                "chunk content offset");
        }

        _activeBlockIndex += count;
        return count;
    }

    private async ValueTask<bool> LoadNextLogicalSectionAsync(
        CancellationToken cancellationToken)
    {
        ulong sectionOffset = _input.Offset;
        SectionHeader header = await ReadSectionHeaderAsync(
            _input,
            _headerBytes,
            cancellationToken).ConfigureAwait(false);

        if (header.Type == CsmFormat.ChunkBlock)
        {
            await LoadChunkBlockAsync(
                sectionOffset,
                header,
                cancellationToken).ConfigureAwait(false);

            return !_suppressEntries;
        }

        if (header.Type != CsmFormat.ChunkEnd)
        {
            throw new InvalidDataException(
                "Only CBLK or CEND may appear after CORE and before CEND.");
        }

        await CompleteFromCendAsync(
            sectionOffset,
            header,
            cancellationToken).ConfigureAwait(false);

        return false;
    }

    private async ValueTask LoadChunkBlockAsync(
        ulong sectionOffset,
        SectionHeader header,
        CancellationToken cancellationToken)
    {
        ValidateKnownSectionFlags(header.Flags);

        if (header.PayloadLength > MaximumCblkPayloadSize ||
            header.PayloadLength
                < CsmFormat.CblkPrefixSize + sizeof(uint))
        {
            throw new InvalidDataException(
                "CBLK PayloadLength is outside the CSM v1 bounded range.");
        }

        int payloadLength = CsmParserMath.ToInt32(
            header.PayloadLength,
            "CBLK PayloadLength");
        int recordLength =
            CsmFormat.SectionHeaderSize + payloadLength;

        _headerBytes.CopyTo(_blockBuffer, 0);
        await _input.ReadExactlyAsync(
            _blockBuffer.AsMemory(
                CsmFormat.SectionHeaderSize,
                payloadLength),
            cancellationToken).ConfigureAwait(false);

        uint count =
            BinaryPrimitives.ReadUInt32LittleEndian(
                _blockBuffer.AsSpan(
                    CsmFormat.SectionHeaderSize,
                    4));
        uint reserved =
            BinaryPrimitives.ReadUInt32LittleEndian(
                _blockBuffer.AsSpan(
                    CsmFormat.SectionHeaderSize + 4,
                    4));
        ulong firstChunkIndex =
            BinaryPrimitives.ReadUInt64LittleEndian(
                _blockBuffer.AsSpan(
                    CsmFormat.SectionHeaderSize + 8,
                    8));
        ulong firstContentOffset =
            BinaryPrimitives.ReadUInt64LittleEndian(
                _blockBuffer.AsSpan(
                    CsmFormat.SectionHeaderSize + 16,
                    8));

        if (count is 0 or > CsmFormat.MaximumChunksPerBlock)
        {
            throw new InvalidDataException(
                $"CBLK ChunkCount must be 1..{CsmFormat.MaximumChunksPerBlock}.");
        }

        if (reserved != 0)
        {
            throw new InvalidDataException(
                "CBLK reserved field must be zero.");
        }

        if (firstChunkIndex != _observedChunkCount ||
            firstContentOffset != _observedContentLength)
        {
            throw new InvalidDataException(
                "CBLK first index/content offset does not match the preceding logical stream.");
        }

        ulong expectedPayloadLength =
            (ulong)CsmFormat.CblkPrefixSize
            + (ulong)count * CsmFormat.HashSize
            + (ulong)count * sizeof(uint)
            + sizeof(uint);

        if (header.PayloadLength != expectedPayloadLength)
        {
            throw new InvalidDataException(
                "CBLK PayloadLength does not match ChunkCount.");
        }

        int crcOffset = recordLength - sizeof(uint);
        uint storedCrc =
            BinaryPrimitives.ReadUInt32LittleEndian(
                _blockBuffer.AsSpan(
                    crcOffset,
                    sizeof(uint)));
        uint computedCrc = Crc32C.Compute(
            _blockBuffer.AsSpan(0, crcOffset));
        bool crcValid = storedCrc == computedCrc;

        int chunkCount = checked((int)count);
        int idsOffset =
            CsmFormat.SectionHeaderSize
            + CsmFormat.CblkPrefixSize;
        int lengthsOffset =
            idsOffset
            + chunkCount * CsmFormat.HashSize;

        ulong blockContentLength = 0;

        for (int index = 0; index < chunkCount; index++)
        {
            ChunkId id = new(
                Hash256.FromBytes(
                    _blockBuffer.AsSpan(
                        idsOffset
                            + index * CsmFormat.HashSize,
                        CsmFormat.HashSize)));

            uint length =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    _blockBuffer.AsSpan(
                        lengthsOffset
                            + index * sizeof(uint),
                        sizeof(uint)));

            if (length == 0)
            {
                throw new InvalidDataException(
                    "CBLK chunk lengths must be positive.");
            }

            // Well-formed CSM, but outside the public .NET model (ChunkInfo.Length
            // is Int32; every stable profile keeps chunks within Int32).
            // Enforced here so every API reaches the same verdict for these bytes.
            if (length > int.MaxValue)
            {
                throw new NotSupportedException(
                    $"CBLK chunk length {length} exceeds the Int32 range of the ChunkShift .NET API.");
            }

            _manifestId.Append(id, length);
            blockContentLength = CsmParserMath.Add(
                blockContentLength,
                length,
                "CBLK content length");
        }

        if (_cblkCount == 0)
        {
            _firstCblkOffset = sectionOffset;
        }

        if (_observedBlocks.Count
            < CsmFormat.MaximumBlockIndexEntries)
        {
            _observedBlocks.Add(
                new BlockIndexEntry(
                    _observedContentLength,
                    sectionOffset));
        }
        else
        {
            _blockIndexTrackingOverflow = true;
        }

        _observedChunkCount = CsmParserMath.Add(
            _observedChunkCount,
            count,
            "observed chunk count");
        _observedContentLength = CsmParserMath.Add(
            _observedContentLength,
            blockContentLength,
            "observed content length");

        if (_observedContentLength > long.MaxValue)
        {
            throw new NotSupportedException(
                "CSM content length exceeds the Int64 range of the ChunkShift .NET API.");
        }

        _cblkCount = CsmParserMath.Add(
            _cblkCount,
            1,
            "CBLK count");

        if (!crcValid)
        {
            _failures |= CsmVerificationFailure.BlockCrc;
            _suppressEntries = true;
            _activeBlockCount = 0;
            _activeBlockIndex = 0;
            return;
        }

        _activeBlockCount = chunkCount;
        _activeBlockIndex = 0;
        _activeIdsOffset = idsOffset;
        _activeLengthsOffset = lengthsOffset;
        _activeFirstIndex = firstChunkIndex;
        _activeEntryOffset = firstContentOffset;
    }

    private async ValueTask DrainToCompletionAsync(
        CancellationToken cancellationToken)
    {
        while (!_completed)
        {
            ulong sectionOffset = _input.Offset;
            SectionHeader header = await ReadSectionHeaderAsync(
                _input,
                _headerBytes,
                cancellationToken).ConfigureAwait(false);

            if (header.Type == CsmFormat.ChunkBlock)
            {
                await LoadChunkBlockAsync(
                    sectionOffset,
                    header,
                    cancellationToken).ConfigureAwait(false);

                _activeBlockCount = 0;
                _activeBlockIndex = 0;
                continue;
            }

            if (header.Type != CsmFormat.ChunkEnd)
            {
                throw new InvalidDataException(
                    "Only CBLK or CEND may appear after CORE and before CEND.");
            }

            await CompleteFromCendAsync(
                sectionOffset,
                header,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask CompleteFromCendAsync(
        ulong sectionOffset,
        SectionHeader header,
        CancellationToken cancellationToken)
    {
        _cendOffset = sectionOffset;

        CendMetadata cend = await ReadCendAsync(
            _input,
            header,
            cancellationToken).ConfigureAwait(false);

        _computedManifestId = _manifestId.Complete();
        _storedManifestId = cend.ManifestId;

        if (cend.TotalChunkCount != _observedChunkCount ||
            cend.TotalContentLength != _observedContentLength)
        {
            _failures |=
                CsmVerificationFailure.LogicalTotals;
        }

        if (_storedManifestId != _computedManifestId)
        {
            _failures |=
                CsmVerificationFailure.ManifestId;
        }

        await ReadPhysicalTailAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask ReadPhysicalTailAsync(
        CancellationToken cancellationToken)
    {
        ulong footOffset = 0;

        while (true)
        {
            ulong sectionOffset = _input.Offset;
            SectionHeader header = await ReadSectionHeaderAsync(
                _input,
                _headerBytes,
                cancellationToken).ConfigureAwait(false);

            if (header.Type == CsmFormat.BlockIndex)
            {
                if (_seenBidx)
                {
                    throw new InvalidDataException(
                        "BIDX may appear at most once.");
                }

                _bidxOffset = sectionOffset;
                await ReadAndValidateBlockIndexAsync(
                    _input,
                    header,
                    _observedBlocks,
                    _blockIndexTrackingOverflow,
                    cancellationToken).ConfigureAwait(false);
                _seenBidx = true;
                continue;
            }

            if (header.Type == CsmFormat.Footer)
            {
                footOffset = sectionOffset;
                await ReadAndValidateFooterAsync(
                    _input,
                    header,
                    _coreOffset,
                    _cendOffset,
                    _bidxOffset,
                    _firstCblkOffset,
                    _cblkCount,
                    cancellationToken).ConfigureAwait(false);
                break;
            }

            // Known logical sections are rejected by type, independent of the
            // REQUIRED flag: the flag only governs unknown section types.
            if (header.Type == CsmFormat.Core ||
                header.Type == CsmFormat.ChunkBlock ||
                header.Type == CsmFormat.ChunkEnd)
            {
                throw new InvalidDataException(
                    $"{DescribeSectionType(header.Type)} must not appear after CEND.");
            }

            if (_seenBidx)
            {
                throw new InvalidDataException(
                    "Only FOOT may follow BIDX in CSM v1.");
            }

            if (header.Type == CsmFormat.Aux0)
            {
                if ((header.Flags
                    & CsmFormat.RequiredSectionFlag) != 0)
                {
                    throw new InvalidDataException(
                        "AUX0 is optional physical metadata and cannot be marked required in CSM v1.");
                }

                await _input.SkipExactlyAsync(
                    header.PayloadLength,
                    cancellationToken).ConfigureAwait(false);
                continue;
            }

            if ((header.Flags
                & CsmFormat.RequiredSectionFlag) != 0)
            {
                throw new InvalidDataException(
                    $"Unknown required CSM section 0x{header.Type:x8}.");
            }

            await _input.SkipExactlyAsync(
                header.PayloadLength,
                cancellationToken).ConfigureAwait(false);
        }

        Hash256 computedFileDigest =
            _input.FinalizePhysicalDigest();

        byte[] trailer = new byte[CsmFormat.TrailerSize];
        await _input.ReadExactlyUnhashedAsync(
            trailer,
            cancellationToken).ConfigureAwait(false);

        TrailerMetadata trailerMetadata =
            ParseTrailer(
                trailer,
                footOffset,
                _input.Offset);

        Hash256 storedFileDigest =
            trailerMetadata.FileDigest;

        if (storedFileDigest != computedFileDigest)
        {
            _failures |=
                CsmVerificationFailure.FileDigest;
        }

        await _input.EnsureEofAsync(cancellationToken)
            .ConfigureAwait(false);

        _result = new CsmReadResult(
            _hashSuite,
            _profileId,
            _profileFingerprint,
            _storedManifestId,
            _computedManifestId,
            storedFileDigest,
            computedFileDigest,
            _observedChunkCount,
            _observedContentLength,
            trailerMetadata.PhysicalLength,
            _cblkCount,
            _seenBidx,
            _failures);

        _completed = true;
    }

    private static async Task ReadAndValidatePreambleAsync(
        CsmInput input,
        CancellationToken cancellationToken)
    {
        byte[] preamble = new byte[CsmFormat.PreambleSize];
        await input.ReadExactlyAsync(
            preamble,
            cancellationToken).ConfigureAwait(false);

        if (!preamble.AsSpan(0, 4)
            .SequenceEqual(CsmFormat.PreambleMagic))
        {
            throw new InvalidDataException(
                "Invalid CSM preamble magic.");
        }

        ushort major =
            BinaryPrimitives.ReadUInt16LittleEndian(
                preamble.AsSpan(4, 2));
        ushort size =
            BinaryPrimitives.ReadUInt16LittleEndian(
                preamble.AsSpan(6, 2));
        ulong requiredFeatures =
            BinaryPrimitives.ReadUInt64LittleEndian(
                preamble.AsSpan(8, 8));
        ulong reserved =
            BinaryPrimitives.ReadUInt64LittleEndian(
                preamble.AsSpan(24, 8));

        if (major != CsmFormat.FormatMajor)
        {
            throw new InvalidDataException(
                $"Unsupported CSM format major {major}.");
        }

        if (size != CsmFormat.PreambleSize)
        {
            throw new InvalidDataException(
                $"CSM v1 requires a {CsmFormat.PreambleSize}-byte preamble.");
        }

        if (requiredFeatures != 0)
        {
            throw new InvalidDataException(
                "CSM v1 contains unknown required physical feature bits.");
        }

        if (reserved != 0)
        {
            throw new InvalidDataException(
                "CSM preamble reserved bytes must be zero.");
        }
    }

    private static async Task<CoreMetadata> ReadCoreAsync(
        CsmInput input,
        SectionHeader header,
        CancellationToken cancellationToken)
    {
        ValidateKnownSectionFlags(header.Flags);

        if (header.PayloadLength < CsmFormat.CorePrefixSize)
        {
            throw new InvalidDataException(
                "CORE payload is smaller than its fixed prefix.");
        }

        byte[] prefix = new byte[CsmFormat.CorePrefixSize];
        await input.ReadExactlyAsync(
            prefix,
            cancellationToken).ConfigureAwait(false);

        ulong requiredSemanticFeatures =
            BinaryPrimitives.ReadUInt64LittleEndian(
                prefix.AsSpan(0, 8));
        ulong optionalSemanticFeatures =
            BinaryPrimitives.ReadUInt64LittleEndian(
                prefix.AsSpan(8, 8));

        if (requiredSemanticFeatures != 0 ||
            optionalSemanticFeatures != 0)
        {
            throw new InvalidDataException(
                "CSM v1 candidate requires both semantic feature fields to be zero.");
        }

        ushort hashIdLength =
            BinaryPrimitives.ReadUInt16LittleEndian(
                prefix.AsSpan(48, 2));
        ushort profileIdLength =
            BinaryPrimitives.ReadUInt16LittleEndian(
                prefix.AsSpan(50, 2));
        uint extensionBytes =
            BinaryPrimitives.ReadUInt32LittleEndian(
                prefix.AsSpan(52, 4));

        ValidateIdentifierLength(
            hashIdLength,
            "HashSuiteId");
        ValidateIdentifierLength(
            profileIdLength,
            "ChunkingProfileId");

        if (extensionBytes != 0)
        {
            throw new InvalidDataException(
                "CSM v1 candidate does not define CORE extensions.");
        }

        ulong expectedPayloadLength =
            (ulong)CsmFormat.CorePrefixSize
            + hashIdLength
            + profileIdLength;

        if (header.PayloadLength != expectedPayloadLength)
        {
            throw new InvalidDataException(
                "CORE PayloadLength does not match its declared identifier lengths.");
        }

        byte[] identifiers =
            new byte[hashIdLength + profileIdLength];

        await input.ReadExactlyAsync(
            identifiers,
            cancellationToken).ConfigureAwait(false);

        string hashIdText;
        string profileIdText;

        try
        {
            hashIdText = StrictUtf8.GetString(
                identifiers.AsSpan(
                    0,
                    hashIdLength));
            profileIdText = StrictUtf8.GetString(
                identifiers.AsSpan(
                    hashIdLength,
                    profileIdLength));
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException(
                $"CORE contains invalid UTF-8 identifiers: {exception.Message}");
        }

        HashSuiteId parsedHashSuite;
        ChunkingProfileId profileId;

        try
        {
            parsedHashSuite =
                new HashSuiteId(hashIdText);
            profileId =
                new ChunkingProfileId(profileIdText);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"CORE contains an invalid ChunkShift identifier: {exception.Message}");
        }

        HashSuiteId hashSuite =
            ChunkScanConfiguration.ResolveHashSuite(
                parsedHashSuite);

        ProfileFingerprint fingerprint = new(
            Hash256.FromBytes(
                prefix.AsSpan(
                    16,
                    CsmFormat.HashSize)));

        return new CoreMetadata(
            hashSuite,
            profileId,
            fingerprint);
    }

    private static async Task<CendMetadata> ReadCendAsync(
        CsmInput input,
        SectionHeader header,
        CancellationToken cancellationToken)
    {
        ValidateKnownSectionFlags(header.Flags);

        if (header.PayloadLength
            != CsmFormat.CendPayloadSize)
        {
            throw new InvalidDataException(
                $"CEND payload must be exactly {CsmFormat.CendPayloadSize} bytes.");
        }

        byte[] payload =
            new byte[CsmFormat.CendPayloadSize];

        await input.ReadExactlyAsync(
            payload,
            cancellationToken).ConfigureAwait(false);

        ulong totalChunkCount =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(0, 8));
        ulong totalContentLength =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(8, 8));
        ManifestId manifestId = new(
            Hash256.FromBytes(
                payload.AsSpan(
                    16,
                    CsmFormat.HashSize)));

        return new CendMetadata(
            totalChunkCount,
            totalContentLength,
            manifestId);
    }

    private static async Task ReadAndValidateBlockIndexAsync(
        CsmInput input,
        SectionHeader header,
        IReadOnlyList<BlockIndexEntry> expected,
        bool trackingOverflow,
        CancellationToken cancellationToken)
    {
        ValidateKnownSectionFlags(header.Flags);

        if ((header.Flags
            & CsmFormat.RequiredSectionFlag) != 0)
        {
            throw new InvalidDataException(
                "BIDX is optional physical metadata and cannot be marked required in CSM v1.");
        }

        if (header.PayloadLength < 8)
        {
            throw new InvalidDataException(
                "BIDX payload is smaller than its fixed prefix.");
        }

        byte[] prefix = new byte[8];
        await input.ReadExactlyAsync(
            prefix,
            cancellationToken).ConfigureAwait(false);

        uint version =
            BinaryPrimitives.ReadUInt32LittleEndian(
                prefix);
        uint count =
            BinaryPrimitives.ReadUInt32LittleEndian(
                prefix.AsSpan(4, 4));

        if (version != 1)
        {
            throw new InvalidDataException(
                $"Unsupported BIDX version {version}.");
        }

        if (count > CsmFormat.MaximumBlockIndexEntries)
        {
            throw new InvalidDataException(
                $"BIDX exceeds the operational limit of {CsmFormat.MaximumBlockIndexEntries} entries.");
        }

        if (trackingOverflow)
        {
            throw new InvalidDataException(
                $"BIDX validation exceeds the operational limit of {CsmFormat.MaximumBlockIndexEntries} tracked CBLK entries.");
        }

        ulong expectedPayloadLength =
            8UL + (ulong)count * 16UL;

        if (header.PayloadLength
            != expectedPayloadLength)
        {
            throw new InvalidDataException(
                "BIDX PayloadLength does not match BlockCount.");
        }

        if (count != (uint)expected.Count)
        {
            throw new InvalidDataException(
                "BIDX BlockCount does not match the observed CBLK sequence.");
        }

        byte[] entryBytes = new byte[16];
        ulong previousContentOffset = 0;
        ulong previousFileOffset = 0;

        for (int index = 0; index < count; index++)
        {
            await input.ReadExactlyAsync(
                entryBytes,
                cancellationToken).ConfigureAwait(false);

            ulong contentOffset =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    entryBytes.AsSpan(0, 8));
            ulong fileOffset =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    entryBytes.AsSpan(8, 8));

            if (index != 0 &&
                (contentOffset <= previousContentOffset ||
                 fileOffset <= previousFileOffset))
            {
                throw new InvalidDataException(
                    "BIDX offsets must be strictly increasing.");
            }

            BlockIndexEntry observed = expected[index];

            if (contentOffset
                    != observed.FirstContentOffset ||
                fileOffset
                    != observed.CblkSectionFileOffset)
            {
                throw new InvalidDataException(
                    "BIDX entry does not correspond to the observed CBLK sequence.");
            }

            previousContentOffset = contentOffset;
            previousFileOffset = fileOffset;
        }
    }

    private static async Task ReadAndValidateFooterAsync(
        CsmInput input,
        SectionHeader header,
        ulong coreOffset,
        ulong cendOffset,
        ulong bidxOffset,
        ulong firstCblkOffset,
        ulong cblkCount,
        CancellationToken cancellationToken)
    {
        ValidateKnownSectionFlags(header.Flags);

        if (header.PayloadLength
            != CsmFormat.FootPayloadSize)
        {
            throw new InvalidDataException(
                $"FOOT payload must be exactly {CsmFormat.FootPayloadSize} bytes.");
        }

        byte[] payload =
            new byte[CsmFormat.FootPayloadSize];

        await input.ReadExactlyAsync(
            payload,
            cancellationToken).ConfigureAwait(false);

        ulong storedCoreOffset =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(0, 8));
        ulong storedCendOffset =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(8, 8));
        ulong storedBidxOffset =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(16, 8));
        ulong storedFirstCblkOffset =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(24, 8));
        ulong storedCblkCount =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(32, 8));
        ulong reserved =
            BinaryPrimitives.ReadUInt64LittleEndian(
                payload.AsSpan(40, 8));

        if (reserved != 0)
        {
            throw new InvalidDataException(
                "FOOT reserved field must be zero.");
        }

        if (storedCoreOffset != coreOffset ||
            storedCendOffset != cendOffset ||
            storedBidxOffset != bidxOffset ||
            storedFirstCblkOffset != firstCblkOffset ||
            storedCblkCount != cblkCount)
        {
            throw new InvalidDataException(
                "FOOT offsets/counts do not match the observed physical section layout.");
        }
    }

    private static TrailerMetadata ParseTrailer(
        byte[] trailer,
        ulong footOffset,
        ulong offsetAfterTrailer)
    {
        if (!trailer.AsSpan(0, 4)
            .SequenceEqual(CsmFormat.TrailerMagic))
        {
            throw new InvalidDataException(
                "Invalid CSM trailer magic.");
        }

        ushort major =
            BinaryPrimitives.ReadUInt16LittleEndian(
                trailer.AsSpan(4, 2));
        ushort size =
            BinaryPrimitives.ReadUInt16LittleEndian(
                trailer.AsSpan(6, 2));
        ulong storedFootOffset =
            BinaryPrimitives.ReadUInt64LittleEndian(
                trailer.AsSpan(8, 8));
        ulong physicalLength =
            BinaryPrimitives.ReadUInt64LittleEndian(
                trailer.AsSpan(16, 8));
        Hash256 fileDigest = Hash256.FromBytes(
            trailer.AsSpan(
                24,
                CsmFormat.HashSize));
        ulong reserved =
            BinaryPrimitives.ReadUInt64LittleEndian(
                trailer.AsSpan(56, 8));

        if (major != CsmFormat.FormatMajor ||
            size != CsmFormat.TrailerSize)
        {
            throw new InvalidDataException(
                "CSM trailer version/size is invalid.");
        }

        if (reserved != 0)
        {
            throw new InvalidDataException(
                "CSM trailer reserved bytes must be zero.");
        }

        if (storedFootOffset != footOffset)
        {
            throw new InvalidDataException(
                "CSM trailer FOOT offset does not match the observed FOOT section.");
        }

        if (physicalLength != offsetAfterTrailer)
        {
            throw new InvalidDataException(
                "CSM trailer PhysicalLength does not match the consumed representation.");
        }

        return new TrailerMetadata(
            physicalLength,
            fileDigest);
    }

    private static async ValueTask<SectionHeader>
        ReadSectionHeaderAsync(
            CsmInput input,
            byte[] buffer,
            CancellationToken cancellationToken)
    {
        await input.ReadExactlyAsync(
            buffer,
            cancellationToken).ConfigureAwait(false);

        uint type =
            BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(0, 4));
        uint flags =
            BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(4, 4));
        ulong payloadLength =
            BinaryPrimitives.ReadUInt64LittleEndian(
                buffer.AsSpan(8, 8));

        if ((flags & ~CsmFormat.KnownSectionFlags) != 0)
        {
            throw new InvalidDataException(
                $"CSM section 0x{type:x8} contains reserved flag bits.");
        }

        input.EnsurePayloadAvailable(payloadLength);

        return new SectionHeader(
            type,
            flags,
            payloadLength);
    }

    private static void ValidateKnownSectionFlags(
        uint flags)
    {
        if ((flags & ~CsmFormat.KnownSectionFlags) != 0)
        {
            throw new InvalidDataException(
                "Known CSM section contains reserved flag bits.");
        }
    }

    private static string DescribeSectionType(uint type)
    {
        if (type == CsmFormat.Core)
        {
            return "CORE";
        }

        if (type == CsmFormat.ChunkBlock)
        {
            return "CBLK";
        }

        if (type == CsmFormat.ChunkEnd)
        {
            return "CEND";
        }

        return $"Section 0x{type:x8}";
    }

    private static void ValidateIdentifierLength(
        ushort length,
        string name)
    {
        if (length is 0 or > CsmFormat.MaximumIdentifierBytes)
        {
            throw new InvalidDataException(
                $"{name} must encode to 1..{CsmFormat.MaximumIdentifierBytes} bytes.");
        }
    }

    private readonly record struct SectionHeader(
        uint Type,
        uint Flags,
        ulong PayloadLength);

    private readonly record struct CoreMetadata(
        HashSuiteId HashSuite,
        ChunkingProfileId ProfileId,
        ProfileFingerprint ProfileFingerprint);

    private readonly record struct CendMetadata(
        ulong TotalChunkCount,
        ulong TotalContentLength,
        ManifestId ManifestId);

    private readonly record struct TrailerMetadata(
        ulong PhysicalLength,
        Hash256 FileDigest);

    private readonly record struct BlockIndexEntry(
        ulong FirstContentOffset,
        ulong CblkSectionFileOffset);
}
