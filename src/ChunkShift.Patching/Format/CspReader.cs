using System.Buffers.Binary;
using System.Collections;
using ChunkShift.Patching.Hashing;
using ChunkShift.Patching.IO;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Format;

/// <summary>
/// One payload-index record as the CSP v1 <c>PIDX</c> section stores it
/// (docs/architecture/CSP-V1.md section 4.7).
/// </summary>
/// <param name="FirstTargetIndex">
/// Index of the first target-manifest record whose identity is the entry's <c>ChunkId</c>.
/// </param>
/// <param name="PayloadOffset">
/// Patch-relative offset of the entry's <c>ChunkId</c> field in its <c>PAYL</c> section.
/// </param>
/// <param name="StoredLength">Stored byte length of the entry.</param>
/// <param name="Encoding">Payload encoding: 0 raw, 1 one zstd frame.</param>
/// <param name="DictionaryCount">Number of named base chunks used as dictionary content.</param>
internal readonly record struct CspIndexEntry(
    ulong FirstTargetIndex,
    ulong PayloadOffset,
    uint StoredLength,
    byte Encoding,
    byte DictionaryCount);

/// <summary>
/// The metadata and stored bytes of one payload entry, read on demand.
/// </summary>
/// <param name="ChunkId">Target chunk identity the stored bytes reproduce.</param>
/// <param name="Encoding">Payload encoding: 0 raw, 1 one zstd frame.</param>
/// <param name="DictionaryChunkIds">Base chunks used as raw dictionary content, in listed order.</param>
/// <param name="StoredBytes">Exactly the entry's stored bytes.</param>
internal sealed record CspEntry(
    ChunkId ChunkId,
    byte Encoding,
    ChunkId[] DictionaryChunkIds,
    byte[] StoredBytes);

/// <summary>
/// Validates a complete CSP v1 artifact up to, but not including, anything that
/// needs the base or the reconstruction
/// (docs/architecture/CSP-V1.md sections 4, 7 and 9.1-9.4).
/// </summary>
/// <remarks>
/// <para>
/// The reader checks, in the verdict order of CSP-V1 section 6: the TRAILER, the
/// PREAMBLE, the section walk with every <c>PAYL</c> and <c>PIDX</c> CRC-32C
/// checked before its fields are interpreted; the embedded target CSM; the
/// patch <c>FileDigest</c>; the payload entries against the target manifest;
/// and the base binding the patch itself reveals. Malformed input throws
/// <see cref="InvalidDataException"/>, unsupported input
/// <see cref="NotSupportedException"/>, more payload entries than the
/// configured maximum <see cref="CspResourceLimitException"/>, and integrity
/// mismatches the patch alone reveals are accumulated in <see cref="Failures"/>.
/// </para>
/// <para>
/// The caller owns the patch stream, which must be readable and seekable and
/// is never disposed. Offsets inside the patch are relative to the caller's
/// position when <see cref="OpenAsync(Stream, CancellationToken)"/> was called,
/// so a patch can be embedded after other bytes in the same stream.
/// </para>
/// <para>
/// Memory is bounded by the configured payload-entry limit plus one 64 KiB
/// read buffer; no field declared by the patch is allocated before it has been
/// validated against the bytes that actually exist.
/// </para>
/// </remarks>
internal sealed class CspReader
{
    private const int ReadBufferBytes = 64 * 1024;
    private const int ManifestBatchEntries = 256;

    // Field offsets inside a PAYL entry record (CSP-V1 section 4.6).
    private const int EntryStoredLengthOffset = 32;
    private const int EntryEncodingOffset = 36;
    private const int EntryDictionaryCountOffset = 37;
    private const int EntryReservedOffset = 38;

    // Field offsets inside a PIDX entry record (section 4.7).
    private const int IndexStoredLengthOffset = 16;
    private const int IndexEncodingOffset = 20;
    private const int IndexDictionaryCountOffset = 21;
    private const int IndexReservedOffset = 22;

    // Field offsets inside the TRAILER (section 4.9).
    private const int TrailerFootOffsetOffset = 8;
    private const int TrailerPhysicalLengthOffset = 16;
    private const int TrailerFileDigestOffset = 24;
    private const int TrailerReservedOffset = 56;

    private readonly Stream _patch;
    private readonly long _start;
    private readonly long _length;
    private readonly int _maximumPayloadEntries;
    private readonly byte[] _readBuffer = new byte[ReadBufferBytes];
    private readonly List<PaylEntry> _entries = [];
    private readonly List<CspIndexEntry> _index = [];
    private readonly PaylChunkIdList _payloadChunkIds;

    private CspVerificationFailure _failures;
    private ManifestVerificationResult? _targetManifest;
    private ManifestId? _expectedBase;
    private bool _dependsOnBase;
    private long[] _firstTargetIndex = [];
    private int[] _targetLength = [];
    private long _tcsmSectionOffset;
    private long _tcsmPayloadOffset;
    private long _tcsmPayloadLength;
    private long _baseSectionOffset;
    private long _pidxSectionOffset;
    private long _firstPaylSectionOffset;
    private long _footSectionOffset;
    private ulong _paylCount;
    private ulong _trailerFootOffset;
    private Hash256 _storedFileDigest;

    private CspReader(Stream patch, long start, long length, int maximumPayloadEntries)
    {
        _patch = patch;
        _start = start;
        _length = length;
        _maximumPayloadEntries = maximumPayloadEntries;
        _payloadChunkIds = new PaylChunkIdList(_entries);
    }

    /// <summary>Gets every integrity mismatch the patch alone reveals.</summary>
    internal CspVerificationFailure Failures => _failures;

    /// <summary>Gets whether no integrity mismatch was detected.</summary>
    internal bool IsValid => _failures == CspVerificationFailure.None;

    /// <summary>Gets the embedded target manifest's verification result.</summary>
    internal ManifestVerificationResult TargetManifest => _targetManifest!;

    /// <summary>
    /// Gets the expected base <c>ManifestId</c> from the <c>BASE</c> section,
    /// or null when the patch carries no <c>BASE</c> section.
    /// </summary>
    internal ManifestId? ExpectedBaseManifestId => _expectedBase;

    /// <summary>
    /// Gets whether the patch needs a base: at least one target record has no
    /// payload entry, or at least one entry names dictionary chunks
    /// (CSP-V1 section 3.3).
    /// </summary>
    internal bool DependsOnBase => _dependsOnBase;

    /// <summary>Gets the payload index, ordered by payload ordinal.</summary>
    internal IReadOnlyList<CspIndexEntry> Index => _index;

    /// <summary>Gets the payload entry identities, ordered by payload ordinal.</summary>
    internal IReadOnlyList<ChunkId> PayloadChunkIds => _payloadChunkIds;

    /// <summary>
    /// Gets the embedded target CSM payload offset, relative to the patch start.
    /// </summary>
    internal long TargetManifestOffset => _tcsmPayloadOffset;

    /// <summary>Gets the embedded target CSM payload length.</summary>
    internal long TargetManifestLength => _tcsmPayloadLength;

    /// <summary>
    /// Reads and validates a CSP v1 artifact from its first byte to the last
    /// byte of the TRAILER.
    /// </summary>
    /// <param name="patch">Readable and seekable patch stream owned by the caller.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>A reader whose <see cref="Failures"/> describe the patch.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="patch"/> is <see langword="null"/>. Thrown by this call, not by
    /// the returned task.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="patch"/> is not readable or not seekable. Thrown by this call,
    /// not by the returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">The patch is not a well-formed CSP v1 artifact.</exception>
    /// <exception cref="NotSupportedException">The patch requires semantics this build does not implement.</exception>
    /// <exception cref="CspResourceLimitException">
    /// The patch holds more payload entries than the configured maximum.
    /// </exception>
    /// <exception cref="OperationCanceledException">Cancellation is observed.</exception>
    internal static Task<CspReader> OpenAsync(
        Stream patch,
        CancellationToken cancellationToken = default) =>
        OpenAsync(patch, CspFormat.DefaultMaximumPayloadEntries, cancellationToken);

    /// <summary>
    /// Reads and validates a CSP v1 artifact, rejecting a patch with more than
    /// <paramref name="maximumPayloadEntries"/> payload entries.
    /// </summary>
    /// <param name="patch">Readable and seekable patch stream owned by the caller.</param>
    /// <param name="maximumPayloadEntries">Configured payload-entry limit, 1..Int32.MaxValue.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>A reader whose <see cref="Failures"/> describe the patch.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maximumPayloadEntries"/> is zero or negative. Thrown by this
    /// call, not by the returned task.
    /// </exception>
    /// <inheritdoc cref="OpenAsync(Stream, CancellationToken)" />
    internal static Task<CspReader> OpenAsync(
        Stream patch,
        int maximumPayloadEntries,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(patch);

        if (!patch.CanRead)
        {
            throw new ArgumentException(
                "CSP patch stream must be readable.",
                nameof(patch));
        }

        if (!patch.CanSeek)
        {
            throw new ArgumentException(
                "CSP patch stream must be seekable.",
                nameof(patch));
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumPayloadEntries);

        return OpenCoreAsync(patch, maximumPayloadEntries, cancellationToken);
    }

    /// <summary>
    /// Opens a new bounded window over the embedded target CSM payload. The
    /// window is positioned at the payload's first byte, is owned by the
    /// caller, and never disposes the patch stream.
    /// </summary>
    internal Stream OpenTargetManifest() =>
        new BoundedReadStream(
            _patch,
            checked(_start + _tcsmPayloadOffset),
            _tcsmPayloadLength);

    /// <summary>
    /// Reads the payload entry with the given ordinal, re-checking that its
    /// header still agrees with the validated index.
    /// </summary>
    /// <param name="ordinal">Zero-based payload ordinal, in PAYL order.</param>
    /// <param name="cancellationToken">Cooperative cancellation token.</param>
    /// <returns>The entry's identity, encoding, dictionary identities and stored bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="ordinal"/> is outside 0..<see cref="Index"/>.Count - 1. Thrown by
    /// this call, not by the returned task.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The entry header no longer agrees with the index that was validated.
    /// </exception>
    internal ValueTask<CspEntry> ReadEntryAsync(
        int ordinal,
        CancellationToken cancellationToken = default)
    {
        if ((uint)ordinal >= (uint)_entries.Count)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ordinal),
                ordinal,
                "The payload ordinal lies outside the patch index.");
        }

        return ReadEntryCoreAsync(ordinal, cancellationToken);
    }

    private static async Task<CspReader> OpenCoreAsync(
        Stream patch,
        int maximumPayloadEntries,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        long start = patch.Position;
        var reader = new CspReader(
            patch,
            start,
            patch.Length - start,
            maximumPayloadEntries);

        await reader.ParseAsync(cancellationToken).ConfigureAwait(false);
        return reader;
    }

    private static InvalidDataException Malformed(string message) => new(message);

    /// <summary>Runs the section 6 checks in its verdict order.</summary>
    private async ValueTask ParseAsync(CancellationToken cancellationToken)
    {
        await ParseStructureAsync(cancellationToken).ConfigureAwait(false);
        await ReadTargetManifestAsync(cancellationToken).ConfigureAwait(false);
        await CheckFileDigestAsync(cancellationToken).ConfigureAwait(false);

        if (_failures != CspVerificationFailure.None)
        {
            return;
        }

        CheckPayloadAgainstTarget();

        if (_failures != CspVerificationFailure.None)
        {
            return;
        }

        CheckBaseDependence();
    }

    private async ValueTask ParseStructureAsync(CancellationToken cancellationToken)
    {
        if (_length < CspFormat.PreambleSize + CspFormat.TrailerSize)
        {
            throw Malformed(
                "The patch is shorter than the CSP PREAMBLE plus TRAILER.");
        }

        long trailerAt = _length - CspFormat.TrailerSize;

        // TRAILER first (CSP-V1 section 6 step 1).
        await ReadExactlyAtAsync(
            trailerAt,
            Scratch(CspFormat.TrailerSize),
            cancellationToken).ConfigureAwait(false);

        if (!_readBuffer.AsSpan(0, 4).SequenceEqual(CspFormat.TrailerMagic) ||
            BinaryPrimitives.ReadUInt16LittleEndian(_readBuffer.AsSpan(6)) != CspFormat.TrailerSize)
        {
            throw Malformed("There is no CSP TRAILER at the physical end of the patch.");
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(_readBuffer.AsSpan(4)) != CspFormat.FormatMajor)
        {
            throw Malformed("The CSP TRAILER FormatMajor is not 1.");
        }

        if (BinaryPrimitives.ReadUInt64LittleEndian(_readBuffer.AsSpan(TrailerReservedOffset)) != 0)
        {
            throw Malformed("The CSP TRAILER reserved field must be zero.");
        }

        if (BinaryPrimitives.ReadUInt64LittleEndian(_readBuffer.AsSpan(TrailerPhysicalLengthOffset)) !=
            (ulong)_length)
        {
            throw Malformed(
                "The CSP TRAILER PhysicalLength does not equal the artifact length.");
        }

        _trailerFootOffset = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(TrailerFootOffsetOffset));
        _storedFileDigest = Hash256.FromBytes(
            _readBuffer.AsSpan(TrailerFileDigestOffset, CspFormat.HashSize));

        await ReadExactlyAtAsync(
            0,
            Scratch(CspFormat.PreambleSize),
            cancellationToken).ConfigureAwait(false);

        if (!_readBuffer.AsSpan(0, 4).SequenceEqual(CspFormat.PreambleMagic) ||
            BinaryPrimitives.ReadUInt16LittleEndian(_readBuffer.AsSpan(4)) != CspFormat.FormatMajor ||
            BinaryPrimitives.ReadUInt16LittleEndian(_readBuffer.AsSpan(6)) != CspFormat.PreambleSize)
        {
            throw Malformed(
                "The CSP PREAMBLE magic, FormatMajor or PreambleSize is wrong.");
        }

        if (BinaryPrimitives.ReadUInt64LittleEndian(_readBuffer.AsSpan(24)) != 0)
        {
            throw Malformed("The CSP PREAMBLE reserved field must be zero.");
        }

        if (BinaryPrimitives.ReadUInt64LittleEndian(_readBuffer.AsSpan(8)) != 0)
        {
            throw new NotSupportedException(
                "The CSP PREAMBLE requires unknown physical feature bits.");
        }

        await WalkSectionsAsync(trailerAt, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask WalkSectionsAsync(
        long trailerAt,
        CancellationToken cancellationToken)
    {
        var phase = Phase.Start;
        long offset = CspFormat.PreambleSize;

        while (true)
        {
            if (trailerAt - offset < CspFormat.SectionHeaderSize)
            {
                throw Malformed("The FOOT section is missing before the TRAILER.");
            }

            await ReadExactlyAtAsync(
                offset,
                Scratch(CspFormat.SectionHeaderSize),
                cancellationToken).ConfigureAwait(false);

            uint kind = BinaryPrimitives.ReadUInt32LittleEndian(
                _readBuffer.AsSpan(0, sizeof(uint)));
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(
                _readBuffer.AsSpan(sizeof(uint), sizeof(uint)));
            ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
                _readBuffer.AsSpan(2 * sizeof(uint), sizeof(ulong)));

            if ((flags & ~CspFormat.KnownSectionFlags) != 0)
            {
                throw Malformed("A CSP section header sets a reserved flag bit.");
            }

            if (payloadLength > (ulong)(trailerAt - offset - CspFormat.SectionHeaderSize))
            {
                throw Malformed(
                    "A CSP section PayloadLength exceeds the bytes before the TRAILER.");
            }

            long payloadAt = offset + CspFormat.SectionHeaderSize;

            if (phase == Phase.Start && kind != CspFormat.TargetManifest)
            {
                throw Malformed("The first CSP section must be TCSM.");
            }

            if (kind == CspFormat.TargetManifest)
            {
                if (phase != Phase.Start)
                {
                    throw Malformed("A CSP patch holds exactly one TCSM section.");
                }

                _tcsmSectionOffset = offset;
                _tcsmPayloadOffset = payloadAt;
                _tcsmPayloadLength = (long)payloadLength;
                phase = Phase.Tcsm;
            }
            else if (kind == CspFormat.Base)
            {
                if ((flags & CspFormat.RequiredSectionFlag) != 0)
                {
                    throw Malformed("BASE is optional and must not be marked REQUIRED.");
                }

                if (phase != Phase.Tcsm)
                {
                    throw Malformed("BASE is duplicated or not directly after TCSM.");
                }

                if (payloadLength != CspFormat.BasePayloadSize)
                {
                    throw Malformed("The BASE payload must be 32 bytes.");
                }

                _baseSectionOffset = offset;
                await ReadExactlyAtAsync(
                    payloadAt,
                    Scratch(CspFormat.BasePayloadSize),
                    cancellationToken).ConfigureAwait(false);

                _expectedBase = new ManifestId(
                    Hash256.FromBytes(_readBuffer.AsSpan(0, CspFormat.HashSize)));
                phase = Phase.Base;
            }
            else if (kind == CspFormat.Payload)
            {
                if (phase != Phase.Tcsm && phase != Phase.Base && phase != Phase.Payl)
                {
                    throw Malformed("PAYL lies outside the payload phase.");
                }

                await ParsePaylAsync(
                    offset,
                    (long)payloadLength,
                    cancellationToken).ConfigureAwait(false);

                if (_paylCount == 0)
                {
                    _firstPaylSectionOffset = offset;
                }

                _paylCount = checked(_paylCount + 1);
                phase = Phase.Payl;
            }
            else if (kind == CspFormat.PayloadIndex)
            {
                if (phase == Phase.Pidx)
                {
                    throw Malformed("A CSP patch holds exactly one PIDX section.");
                }

                await ParsePidxAsync(
                    offset,
                    (long)payloadLength,
                    cancellationToken).ConfigureAwait(false);

                _pidxSectionOffset = offset;
                phase = Phase.Pidx;
            }
            else if (kind == CspFormat.Footer)
            {
                if (phase != Phase.Pidx)
                {
                    throw Malformed("FOOT must directly follow PIDX.");
                }

                if (payloadLength != CspFormat.FootPayloadSize)
                {
                    throw Malformed("The FOOT payload must be 56 bytes.");
                }

                if (payloadAt + CspFormat.FootPayloadSize != trailerAt)
                {
                    throw Malformed("Bytes lie between FOOT and the TRAILER.");
                }

                _footSectionOffset = offset;
                await ParseFootAsync(payloadAt, cancellationToken).ConfigureAwait(false);
                return;
            }
            else
            {
                if ((flags & CspFormat.RequiredSectionFlag) != 0)
                {
                    throw Malformed(
                        "An optional or unknown CSP section is marked REQUIRED.");
                }

                if (phase == Phase.Pidx)
                {
                    throw Malformed("An optional or unknown CSP section lies after PIDX.");
                }

                phase = Phase.Optional;
            }

            offset = payloadAt + (long)payloadLength;
        }
    }

    /// <summary>
    /// Parses one <c>PAYL</c> section: its CRC-32C first, then the prefix and
    /// every entry header. Stored bytes and dictionary identities are skipped
    /// rather than materialized.
    /// </summary>
    private async ValueTask ParsePaylAsync(
        long sectionOffset,
        long payloadLength,
        CancellationToken cancellationToken)
    {
        if (payloadLength < CspFormat.PaylPrefixSize + CspFormat.CrcSize)
        {
            throw Malformed("A PAYL payload is shorter than its prefix and CRC.");
        }

        await VerifySectionCrcAsync(
            sectionOffset,
            payloadLength,
            "PAYL",
            cancellationToken).ConfigureAwait(false);

        long start = sectionOffset + CspFormat.SectionHeaderSize;
        long end = start + payloadLength - CspFormat.CrcSize;

        await ReadExactlyAtAsync(
            start,
            Scratch(CspFormat.PaylPrefixSize),
            cancellationToken).ConfigureAwait(false);

        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(
            _readBuffer.AsSpan(0, sizeof(uint)));
        uint reserved = BinaryPrimitives.ReadUInt32LittleEndian(
            _readBuffer.AsSpan(sizeof(uint), sizeof(uint)));
        ulong firstEntryOrdinal = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(2 * sizeof(uint), sizeof(ulong)));

        if (entryCount == 0 || entryCount > CspFormat.MaximumEntriesPerPayl)
        {
            throw Malformed("A PAYL EntryCount must be 1..4096.");
        }

        if (reserved != 0)
        {
            throw Malformed("The PAYL prefix reserved field must be zero.");
        }

        if (firstEntryOrdinal != (ulong)_entries.Count)
        {
            throw Malformed(
                "A PAYL FirstEntryOrdinal does not match the preceding entries.");
        }

        long position = start + CspFormat.PaylPrefixSize;

        for (uint index = 0; index < entryCount; index++)
        {
            if (_entries.Count >= _maximumPayloadEntries)
            {
                throw new CspResourceLimitException(
                    $"The CSP patch holds more than the configured maximum of {_maximumPayloadEntries} payload entries.");
            }

            if (end - position < CspFormat.PaylEntryHeaderSize)
            {
                throw Malformed("A PAYL entry header overruns its section.");
            }

            await ReadExactlyAtAsync(
                position,
                Scratch(CspFormat.PaylEntryHeaderSize),
                cancellationToken).ConfigureAwait(false);

            var chunkId = new ChunkId(
                Hash256.FromBytes(_readBuffer.AsSpan(0, CspFormat.HashSize)));
            uint storedLength = BinaryPrimitives.ReadUInt32LittleEndian(
                _readBuffer.AsSpan(EntryStoredLengthOffset, sizeof(uint)));
            byte encoding = _readBuffer[EntryEncodingOffset];
            byte dictionaryCount = _readBuffer[EntryDictionaryCountOffset];
            ushort entryReserved = BinaryPrimitives.ReadUInt16LittleEndian(
                _readBuffer.AsSpan(EntryReservedOffset, sizeof(ushort)));

            if (entryReserved != 0)
            {
                throw Malformed("A PAYL entry reserved field must be zero.");
            }

            if (storedLength == 0)
            {
                throw Malformed("A PAYL StoredLength must be greater than zero.");
            }

            if (encoding == CspFormat.EncodingRaw && dictionaryCount != 0)
            {
                throw Malformed("A raw PAYL entry must not name dictionary chunks.");
            }

            if (encoding == CspFormat.EncodingZstd &&
                dictionaryCount > CspFormat.MaximumDictionaryCount)
            {
                throw Malformed(
                    "An encoding-1 PAYL entry names more than four dictionary chunks.");
            }

            long body = CspFormat.PaylEntryHeaderSize
                + ((long)dictionaryCount * CspFormat.DictionaryReferenceSize)
                + storedLength;

            if (end - position < body)
            {
                throw Malformed("A PAYL entry overruns its section.");
            }

            if (encoding != CspFormat.EncodingRaw && encoding != CspFormat.EncodingZstd)
            {
                throw new NotSupportedException(
                    $"CSP payload encoding {encoding} is not implemented.");
            }

            _entries.Add(new PaylEntry(
                chunkId,
                position,
                storedLength,
                encoding,
                dictionaryCount));
            position = checked(position + body);
        }

        if (position != end)
        {
            throw Malformed("A PAYL PayloadLength does not match its entries.");
        }
    }

    /// <summary>
    /// Parses one <c>PIDX</c> section: its CRC-32C first, then the prefix and
    /// the fixed entries, validated against the parsed <c>PAYL</c> entries.
    /// </summary>
    private async ValueTask ParsePidxAsync(
        long sectionOffset,
        long payloadLength,
        CancellationToken cancellationToken)
    {
        if (payloadLength < CspFormat.PidxPrefixSize + CspFormat.CrcSize)
        {
            throw Malformed("A PIDX payload is shorter than its prefix and CRC.");
        }

        await VerifySectionCrcAsync(
            sectionOffset,
            payloadLength,
            "PIDX",
            cancellationToken).ConfigureAwait(false);

        long start = sectionOffset + CspFormat.SectionHeaderSize;

        await ReadExactlyAtAsync(
            start,
            Scratch(CspFormat.PidxPrefixSize),
            cancellationToken).ConfigureAwait(false);

        uint version = BinaryPrimitives.ReadUInt32LittleEndian(
            _readBuffer.AsSpan(0, sizeof(uint)));
        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(
            _readBuffer.AsSpan(sizeof(uint), sizeof(uint)));

        if (version != CspFormat.IndexVersion)
        {
            throw Malformed("The PIDX IndexVersion must be 1.");
        }

        if ((ulong)payloadLength !=
            CspFormat.PidxPrefixSize +
            ((ulong)entryCount * CspFormat.PidxEntrySize) +
            CspFormat.CrcSize)
        {
            throw Malformed("A PIDX PayloadLength does not match its EntryCount.");
        }

        if ((ulong)entryCount > (ulong)_maximumPayloadEntries)
        {
            throw new CspResourceLimitException(
                $"The CSP patch index holds more than the configured maximum of {_maximumPayloadEntries} payload entries.");
        }

        if ((ulong)entryCount != (ulong)_entries.Count)
        {
            throw Malformed("The PIDX and PAYL sections disagree on the entry count.");
        }

        int remaining = (int)entryCount;
        int index = 0;
        bool hasPrevious = false;
        ulong previous = 0;
        long entriesAt = start + CspFormat.PidxPrefixSize;
        int batchCapacity = _readBuffer.Length / CspFormat.PidxEntrySize;

        while (index < remaining)
        {
            int batch = Math.Min(remaining - index, batchCapacity);
            int batchBytes = checked(batch * CspFormat.PidxEntrySize);

            await ReadExactlyAtAsync(
                entriesAt + (index * (long)CspFormat.PidxEntrySize),
                _readBuffer.AsMemory(0, batchBytes),
                cancellationToken).ConfigureAwait(false);

            for (int item = 0; item < batch; item++)
            {
                Span<byte> record = _readBuffer.AsSpan(
                    item * CspFormat.PidxEntrySize,
                    CspFormat.PidxEntrySize);

                ulong firstTargetIndex = BinaryPrimitives.ReadUInt64LittleEndian(record);
                ulong payloadOffset = BinaryPrimitives.ReadUInt64LittleEndian(record[8..]);
                uint storedLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record[IndexStoredLengthOffset..]);
                byte encoding = record[IndexEncodingOffset];
                byte dictionaryCount = record[IndexDictionaryCountOffset];
                ushort reserved = BinaryPrimitives.ReadUInt16LittleEndian(
                    record[IndexReservedOffset..]);

                PaylEntry payl = _entries[index + item];

                if (reserved != 0)
                {
                    throw Malformed("A PIDX entry reserved field must be zero.");
                }

                if (storedLength != payl.StoredLength ||
                    encoding != payl.Encoding ||
                    dictionaryCount != payl.DictionaryCount)
                {
                    throw Malformed(
                        "A PIDX entry disagrees with its PAYL entry.");
                }

                if (payloadOffset != (ulong)payl.RecordOffset)
                {
                    throw Malformed(
                        "A PIDX PayloadOffset does not point at its PAYL entry.");
                }

                if (hasPrevious && firstTargetIndex <= previous)
                {
                    throw Malformed(
                        "PIDX FirstTargetIndex values must strictly increase.");
                }

                previous = firstTargetIndex;
                hasPrevious = true;
                _index.Add(new CspIndexEntry(
                    firstTargetIndex,
                    payloadOffset,
                    storedLength,
                    encoding,
                    dictionaryCount));
            }

            index += batch;
        }
    }

    /// <summary>Parses and checks the fixed <c>FOOT</c> payload.</summary>
    private async ValueTask ParseFootAsync(
        long payloadAt,
        CancellationToken cancellationToken)
    {
        await ReadExactlyAtAsync(
            payloadAt,
            Scratch(CspFormat.FootPayloadSize),
            cancellationToken).ConfigureAwait(false);

        ulong tcsSectionOffset = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(0));
        ulong baseSectionOffset = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(8));
        ulong pidxSectionOffset = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(16));
        ulong firstPaylSectionOffset = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(24));
        ulong paylCount = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(32));
        ulong payloadEntryCount = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(40));
        ulong reserved = BinaryPrimitives.ReadUInt64LittleEndian(
            _readBuffer.AsSpan(48));

        if (reserved != 0)
        {
            throw Malformed("The FOOT reserved field must be zero.");
        }

        if (tcsSectionOffset != (ulong)_tcsmSectionOffset ||
            baseSectionOffset != (ulong)_baseSectionOffset ||
            pidxSectionOffset != (ulong)_pidxSectionOffset ||
            firstPaylSectionOffset != (ulong)_firstPaylSectionOffset ||
            paylCount != _paylCount ||
            payloadEntryCount != (ulong)_entries.Count)
        {
            throw Malformed("The FOOT fields disagree with the observed sections.");
        }

        if (_trailerFootOffset != (ulong)_footSectionOffset)
        {
            throw Malformed("The TRAILER FootSectionOffset does not locate FOOT.");
        }
    }

    /// <summary>
    /// Streams the CRC-32C over a section header plus every payload byte
    /// preceding the CRC field, then compares it with the stored value.
    /// </summary>
    private async ValueTask VerifySectionCrcAsync(
        long sectionOffset,
        long payloadLength,
        string sectionName,
        CancellationToken cancellationToken)
    {
        long recordLength = CspFormat.SectionHeaderSize + payloadLength;
        long crcOffset = sectionOffset + recordLength - CspFormat.CrcSize;
        uint state = Crc32C.Start();
        long position = sectionOffset;

        while (position < crcOffset)
        {
            int requested = (int)Math.Min(_readBuffer.Length, crcOffset - position);
            int read = await ReadAsyncAtAsync(
                position,
                requested,
                cancellationToken).ConfigureAwait(false);

            state = Crc32C.Append(state, _readBuffer.AsSpan(0, read));
            position += read;
        }

        await ReadExactlyAtAsync(
            crcOffset,
            Scratch(CspFormat.CrcSize),
            cancellationToken).ConfigureAwait(false);

        uint stored = BinaryPrimitives.ReadUInt32LittleEndian(
            _readBuffer.AsSpan(0, CspFormat.CrcSize));

        if (Crc32C.Finalize(state) != stored)
        {
            throw Malformed($"The {sectionName} CRC-32C does not match.");
        }
    }

    /// <summary>
    /// Reads the embedded target CSM through a bounded window and streams every
    /// record, remembering the first target index and length of each payload
    /// identity.
    /// </summary>
    private async ValueTask ReadTargetManifestAsync(CancellationToken cancellationToken)
    {
        var bounded = new BoundedReadStream(
            _patch,
            checked(_start + _tcsmPayloadOffset),
            _tcsmPayloadLength);

        using ManifestReader reader =
            await ManifestReader.OpenAsync(bounded, cancellationToken).ConfigureAwait(false);

        var ordinals = new Dictionary<ChunkId, int>(_entries.Count);

        for (int index = 0; index < _entries.Count; index++)
        {
            _ = ordinals.TryAdd(_entries[index].ChunkId, index);
        }

        _firstTargetIndex = new long[_entries.Count];
        Array.Fill(_firstTargetIndex, -1L);
        _targetLength = new int[_entries.Count];

        var batch = new ChunkInfo[ManifestBatchEntries];
        long recordIndex = 0;

        while (true)
        {
            int count = await reader
                .ReadAsync(batch, cancellationToken)
                .ConfigureAwait(false);

            if (count == 0)
            {
                break;
            }

            for (int index = 0; index < count; index++)
            {
                ChunkInfo record = batch[index];

                if (ordinals.TryGetValue(record.Id, out int ordinal))
                {
                    if (_firstTargetIndex[ordinal] < 0)
                    {
                        _firstTargetIndex[ordinal] = recordIndex;
                        _targetLength[ordinal] = record.Length;
                    }
                }
                else
                {
                    _dependsOnBase = true;
                }

                recordIndex++;
            }
        }

        ManifestVerificationResult result = reader.VerificationResult
            ?? throw Malformed(
                "The embedded CSM reader ended without a verification result.");

        _targetManifest = result;

        if (result.Manifest.PhysicalLength < 0 ||
            (ulong)result.Manifest.PhysicalLength != (ulong)_tcsmPayloadLength)
        {
            throw Malformed(
                "The embedded CSM PhysicalLength differs from the TCSM PayloadLength.");
        }

        if ((result.Failures &
            (ManifestVerificationFailure.BlockCrc |
             ManifestVerificationFailure.LogicalTotals |
             ManifestVerificationFailure.ManifestId |
             ManifestVerificationFailure.FileDigest)) != 0)
        {
            _failures |= CspVerificationFailure.EmbeddedManifest;
        }

        if ((result.Failures & ManifestVerificationFailure.ProfileSemantics) != 0)
        {
            _failures |= CspVerificationFailure.ProfileSemantics;
        }
    }

    /// <summary>
    /// Recomputes the patch physical digest over every byte before the TRAILER
    /// with the embedded manifest's HashSuite.
    /// </summary>
    private async ValueTask CheckFileDigestAsync(CancellationToken cancellationToken)
    {
        HashSuiteId hashSuite = TargetManifest.Manifest.HashSuite;

        if (!PatchHashing.IsSupported(hashSuite))
        {
            throw new NotSupportedException($"Unsupported HashSuiteId '{hashSuite}'.");
        }

        using IncrementalPatchHash hasher = PatchHashing.CreateIncremental(hashSuite);
        long remaining = _length - CspFormat.TrailerSize;

        SeekTo(0);

        while (remaining > 0)
        {
            int requested = (int)Math.Min(_readBuffer.Length, remaining);

            cancellationToken.ThrowIfCancellationRequested();
            int read = await _patch
                .ReadAsync(_readBuffer.AsMemory(0, requested), cancellationToken)
                .ConfigureAwait(false);

            if ((uint)read > (uint)requested)
            {
                throw new InvalidOperationException(
                    "The CSP patch stream returned a byte count outside the Stream contract.");
            }

            if (read == 0)
            {
                throw Malformed("The CSP patch ended before its declared structure.");
            }

            hasher.Append(_readBuffer.AsSpan(0, read));
            remaining -= read;
        }

        if (hasher.FinalizeHash() != _storedFileDigest)
        {
            _failures |= CspVerificationFailure.FileDigest;
        }
    }

    /// <summary>
    /// Checks the payload entries against the target manifest (rule 17), the
    /// payload index's first-occurrence claim (rule 12) and the stored lengths
    /// (rule 18). Accrued verification failures stop before the length checks.
    /// </summary>
    private void CheckPayloadAgainstTarget()
    {
        var seen = new HashSet<ChunkId>();
        var unique = new List<int>(_entries.Count);

        for (int ordinal = 0; ordinal < _entries.Count; ordinal++)
        {
            ChunkId chunkId = _entries[ordinal].ChunkId;

            if (!seen.Add(chunkId))
            {
                _failures |= CspVerificationFailure.DuplicatePayload;
                continue;
            }

            if (_firstTargetIndex[ordinal] < 0)
            {
                _failures |= CspVerificationFailure.PayloadNotInTarget;
                continue;
            }

            unique.Add(ordinal);
        }

        // A misplaced FirstTargetIndex is malformed and reported before any
        // accrued failure, because it breaks the index-to-target relation that
        // every later stage relies on.
        foreach (int ordinal in unique)
        {
            if (_index[ordinal].FirstTargetIndex != (ulong)_firstTargetIndex[ordinal])
            {
                throw Malformed(
                    "A PIDX FirstTargetIndex is not the first occurrence of its ChunkId.");
            }
        }

        foreach (int ordinal in unique)
        {
            PaylEntry entry = _entries[ordinal];
            uint targetLength = (uint)_targetLength[ordinal];

            if (entry.StoredLength > targetLength ||
                (entry.Encoding == CspFormat.EncodingRaw &&
                 entry.StoredLength != targetLength))
            {
                _failures |= CspVerificationFailure.PayloadLength;
            }
        }
    }

    /// <summary>
    /// Completes the base binding the patch alone reveals: a base-dependent
    /// patch must carry <c>BASE</c> (rule 13).
    /// </summary>
    private void CheckBaseDependence()
    {
        foreach (PaylEntry entry in _entries)
        {
            if (entry.Encoding == CspFormat.EncodingZstd && entry.DictionaryCount > 0)
            {
                _dependsOnBase = true;
                break;
            }
        }

        if (_dependsOnBase && _expectedBase is null)
        {
            throw Malformed("The patch depends on a base but holds no BASE section.");
        }
    }

    private async ValueTask<CspEntry> ReadEntryCoreAsync(
        int ordinal,
        CancellationToken cancellationToken)
    {
        CspIndexEntry index = _index[ordinal];
        PaylEntry entry = _entries[ordinal];

        await ReadExactlyAtAsync(
            (long)index.PayloadOffset,
            Scratch(CspFormat.PaylEntryHeaderSize),
            cancellationToken).ConfigureAwait(false);

        var chunkId = new ChunkId(
            Hash256.FromBytes(_readBuffer.AsSpan(0, CspFormat.HashSize)));
        uint storedLength = BinaryPrimitives.ReadUInt32LittleEndian(
            _readBuffer.AsSpan(EntryStoredLengthOffset, sizeof(uint)));
        byte encoding = _readBuffer[EntryEncodingOffset];
        byte dictionaryCount = _readBuffer[EntryDictionaryCountOffset];
        ushort reserved = BinaryPrimitives.ReadUInt16LittleEndian(
            _readBuffer.AsSpan(EntryReservedOffset, sizeof(ushort)));

        if (reserved != 0 ||
            chunkId != entry.ChunkId ||
            storedLength != index.StoredLength ||
            encoding != index.Encoding ||
            dictionaryCount != index.DictionaryCount)
        {
            throw Malformed(
                "The payload entry no longer agrees with the validated index.");
        }

        if (storedLength > int.MaxValue)
        {
            throw new CspResourceLimitException(
                "The payload entry stores more bytes than a single buffer can hold.");
        }

        long dictionaryOffset =
            (long)index.PayloadOffset + CspFormat.PaylEntryHeaderSize;
        var dictionary = new ChunkId[dictionaryCount];

        if (dictionaryCount > 0)
        {
            await ReadExactlyAtAsync(
                dictionaryOffset,
                Scratch(dictionaryCount * CspFormat.DictionaryReferenceSize),
                cancellationToken).ConfigureAwait(false);

            for (int reference = 0; reference < dictionaryCount; reference++)
            {
                dictionary[reference] = new ChunkId(Hash256.FromBytes(
                    _readBuffer.AsSpan(
                        reference * CspFormat.DictionaryReferenceSize,
                        CspFormat.HashSize)));
            }
        }

        var storedBytes = new byte[(int)storedLength];
        await ReadExactlyAtAsync(
            dictionaryOffset + (dictionaryCount * CspFormat.DictionaryReferenceSize),
            storedBytes,
            cancellationToken).ConfigureAwait(false);

        return new CspEntry(chunkId, encoding, dictionary, storedBytes);
    }

    /// <summary>
    /// Seeks to a patch-relative offset and reads exactly
    /// <paramref name="destination"/>.Length bytes, converting a premature end
    /// of stream into malformed input.
    /// </summary>
    private async ValueTask ReadExactlyAtAsync(
        long offset,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        SeekTo(offset);
        int written = 0;

        while (written < destination.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = await _patch
                .ReadAsync(destination[written..], cancellationToken)
                .ConfigureAwait(false);

            if ((uint)read > (uint)(destination.Length - written))
            {
                throw new InvalidOperationException(
                    "The CSP patch stream returned a byte count outside the Stream contract.");
            }

            if (read == 0)
            {
                throw Malformed("The CSP patch ended before its declared structure.");
            }

            written += read;
        }
    }

    /// <summary>
    /// Seeks to a patch-relative offset and reads one non-empty chunk into the
    /// read buffer, converting a premature end of stream into malformed input.
    /// </summary>
    private async ValueTask<int> ReadAsyncAtAsync(
        long offset,
        int count,
        CancellationToken cancellationToken)
    {
        SeekTo(offset);
        cancellationToken.ThrowIfCancellationRequested();

        int read = await _patch
            .ReadAsync(_readBuffer.AsMemory(0, count), cancellationToken)
            .ConfigureAwait(false);

        if ((uint)read > (uint)count)
        {
            throw new InvalidOperationException(
                "The CSP patch stream returned a byte count outside the Stream contract.");
        }

        if (read == 0)
        {
            throw Malformed("The CSP patch ended before its declared structure.");
        }

        return read;
    }

    private void SeekTo(long offset) =>
        _patch.Position = checked(_start + offset);

    private Memory<byte> Scratch(int count) => _readBuffer.AsMemory(0, count);

    private enum Phase
    {
        Start,
        Tcsm,
        Base,
        Payl,
        Optional,
        Pidx,
    }

    /// <summary>One parsed <c>PAYL</c> entry header (CSP-V1 section 4.6).</summary>
    private readonly struct PaylEntry
    {
        internal PaylEntry(
            ChunkId chunkId,
            long recordOffset,
            uint storedLength,
            byte encoding,
            byte dictionaryCount)
        {
            ChunkId = chunkId;
            RecordOffset = recordOffset;
            StoredLength = storedLength;
            Encoding = encoding;
            DictionaryCount = dictionaryCount;
        }

        internal ChunkId ChunkId { get; }

        /// <summary>Patch-relative offset of the entry's <c>ChunkId</c> field.</summary>
        internal long RecordOffset { get; }

        internal uint StoredLength { get; }

        internal byte Encoding { get; }

        internal byte DictionaryCount { get; }
    }

    /// <summary>Read-only identity view over the parsed payload entries.</summary>
    private sealed class PaylChunkIdList : IReadOnlyList<ChunkId>
    {
        private readonly List<PaylEntry> _entries;

        internal PaylChunkIdList(List<PaylEntry> entries) => _entries = entries;

        public int Count => _entries.Count;

        public ChunkId this[int index] => _entries[index].ChunkId;

        public IEnumerator<ChunkId> GetEnumerator()
        {
            foreach (PaylEntry entry in _entries)
            {
                yield return entry.ChunkId;
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
