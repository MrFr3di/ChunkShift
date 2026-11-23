using System.Buffers.Binary;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Format;

/// <summary>One payload entry as the independent CSP byte builder records it.</summary>
internal sealed record CspPatchEntry(
    ChunkId ChunkId,
    ulong FirstTargetIndex,
    byte Encoding,
    byte[] StoredBytes,
    ChunkId[] DictionaryChunkIds);

/// <summary>One section of a CSP v1 representation.</summary>
internal readonly record struct CspSectionInfo(
    uint Type,
    int Offset,
    uint Flags,
    ulong PayloadLength);

/// <summary>One payload entry read back from a CSP v1 representation.</summary>
internal readonly record struct CspPaylEntryInfo(
    ChunkId ChunkId,
    uint StoredLength,
    byte Encoding,
    ChunkId[] DictionaryChunkIds,
    int RecordOffset);

/// <summary>One PIDX entry read back from a CSP v1 representation.</summary>
internal readonly record struct CspPidxEntryInfo(
    ulong FirstTargetIndex,
    ulong PayloadOffset,
    uint StoredLength,
    byte Encoding,
    byte DictionaryCount);

/// <summary>
/// Independent CSP v1 byte builder. It never calls <c>CspWriter</c>: every
/// field, CRC and digest is written here from explicit values, so a test states
/// the expected bytes instead of repeating writer logic.
/// </summary>
internal sealed class CspPatchBuilder
{
    internal HashSuiteId HashSuite { get; set; } = HashSuiteIds.Sha256V1;

    internal byte[] TargetManifest { get; set; } = [];

    internal ManifestId? ExpectedBase { get; set; }

    internal List<CspPatchEntry> Entries { get; } = [];

    internal int EntriesPerBlock { get; set; } = (int)CspFormat.MaximumEntriesPerPayl;

    internal int BlockBytes { get; set; } = int.MaxValue;

    internal uint TcsFlags { get; set; } = CspFormat.RequiredSectionFlag;

    internal uint BaseFlags { get; set; }

    internal uint PaylFlags { get; set; } = CspFormat.RequiredSectionFlag;

    internal uint PidxFlags { get; set; } = CspFormat.RequiredSectionFlag;

    internal uint FootFlags { get; set; } = CspFormat.RequiredSectionFlag;

    internal CspPatchBuilder AddEntries(IEnumerable<CspPatchEntry> entries)
    {
        Entries.AddRange(entries);
        return this;
    }

    internal byte[] Build()
    {
        var writer = new PatchWriter();

        // PREAMBLE, fixed 32 bytes.
        writer.Bytes(CspFormat.PreambleMagic);
        writer.U16(CspFormat.FormatMajor);
        writer.U16(CspFormat.PreambleSize);
        writer.U64(0);
        writer.U64(0);
        writer.U64(0);

        // TCSM.
        int tcsOffset = writer.Offset;
        writer.U32(CspFormat.TargetManifest);
        writer.U32(TcsFlags);
        writer.U64(checked((ulong)TargetManifest.Length));
        writer.Bytes(TargetManifest);

        // BASE, optional.
        ulong baseOffset = 0;
        if (ExpectedBase.HasValue)
        {
            baseOffset = checked((ulong)writer.Offset);
            writer.U32(CspFormat.Base);
            writer.U32(BaseFlags);
            writer.U64(CspFormat.BasePayloadSize);
            writer.Digest(ExpectedBase.Value.Value);
        }

        // PAYL blocks.
        ulong firstPaylOffset = 0;
        ulong paylCount = 0;
        var index = new List<CspPidxEntryInfo>();

        foreach ((int start, int count) in GroupEntries())
        {
            int sectionOffset = writer.Offset;
            if (firstPaylOffset == 0)
            {
                firstPaylOffset = checked((ulong)sectionOffset);
            }

            paylCount++;

            long entryBytes = 0;
            for (int entry = start; entry < start + count; entry++)
            {
                entryBytes += EntrySize(Entries[entry]);
            }

            writer.U32(CspFormat.Payload);
            writer.U32(PaylFlags);
            writer.U64(
                checked((ulong)(CspFormat.PaylPrefixSize + entryBytes + CspFormat.CrcSize)));
            writer.U32(checked((uint)count));
            writer.U32(0);
            writer.U64(checked((ulong)start));

            for (int entry = start; entry < start + count; entry++)
            {
                CspPatchEntry value = Entries[entry];
                index.Add(new CspPidxEntryInfo(
                    value.FirstTargetIndex,
                    checked((ulong)writer.Offset),
                    checked((uint)value.StoredBytes.Length),
                    value.Encoding,
                    checked((byte)value.DictionaryChunkIds.Length)));

                writer.Digest(value.ChunkId.Value);
                writer.U32(checked((uint)value.StoredBytes.Length));
                writer.U8(value.Encoding);
                writer.U8(checked((byte)value.DictionaryChunkIds.Length));
                writer.U16(0);

                foreach (ChunkId dictionary in value.DictionaryChunkIds)
                {
                    writer.Digest(dictionary.Value);
                }

                writer.Bytes(value.StoredBytes);
            }

            writer.U32(Crc32C.Compute(writer.SpanFrom(sectionOffset)));
        }

        // PIDX.
        int pidxSectionOffset = writer.Offset;
        ulong pidxOffset = checked((ulong)pidxSectionOffset);
        writer.U32(CspFormat.PayloadIndex);
        writer.U32(PidxFlags);
        writer.U64(
            checked((ulong)(CspFormat.PidxPrefixSize
                + (index.Count * CspFormat.PidxEntrySize)
                + CspFormat.CrcSize)));
        writer.U32(CspFormat.IndexVersion);
        writer.U32(checked((uint)index.Count));

        foreach (CspPidxEntryInfo entry in index)
        {
            writer.U64(entry.FirstTargetIndex);
            writer.U64(entry.PayloadOffset);
            writer.U32(entry.StoredLength);
            writer.U8(entry.Encoding);
            writer.U8(entry.DictionaryCount);
            writer.U16(0);
        }

        writer.U32(Crc32C.Compute(writer.SpanFrom(pidxSectionOffset)));

        // FOOT.
        ulong footOffset = checked((ulong)writer.Offset);
        writer.U32(CspFormat.Footer);
        writer.U32(FootFlags);
        writer.U64(CspFormat.FootPayloadSize);
        writer.U64(checked((ulong)tcsOffset));
        writer.U64(baseOffset);
        writer.U64(pidxOffset);
        writer.U64(firstPaylOffset);
        writer.U64(paylCount);
        writer.U64(checked((ulong)Entries.Count));
        writer.U64(0);

        // TRAILER over every byte before it.
        ulong physicalLength = checked((ulong)(writer.Offset + CspFormat.TrailerSize));
        Hash256 digest = PatchHashing.Hash(HashSuite, writer.SpanFrom(0));
        writer.Bytes(CspFormat.TrailerMagic);
        writer.U16(CspFormat.FormatMajor);
        writer.U16(CspFormat.TrailerSize);
        writer.U64(footOffset);
        writer.U64(physicalLength);
        writer.Digest(digest);
        writer.U64(0);

        return writer.ToArray();
    }

    private static long EntrySize(CspPatchEntry entry) =>
        CspFormat.PaylEntryHeaderSize
        + (entry.DictionaryChunkIds.Length * CspFormat.DictionaryReferenceSize)
        + entry.StoredBytes.Length;

    /// <summary>
    /// Groups entries by the writer's block rules: at most
    /// <see cref="EntriesPerBlock"/> entries, a flush before an entry that would
    /// push the open block above <see cref="BlockBytes"/>, and an entry larger
    /// than the budget in a block of its own.
    /// </summary>
    private List<(int Start, int Count)> GroupEntries()
    {
        if (EntriesPerBlock <= 0)
        {
            throw new InvalidOperationException("EntriesPerBlock must be positive.");
        }

        var groups = new List<(int Start, int Count)>();
        int start = 0;

        while (start < Entries.Count)
        {
            int count = 0;
            long bytes = 0;

            while (start + count < Entries.Count && count < EntriesPerBlock)
            {
                long size = EntrySize(Entries[start + count]);
                if (count > 0 && bytes + size > BlockBytes)
                {
                    break;
                }

                bytes += size;
                count++;
            }

            groups.Add((start, count));
            start += count;
        }

        return groups;
    }

    /// <summary>Little-endian append-only buffer for the explicit field values.</summary>
    private sealed class PatchWriter
    {
        private byte[] _buffer = new byte[256];
        private int _length;

        internal int Offset => _length;

        internal void U8(byte value)
        {
            EnsureCapacity(1);
            _buffer[_length] = value;
            _length++;
        }

        internal void U16(ushort value)
        {
            EnsureCapacity(sizeof(ushort));
            BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(_length), value);
            _length += sizeof(ushort);
        }

        internal void U32(uint value)
        {
            EnsureCapacity(sizeof(uint));
            BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_length), value);
            _length += sizeof(uint);
        }

        internal void U64(ulong value)
        {
            EnsureCapacity(sizeof(ulong));
            BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_length), value);
            _length += sizeof(ulong);
        }

        internal void Bytes(ReadOnlySpan<byte> value)
        {
            EnsureCapacity(value.Length);
            value.CopyTo(_buffer.AsSpan(_length));
            _length += value.Length;
        }

        internal void Digest(Hash256 value)
        {
            EnsureCapacity(CspFormat.HashSize);
            value.CopyTo(_buffer.AsSpan(_length));
            _length += CspFormat.HashSize;
        }

        internal ReadOnlySpan<byte> SpanFrom(int start) =>
            _buffer.AsSpan(start, checked(_length - start));

        internal byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();

        private void EnsureCapacity(int count)
        {
            int required = checked(_length + count);

            if (required <= _buffer.Length)
            {
                return;
            }

            int capacity = _buffer.Length;
            while (capacity < required)
            {
                capacity = checked(capacity * 2);
            }

            Array.Resize(ref _buffer, capacity);
        }
    }
}

/// <summary>
/// Byte-level helpers for CSP v1 tests: deterministic inputs, a real CSM target
/// manifest from Core's public API, section readers and field mutators.
/// </summary>
internal static class CspBytes
{
    internal static byte[] CreateXorShiftBytes(int length, uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int index = 0; index < bytes.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[index] = (byte)state;
        }

        return bytes;
    }

    internal static ChunkId ChunkId(ulong value)
    {
        var bytes = new byte[CspFormat.HashSize];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);

        for (int index = sizeof(ulong); index < bytes.Length; index++)
        {
            bytes[index] = (byte)(value + (ulong)index);
        }

        return new ChunkId(Hash256.FromBytes(bytes));
    }

    /// <summary>
    /// Creates a real CSM target manifest through Core's public API over
    /// deterministic xorshift bytes.
    /// </summary>
    internal static async Task<byte[]> CreateCsmAsync(
        HashSuiteId hashSuite,
        int sourceLength = 256 * 1024,
        uint seed = 0x7A11C0DEu)
    {
        byte[] input = CreateXorShiftBytes(sourceLength, seed);
        using var destination = new MemoryStream();

        await ChunkManifest.CreateAsync(
            new MemoryStream(input, writable: false),
            destination,
            new ManifestCreationOptions { HashSuite = hashSuite },
            CancellationToken.None);

        return destination.ToArray();
    }

    internal static IReadOnlyList<CspSectionInfo> EnumerateSections(byte[] patch)
    {
        var sections = new List<CspSectionInfo>();
        int end = patch.Length - CspFormat.TrailerSize;
        int offset = CspFormat.PreambleSize;

        while (offset < end)
        {
            ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
                patch.AsSpan(offset + 8, sizeof(ulong)));

            sections.Add(new CspSectionInfo(
                BinaryPrimitives.ReadUInt32LittleEndian(
                    patch.AsSpan(offset, sizeof(uint))),
                offset,
                BinaryPrimitives.ReadUInt32LittleEndian(
                    patch.AsSpan(offset + 4, sizeof(uint))),
                payloadLength));

            offset = checked(offset + CspFormat.SectionHeaderSize + (int)payloadLength);
        }

        if (offset != end)
        {
            throw new InvalidOperationException(
                "CSP section walk did not end at the TRAILER.");
        }

        return sections;
    }

    internal static CspSectionInfo FindSection(byte[] patch, uint type, int occurrence = 0)
    {
        int seen = 0;

        foreach (CspSectionInfo section in EnumerateSections(patch))
        {
            if (section.Type == type && seen++ == occurrence)
            {
                return section;
            }
        }

        throw new InvalidOperationException(
            $"CSP section 0x{type:x8} occurrence {occurrence} was not found.");
    }

    internal static IReadOnlyList<CspSectionInfo> FindSections(byte[] patch, uint type)
    {
        var sections = new List<CspSectionInfo>();

        foreach (CspSectionInfo section in EnumerateSections(patch))
        {
            if (section.Type == type)
            {
                sections.Add(section);
            }
        }

        return sections;
    }

    internal static uint ReadPaylEntryCount(byte[] patch, int sectionOffset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(
            patch.AsSpan(sectionOffset + CspFormat.SectionHeaderSize, sizeof(uint)));

    internal static ulong ReadPaylFirstEntryOrdinal(byte[] patch, int sectionOffset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(
            patch.AsSpan(
                sectionOffset + CspFormat.SectionHeaderSize + sizeof(ulong),
                sizeof(ulong)));

    internal static IReadOnlyList<CspPaylEntryInfo> ReadPaylEntries(
        byte[] patch,
        int sectionOffset)
    {
        uint entryCount = ReadPaylEntryCount(patch, sectionOffset);
        int offset = sectionOffset
            + CspFormat.SectionHeaderSize
            + CspFormat.PaylPrefixSize;
        var entries = new List<CspPaylEntryInfo>();

        for (int index = 0; index < entryCount; index++)
        {
            byte dictionaryCount = patch[offset + 37];
            var dictionary = new ChunkId[dictionaryCount];

            for (int reference = 0; reference < dictionaryCount; reference++)
            {
                dictionary[reference] = new ChunkId(Hash256.FromBytes(
                    patch.AsSpan(
                        offset
                        + CspFormat.PaylEntryHeaderSize
                        + (reference * CspFormat.DictionaryReferenceSize),
                        CspFormat.HashSize)));
            }

            uint storedLength = BinaryPrimitives.ReadUInt32LittleEndian(
                patch.AsSpan(offset + 32, sizeof(uint)));

            entries.Add(new CspPaylEntryInfo(
                new ChunkId(Hash256.FromBytes(
                    patch.AsSpan(offset, CspFormat.HashSize))),
                storedLength,
                patch[offset + 36],
                dictionary,
                offset));

            offset = checked(
                offset
                + CspFormat.PaylEntryHeaderSize
                + (dictionaryCount * CspFormat.DictionaryReferenceSize)
                + (int)storedLength);
        }

        return entries;
    }

    internal static IReadOnlyList<CspPaylEntryInfo> ReadAllPaylEntries(byte[] patch)
    {
        var entries = new List<CspPaylEntryInfo>();

        foreach (CspSectionInfo section in FindSections(patch, CspFormat.Payload))
        {
            entries.AddRange(ReadPaylEntries(patch, section.Offset));
        }

        return entries;
    }

    internal static IReadOnlyList<CspPidxEntryInfo> ReadPidxEntries(byte[] patch)
    {
        CspSectionInfo section = FindSection(patch, CspFormat.PayloadIndex);
        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(
            patch.AsSpan(
                section.Offset + CspFormat.SectionHeaderSize + sizeof(uint),
                sizeof(uint)));
        int offset = section.Offset
            + CspFormat.SectionHeaderSize
            + CspFormat.PidxPrefixSize;
        var entries = new List<CspPidxEntryInfo>();

        for (int index = 0; index < entryCount; index++)
        {
            entries.Add(new CspPidxEntryInfo(
                BinaryPrimitives.ReadUInt64LittleEndian(
                    patch.AsSpan(offset, sizeof(ulong))),
                BinaryPrimitives.ReadUInt64LittleEndian(
                    patch.AsSpan(offset + 8, sizeof(ulong))),
                BinaryPrimitives.ReadUInt32LittleEndian(
                    patch.AsSpan(offset + 16, sizeof(uint))),
                patch[offset + 20],
                patch[offset + 21]));

            offset += CspFormat.PidxEntrySize;
        }

        return entries;
    }

    /// <summary>
    /// Recomputes the CRC-32C of the PAYL or PIDX record starting at
    /// <paramref name="sectionOffset"/> after a field mutation.
    /// </summary>
    internal static void RewriteSectionCrc(byte[] patch, int sectionOffset)
    {
        ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            patch.AsSpan(sectionOffset + 8, sizeof(ulong)));
        int recordLength = checked(CspFormat.SectionHeaderSize + (int)payloadLength);
        int crcOffset = checked(sectionOffset + recordLength - CspFormat.CrcSize);

        BinaryPrimitives.WriteUInt32LittleEndian(
            patch.AsSpan(crcOffset, CspFormat.CrcSize),
            Crc32C.Compute(patch.AsSpan(sectionOffset, crcOffset - sectionOffset)));
    }

    internal static void RewritePidxCrc(byte[] patch) =>
        RewriteSectionCrc(patch, FindSection(patch, CspFormat.PayloadIndex).Offset);

    /// <summary>
    /// Recomputes TRAILER.FileDigest after a mutation of the hashed bytes.
    /// </summary>
    internal static void RewriteFileDigest(byte[] patch, HashSuiteId hashSuite)
    {
        int trailerOffset = patch.Length - CspFormat.TrailerSize;
        Hash256 digest = PatchHashing.Hash(
            hashSuite,
            patch.AsSpan(0, trailerOffset));

        digest.CopyTo(patch.AsSpan(trailerOffset + 24, CspFormat.HashSize));
    }
}
