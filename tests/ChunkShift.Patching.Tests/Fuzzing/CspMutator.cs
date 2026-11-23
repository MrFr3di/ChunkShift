using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Fuzzing;

/// <summary>
/// Deterministic SplitMix64 generator. Seeded runs are reproducible on every
/// platform and runtime, which is what makes a failing fuzz case replayable.
/// </summary>
internal sealed class FuzzRandom(ulong seed)
{
    private ulong _state = seed;

    internal ulong NextUInt64()
    {
        ulong z = _state += 0x9E3779B97F4A7C15UL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    /// <summary>Uniform value in [0, exclusiveMax).</summary>
    internal int Next(int exclusiveMax)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(exclusiveMax);

        return (int)(NextUInt64() % (ulong)exclusiveMax);
    }

    internal bool Chance(int percent) => Next(100) < percent;

    internal T Pick<T>(IReadOnlyList<T> items) => items[Next(items.Count)];
}

/// <summary>
/// Structure-aware mutator for CSP v1 representations.
/// </summary>
/// <remarks>
/// Mutations mix blind byte-level edits with edits aimed at the fields the
/// applier parses (section headers, payload lengths, PAYL and PIDX entry
/// records, FOOT offsets). After mutating, the mutator can optionally re-seal
/// the <c>PAYL</c>/<c>PIDX</c> CRC-32C values and the TRAILER <c>FileDigest</c>
/// so that integrity checks do not stop every case before the deeper
/// structural and logical rules run.
/// </remarks>
internal static class CspMutator
{
    private static readonly ulong[] InterestingUInt64 =
    [
        0,
        1,
        2,
        3,
        4,
        7,
        8,
        15,
        16,
        17,
        24,
        31,
        32,
        33,
        40,
        47,
        48,
        49,
        55,
        56,
        57,
        63,
        64,
        65,
        127,
        128,
        129,
        255,
        256,
        4095,
        4096,
        4097,
        65_535,
        65_536,
        65_537,
        1_048_575,
        1_048_576,
        1_048_577,
        4_194_303,
        4_194_304,
        4_194_305,
        int.MaxValue,
        (ulong)int.MaxValue + 1,
        uint.MaxValue,
        (ulong)uint.MaxValue + 1,
        long.MaxValue,
        (ulong)long.MaxValue + 1,
        ulong.MaxValue - 15,
        ulong.MaxValue - 1,
        ulong.MaxValue,
    ];

    private static readonly byte[] InterestingBytes =
    [
        0x00,
        0x01,
        0x7F,
        0x80,
        0xFF,
    ];

    private static readonly uint[] KnownFourCcs =
    [
        CspFormat.TargetManifest,
        CspFormat.Base,
        CspFormat.Payload,
        CspFormat.Aux0,
        CspFormat.PayloadIndex,
        CspFormat.Footer,
    ];

    internal static byte[] Mutate(
        byte[] seed,
        IReadOnlyList<byte[]> corpus,
        FuzzRandom random,
        StringBuilder trace)
    {
        // The seed stays untouched: every operation, including the re-seal
        // pass below, mutates only this copy.
        byte[] data = (byte[])seed.Clone();
        int rounds = random.Next(10) switch
        {
            < 7 => 1,
            < 9 => 2,
            _ => 3 + random.Next(2),
        };

        for (int round = 0; round < rounds; round++)
        {
            data = MutateOnce(data, corpus, random, trace);
        }

        // A real encoder computes the section CRCs and the TRAILER FileDigest
        // over the final bytes; re-sealing them undoes the cheapest detections
        // so that many cases reach the rules behind them.
        if (random.Chance(50))
        {
            trace.Append("reseal-crc;");
            ResealSectionCrcs(data);
            trace.Append("reseal-digest;");
            ResealFileDigest(data);
        }

        return data;
    }

    private static byte[] MutateOnce(
        byte[] data,
        IReadOnlyList<byte[]> corpus,
        FuzzRandom random,
        StringBuilder trace)
    {
        List<Section> sections = WalkSections(data);
        List<Field> fields = FindFields(data, sections);

        switch (random.Next(13))
        {
            case 0 when data.Length > 0:
            {
                int offset = random.Next(data.Length);
                int bit = random.Next(8);
                trace.Append(CultureInfo.InvariantCulture, $"flip@{offset}.{bit};");
                byte[] copy = (byte[])data.Clone();
                copy[offset] ^= (byte)(1 << bit);
                return copy;
            }

            case 1 when data.Length > 0:
            {
                int offset = random.Next(data.Length);
                byte value = random.Pick(InterestingBytes);
                trace.Append(CultureInfo.InvariantCulture, $"byte@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                copy[offset] = value;
                return copy;
            }

            case 2 when data.Length >= 2:
            {
                int offset = random.Next(data.Length - 1);
                ulong value = random.Pick(InterestingUInt64);
                trace.Append(CultureInfo.InvariantCulture, $"u16@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt16LittleEndian(copy.AsSpan(offset, 2), (ushort)value);
                return copy;
            }

            case 3 when data.Length >= 4:
            {
                int offset = random.Next(data.Length - 3);
                ulong value = random.Pick(InterestingUInt64);
                trace.Append(CultureInfo.InvariantCulture, $"u32@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset, 4), (uint)value);
                return copy;
            }

            case 4 when data.Length >= 8:
            {
                int offset = random.Next(data.Length - 7);
                ulong value = random.Pick(InterestingUInt64);
                trace.Append(CultureInfo.InvariantCulture, $"u64@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(offset, 8), value);
                return copy;
            }

            case 5 when fields.Count > 0:
            {
                // A field of a walkable section: header, PAYL/PIDX entry or
                // FOOT, with the interesting values plus the current value,
                // lengths and the patch length.
                var field = random.Pick(fields);
                ulong value = random.Pick(FieldValues(data, field));
                trace.Append(
                    CultureInfo.InvariantCulture,
                    $"field@{field.Offset}.{field.Size}={value};");
                byte[] copy = (byte[])data.Clone();
                WriteLittleEndian(copy, field.Offset, field.Size, value);
                return copy;
            }

            case 6 when data.Length > 1:
            {
                int length = random.Next(data.Length);
                trace.Append(CultureInfo.InvariantCulture, $"truncate={length};");
                return data.AsSpan(0, length).ToArray();
            }

            case 7:
            {
                int count = 1 + random.Next(random.Chance(10) ? 4096 : 32);
                byte[] tail = new byte[count];
                for (int index = 0; index < tail.Length; index++)
                {
                    tail[index] = (byte)random.NextUInt64();
                }

                trace.Append(CultureInfo.InvariantCulture, $"append={count};");
                return [.. data, .. tail];
            }

            case 8 when data.Length > 1:
            {
                int start = random.Next(data.Length);
                int length = 1 + random.Next(Math.Min(256, data.Length - start));
                trace.Append(CultureInfo.InvariantCulture, $"delete@{start}+{length};");
                return [.. data.AsSpan(0, start), .. data.AsSpan(start + length)];
            }

            case 9 when data.Length > 0:
            {
                int start = random.Next(data.Length);
                int length = 1 + random.Next(Math.Min(256, data.Length - start));
                int insertAt = random.Next(data.Length + 1);
                trace.Append(
                    CultureInfo.InvariantCulture,
                    $"duplicate@{start}+{length}->{insertAt};");
                return
                [
                    .. data.AsSpan(0, insertAt),
                    .. data.AsSpan(start, length),
                    .. data.AsSpan(insertAt),
                ];
            }

            case 10 when data.Length > 0:
            {
                byte[] donor = random.Pick(corpus);
                if (donor.Length == 0)
                {
                    return data;
                }

                int cut = random.Next(data.Length);
                int donorStart = random.Next(donor.Length);
                trace.Append(CultureInfo.InvariantCulture, $"splice@{cut}<-{donorStart};");
                return [.. data.AsSpan(0, cut), .. donor.AsSpan(donorStart)];
            }

            case 11 when sections.Count > 1:
            {
                int first = random.Next(sections.Count);
                int second = random.Next(sections.Count - 1);
                if (second >= first)
                {
                    second++;
                }

                Section a = sections[Math.Min(first, second)];
                Section b = sections[Math.Max(first, second)];
                trace.Append(CultureInfo.InvariantCulture, $"swap@{a.Offset}<>{b.Offset};");
                return
                [
                    .. data.AsSpan(0, a.Offset),
                    .. data.AsSpan(b.Offset, b.RecordLength),
                    .. data.AsSpan(a.Offset + a.RecordLength, b.Offset - a.Offset - a.RecordLength),
                    .. data.AsSpan(a.Offset, a.RecordLength),
                    .. data.AsSpan(b.Offset + b.RecordLength),
                ];
            }

            case 12 when sections.Count > 0:
            {
                Section section = random.Pick(sections);
                uint type;
                do
                {
                    type = random.Pick(KnownFourCcs);
                }
                while (type == section.Type);

                trace.Append(CultureInfo.InvariantCulture, $"type@{section.Offset}={type:x8};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(section.Offset, 4), type);
                return copy;
            }

            default:
                return data;
        }
    }

    /// <summary>
    /// Recomputes the CRC-32C of every walkable <c>PAYL</c> and <c>PIDX</c>
    /// record whose declared layout fits.
    /// </summary>
    internal static void ResealSectionCrcs(byte[] data)
    {
        foreach (Section section in WalkSections(data))
        {
            int minimum = section.Type == CspFormat.Payload
                ? CspFormat.PaylPrefixSize + CspFormat.CrcSize
                : CspFormat.PidxPrefixSize + CspFormat.CrcSize;

            if ((section.Type != CspFormat.Payload &&
                 section.Type != CspFormat.PayloadIndex) ||
                section.PayloadLength < minimum)
            {
                continue;
            }

            int crcOffset = section.Offset + section.RecordLength - CspFormat.CrcSize;
            uint crc = Crc32C.Compute(data.AsSpan(section.Offset, crcOffset - section.Offset));
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(crcOffset, CspFormat.CrcSize), crc);
        }
    }

    /// <summary>
    /// Rewrites TRAILER.FileDigest over every byte before the TRAILER, using
    /// the SHA-256 suite the corpus patches declare (the independent decoder
    /// cannot compute BLAKE3).
    /// </summary>
    internal static void ResealFileDigest(byte[] data)
    {
        if (data.Length < CspFormat.PreambleSize + CspFormat.TrailerSize)
        {
            return;
        }

        int trailerOffset = data.Length - CspFormat.TrailerSize;
        Hash256 digest = PatchHashing.Hash(HashSuiteIds.Sha256V1, data.AsSpan(0, trailerOffset));
        digest.CopyTo(data.AsSpan(trailerOffset + 24, CspFormat.HashSize));
    }

    /// <summary>
    /// Walks section headers from the end of PREAMBLE while they fit, stopping
    /// before the fixed TRAILER. Never throws on malformed input.
    /// </summary>
    internal static List<Section> WalkSections(byte[] data)
    {
        var sections = new List<Section>();
        int offset = CspFormat.PreambleSize;
        int end = data.Length - CspFormat.TrailerSize;

        while (offset >= 0 && offset + CspFormat.SectionHeaderSize <= end)
        {
            ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 8, 8));
            if (payloadLength > (ulong)(end - offset - CspFormat.SectionHeaderSize))
            {
                break;
            }

            uint type = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
            sections.Add(new Section(offset, type, (int)payloadLength));
            offset += CspFormat.SectionHeaderSize + (int)payloadLength;
        }

        return sections;
    }

    /// <summary>
    /// Collects the field offsets the applier interprets: every section header
    /// and, inside the fixed layouts, the PAYL, PIDX and FOOT fields.
    /// </summary>
    private static List<Field> FindFields(byte[] data, List<Section> sections)
    {
        var fields = new List<Field>();

        foreach (Section section in sections)
        {
            fields.Add(new Field(section.Offset, 4));
            fields.Add(new Field(section.Offset + 4, 4));
            fields.Add(new Field(section.Offset + 8, 8));

            if (section.Type == CspFormat.Payload)
            {
                AddPaylFields(data, section, fields);
            }
            else if (section.Type == CspFormat.PayloadIndex)
            {
                AddPidxFields(section, fields);
            }
            else if (section.Type == CspFormat.Footer &&
                section.PayloadLength >= CspFormat.FootPayloadSize)
            {
                for (int offset = 0; offset < CspFormat.FootPayloadSize; offset += 8)
                {
                    fields.Add(new Field(section.PayloadOffset + offset, 8));
                }
            }
        }

        return fields;
    }

    private static void AddPaylFields(byte[] data, Section section, List<Field> fields)
    {
        if (section.PayloadLength < CspFormat.PaylPrefixSize + CspFormat.CrcSize)
        {
            return;
        }

        int start = section.PayloadOffset;
        fields.Add(new Field(start, 4));
        fields.Add(new Field(start + 4, 4));
        fields.Add(new Field(start + 8, 8));

        int end = section.PayloadOffset + section.PayloadLength - CspFormat.CrcSize;
        int position = start + CspFormat.PaylPrefixSize;

        while (position + CspFormat.PaylEntryHeaderSize <= end)
        {
            fields.Add(new Field(position + 32, 4));
            fields.Add(new Field(position + 36, 1));
            fields.Add(new Field(position + 37, 1));
            fields.Add(new Field(position + 38, 2));

            uint storedLength = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(position + 32, 4));
            byte dictionaryCount = data[position + 37];
            long body = CspFormat.PaylEntryHeaderSize
                + ((long)dictionaryCount * CspFormat.DictionaryReferenceSize)
                + storedLength;

            if (body <= 0 || position + body > end)
            {
                break;
            }

            position += (int)body;
        }
    }

    private static void AddPidxFields(Section section, List<Field> fields)
    {
        if (section.PayloadLength < CspFormat.PidxPrefixSize + CspFormat.CrcSize)
        {
            return;
        }

        int start = section.PayloadOffset;
        fields.Add(new Field(start, 4));
        fields.Add(new Field(start + 4, 4));

        int end = section.PayloadOffset + section.PayloadLength - CspFormat.CrcSize;
        int position = start + CspFormat.PidxPrefixSize;

        while (position + CspFormat.PidxEntrySize <= end)
        {
            fields.Add(new Field(position, 8));
            fields.Add(new Field(position + 8, 8));
            fields.Add(new Field(position + 16, 4));
            fields.Add(new Field(position + 20, 1));
            fields.Add(new Field(position + 21, 1));
            fields.Add(new Field(position + 22, 2));
            position += CspFormat.PidxEntrySize;
        }
    }

    /// <summary>
    /// Interesting values for one walked field: the shared list plus the
    /// field's current value, its neighbours and the patch length.
    /// </summary>
    private static ulong[] FieldValues(byte[] data, Field field)
    {
        ulong current = ReadLittleEndian(data, field.Offset, field.Size);

        return
        [
            .. InterestingUInt64,
            current == 0 ? 0UL : current - 1,
            current + 1,
            (ulong)Math.Max(0, data.Length - 1),
            (ulong)data.Length,
            (ulong)data.Length + 1,
        ];
    }

    private static ulong ReadLittleEndian(byte[] data, int offset, int size) => size switch
    {
        1 => data[offset],
        2 => BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset, 2)),
        4 => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4)),
        _ => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8)),
    };

    private static void WriteLittleEndian(byte[] data, int offset, int size, ulong value)
    {
        switch (size)
        {
            case 1:
                data[offset] = (byte)value;
                break;
            case 2:
                BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset, 2), (ushort)value);
                break;
            case 4:
                BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset, 4), (uint)value);
                break;
            default:
                BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(offset, 8), value);
                break;
        }
    }

    internal readonly record struct Section(int Offset, uint Type, int PayloadLength)
    {
        internal int PayloadOffset => Offset + CspFormat.SectionHeaderSize;

        internal int RecordLength => CspFormat.SectionHeaderSize + PayloadLength;
    }

    /// <summary>One writable field: an offset and its width in bytes.</summary>
    private readonly record struct Field(int Offset, int Size);
}
