using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Fuzzing;

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
/// Structure-aware mutator for CSM representations.
/// </summary>
/// <remarks>
/// Mutations mix blind byte-level edits with edits aimed at the fields the
/// reader parses (section headers, lengths, counts, offsets). After mutating,
/// the mutator can optionally re-seal CBLK CRCs and the TRAILER FileDigest so
/// that integrity checks do not stop every case before the deeper structural
/// and logical checks run.
/// </remarks>
internal static class CsmMutator
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
        24,
        28,
        31,
        32,
        47,
        48,
        49,
        55,
        56,
        57,
        63,
        64,
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
        147_484,
        262_144,
        262_145,
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

    private static readonly uint[] KnownFourCcs =
    [
        CsmFormat.Core,
        CsmFormat.ChunkBlock,
        CsmFormat.ChunkEnd,
        CsmFormat.Aux0,
        CsmFormat.BlockIndex,
        CsmFormat.Footer,
        CsmFormat.FourCc("XTRA"u8),
        CsmFormat.FourCc("CSMT"u8),
        CsmFormat.FourCc("CSM1"u8),
    ];

    internal static byte[] Mutate(
        byte[] seed,
        IReadOnlyList<byte[]> corpus,
        FuzzRandom random,
        StringBuilder trace)
    {
        byte[] data = seed;
        int rounds = random.Next(10) switch
        {
            < 7 => 1,
            < 9 => 2 + random.Next(2),
            _ => 4 + random.Next(5),
        };

        for (int round = 0; round < rounds; round++)
        {
            data = MutateOnce(data, corpus, random, trace);
        }

        // Re-sealing undoes the easy detections (CRC, FOOT/TRAILER offsets,
        // FileDigest) so that many cases reach the deeper checks behind them.
        if (random.Chance(60))
        {
            trace.Append("reseal-crc;");
            ResealBlockCrcs(data);
        }

        if (random.Chance(50))
        {
            trace.Append("reseal-layout;");
            ResealLayout(data);
        }

        if (random.Chance(80))
        {
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
        int operation = random.Next(sections.Count > 0 ? 16 : 8);

        switch (operation)
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
                byte value = random.Pick<byte>([0x00, 0x01, 0x7F, 0x80, 0xFF]);
                trace.Append(CultureInfo.InvariantCulture, $"byte@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                copy[offset] = value;
                return copy;
            }

            case 2 when data.Length >= 8:
            {
                int offset = random.Next(data.Length - 7);
                ulong value = random.Pick(InterestingUInt64);
                trace.Append(CultureInfo.InvariantCulture, $"u64@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(offset, 8), value);
                return copy;
            }

            case 3 when data.Length >= 4:
            {
                int offset = random.Next(data.Length - 3);
                uint value = (uint)random.Pick(InterestingUInt64);
                trace.Append(CultureInfo.InvariantCulture, $"u32@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(offset, 4), value);
                return copy;
            }

            case 4 when data.Length > 0:
            {
                int length = random.Next(data.Length);
                trace.Append(CultureInfo.InvariantCulture, $"truncate={length};");
                return data.AsSpan(0, length).ToArray();
            }

            case 5:
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

            case 6 when data.Length > 1:
            {
                int start = random.Next(data.Length);
                int length = 1 + random.Next(Math.Min(256, data.Length - start));
                trace.Append(CultureInfo.InvariantCulture, $"delete@{start}+{length};");
                return [.. data.AsSpan(0, start), .. data.AsSpan(start + length)];
            }

            case 7 when data.Length > 1:
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

            // Structure-aware operations below require at least one section.
            case 8:
            {
                Section section = random.Pick(sections);
                uint type = random.Pick(KnownFourCcs);
                trace.Append(CultureInfo.InvariantCulture, $"type@{section.Offset}={type:x8};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(section.Offset, 4), type);
                return copy;
            }

            case 9:
            {
                Section section = random.Pick(sections);
                uint flags = random.Pick<uint>([0, 1, 2, 3, 0x8000_0000, uint.MaxValue]);
                trace.Append(CultureInfo.InvariantCulture, $"flags@{section.Offset}={flags};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt32LittleEndian(copy.AsSpan(section.Offset + 4, 4), flags);
                return copy;
            }

            case 10:
            {
                Section section = random.Pick(sections);
                ulong length = random.Chance(50)
                    ? random.Pick(InterestingUInt64)
                    : (ulong)Math.Max(0, section.PayloadLength + random.Next(9) - 4);
                trace.Append(CultureInfo.InvariantCulture, $"length@{section.Offset}={length};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(section.Offset + 8, 8), length);
                return copy;
            }

            case 11:
            {
                // Overwrite a field inside a payload at an 8-byte aligned slot,
                // where the fixed-layout counts and offsets live.
                Section section = random.Pick(sections);
                int slots = section.PayloadLength / 8;
                if (slots == 0)
                {
                    return data;
                }

                int offset = section.PayloadOffset + (8 * random.Next(Math.Min(slots, 8)));
                ulong value = random.Pick(InterestingUInt64);
                trace.Append(CultureInfo.InvariantCulture, $"field@{offset}={value};");
                byte[] copy = (byte[])data.Clone();
                BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(offset, 8), value);
                return copy;
            }

            case 12:
            {
                Section section = random.Pick(sections);
                int insertAt = random.Pick(sections).Offset;
                trace.Append(CultureInfo.InvariantCulture, $"duplicate@{section.Offset}->{insertAt};");
                return
                [
                    .. data.AsSpan(0, insertAt),
                    .. data.AsSpan(section.Offset, section.RecordLength),
                    .. data.AsSpan(insertAt),
                ];
            }

            case 13:
            {
                Section section = random.Pick(sections);
                trace.Append(CultureInfo.InvariantCulture, $"remove@{section.Offset};");
                return
                [
                    .. data.AsSpan(0, section.Offset),
                    .. data.AsSpan(section.Offset + section.RecordLength),
                ];
            }

            case 14 when sections.Count > 1:
            {
                int first = random.Next(sections.Count - 1);
                Section a = sections[first];
                Section b = sections[first + 1];
                trace.Append(CultureInfo.InvariantCulture, $"swap@{a.Offset}<>{b.Offset};");
                return
                [
                    .. data.AsSpan(0, a.Offset),
                    .. data.AsSpan(b.Offset, b.RecordLength),
                    .. data.AsSpan(a.Offset, a.RecordLength),
                    .. data.AsSpan(b.Offset + b.RecordLength),
                ];
            }

            case 15:
            {
                Section section = random.Pick(sections);
                int insertAt = random.Chance(50) ? section.Offset : section.Offset + section.RecordLength;
                uint type = random.Pick(KnownFourCcs);
                uint flags = random.Pick<uint>([0, 1]);
                int payloadLength = random.Next(64);
                byte[] record = new byte[CsmFormat.SectionHeaderSize + payloadLength];
                BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(0, 4), type);
                BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(4, 4), flags);
                BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(8, 8), (ulong)payloadLength);
                trace.Append(CultureInfo.InvariantCulture, $"insert@{insertAt}:{type:x8}/{flags}/{payloadLength};");
                return [.. data.AsSpan(0, insertAt), .. record, .. data.AsSpan(insertAt)];
            }

            default:
                return data;
        }
    }

    /// <summary>
    /// Recomputes the CRC-32C of every walkable CBLK whose declared layout fits.
    /// </summary>
    internal static void ResealBlockCrcs(byte[] data)
    {
        foreach (Section section in WalkSections(data))
        {
            if (section.Type != CsmFormat.ChunkBlock ||
                section.PayloadLength < CsmFormat.CblkPrefixSize + sizeof(uint))
            {
                continue;
            }

            int crcOffset = section.Offset + section.RecordLength - sizeof(uint);
            uint crc = Crc32C.Compute(data.AsSpan(section.Offset, crcOffset - section.Offset));
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(crcOffset, 4), crc);
        }
    }

    /// <summary>
    /// Rewrites the FOOT offsets/count and the TRAILER FootSectionOffset and
    /// PhysicalLength from the sections actually present, when a FOOT exists.
    /// </summary>
    internal static void ResealLayout(byte[] data)
    {
        List<Section> sections = WalkSections(data);
        int footIndex = sections.FindLastIndex(section =>
            section.Type == CsmFormat.Footer &&
            section.PayloadLength == CsmFormat.FootPayloadSize);

        if (footIndex < 0 || data.Length < CsmFormat.TrailerSize)
        {
            return;
        }

        ulong coreOffset = 0;
        ulong cendOffset = 0;
        ulong bidxOffset = 0;
        ulong firstCblkOffset = 0;
        ulong cblkCount = 0;

        for (int index = 0; index < footIndex; index++)
        {
            Section section = sections[index];

            if (section.Type == CsmFormat.Core && coreOffset == 0)
            {
                coreOffset = (ulong)section.Offset;
            }
            else if (section.Type == CsmFormat.ChunkBlock)
            {
                if (cblkCount++ == 0)
                {
                    firstCblkOffset = (ulong)section.Offset;
                }
            }
            else if (section.Type == CsmFormat.ChunkEnd && cendOffset == 0)
            {
                cendOffset = (ulong)section.Offset;
            }
            else if (section.Type == CsmFormat.BlockIndex && bidxOffset == 0)
            {
                bidxOffset = (ulong)section.Offset;
            }
        }

        Section foot = sections[footIndex];
        Span<byte> payload = data.AsSpan(foot.PayloadOffset, CsmFormat.FootPayloadSize);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[0..8], coreOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[8..16], cendOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[16..24], bidxOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[24..32], firstCblkOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(payload[32..40], cblkCount);

        int trailerOffset = data.Length - CsmFormat.TrailerSize;
        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(trailerOffset + 8, 8),
            (ulong)foot.Offset);
        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(trailerOffset + 16, 8),
            (ulong)data.Length);
    }

    /// <summary>
    /// Rewrites TRAILER.FileDigest over everything before the last 64 bytes,
    /// using the HashSuite named by CORE when it is one this build knows.
    /// </summary>
    internal static void ResealFileDigest(byte[] data)
    {
        if (data.Length < CsmFormat.PreambleSize + CsmFormat.TrailerSize ||
            !TryReadHashSuite(data, out HashSuiteId? hashSuite))
        {
            return;
        }

        int trailerOffset = data.Length - CsmFormat.TrailerSize;
        Hash256 digest = HashSuiteHasher.Hash(hashSuite, data.AsSpan(0, trailerOffset));
        digest.CopyTo(data.AsSpan(trailerOffset + 24, CsmFormat.HashSize));
    }

    internal static bool TryReadHashSuite(
        byte[] data,
        [NotNullWhen(true)] out HashSuiteId? hashSuite)
    {
        hashSuite = null;
        int core = CsmFormat.PreambleSize;
        int prefix = core + CsmFormat.SectionHeaderSize;

        if (data.Length < prefix + CsmFormat.CorePrefixSize)
        {
            return false;
        }

        int suiteLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(prefix + 48, 2));
        int suiteOffset = prefix + CsmFormat.CorePrefixSize;

        if (suiteLength == 0 || suiteOffset + suiteLength > data.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> suite = data.AsSpan(suiteOffset, suiteLength);

        if (suite.SequenceEqual("chunkshift.sha256.v1"u8))
        {
            hashSuite = HashSuiteIds.Sha256V1;
            return true;
        }

        if (suite.SequenceEqual("chunkshift.blake3-256.v1"u8))
        {
            hashSuite = HashSuiteIds.Blake3256V1;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Walks section headers from the end of PREAMBLE while they fit, stopping
    /// before the fixed TRAILER. Never throws on malformed input.
    /// </summary>
    internal static List<Section> WalkSections(byte[] data)
    {
        var sections = new List<Section>();
        int offset = CsmFormat.PreambleSize;
        int end = data.Length - CsmFormat.TrailerSize;

        while (offset >= 0 && offset + CsmFormat.SectionHeaderSize <= end)
        {
            ulong payloadLength = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 8, 8));
            if (payloadLength > (ulong)(end - offset - CsmFormat.SectionHeaderSize))
            {
                break;
            }

            uint type = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
            sections.Add(new Section(offset, type, (int)payloadLength));
            offset += CsmFormat.SectionHeaderSize + (int)payloadLength;
        }

        return sections;
    }

    internal readonly record struct Section(int Offset, uint Type, int PayloadLength)
    {
        internal int PayloadOffset => Offset + CsmFormat.SectionHeaderSize;

        internal int RecordLength => CsmFormat.SectionHeaderSize + PayloadLength;
    }
}
