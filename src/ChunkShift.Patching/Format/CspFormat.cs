namespace ChunkShift.Patching.Format;

/// <summary>
/// Fixed CSP v1 sizes, FourCC section types and byte-level constants
/// (docs/architecture/CSP-V1.md sections 4 and 8).
/// </summary>
internal static class CspFormat
{
    internal const ushort FormatMajor = 1;
    internal const ushort PreambleSize = 32;
    internal const int SectionHeaderSize = 16;
    internal const ushort TrailerSize = 64;
    internal const int HashSize = 32;
    internal const int CrcSize = 4;

    internal const int BasePayloadSize = 32;
    internal const int PaylPrefixSize = 16;
    internal const int PaylEntryHeaderSize = 40;
    internal const int DictionaryReferenceSize = 32;
    internal const uint MaximumEntriesPerPayl = 4096;
    internal const int MaximumDictionaryCount = 4;

    internal const int PidxPrefixSize = 8;
    internal const int PidxEntrySize = 24;
    internal const uint IndexVersion = 1;

    internal const int FootPayloadSize = 56;

    internal const uint RequiredSectionFlag = 1;
    internal const uint KnownSectionFlags = RequiredSectionFlag;

    internal const byte EncodingRaw = 0;
    internal const byte EncodingZstd = 1;

    // CSP-V1 section 8 operational default, not a persisted limit.
    internal const int DefaultMaximumPayloadEntries = 1_048_576;

    internal static ReadOnlySpan<byte> PreambleMagic => "CSP1"u8;
    internal static ReadOnlySpan<byte> TrailerMagic => "CSPT"u8;
    internal static ReadOnlySpan<byte> ZstdDictionaryMagic => [0x37, 0xA4, 0x30, 0xEC];

    internal static uint FourCc(ReadOnlySpan<byte> value)
    {
        if (value.Length != 4)
        {
            throw new ArgumentException("FourCC requires exactly four bytes.", nameof(value));
        }

        return (uint)value[0]
            | ((uint)value[1] << 8)
            | ((uint)value[2] << 16)
            | ((uint)value[3] << 24);
    }

    internal static readonly uint TargetManifest = FourCc("TCSM"u8);
    internal static readonly uint Base = FourCc("BASE"u8);
    internal static readonly uint Payload = FourCc("PAYL"u8);
    internal static readonly uint Aux0 = FourCc("AUX0"u8);
    internal static readonly uint PayloadIndex = FourCc("PIDX"u8);
    internal static readonly uint Footer = FourCc("FOOT"u8);
}
