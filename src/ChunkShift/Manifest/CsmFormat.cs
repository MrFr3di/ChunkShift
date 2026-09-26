namespace ChunkShift.Manifest;

internal static class CsmFormat
{
    internal const ushort FormatMajor = 1;
    internal const ushort PreambleSize = 32;
    internal const int SectionHeaderSize = 16;
    internal const int CorePrefixSize = 56;
    internal const int CblkPrefixSize = 24;
    internal const int CendPayloadSize = 48;
    internal const int FootPayloadSize = 48;
    internal const ushort TrailerSize = 64;
    internal const int HashSize = 32;

    internal const int MaximumIdentifierBytes = 128;
    internal const uint MaximumCoreExtensionBytes = 65_536;
    internal const uint MaximumChunksPerBlock = 4096;

    // Operational bound for optional BIDX materialization/validation. This is
    // not a persisted format maximum. 262,144 blocks cover >1 billion chunks.
    internal const int MaximumBlockIndexEntries = 262_144;

    internal const uint RequiredSectionFlag = 1;
    internal const uint KnownSectionFlags = RequiredSectionFlag;

    internal static ReadOnlySpan<byte> PreambleMagic => "CSM1"u8;
    internal static ReadOnlySpan<byte> TrailerMagic => "CSMT"u8;

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

    internal static readonly uint Core = FourCc("CORE"u8);
    internal static readonly uint ChunkBlock = FourCc("CBLK"u8);
    internal static readonly uint ChunkEnd = FourCc("CEND"u8);
    internal static readonly uint Aux0 = FourCc("AUX0"u8);
    internal static readonly uint BlockIndex = FourCc("BIDX"u8);
    internal static readonly uint Footer = FourCc("FOOT"u8);
}
