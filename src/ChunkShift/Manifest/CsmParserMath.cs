namespace ChunkShift.Manifest;

internal static class CsmParserMath
{
    internal static ulong Add(ulong left, ulong right, string field)
    {
        if (ulong.MaxValue - left < right)
        {
            throw new InvalidDataException(
                $"CSM {field} overflows UInt64.");
        }

        return left + right;
    }

    internal static int ToInt32(ulong value, string field)
    {
        if (value > int.MaxValue)
        {
            throw new InvalidDataException(
                $"CSM {field} exceeds the .NET Int32 implementation boundary.");
        }

        return (int)value;
    }

    // Public API boundary: CSM stores UInt64/UInt32, the .NET API exposes
    // Int64/Int32. A well-formed manifest whose value does not fit is valid CSM
    // this API cannot represent, so it is NotSupported rather than InvalidData.
    internal static long ToPublicInt64(ulong value, string field)
    {
        if (value > long.MaxValue)
        {
            throw new NotSupportedException(
                $"CSM {field} {value} exceeds the Int64 range of the ChunkShift .NET API.");
        }

        return (long)value;
    }

    internal static int ToPublicInt32(uint value, string field)
    {
        if (value > int.MaxValue)
        {
            throw new NotSupportedException(
                $"CSM {field} {value} exceeds the Int32 range of the ChunkShift .NET API.");
        }

        return (int)value;
    }
}
