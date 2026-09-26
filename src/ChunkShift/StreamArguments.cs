namespace ChunkShift;

/// <summary>
/// Synchronous argument checks shared by the public stream operations, so a
/// wrong argument throws at the call site with the public parameter name.
/// </summary>
internal static class StreamArguments
{
    internal static void ThrowIfNotReadable(Stream? stream, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(stream, parameterName);

        if (!stream.CanRead)
        {
            throw new ArgumentException(
                "The stream must be readable.",
                parameterName);
        }
    }

    internal static void ThrowIfNotWritable(Stream? stream, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(stream, parameterName);

        if (!stream.CanWrite)
        {
            throw new ArgumentException(
                "The stream must be writable.",
                parameterName);
        }
    }

    internal static void ThrowIfSameInstance(
        Stream first,
        Stream second,
        string secondParameterName)
    {
        if (ReferenceEquals(first, second))
        {
            throw new ArgumentException(
                "Content and manifest roles must use distinct Stream instances.",
                secondParameterName);
        }
    }
}
