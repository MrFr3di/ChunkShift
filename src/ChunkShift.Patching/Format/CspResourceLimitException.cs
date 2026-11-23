namespace ChunkShift.Patching.Format;

/// <summary>
/// A configured CSP operational limit was exceeded
/// (docs/architecture/CSP-V1.md section 8, rule 26): the patch holds
/// more payload entries than the reader was configured to accept.
/// </summary>
internal sealed class CspResourceLimitException : Exception
{
    /// <summary>Initializes an instance with a default message.</summary>
    public CspResourceLimitException()
    {
    }

    /// <summary>Initializes an instance with the specified message.</summary>
    /// <param name="message">Message that describes the limit that was exceeded.</param>
    public CspResourceLimitException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes an instance with the specified message and inner exception.</summary>
    /// <param name="message">Message that describes the limit that was exceeded.</param>
    /// <param name="innerException">Exception that caused this limit failure.</param>
    public CspResourceLimitException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
