namespace ChunkShift.Primitives;

/// <summary>
/// Known stable hash-suite identifiers.
/// </summary>
public static class HashSuiteIds
{
    /// <summary>
    /// BLAKE3 with the standard 256-bit output. This is the default ChunkShift suite.
    /// </summary>
    public static readonly HashSuiteId Blake3256V1 = new("chunkshift.blake3-256.v1");

    /// <summary>
    /// SHA-256 compatibility/compliance suite.
    /// </summary>
    public static readonly HashSuiteId Sha256V1 = new("chunkshift.sha256.v1");

    /// <summary>
    /// The default hash suite used when product policy does not explicitly select another suite.
    /// </summary>
    public static readonly HashSuiteId Default = Blake3256V1;
}
