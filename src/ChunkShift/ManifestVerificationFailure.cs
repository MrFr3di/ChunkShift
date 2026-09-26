namespace ChunkShift;

/// <summary>
/// Identifies non-exceptional integrity mismatches found while verifying CSM.
/// </summary>
[Flags]
public enum ManifestVerificationFailure
{
    /// <summary>No verification mismatch was found.</summary>
    None = 0,

    /// <summary>At least one CBLK CRC-32C did not match.</summary>
    BlockCrc = 1 << 0,

    /// <summary>CEND totals did not match the streamed logical entries.</summary>
    LogicalTotals = 1 << 1,

    /// <summary>The stored ManifestId did not match the recomputed identity.</summary>
    ManifestId = 1 << 2,

    /// <summary>The stored physical FileDigest did not match the CSM bytes.</summary>
    FileDigest = 1 << 3,

    /// <summary>
    /// The declared ProfileId is known to this build, but the ProfileFingerprint
    /// recorded next to it differs from the fingerprint of that profile's semantics.
    /// </summary>
    /// <remarks>
    /// Reported by manifest-only and content verification alike. An unknown ProfileId
    /// is not this failure: manifest-only verification accepts it, and content
    /// verification throws <see cref="NotSupportedException"/> because it cannot chunk
    /// with semantics it does not have. When this flag is set, content verification
    /// does not chunk the content and does not report <see cref="Content"/>.
    /// </remarks>
    ProfileSemantics = 1 << 4,

    /// <summary>
    /// The supplied content matches neither the stored ManifestId nor the identity
    /// recomputed from the manifest's chunk entries.
    /// </summary>
    /// <remarks>
    /// When only the stored ManifestId is damaged and the content matches the
    /// chunk entries, the result reports <see cref="ManifestId"/> without this flag.
    /// </remarks>
    Content = 1 << 5,
}
