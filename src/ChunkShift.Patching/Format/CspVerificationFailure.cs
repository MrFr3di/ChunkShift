namespace ChunkShift.Patching.Format;

/// <summary>
/// Identifies an integrity failure that a CSP v1 patch reveals without a base
/// or a reconstruction (docs/architecture/CSP-V1.md section 7,
/// rules 17, 18 and 25; section 9.6 for profile semantics).
/// </summary>
[Flags]
internal enum CspVerificationFailure
{
    /// <summary>No integrity failure was found.</summary>
    None = 0,

    /// <summary>
    /// The TRAILER <c>FileDigest</c> does not match the bytes before the
    /// TRAILER under the embedded manifest's HashSuite (rule 25).
    /// </summary>
    FileDigest = 1 << 0,

    /// <summary>
    /// The embedded target CSM fails a CSM §14 check: a CBLK CRC-32C, the CEND
    /// logical totals, its <c>ManifestId</c> or its physical <c>FileDigest</c>
    /// (rules 14 and 25).
    /// </summary>
    EmbeddedManifest = 1 << 1,

    /// <summary>
    /// The embedded target CSM declares a ProfileId this build knows, but the
    /// recorded ProfileFingerprint differs from that profile's semantics
    /// (section 9.6).
    /// </summary>
    ProfileSemantics = 1 << 2,

    /// <summary>More than one payload entry names the same target ChunkId (rule 17).</summary>
    DuplicatePayload = 1 << 3,

    /// <summary>A payload entry names a ChunkId that is no target-manifest ChunkId (rule 17).</summary>
    PayloadNotInTarget = 1 << 4,

    /// <summary>
    /// A payload entry's <c>StoredLength</c> exceeds its target chunk length, or
    /// a raw entry's <c>StoredLength</c> differs from it (rule 18).
    /// </summary>
    PayloadLength = 1 << 5,
}
