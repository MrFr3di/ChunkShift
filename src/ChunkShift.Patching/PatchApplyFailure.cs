using ChunkShift.Primitives;

namespace ChunkShift.Patching;

/// <summary>
/// Identifies every integrity mismatch that can stop a CSP patch from being
/// applied (docs/architecture/CSP-V1.md section 7, "verification").
/// </summary>
/// <remarks>
/// <para>
/// Returned in <see cref="PatchApplyResult.Failures"/>; instances are produced
/// by the library, never by callers. The flags can be combined when one patch
/// reveals more than one mismatch.
/// </para>
/// <para>
/// A result that carries any of these flags leaves the destination path
/// untouched and no temporary file behind.
/// </para>
/// </remarks>
[Flags]
public enum PatchApplyFailure
{
    /// <summary>No integrity mismatch was found.</summary>
    None = 0,

    /// <summary>
    /// The patch TRAILER <c>FileDigest</c> does not match the patch bytes under
    /// the embedded manifest's hash suite.
    /// </summary>
    PatchFileDigest = 1 << 0,

    /// <summary>
    /// The embedded target CSM fails a CSM integrity check: a <c>CBLK</c>
    /// CRC-32C, the <c>CEND</c> logical totals, its <c>ManifestId</c> or its
    /// physical <c>FileDigest</c>.
    /// </summary>
    EmbeddedManifest = 1 << 1,

    /// <summary>
    /// The embedded target CSM declares a ProfileId this build knows, but the
    /// recorded ProfileFingerprint differs from that profile's semantics.
    /// </summary>
    ProfileSemantics = 1 << 2,

    /// <summary>More than one payload entry names the same target ChunkId.</summary>
    DuplicatePayload = 1 << 3,

    /// <summary>A payload entry names a ChunkId that is no target-manifest ChunkId.</summary>
    PayloadNotInTarget = 1 << 4,

    /// <summary>
    /// A payload entry's <c>StoredLength</c> exceeds its target chunk length, or
    /// a raw entry's <c>StoredLength</c> differs from it.
    /// </summary>
    PayloadLength = 1 << 5,

    /// <summary>
    /// The patch requires a base that was not supplied, or the supplied base
    /// manifest's <see cref="ManifestId"/> or hash suite differs from what the
    /// patch expects.
    /// </summary>
    BaseMismatch = 1 << 6,

    /// <summary>
    /// The supplied base manifest fails a CSM integrity check other than
    /// <see cref="ProfileSemantics"/>.
    /// </summary>
    BaseManifest = 1 << 7,

    /// <summary>
    /// A target chunk taken from the base does not match its <see cref="ChunkId"/>
    /// or its target chunk length.
    /// </summary>
    BaseChunk = 1 << 8,

    /// <summary>
    /// A base chunk named as dictionary content cannot be read or does not match
    /// its <see cref="ChunkId"/>, or the concatenated dictionary is unusable.
    /// </summary>
    DictionaryChunk = 1 << 9,

    /// <summary>
    /// Decoded payload bytes do not match the entry's target <see cref="ChunkId"/>
    /// or its target chunk length.
    /// </summary>
    PayloadChunk = 1 << 10,

    /// <summary>
    /// A target chunk is neither supplied by the payload nor present in the base.
    /// </summary>
    MissingPayload = 1 << 11,

    /// <summary>
    /// The total reconstructed length differs from the embedded manifest's
    /// total content length.
    /// </summary>
    ContentLength = 1 << 12,

    /// <summary>
    /// The reconstruction was re-chunked with the embedded manifest's registered
    /// profile and does not reproduce that manifest.
    /// </summary>
    ProfileContent = 1 << 13,

    /// <summary>An operational resource limit of the CSP specification was exceeded.</summary>
    ResourceLimit = 1 << 14,
}
