namespace ChunkShift.Patching;

/// <summary>
/// Reports the chunk reuse between a base and a target CSM manifest.
/// </summary>
/// <remarks>
/// <para>
/// Returned by <see cref="ChunkPatch.PlanAsync"/>; instances are created by the
/// library, never by callers.
/// </para>
/// <para>
/// Integrity mismatches in either manifest are exposed through <see cref="Base"/>
/// and <see cref="Target"/> rather than thrown, and the counts are computed even
/// when a manifest is invalid.
/// </para>
/// <para>
/// Chunk IDs are comparable only within one hash suite, and a patch needs one
/// suite for both manifests. When they declare different hash suites the counts
/// do not describe a usable patch; compare <c>Base.Manifest.HashSuite</c> with
/// <c>Target.Manifest.HashSuite</c> before relying on them.
/// </para>
/// </remarks>
public sealed class PatchPlan
{
    internal PatchPlan(
        ManifestVerificationResult baseResult,
        ManifestVerificationResult targetResult,
        long reusedChunks,
        long reusedBytes,
        long missingChunks,
        long missingBytes,
        long uniqueMissingChunks,
        long uniqueMissingBytes)
    {
        Base = baseResult;
        Target = targetResult;
        ReusedChunks = reusedChunks;
        ReusedBytes = reusedBytes;
        MissingChunks = missingChunks;
        MissingBytes = missingBytes;
        UniqueMissingChunks = uniqueMissingChunks;
        UniqueMissingBytes = uniqueMissingBytes;
    }

    /// <summary>
    /// Gets the verification result of the base manifest.
    /// </summary>
    public ManifestVerificationResult Base { get; }

    /// <summary>
    /// Gets the verification result of the target manifest.
    /// </summary>
    public ManifestVerificationResult Target { get; }

    /// <summary>
    /// Gets whether both manifests are free of integrity mismatches.
    /// </summary>
    public bool IsValid => Base.IsValid && Target.IsValid;

    /// <summary>
    /// Gets the number of target chunk records the base manifest supplies.
    /// </summary>
    public long ReusedChunks { get; }

    /// <summary>
    /// Gets the total length in bytes of the reused target chunk records.
    /// </summary>
    public long ReusedBytes { get; }

    /// <summary>
    /// Gets the number of target chunk records the base manifest does not supply.
    /// </summary>
    public long MissingChunks { get; }

    /// <summary>
    /// Gets the total length in bytes of the missing target chunk records, counting
    /// every occurrence.
    /// </summary>
    public long MissingBytes { get; }

    /// <summary>
    /// Gets the number of distinct missing target chunk IDs.
    /// </summary>
    public long UniqueMissingChunks { get; }

    /// <summary>
    /// Gets the total length in bytes of the missing target chunks, counting one
    /// length per distinct missing chunk ID.
    /// </summary>
    /// <remarks>
    /// Repeated occurrences of the same missing chunk are counted once. This is the
    /// chunk-level payload lower bound of a patch.
    /// </remarks>
    public long UniqueMissingBytes { get; }
}
