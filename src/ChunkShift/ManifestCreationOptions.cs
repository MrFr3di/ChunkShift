using ChunkShift.Primitives;

namespace ChunkShift;

/// <summary>
/// Selects semantic and physical options for CSM manifest creation.
/// </summary>
public sealed class ManifestCreationOptions
{
    /// <summary>
    /// Gets the chunking profile to persist in the manifest.
    /// When omitted, ChunkShift uses its current pre-release default candidate.
    /// </summary>
    public ChunkingProfileId? ProfileId { get; init; }

    /// <summary>
    /// Gets the hash suite used for ChunkId, ManifestId, and physical FileDigest.
    /// When omitted, ChunkShift uses <see cref="HashSuiteIds.Default"/>.
    /// </summary>
    public HashSuiteId? HashSuite { get; init; }

    /// <summary>
    /// Gets whether to append the optional physical block index.
    /// This option never changes logical ManifestId.
    /// </summary>
    public bool IncludeBlockIndex { get; init; }
}
