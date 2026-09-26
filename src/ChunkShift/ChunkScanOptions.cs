using ChunkShift.Primitives;

namespace ChunkShift;

/// <summary>
/// Selects semantic chunking and hashing behavior for a raw content scan.
/// </summary>
/// <remarks>
/// Physical tuning such as buffer sizes, pooling, SIMD backends, prefetch depth,
/// worker counts, and pipeline implementation are intentionally not public options.
/// </remarks>
public sealed class ChunkScanOptions
{
    /// <summary>
    /// Gets the chunking profile to use.
    /// </summary>
    /// <remarks>
    /// A <see langword="null"/> value selects the current pre-release default.
    /// The default will be frozen before the first public compatibility release.
    /// </remarks>
    public ChunkingProfileId? ProfileId { get; init; }

    /// <summary>
    /// Gets the hash suite used to create each <see cref="ChunkInfo.Id"/>.
    /// </summary>
    /// <remarks>
    /// A <see langword="null"/> value selects <see cref="HashSuiteIds.Default"/>.
    /// </remarks>
    public HashSuiteId? HashSuite { get; init; }
}
