namespace ChunkShift.Patching.Application;

/// <summary>
/// How apply runs the optional re-chunk check (CSP-V1 section 9.5). Internal: the public API always uses
/// <see cref="CspApplier.DefaultChunkingCheck"/>, and the other values exist
/// for tests.
/// </summary>
internal enum ChunkingCheck
{
    /// <summary>No re-chunk check.</summary>
    Off,

    /// <summary>
    /// After the reconstruction and the length check, re-read the temporary
    /// file and verify it against the embedded manifest.
    /// </summary>
    Sequential,

    /// <summary>
    /// Verify the reconstruction while it is written: every verified chunk is
    /// also fed, in target order, through a bounded in-memory pipe into a
    /// concurrently running verification (<see cref="OverlappedChunkingCheck"/>).
    /// </summary>
    Overlapped,

    /// <summary>
    /// For the stable Core profile, check only that the profile cuts where
    /// the records end, while the reconstruction is written
    /// (<see cref="BoundaryChunkingCheck"/>);
    /// any other profile gets the <see cref="Overlapped"/> check.
    /// </summary>
    Boundary,
}
