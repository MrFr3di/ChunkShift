namespace ChunkShift.Patching;

/// <summary>
/// Reports the outcome of applying one CSP patch.
/// </summary>
/// <remarks>
/// <para>
/// Returned by <see cref="ChunkPatch.ApplyAsync(Stream, Stream, Stream, string, CancellationToken)"/>
/// and its self-contained overload; instances are created by the library, never
/// by callers.
/// </para>
/// <para>
/// <see cref="IsApplied"/> is <see langword="true"/> only when every check
/// passed and the verified target was published at the destination path. A
/// result that is not applied carries the integrity mismatches in
/// <see cref="Failures"/> and leaves an existing destination file unchanged.
/// </para>
/// </remarks>
public sealed class PatchApplyResult
{
    internal PatchApplyResult(PatchApplyFailure failures, ManifestInfo? target)
    {
        Failures = failures;
        Target = target;
    }

    /// <summary>
    /// Gets whether the target was verified and published at the destination
    /// path.
    /// </summary>
    public bool IsApplied => Failures == PatchApplyFailure.None;

    /// <summary>
    /// Gets every integrity mismatch that prevented publication.
    /// </summary>
    public PatchApplyFailure Failures { get; }

    /// <summary>
    /// Gets the embedded target manifest, or <see langword="null"/> when the
    /// patch was rejected before that manifest could be read.
    /// </summary>
    public ManifestInfo? Target { get; }
}
