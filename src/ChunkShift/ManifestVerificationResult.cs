namespace ChunkShift;

/// <summary>
/// Reports CSM verification without turning integrity mismatches into exceptions.
/// </summary>
public sealed class ManifestVerificationResult
{
    internal ManifestVerificationResult(
        ManifestInfo manifest,
        ManifestVerificationFailure failures)
    {
        Manifest = manifest;
        Failures = failures;
    }

    /// <summary>Gets the parsed manifest information.</summary>
    public ManifestInfo Manifest { get; }

    /// <summary>Gets all detected integrity mismatches.</summary>
    public ManifestVerificationFailure Failures { get; }

    /// <summary>Gets whether no integrity mismatch was detected.</summary>
    public bool IsValid => Failures == ManifestVerificationFailure.None;
}
