using ChunkShift.Primitives;

namespace ChunkShift.Patching;

/// <summary>
/// Reports the physical representation and bound identities of one created CSP
/// patch.
/// </summary>
/// <remarks>
/// <para>
/// Returned by <see cref="ChunkPatch.CreateAsync(Stream, Stream, Stream, Stream, Stream, CancellationToken)"/>
/// and its self-contained overload; instances are created by the library, never
/// by callers.
/// </para>
/// <para>
/// The stored patch bytes are a physical representation, not a contract: two
/// versions may emit different bytes for the same inputs. The reconstructed
/// target, the manifest identities and the hash suite do not change;
/// <see cref="FileDigest"/>, <see cref="PhysicalLength"/> and the payload
/// totals describe these particular bytes.
/// </para>
/// </remarks>
public sealed class PatchInfo
{
    internal PatchInfo(
        ManifestId targetManifestId,
        ManifestId? baseManifestId,
        HashSuiteId hashSuite,
        Hash256 fileDigest,
        long physicalLength,
        long payloadEntryCount,
        long payloadBytes)
    {
        TargetManifestId = targetManifestId;
        BaseManifestId = baseManifestId;
        HashSuite = hashSuite;
        FileDigest = fileDigest;
        PhysicalLength = physicalLength;
        PayloadEntryCount = payloadEntryCount;
        PayloadBytes = payloadBytes;
    }

    /// <summary>
    /// Gets the logical identity of the target manifest embedded in the patch.
    /// </summary>
    public ManifestId TargetManifestId { get; }

    /// <summary>
    /// Gets the expected base manifest's logical identity, or <see langword="null"/>
    /// when the patch is self-contained and carries no <c>BASE</c> section.
    /// </summary>
    public ManifestId? BaseManifestId { get; }

    /// <summary>
    /// Gets the hash suite the patch identities and the physical digest use.
    /// </summary>
    public HashSuiteId HashSuite { get; }

    /// <summary>
    /// Gets the patch physical digest over every byte before the TRAILER.
    /// </summary>
    public Hash256 FileDigest { get; }

    /// <summary>
    /// Gets the complete patch length in bytes, including the TRAILER.
    /// </summary>
    public long PhysicalLength { get; }

    /// <summary>
    /// Gets the number of payload entries the patch stores.
    /// </summary>
    public long PayloadEntryCount { get; }

    /// <summary>
    /// Gets the sum of every payload entry's stored byte length.
    /// </summary>
    public long PayloadBytes { get; }
}
