using ChunkShift.Primitives;

namespace ChunkShift;

/// <summary>
/// Describes one CSM manifest representation and its logical identity.
/// </summary>
public sealed class ManifestInfo
{
    internal ManifestInfo(
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint profileFingerprint,
        ManifestId manifestId,
        Hash256 fileDigest,
        long chunkCount,
        long contentLength,
        long physicalLength,
        long chunkBlockCount,
        bool hasBlockIndex)
    {
        HashSuite = hashSuite;
        ProfileId = profileId;
        ProfileFingerprint = profileFingerprint;
        ManifestId = manifestId;
        FileDigest = fileDigest;
        ChunkCount = chunkCount;
        ContentLength = contentLength;
        PhysicalLength = physicalLength;
        ChunkBlockCount = chunkBlockCount;
        HasBlockIndex = hasBlockIndex;
    }

    /// <summary>Gets the hash suite declared by the manifest.</summary>
    public HashSuiteId HashSuite { get; }

    /// <summary>Gets the chunking profile identifier declared by the manifest.</summary>
    public ChunkingProfileId ProfileId { get; }

    /// <summary>Gets the semantic fingerprint of the declared chunking profile.</summary>
    public ProfileFingerprint ProfileFingerprint { get; }

    /// <summary>Gets the logical manifest identity.</summary>
    public ManifestId ManifestId { get; }

    /// <summary>
    /// Gets the digest of the exact physical CSM bytes preceding the trailer.
    /// </summary>
    public Hash256 FileDigest { get; }

    /// <summary>Gets the number of logical chunk entries.</summary>
    public long ChunkCount { get; }

    /// <summary>Gets the total logical content length in bytes.</summary>
    public long ContentLength { get; }

    /// <summary>Gets the complete physical CSM length in bytes.</summary>
    public long PhysicalLength { get; }

    /// <summary>Gets the number of physical CBLK sections.</summary>
    public long ChunkBlockCount { get; }

    /// <summary>Gets whether this representation contains BIDX.</summary>
    public bool HasBlockIndex { get; }
}
