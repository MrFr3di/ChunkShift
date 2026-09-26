using ChunkShift.Primitives;

namespace ChunkShift;

/// <summary>
/// Describes the logical position and identity of one chunk in a content sequence.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ChunkScanner"/> emits it for every chunk of a scan, and
/// <see cref="ManifestReader"/> returns it for every entry of a CSM manifest.
/// </para>
/// <para>
/// <see cref="Index"/> and <see cref="Offset"/> are positions in that sequence only.
/// They are not part of the persisted chunk identity. For a scan, <see cref="Offset"/>
/// is relative to the first byte the scan consumed, even when the underlying seekable
/// stream started at a non-zero position; for a manifest, it is the logical content
/// offset recorded by the manifest.
/// </para>
/// </remarks>
public readonly struct ChunkInfo
{
    internal ChunkInfo(long index, long offset, int length, ChunkId id)
    {
        Index = index;
        Offset = offset;
        Length = length;
        Id = id;
    }

    /// <summary>
    /// Gets the zero-based ordinal of this chunk in the sequence.
    /// </summary>
    public long Index { get; }

    /// <summary>
    /// Gets the byte offset of this chunk from the beginning of the sequence.
    /// </summary>
    public long Offset { get; }

    /// <summary>
    /// Gets the chunk length in bytes.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the content identity of the exact chunk bytes.
    /// </summary>
    public ChunkId Id { get; }
}
