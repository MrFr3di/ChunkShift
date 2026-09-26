using System;
using System.Diagnostics;

namespace ChunkShift.Primitives;

/// <summary>
/// Identifies the exact uncompressed bytes of one content chunk.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public readonly struct ChunkId : IEquatable<ChunkId>
{
    /// <summary>
    /// Gets the 256-bit digest value.
    /// </summary>
    public Hash256 Value { get; }

    /// <summary>
    /// Creates a chunk identity from a 256-bit digest.
    /// </summary>
    public ChunkId(Hash256 value)
    {
        Value = value;
    }

    /// <inheritdoc />
    public bool Equals(ChunkId other) => Value.Equals(other.Value);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ChunkId other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode();

    /// <inheritdoc />
    public override string ToString() => Value.ToHexLower();

    /// <summary>
    /// Equality comparison operator.
    /// </summary>
    public static bool operator ==(ChunkId left, ChunkId right) => left.Equals(right);

    /// <summary>
    /// Inequality comparison operator.
    /// </summary>
    public static bool operator !=(ChunkId left, ChunkId right) => !left.Equals(right);
}
