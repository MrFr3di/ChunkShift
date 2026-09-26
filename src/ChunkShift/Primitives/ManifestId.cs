using System;
using System.Diagnostics;

namespace ChunkShift.Primitives;

/// <summary>
/// Identifies the logical manifest content independently of its physical encoding.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public readonly struct ManifestId : IEquatable<ManifestId>
{
    /// <summary>
    /// Gets the 256-bit digest value.
    /// </summary>
    public Hash256 Value { get; }

    /// <summary>
    /// Creates a logical manifest identity from a 256-bit digest.
    /// </summary>
    public ManifestId(Hash256 value)
    {
        Value = value;
    }

    /// <inheritdoc />
    public bool Equals(ManifestId other) => Value.Equals(other.Value);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ManifestId other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode();

    /// <inheritdoc />
    public override string ToString() => Value.ToHexLower();

    /// <summary>
    /// Equality comparison operator.
    /// </summary>
    public static bool operator ==(ManifestId left, ManifestId right) => left.Equals(right);

    /// <summary>
    /// Inequality comparison operator.
    /// </summary>
    public static bool operator !=(ManifestId left, ManifestId right) => !left.Equals(right);
}
