using System;
using System.Diagnostics;

namespace ChunkShift.Primitives;

/// <summary>
/// Identifies the canonical semantic definition of a chunking profile.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public readonly struct ProfileFingerprint : IEquatable<ProfileFingerprint>
{
    /// <summary>
    /// Gets the 256-bit digest value.
    /// </summary>
    public Hash256 Value { get; }

    /// <summary>
    /// Creates a semantic profile fingerprint from a 256-bit digest.
    /// </summary>
    public ProfileFingerprint(Hash256 value)
    {
        Value = value;
    }

    /// <inheritdoc />
    public bool Equals(ProfileFingerprint other) => Value.Equals(other.Value);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is ProfileFingerprint other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode();

    /// <inheritdoc />
    public override string ToString() => Value.ToHexLower();

    /// <summary>
    /// Equality comparison operator.
    /// </summary>
    public static bool operator ==(ProfileFingerprint left, ProfileFingerprint right) => left.Equals(right);

    /// <summary>
    /// Inequality comparison operator.
    /// </summary>
    public static bool operator !=(ProfileFingerprint left, ProfileFingerprint right) => !left.Equals(right);
}
