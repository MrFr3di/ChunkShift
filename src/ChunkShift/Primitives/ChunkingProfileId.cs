using System;
using System.Diagnostics;

namespace ChunkShift.Primitives;

/// <summary>
/// Identifies a specific chunking profile (e.g., "fastcdc.gear.chunkshift.v1.64k", "fixed.v1.64k").
/// </summary>
/// <remarks>
/// Instances are immutable and always hold a value that satisfies the ChunkShift
/// identifier grammar. Equality is ordinal. An absent selection is expressed with a
/// <see langword="null"/> reference, not with a special instance.
/// </remarks>
[DebuggerDisplay("{Value,nq}")]
public sealed class ChunkingProfileId : IEquatable<ChunkingProfileId>
{
    /// <summary>
    /// Creates a new <see cref="ChunkingProfileId"/> from a string value.
    /// </summary>
    /// <param name="value">The chunking profile identifier string. Must satisfy the ChunkShift ID grammar.</param>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="value"/> does not satisfy the ID grammar.</exception>
    public ChunkingProfileId(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        IdGrammar.Validate(value, nameof(value));
        Value = value;
    }

    /// <summary>
    /// Gets the string value of this chunking profile identifier.
    /// </summary>
    public string Value { get; }

    /// <inheritdoc />
    public bool Equals(ChunkingProfileId? other)
    {
        return other is not null
            && (ReferenceEquals(this, other)
                || string.Equals(Value, other.Value, StringComparison.Ordinal));
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return Equals(obj as ChunkingProfileId);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return StringComparer.Ordinal.GetHashCode(Value);
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return Value;
    }

    /// <summary>
    /// Equality comparison operator.
    /// </summary>
    public static bool operator ==(ChunkingProfileId? left, ChunkingProfileId? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>
    /// Inequality comparison operator.
    /// </summary>
    public static bool operator !=(ChunkingProfileId? left, ChunkingProfileId? right)
    {
        return !(left == right);
    }
}
