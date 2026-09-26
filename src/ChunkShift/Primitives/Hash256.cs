using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace ChunkShift.Primitives;

/// <summary>
/// Represents an arbitrary 256-bit value (32 bytes).
/// Every possible bit pattern is valid, including the all-zero value.
/// </summary>
[DebuggerDisplay("{ToHexLower(),nq}")]
public readonly struct Hash256 : IEquatable<Hash256>
{
    private readonly ulong _a;
    private readonly ulong _b;
    private readonly ulong _c;
    private readonly ulong _d;

    private Hash256(ulong a, ulong b, ulong c, ulong d)
    {
        _a = a;
        _b = b;
        _c = c;
        _d = d;
    }

    /// <summary>
    /// Creates a Hash256 from exactly 32 bytes.
    /// </summary>
    /// <param name="bytes">Exactly 32 bytes representing the value.</param>
    /// <returns>A new Hash256 instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="bytes"/> is not exactly 32 bytes.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Hash256 FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32)
        {
            throw new ArgumentException("Hash256 requires exactly 32 bytes.", nameof(bytes));
        }

        return new Hash256(
            BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(0, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(8, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(16, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(24, 8)));
    }

    /// <summary>
    /// Tries to parse a 64-character lowercase hexadecimal string.
    /// </summary>
    /// <param name="hex">Exactly 64 lowercase hexadecimal characters.</param>
    /// <param name="value">The parsed value, or zero when parsing fails.</param>
    /// <returns>True if parsing succeeded.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryParseHexLower(ReadOnlySpan<char> hex, out Hash256 value)
    {
        value = default;

        if (hex.Length != 64)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[32];

        for (int i = 0; i < bytes.Length; i++)
        {
            int high = HexCharToNibble(hex[i * 2]);
            int low = HexCharToNibble(hex[(i * 2) + 1]);

            if (high < 0 || low < 0)
            {
                return false;
            }

            bytes[i] = (byte)((high << 4) | low);
        }

        value = FromBytes(bytes);
        return true;
    }

    /// <summary>
    /// Copies the 32-byte value to <paramref name="destination"/>.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when the destination is smaller than 32 bytes.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void CopyTo(Span<byte> destination)
    {
        if (destination.Length < 32)
        {
            throw new ArgumentException("Destination must be at least 32 bytes.", nameof(destination));
        }

        WriteBytes(destination);
    }

    /// <summary>
    /// Tries to copy the 32-byte value to <paramref name="destination"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryCopyTo(Span<byte> destination)
    {
        if (destination.Length < 32)
        {
            return false;
        }

        WriteBytes(destination);
        return true;
    }

    /// <summary>
    /// Returns the 64-character lowercase hexadecimal representation.
    /// </summary>
    public string ToHexLower()
    {
        return string.Create(
            64,
            this,
            static (destination, value) => _ = value.TryFormatHexLower(destination));
    }

    /// <summary>
    /// Tries to format this value as 64 lowercase hexadecimal characters.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryFormatHexLower(Span<char> destination)
    {
        if (destination.Length < 64)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[32];
        WriteBytes(bytes);

        for (int i = 0; i < bytes.Length; i++)
        {
            destination[i * 2] = ToLowerHexNibble((byte)(bytes[i] >> 4));
            destination[(i * 2) + 1] = ToLowerHexNibble((byte)(bytes[i] & 0x0F));
        }

        return true;
    }

    /// <summary>
    /// Compares this value with another using normal value equality.
    /// </summary>
    public bool Equals(Hash256 other)
    {
        return _a == other._a && _b == other._b && _c == other._c && _d == other._d;
    }

    /// <summary>
    /// Compares this value with another in time that does not depend on where the
    /// values differ.
    /// </summary>
    /// <remarks>
    /// Use this when comparing a secret-derived or attacker-probed digest; ordinary
    /// equality may return at the first differing word. The comparison combines all
    /// four 64-bit words without branching and allocates nothing.
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public bool FixedTimeEquals(Hash256 other)
    {
        ulong difference =
            (_a ^ other._a)
            | (_b ^ other._b)
            | (_c ^ other._c)
            | (_d ^ other._d);

        return difference == 0;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Hash256 other && Equals(other);

    /// <inheritdoc />
    /// <remarks>
    /// Deliberately randomized per process (<see cref="HashCode"/>), so digests that an
    /// attacker can choose cannot be crafted to collide in a hash table. Never persist
    /// or compare hash codes across processes; use the 256-bit value itself.
    /// </remarks>
    public override int GetHashCode() => HashCode.Combine(_a, _b, _c, _d);

    /// <summary>
    /// Equality comparison operator.
    /// </summary>
    public static bool operator ==(Hash256 left, Hash256 right) => left.Equals(right);

    /// <summary>
    /// Inequality comparison operator.
    /// </summary>
    public static bool operator !=(Hash256 left, Hash256 right) => !left.Equals(right);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void WriteBytes(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(0, 8), _a);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8, 8), _b);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(16, 8), _c);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(24, 8), _d);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int HexCharToNibble(char value)
    {
        if ((uint)(value - '0') <= 9)
        {
            return value - '0';
        }

        if ((uint)(value - 'a') <= 5)
        {
            return value - 'a' + 10;
        }

        return -1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static char ToLowerHexNibble(byte value)
    {
        return (char)(value < 10 ? '0' + value : 'a' + value - 10);
    }
}
