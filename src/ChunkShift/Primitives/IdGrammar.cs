using System;

namespace ChunkShift.Primitives;

/// <summary>
/// Internal grammar rules for all ChunkShift identifier types.
/// IDs must be ASCII lowercase, start with a-z or 0-9, contain only [a-z0-9._-], max 128 chars.
/// </summary>
internal static class IdGrammar
{
    /// <summary>
    /// Maximum length of a ChunkShift identifier.
    /// </summary>
    public const int MaxLength = 128;

    /// <summary>
    /// Returns true if the value satisfies the ChunkShift ID grammar.
    /// Does not allocate.
    /// </summary>
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty || value.Length > MaxLength)
        {
            return false;
        }

        // First character must be a-z or 0-9.
        if (!IsLowerAsciiLetterOrDigit(value[0]))
        {
            return false;
        }

        // Remaining characters: a-z, 0-9, dot, dash, underscore.
        for (int i = 0; i < value.Length; i++)
        {
            if (!IsValidChar(value[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Validates that the value satisfies the ChunkShift ID grammar.
    /// Throws <see cref="ArgumentException"/> if invalid.
    /// </summary>
    /// <param name="value">The string value to validate.</param>
    /// <param name="parameterName">The name of the parameter being validated, included in the exception message.</param>
    /// <exception cref="ArgumentException">Thrown when value is null, empty, or does not satisfy the ID grammar.</exception>
    public static void Validate(string? value, string parameterName)
    {
        if (value is null || !IsValid(value.AsSpan()))
        {
            throw new ArgumentException(
                $"Invalid ID value. Must be ASCII lowercase, start with a letter or digit, contain only [a-z0-9._-], and be at most {MaxLength} characters. Actual value: '{value ?? "<null>"}'.",
                parameterName);
        }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private static bool IsLowerAsciiLetterOrDigit(char c)
    {
        return (uint)(c - 'a') <= 25 || (uint)(c - '0') <= 9;
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private static bool IsValidChar(char c)
    {
        return (uint)(c - 'a') <= 25 || (uint)(c - '0') <= 9 || c == '.' || c == '-' || c == '_';
    }
}