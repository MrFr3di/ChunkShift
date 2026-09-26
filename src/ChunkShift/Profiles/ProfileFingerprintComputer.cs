using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using ChunkShift.Primitives;

namespace ChunkShift.Profiles;

/// <summary>
/// Computes a profile fingerprint from canonical semantic parameters rather than authoring-artifact bytes.
/// </summary>
internal static class ProfileFingerprintComputer
{
    internal const int MaxNumericTokenChars = 128;
    internal const int MaxCanonicalIntegerDigits = 128;
    internal const int MaxExponentMagnitude = 1024;

    private static ReadOnlySpan<byte> Domain => "chunkshift.profile-fingerprint.v1\0"u8;

    public static ProfileFingerprint Compute(ReadOnlySpan<byte> profileArtifactUtf8)
    {
        using var document = JsonDocument.Parse(profileArtifactUtf8.ToArray());

        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("semantics", out var semantics) ||
            semantics.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("Profile artifact must contain a top-level 'semantics' object.");
        }

        var writer = new ArrayBufferWriter<byte>();
        WriteBytes(writer, Domain);
        WriteElement(writer, semantics);

        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(writer.WrittenSpan, digest);
        return new ProfileFingerprint(Hash256.FromBytes(digest));
    }

    private static void WriteElement(ArrayBufferWriter<byte> writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Null:
                WriteByte(writer, 0x00);
                return;

            case JsonValueKind.False:
                WriteByte(writer, 0x01);
                return;

            case JsonValueKind.True:
                WriteByte(writer, 0x02);
                return;

            case JsonValueKind.Number:
                WriteByte(writer, 0x03);
                WriteString(writer, CanonicalizeInteger(element));
                return;

            case JsonValueKind.String:
                WriteByte(writer, 0x04);
                WriteString(writer, element.GetString() ?? string.Empty);
                return;

            case JsonValueKind.Array:
                WriteByte(writer, 0x05);
                WriteArray(writer, element);
                return;

            case JsonValueKind.Object:
                WriteByte(writer, 0x06);
                WriteObject(writer, element);
                return;

            default:
                throw new FormatException($"Unsupported JSON value kind '{element.ValueKind}'.");
        }
    }

    private static void WriteArray(ArrayBufferWriter<byte> writer, JsonElement element)
    {
        var items = element.EnumerateArray().ToArray();
        WriteUInt32(writer, checked((uint)items.Length));

        foreach (var item in items)
        {
            WriteElement(writer, item);
        }
    }

    private static void WriteObject(ArrayBufferWriter<byte> writer, JsonElement element)
    {
        var properties = element.EnumerateObject().ToArray();
        Array.Sort(properties, static (left, right) => StringComparer.Ordinal.Compare(left.Name, right.Name));

        for (int i = 1; i < properties.Length; i++)
        {
            if (string.Equals(properties[i - 1].Name, properties[i].Name, StringComparison.Ordinal))
            {
                throw new FormatException($"Duplicate semantic property '{properties[i].Name}'.");
            }
        }

        WriteUInt32(writer, checked((uint)properties.Length));

        foreach (var property in properties)
        {
            WriteString(writer, property.Name);
            WriteElement(writer, property.Value);
        }
    }

    private static string CanonicalizeInteger(JsonElement element)
    {
        string raw = element.GetRawText();

        if (raw.Length == 0 || raw.Length > MaxNumericTokenChars)
        {
            throw InvalidSemanticNumber(raw, $"token length must be 1..{MaxNumericTokenChars} characters");
        }

        ReadOnlySpan<char> token = raw.AsSpan();
        int index = 0;
        bool negative = token[index] == '-';

        if (negative)
        {
            index++;
        }

        int integerStart = index;
        while (index < token.Length && IsAsciiDigit(token[index]))
        {
            index++;
        }

        int integerLength = index - integerStart;
        if (integerLength == 0)
        {
            throw InvalidSemanticNumber(raw, "missing integer digits");
        }

        int fractionStart = index;
        int fractionLength = 0;

        if (index < token.Length && token[index] == '.')
        {
            index++;
            fractionStart = index;

            while (index < token.Length && IsAsciiDigit(token[index]))
            {
                index++;
            }

            fractionLength = index - fractionStart;
            if (fractionLength == 0)
            {
                throw InvalidSemanticNumber(raw, "missing fractional digits");
            }
        }

        int exponent = 0;
        if (index < token.Length && (token[index] == 'e' || token[index] == 'E'))
        {
            index++;
            bool exponentNegative = false;

            if (index < token.Length && (token[index] == '+' || token[index] == '-'))
            {
                exponentNegative = token[index] == '-';
                index++;
            }

            int exponentStart = index;
            int magnitude = 0;

            while (index < token.Length && IsAsciiDigit(token[index]))
            {
                int digit = token[index] - '0';
                if (magnitude > ((MaxExponentMagnitude - digit) / 10))
                {
                    throw InvalidSemanticNumber(raw, $"exponent magnitude must be <= {MaxExponentMagnitude}");
                }

                magnitude = (magnitude * 10) + digit;
                index++;
            }

            if (index == exponentStart)
            {
                throw InvalidSemanticNumber(raw, "missing exponent digits");
            }

            exponent = exponentNegative ? -magnitude : magnitude;
        }

        if (index != token.Length)
        {
            throw InvalidSemanticNumber(raw, "unsupported numeric syntax");
        }

        int digitCount = checked(integerLength + fractionLength);
        Span<char> digits = digitCount <= 256
            ? stackalloc char[digitCount]
            : throw InvalidSemanticNumber(raw, "numeric token is too large");

        token.Slice(integerStart, integerLength).CopyTo(digits);
        if (fractionLength != 0)
        {
            token.Slice(fractionStart, fractionLength).CopyTo(digits.Slice(integerLength));
        }

        if (IsAllZero(digits))
        {
            return "0";
        }

        int scale = checked(fractionLength - exponent);
        int significantLength = digitCount;

        if (scale > 0)
        {
            if (scale > digitCount)
            {
                throw InvalidSemanticNumber(raw, "value is fractional");
            }

            ReadOnlySpan<char> fractionalTail = digits.Slice(digitCount - scale, scale);
            if (!IsAllZero(fractionalTail))
            {
                throw InvalidSemanticNumber(raw, "value is fractional");
            }

            significantLength -= scale;
        }

        int leadingZeros = 0;
        while (leadingZeros < significantLength && digits[leadingZeros] == '0')
        {
            leadingZeros++;
        }

        int coreDigits = significantLength - leadingZeros;
        int appendedZeros = scale < 0 ? -scale : 0;
        int canonicalDigits = checked(coreDigits + appendedZeros);

        if (canonicalDigits <= 0)
        {
            return "0";
        }

        if (canonicalDigits > MaxCanonicalIntegerDigits)
        {
            throw InvalidSemanticNumber(
                raw,
                $"canonical integer must contain at most {MaxCanonicalIntegerDigits} digits");
        }

        string core = digits.Slice(leadingZeros, coreDigits).ToString();
        string canonical = appendedZeros == 0
            ? core
            : string.Concat(core, new string('0', appendedZeros));

        return negative ? string.Concat("-", canonical) : canonical;
    }

    private static bool IsAsciiDigit(char value) => (uint)(value - '0') <= 9;

    private static bool IsAllZero(ReadOnlySpan<char> value)
    {
        foreach (char digit in value)
        {
            if (digit != '0')
            {
                return false;
            }
        }

        return true;
    }

    private static FormatException InvalidSemanticNumber(string raw, string reason)
    {
        return new FormatException($"Profile semantic number '{raw}' is invalid: {reason}.");
    }

    private static void WriteString(ArrayBufferWriter<byte> writer, string value)
    {
        int byteCount = Encoding.UTF8.GetByteCount(value);
        WriteUInt32(writer, checked((uint)byteCount));

        Span<byte> destination = writer.GetSpan(byteCount);
        int written = Encoding.UTF8.GetBytes(value.AsSpan(), destination);
        writer.Advance(written);
    }

    private static void WriteUInt32(ArrayBufferWriter<byte> writer, uint value)
    {
        Span<byte> destination = writer.GetSpan(sizeof(uint));
        BinaryPrimitives.WriteUInt32LittleEndian(destination, value);
        writer.Advance(sizeof(uint));
    }

    private static void WriteByte(ArrayBufferWriter<byte> writer, byte value)
    {
        Span<byte> destination = writer.GetSpan(1);
        destination[0] = value;
        writer.Advance(1);
    }

    private static void WriteBytes(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }
}
