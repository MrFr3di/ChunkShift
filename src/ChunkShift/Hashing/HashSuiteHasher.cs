using System;
using System.Security.Cryptography;
using Blake3;
using ChunkShift.Primitives;

namespace ChunkShift.Hashing;

/// <summary>
/// Reference hash-suite dispatch for one-shot hashing of complete inputs.
/// </summary>
internal static class HashSuiteHasher
{
    public static Hash256 Hash(HashSuiteId hashSuite, ReadOnlySpan<byte> data)
    {
        if (hashSuite == HashSuiteIds.Blake3256V1)
        {
            var digest = Hasher.Hash(data);
            return Hash256.FromBytes(digest.AsSpan());
        }

        if (hashSuite == HashSuiteIds.Sha256V1)
        {
            Span<byte> digest = stackalloc byte[32];
            _ = SHA256.HashData(data, digest);
            return Hash256.FromBytes(digest);
        }

        throw new NotSupportedException($"Unsupported HashSuiteId '{hashSuite}'.");
    }
}
