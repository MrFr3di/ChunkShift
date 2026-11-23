using System.Security.Cryptography;
using Blake3;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Hashing;

/// <summary>
/// Hash-suite dispatch for the two registered suites, used for CSP physical
/// digests and payload verification. Patching cannot reach Core's internal
/// hashers, and it never computes a ManifestId.
/// </summary>
internal static class PatchHashing
{
    internal static bool IsSupported(HashSuiteId hashSuite)
    {
        ArgumentNullException.ThrowIfNull(hashSuite);

        return hashSuite == HashSuiteIds.Blake3256V1
            || hashSuite == HashSuiteIds.Sha256V1;
    }

    internal static Hash256 Hash(HashSuiteId hashSuite, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(hashSuite);

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

    internal static IncrementalPatchHash CreateIncremental(HashSuiteId hashSuite)
    {
        ArgumentNullException.ThrowIfNull(hashSuite);

        return new IncrementalPatchHash(hashSuite);
    }
}

internal sealed class IncrementalPatchHash : IDisposable
{
    private readonly Hasher? _blake3;
    private readonly IncrementalHash? _sha256;
    private bool _finalized;
    private bool _disposed;

    internal IncrementalPatchHash(HashSuiteId hashSuite)
    {
        if (hashSuite == HashSuiteIds.Blake3256V1)
        {
            _blake3 = Hasher.New();
            return;
        }

        if (hashSuite == HashSuiteIds.Sha256V1)
        {
            _sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            return;
        }

        throw new NotSupportedException($"Unsupported HashSuiteId '{hashSuite}'.");
    }

    internal void Append(ReadOnlySpan<byte> data)
    {
        ThrowIfUnavailable();

        if (_blake3 is not null)
        {
            _blake3.Update(data);
            return;
        }

        _sha256!.AppendData(data);
    }

    internal Hash256 FinalizeHash()
    {
        ThrowIfUnavailable();
        _finalized = true;

        if (_blake3 is not null)
        {
            var digest = _blake3.Finalize();
            return Hash256.FromBytes(digest.AsSpan());
        }

        Span<byte> digestBytes = stackalloc byte[32];
        if (!_sha256!.TryGetHashAndReset(digestBytes, out int written) ||
            written != digestBytes.Length)
        {
            throw new CryptographicException("SHA-256 incremental finalization failed.");
        }

        return Hash256.FromBytes(digestBytes);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _blake3?.Dispose();
        _sha256?.Dispose();
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_finalized)
        {
            throw new InvalidOperationException("Hash state has already been finalized.");
        }
    }
}
