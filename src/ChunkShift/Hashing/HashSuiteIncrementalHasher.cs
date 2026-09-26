using System.Security.Cryptography;
using Blake3;
using ChunkShift.Primitives;

namespace ChunkShift.Hashing;

internal sealed class HashSuiteIncrementalHasher : IDisposable
{
    private readonly Hasher? _blake3;
    private readonly IncrementalHash? _sha256;
    private bool _finalized;
    private bool _disposed;

    private HashSuiteIncrementalHasher(HashSuiteId hashSuite)
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

    internal static HashSuiteIncrementalHasher Create(HashSuiteId hashSuite) =>
        new(hashSuite);

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
            Blake3.Hash digest = _blake3.Finalize();
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
