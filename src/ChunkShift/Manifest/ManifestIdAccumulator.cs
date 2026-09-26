using System.Buffers.Binary;
using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Manifest;

internal sealed class ManifestIdAccumulator : IDisposable
{
    private static ReadOnlySpan<byte> Domain => "chunkshift.manifest-id.v1\0"u8;

    private readonly HashSuiteIncrementalHasher _hasher;
    private ulong _chunkCount;
    private ulong _contentLength;
    private bool _completed;
    private bool _disposed;

    internal ManifestIdAccumulator(
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint profileFingerprint)
    {
        ArgumentNullException.ThrowIfNull(hashSuite);
        ArgumentNullException.ThrowIfNull(profileId);

        _hasher = HashSuiteIncrementalHasher.Create(hashSuite);
        _hasher.Append(Domain);
        AppendIdentifier(hashSuite.Value);
        AppendIdentifier(profileId.Value);

        Span<byte> fingerprint = stackalloc byte[CsmFormat.HashSize];
        profileFingerprint.Value.CopyTo(fingerprint);
        _hasher.Append(fingerprint);
    }

    internal ulong ChunkCount => _chunkCount;

    internal ulong ContentLength => _contentLength;

    internal void Append(ChunkId chunkId, int length)
    {
        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                "Manifest chunk lengths must be positive.");
        }

        Append(chunkId, checked((uint)length));
    }

    internal void Append(ChunkId chunkId, uint length)
    {
        ThrowIfUnavailable();

        if (length == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                "Manifest chunk lengths must be positive.");
        }

        Span<byte> entry = stackalloc byte[CsmFormat.HashSize + sizeof(uint)];
        chunkId.Value.CopyTo(entry);
        BinaryPrimitives.WriteUInt32LittleEndian(
            entry[CsmFormat.HashSize..],
            length);

        _hasher.Append(entry);
        _chunkCount = checked(_chunkCount + 1);
        _contentLength = checked(_contentLength + length);
    }

    internal ManifestId Complete()
    {
        ThrowIfUnavailable();

        Span<byte> totals = stackalloc byte[sizeof(ulong) * 2];
        BinaryPrimitives.WriteUInt64LittleEndian(totals, _chunkCount);
        BinaryPrimitives.WriteUInt64LittleEndian(totals[sizeof(ulong)..], _contentLength);
        _hasher.Append(totals);

        _completed = true;
        return new ManifestId(_hasher.FinalizeHash());
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _hasher.Dispose();
    }

    private void AppendIdentifier(string value)
    {
        int byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount is <= 0 or > CsmFormat.MaximumIdentifierBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                $"CSM identifiers must encode to 1..{CsmFormat.MaximumIdentifierBytes} UTF-8 bytes.");
        }

        Span<byte> length = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16LittleEndian(length, checked((ushort)byteCount));
        _hasher.Append(length);

        Span<byte> bytes = stackalloc byte[byteCount];
        int written = Encoding.UTF8.GetBytes(value, bytes);
        if (written != byteCount)
        {
            throw new InvalidOperationException("UTF-8 identifier byte count changed during encoding.");
        }

        _hasher.Append(bytes);
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_completed)
        {
            throw new InvalidOperationException("Manifest identity has already been completed.");
        }
    }
}
