using ChunkShift.Chunking;
using ChunkShift.Primitives;

namespace ChunkShift.Manifest;

internal static class CsmWriter
{
    internal static async Task<CsmWriteResult> CreateAsync(
        Stream source,
        Stream destination,
        ChunkScanOptions? options = null,
        bool includeBlockIndex = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(destination);

        if (ReferenceEquals(source, destination))
        {
            throw new ArgumentException(
                "CSM source and destination must be distinct Stream instances.",
                nameof(destination));
        }

        if (!source.CanRead)
        {
            throw new ArgumentException(
                "CSM source stream must be readable.",
                nameof(source));
        }

        ChunkScanConfiguration.ProfileRegistration registration =
            ChunkScanConfiguration.ResolveProfileRegistration(
                options?.ProfileId);
        HashSuiteId hashSuite =
            ChunkScanConfiguration.ResolveHashSuite(
                options?.HashSuite);

        using CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                destination,
                hashSuite,
                registration.Id,
                registration.Fingerprint,
                includeBlockIndex,
                cancellationToken).ConfigureAwait(false);

        await ChunkingKernel.ScanAsync(
            source,
            registration.KernelProfile,
            hashSuite,
            OnChunkAsync,
            cancellationToken).ConfigureAwait(false);

        return await encoder.CompleteAsync(cancellationToken)
            .ConfigureAwait(false);

        ValueTask OnChunkAsync(
            ChunkKernelChunk chunk,
            ReadOnlyMemory<byte> _,
            CancellationToken handlerCancellationToken)
        {
            if (chunk.Offset < 0 ||
                (ulong)chunk.Offset != encoder.ContentLength)
            {
                throw new InvalidOperationException(
                    "The canonical kernel emitted a non-contiguous chunk offset.");
            }

            if (chunk.Length <= 0)
            {
                throw new InvalidOperationException(
                    "The canonical kernel emitted a non-positive chunk length.");
            }

            return encoder.AppendAsync(
                chunk.Id,
                checked((uint)chunk.Length),
                handlerCancellationToken);
        }
    }
}

internal readonly record struct CsmWriteResult(
    HashSuiteId HashSuite,
    ChunkingProfileId ProfileId,
    ProfileFingerprint ProfileFingerprint,
    ManifestId ManifestId,
    Hash256 FileDigest,
    ulong ChunkCount,
    ulong ContentLength,
    ulong PhysicalLength,
    ulong ChunkBlockCount,
    bool HasBlockIndex);
