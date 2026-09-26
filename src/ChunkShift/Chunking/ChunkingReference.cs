using System;
using System.Collections.Generic;
using ChunkShift.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Chunking;

internal static class ChunkingReference
{
    internal static ChunkKernelChunk[] Chunk(
        ReadOnlySpan<byte> data,
        ChunkingKernelProfile profile,
        HashSuiteId hashSuite)
    {
        if (data.IsEmpty)
        {
            return Array.Empty<ChunkKernelChunk>();
        }

        int estimated = Math.Max(1, (data.Length / Math.Max(1, profile.Target)) + 2);
        int initialCapacity = Math.Min(4096, estimated);
        var chunks = new List<ChunkKernelChunk>(initialCapacity);

        int offset = 0;
        while (offset < data.Length)
        {
            ReadOnlySpan<byte> remaining = data[offset..];
            int length = profile.Kind switch
            {
                ChunkingKernelKind.Fixed => Math.Min(profile.Target, remaining.Length),
                ChunkingKernelKind.FastCdcGearV1 => FastCdcScalar.FindCut(remaining, profile.FastCdc),
                _ => throw new InvalidOperationException($"Unsupported chunking kernel '{profile.Kind}'."),
            };

            if (length <= 0)
            {
                throw new InvalidOperationException("Chunking kernel produced a non-positive chunk length.");
            }

            Hash256 hash = HashSuiteHasher.Hash(hashSuite, remaining[..length]);
            chunks.Add(new ChunkKernelChunk(offset, length, new ChunkId(hash)));
            offset = checked(offset + length);
        }

        return chunks.ToArray();
    }
}
