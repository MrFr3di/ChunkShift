using ChunkShift.Primitives;

namespace ChunkShift.Chunking;

internal readonly record struct ChunkKernelChunk(
    long Offset,
    int Length,
    ChunkId Id);
