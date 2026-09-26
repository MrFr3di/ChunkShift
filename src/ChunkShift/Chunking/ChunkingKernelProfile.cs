using System;

namespace ChunkShift.Chunking;

internal enum ChunkingKernelKind : byte
{
    Fixed = 0,
    FastCdcGearV1 = 1,
}

internal readonly struct ChunkingKernelProfile
{
    internal ChunkingKernelKind Kind { get; }
    internal int Minimum { get; }
    internal int Target { get; }
    internal int Maximum { get; }
    internal FastCdcProfile FastCdc { get; }

    private ChunkingKernelProfile(
        ChunkingKernelKind kind,
        int minimum,
        int target,
        int maximum,
        FastCdcProfile fastCdc)
    {
        Kind = kind;
        Minimum = minimum;
        Target = target;
        Maximum = maximum;
        FastCdc = fastCdc;
    }

    internal static ChunkingKernelProfile Fixed(int chunkSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(chunkSize);
        return new ChunkingKernelProfile(
            ChunkingKernelKind.Fixed,
            chunkSize,
            chunkSize,
            chunkSize,
            default);
    }

    internal static ChunkingKernelProfile FastCdcGear(FastCdcProfile profile) =>
        new(
            ChunkingKernelKind.FastCdcGearV1,
            profile.Minimum,
            profile.Target,
            profile.Maximum,
            profile);
}
