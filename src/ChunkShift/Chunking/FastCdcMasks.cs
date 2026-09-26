using System;
using System.Numerics;

namespace ChunkShift.Chunking;

internal static class FastCdcMasks
{
    private const int MinimumBits = 5;
    private const int MaximumBits = 25;

    internal static (ulong Strict, ulong Relaxed) ForTarget(int target)
    {
        if (target <= 0 || !BitOperations.IsPow2((uint)target))
        {
            throw new ArgumentOutOfRangeException(nameof(target), "FastCDC target must be a positive power of two.");
        }

        int bits = BitOperations.Log2((uint)target);
        if (bits - 1 < MinimumBits || bits + 1 > MaximumBits)
        {
            throw new ArgumentOutOfRangeException(nameof(target), "FastCDC target is outside the canonical mask table.");
        }

        return (Get(bits + 1), Get(bits - 1));
    }

    internal static ulong Get(int bits) => bits switch
    {
        5 => 0x0000000001804110UL,
        6 => 0x0000000001803110UL,
        7 => 0x0000000018035100UL,
        8 => 0x0000001800035300UL,
        9 => 0x0000019000353000UL,
        10 => 0x0000590003530000UL,
        11 => 0x0000d90003530000UL,
        12 => 0x0000d90103530000UL,
        13 => 0x0000d90303530000UL,
        14 => 0x0000d90313530000UL,
        15 => 0x0000d90f03530000UL,
        16 => 0x0000d90303537000UL,
        17 => 0x0000d90703537000UL,
        18 => 0x0000d90707537000UL,
        19 => 0x0000d91707537000UL,
        20 => 0x0000d91747537000UL,
        21 => 0x0000d91767537000UL,
        22 => 0x0000d93767537000UL,
        23 => 0x0000d93777537000UL,
        24 => 0x0000d93777577000UL,
        25 => 0x0000db3777577000UL,
        _ => throw new ArgumentOutOfRangeException(nameof(bits), "No canonical FastCDC mask exists for the requested bit count."),
    };
}
