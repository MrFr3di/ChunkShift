using System;

namespace ChunkShift.Chunking;

internal static class FastCdcScalar
{
    internal static int FindCut(ReadOnlySpan<byte> source, FastCdcProfile profile)
    {
        int remaining = Math.Min(source.Length, profile.Maximum);

        if (remaining <= profile.Minimum)
        {
            return remaining;
        }

        int center = Math.Min(profile.Target, remaining);
        ulong hash = 0;

        for (int index = profile.Minimum; index < center; index++)
        {
            hash = unchecked((hash << 1) + FastCdcGearTable.Get(source[index]));
            if ((hash & profile.StrictMask) == 0)
            {
                return index;
            }
        }

        for (int index = center; index < remaining; index++)
        {
            hash = unchecked((hash << 1) + FastCdcGearTable.Get(source[index]));
            if ((hash & profile.RelaxedMask) == 0)
            {
                return index;
            }
        }

        return remaining;
    }
}
