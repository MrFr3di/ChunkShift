using ChunkShift.Chunking;

namespace ChunkShift.Tests.Chunking;

public class ChunkBoundaryStateTests
{
    // Small enough that every range (prefix, strict, relaxed, forced cut) is
    // crossed many times by short inputs and short windows.
    private static readonly FastCdcProfile SmallProfile = new(64, 256, 1024);

    public static TheoryData<string> Inputs => new() { "random", "zeros", "mixed" };

    [Theory]
    [MemberData(nameof(Inputs))]
    public void EveryFixedWindowSizeMatchesScalarCuts(string input)
    {
        byte[] data = CreateInput(input, 48 * 1024);
        int[] expected = ScalarCuts(data, SmallProfile);

        foreach (int window in new[] { 1, 2, 3, 7, 63, 64, 65, 191, 192, 193, 255, 256, 257, 767, 768, 769, 1023, 1024, 1025, 4096 })
        {
            Assert.Equal(expected, StreamingCuts(data, SmallProfile, _ => window));
        }
    }

    [Theory]
    [MemberData(nameof(Inputs))]
    public void RandomWindowsMatchScalarCuts(string input)
    {
        byte[] data = CreateInput(input, 48 * 1024);
        int[] expected = ScalarCuts(data, SmallProfile);

        for (int seed = 1; seed <= 16; seed++)
        {
            var random = new Random(seed);
            Assert.Equal(expected, StreamingCuts(data, SmallProfile, _ => random.Next(1, 1500)));
        }
    }

    [Fact]
    public void WindowsEndingAtEveryPositionOfTheFirstChunkMatchScalarCuts()
    {
        byte[] data = CreateInput("random", 8 * 1024);
        int[] expected = ScalarCuts(data, SmallProfile);

        // Split the first window at every chunk-relative position, including the
        // Minimum/Target/Maximum edges and the cut candidate itself.
        for (int split = 1; split <= SmallProfile.Maximum + 1; split++)
        {
            int first = split;
            Assert.Equal(expected, StreamingCuts(data, SmallProfile, call => call == 0 ? first : 97));
        }
    }

    [Fact]
    public void ZeroInputIsForcedAtMaximum()
    {
        byte[] data = new byte[10 * SmallProfile.Maximum + 5];

        int[] cuts = StreamingCuts(data, SmallProfile, _ => 333);

        Assert.Equal(Enumerable.Repeat(SmallProfile.Maximum, 10).Append(5), cuts);
        Assert.Equal(ScalarCuts(data, SmallProfile), cuts);
    }

    private static int[] ScalarCuts(ReadOnlySpan<byte> data, FastCdcProfile profile)
    {
        var cuts = new List<int>();

        for (int offset = 0; offset < data.Length;)
        {
            int length = FastCdcScalar.FindCut(data[offset..], profile);
            cuts.Add(length);
            offset += length;
        }

        return [.. cuts];
    }

    private static int[] StreamingCuts(byte[] data, FastCdcProfile profile, Func<int, int> windowLength)
    {
        var state = new ChunkBoundaryState(ChunkingKernelProfile.FastCdcGear(profile));
        var cuts = new List<int>();
        int pending = 0;
        int call = 0;

        for (int offset = 0; offset < data.Length;)
        {
            ReadOnlySpan<byte> window = data.AsSpan(offset, Math.Min(windowLength(call++), data.Length - offset));
            int index = 0;

            while (index < window.Length)
            {
                ChunkBoundaryScanResult result = state.Scan(window[index..]);
                index += result.Consumed;
                pending += result.Consumed;

                Assert.True(result.Consumed > 0 || result.HasBoundary, "Scan made no progress.");

                if (result.HasBoundary)
                {
                    Assert.Equal(pending, result.CompletedChunkLength);
                    cuts.Add(result.CompletedChunkLength);
                    pending = 0;
                }

                Assert.Equal(pending, state.PendingChunkLength);
            }

            offset += window.Length;
        }

        int last = state.Finish();
        if (last != 0)
        {
            cuts.Add(last);
        }

        return [.. cuts];
    }

    private static byte[] CreateInput(string kind, int length)
    {
        byte[] data = new byte[length];

        if (kind == "zeros")
        {
            return data;
        }

        new Random(0x5EED).NextBytes(data);

        if (kind == "mixed")
        {
            // Alternate random and constant runs so chunks cut both by the
            // predicate and by Maximum.
            for (int start = 0; start < length; start += 4096)
            {
                if ((start / 4096) % 2 == 1)
                {
                    data.AsSpan(start, Math.Min(4096, length - start)).Clear();
                }
            }
        }

        return data;
    }
}
