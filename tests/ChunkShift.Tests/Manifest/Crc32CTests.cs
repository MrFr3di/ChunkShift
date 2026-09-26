using System.Text;
using ChunkShift.Manifest;

namespace ChunkShift.Tests.Manifest;

public sealed class Crc32CTests
{
    [Fact]
    public void StandardCheckVector_MatchesCastagnoli()
    {
        uint actual = Crc32C.Compute(Encoding.ASCII.GetBytes("123456789"));

        Assert.Equal(0xE3069283u, actual);
    }

    [Fact]
    public void IncrementalUpdates_MatchOneShot()
    {
        byte[] input = Encoding.ASCII.GetBytes("chunkshift-csm-v1");

        uint state = Crc32C.Start();
        state = Crc32C.Append(state, input.AsSpan(0, 5));
        state = Crc32C.Append(state, input.AsSpan(5, 7));
        state = Crc32C.Append(state, input.AsSpan(12));

        Assert.Equal(Crc32C.Compute(input), Crc32C.Finalize(state));
    }

    [Fact]
    public void EveryLengthAndAlignment_MatchesTheBitwiseDefinition()
    {
        byte[] data = new byte[1024 + 7];
        new Random(0x32C).NextBytes(data);

        // Covers the 8-byte word loop, every tail length and unaligned starts.
        for (int start = 0; start < 8; start++)
        {
            for (int length = 0; length <= 300; length++)
            {
                ReadOnlySpan<byte> slice = data.AsSpan(start, length);
                Assert.Equal(BitwiseCrc32C(slice), Crc32C.Compute(slice));
            }
        }

        Assert.Equal(BitwiseCrc32C(data), Crc32C.Compute(data));
    }

    [Fact]
    public void SplitAtEveryOffset_MatchesOneShot()
    {
        byte[] data = new byte[67];
        new Random(0x5B1).NextBytes(data);
        uint expected = BitwiseCrc32C(data);

        for (int split = 0; split <= data.Length; split++)
        {
            uint state = Crc32C.Start();
            state = Crc32C.Append(state, data.AsSpan(0, split));
            state = Crc32C.Append(state, data.AsSpan(split));

            Assert.Equal(expected, Crc32C.Finalize(state));
        }
    }

    // Independent oracle: the reflected Castagnoli CRC one bit at a time, as
    // written in CSM-V1, with no shared code with Crc32C.
    private static uint BitwiseCrc32C(ReadOnlySpan<byte> data)
    {
        uint state = 0xFFFFFFFFu;

        foreach (byte value in data)
        {
            state ^= value;

            for (int bit = 0; bit < 8; bit++)
            {
                state = (state & 1u) != 0
                    ? (state >> 1) ^ 0x82F63B78u
                    : state >> 1;
            }
        }

        return ~state;
    }
}
