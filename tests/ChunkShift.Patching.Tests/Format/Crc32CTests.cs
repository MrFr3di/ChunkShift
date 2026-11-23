using ChunkShift.Patching.Format;

namespace ChunkShift.Patching.Tests.Format;

public sealed class Crc32CTests
{
    [Fact]
    public void StandardCheckVector_MatchesCastagnoli()
    {
        uint actual = Crc32C.Compute("123456789"u8);

        Assert.Equal(0xE3069283u, actual);
    }

    [Fact]
    public void EmptyInput_IsZero()
    {
        Assert.Equal(0u, Crc32C.Compute(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void EverySplit_MatchesOneShot()
    {
        byte[] data = CspBytes.CreateXorShiftBytes(97, 0xC3C32Cu);
        uint expected = Crc32C.Compute(data);

        for (int split = 0; split <= data.Length; split++)
        {
            uint state = Crc32C.Start();
            state = Crc32C.Append(state, data.AsSpan(0, split));
            state = Crc32C.Append(state, data.AsSpan(split));

            Assert.Equal(expected, Crc32C.Finalize(state));
        }
    }
}
