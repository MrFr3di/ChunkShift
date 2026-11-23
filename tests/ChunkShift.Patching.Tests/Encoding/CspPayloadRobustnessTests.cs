using System.Text;
using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;

namespace ChunkShift.Patching.Tests.Encoding;

/// <summary>
/// Exception discipline for hostile encoding-1 stored bytes: a mutated or
/// truncated frame either fails as malformed input or decodes, and never
/// escapes as another exception type or writes outside the destination span.
/// </summary>
public sealed class CspPayloadRobustnessTests
{
    private const byte Untouched = 0xCC;

    [Fact]
    public void EverySingleByteFlip_ThrowsOnlyInvalidDataExceptionOrDecodes()
    {
        byte[] chunk = CreateChunk();
        byte[] dictionary = CreateDictionary();
        using var encoder = new CspPayloadEncoder(1);
        byte[] frame = encoder.EncodeZstd(chunk, dictionary).ToArray();

        using var decoder = new CspPayloadDecoder();
        AssertDecodes(decoder, frame, dictionary, chunk);

        for (int position = 0; position < frame.Length; position++)
        {
            byte[] mutated = (byte[])frame.Clone();
            mutated[position] ^= 0x5A;
            Attempt(decoder, mutated, dictionary, chunk.Length);
        }
    }

    [Fact]
    public void EveryTruncation_ThrowsOnlyInvalidDataExceptionOrDecodes()
    {
        byte[] chunk = CreateChunk();
        byte[] dictionary = CreateDictionary();
        using var encoder = new CspPayloadEncoder(1);
        byte[] frame = encoder.EncodeZstd(chunk, dictionary).ToArray();

        using var decoder = new CspPayloadDecoder();
        AssertDecodes(decoder, frame, dictionary, chunk);

        for (int length = 0; length < frame.Length; length++)
        {
            Attempt(decoder, frame.AsSpan(0, length).ToArray(), dictionary, chunk.Length);
        }
    }

    private static void Attempt(
        CspPayloadDecoder decoder,
        byte[] stored,
        byte[] dictionary,
        int destinationLength)
    {
        // The decode destination is the target chunk length; the sentinel tail
        // proves nothing was written past it whatever the frame declared.
        byte[] buffer = new byte[destinationLength + 16];
        buffer.AsSpan().Fill(Untouched);

        try
        {
            decoder.Decode(
                CspFormat.EncodingZstd,
                stored,
                dictionary,
                buffer.AsSpan(0, destinationLength));
        }
        catch (InvalidDataException)
        {
        }

        Assert.True(
            buffer.AsSpan(destinationLength).IndexOfAnyExcept(Untouched) < 0,
            "The decoder wrote beyond the destination span.");
    }

    private static void AssertDecodes(
        CspPayloadDecoder decoder,
        byte[] frame,
        byte[] dictionary,
        byte[] chunk)
    {
        byte[] destination = new byte[chunk.Length];
        decoder.Decode(CspFormat.EncodingZstd, frame, dictionary, destination);
        Assert.Equal(chunk, destination);
    }

    private static byte[] CreateChunk() =>
        System.Text.Encoding.ASCII.GetBytes(string.Concat(
            Enumerable.Repeat("ChunkShift declarative patch payload, ", 8)));

    private static byte[] CreateDictionary() =>
        System.Text.Encoding.ASCII.GetBytes(string.Concat(
            Enumerable.Repeat("declarative patch payload, ChunkShift ", 4)));
}
