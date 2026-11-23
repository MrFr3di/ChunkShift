using System.Text;
using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;

namespace ChunkShift.Patching.Tests.Encoding;

/// <summary>
/// Codec round trips and guards for CSP payload encodings 0 and 1
/// (docs/architecture/CSP-V1.md section 5).
/// </summary>
public sealed class CspPayloadCodecTests
{
    [Theory]
    [InlineData(1, true, false)]
    [InlineData(1, true, true)]
    [InlineData(1, false, false)]
    [InlineData(1, false, true)]
    [InlineData(3, true, false)]
    [InlineData(3, true, true)]
    [InlineData(3, false, false)]
    [InlineData(3, false, true)]
    [InlineData(19, true, false)]
    [InlineData(19, true, true)]
    [InlineData(19, false, false)]
    [InlineData(19, false, true)]
    public void RoundTrips_AtEveryLevel(int level, bool compressible, bool withDictionary)
    {
        byte[] chunk = compressible
            ? Compressible(64 * 1024)
            : RandomBytes(4096, 0xC0FFEEu);
        byte[] dictionary = withDictionary ? DictionaryFor(compressible) : [];

        using var encoder = new CspPayloadEncoder(level);
        byte[] frame = encoder.EncodeZstd(chunk, dictionary).ToArray();

        ZstdFrameEnvelope.Validate(frame, chunk.Length);

        (ulong contentSize, ulong window) = ZstdFrameHeader.Read(frame);
        Assert.Equal((ulong)chunk.Length, contentSize);
        Assert.InRange(window, 1UL, (ulong)ZstdFrameEnvelope.MaximumWindowBytes);

        byte[] destination = new byte[chunk.Length];
        using var decoder = new CspPayloadDecoder();
        decoder.Decode(CspFormat.EncodingZstd, frame, dictionary, destination);

        Assert.Equal(chunk, destination);
    }

    [Fact]
    public void ChunkLargerThanOneMiB_ProducesABoundedWindowAndDecodes()
    {
        byte[] chunk = Compressible(1_500_000);

        using var encoder = new CspPayloadEncoder(3);
        byte[] frame = encoder.EncodeZstd(chunk, []).ToArray();

        ZstdFrameEnvelope.Validate(frame, chunk.Length);

        (ulong contentSize, ulong window) = ZstdFrameHeader.Read(frame);
        Assert.Equal((ulong)chunk.Length, contentSize);
        Assert.InRange(window, 1UL, (ulong)ZstdFrameEnvelope.MaximumWindowBytes);

        byte[] destination = new byte[chunk.Length];
        using var decoder = new CspPayloadDecoder();
        decoder.Decode(CspFormat.EncodingZstd, frame, [], destination);

        Assert.Equal(chunk, destination);
    }

    [Fact]
    public void ReusingOneEncoder_ClearsThePreviousDictionary()
    {
        byte[] chunk = Compressible(8 * 1024);
        byte[] dictionary = DictionaryFor(compressible: true);

        using var encoder = new CspPayloadEncoder(3);
        byte[] withDictionary = encoder.EncodeZstd(chunk, dictionary).ToArray();
        byte[] withoutDictionary = encoder.EncodeZstd(chunk, []).ToArray();

        using var decoder = new CspPayloadDecoder();
        byte[] destination = new byte[chunk.Length];

        decoder.Decode(CspFormat.EncodingZstd, withDictionary, dictionary, destination);
        Assert.Equal(chunk, destination);

        // If the second call had kept the first dictionary, this frame would
        // only decode correctly against it.
        decoder.Decode(CspFormat.EncodingZstd, withoutDictionary, [], destination);
        Assert.Equal(chunk, destination);
    }

    // Every dictionary load mode must use the dictionary, so
    // an edited copy of 64 KiB of random base bytes compresses to a fraction
    // of the chunk, and each frame decodes against the raw content only.
    [Theory]
    [InlineData(3, 0, 0, 0)]
    [InlineData(3, 1, 0, 0)]
    [InlineData(3, 2, 0, 0)]
    [InlineData(19, 0, 0, 0)]
    [InlineData(19, 1, 0, 0)]
    [InlineData(19, 2, 0, 0)]
    [InlineData(19, 0, 18, 19)]
    [InlineData(19, 1, 18, 19)]
    [InlineData(19, 2, 18, 19)]
    public void DictionaryLoadModes_UseTheDictionary(int level, int load, int hashLog, int chainLog)
    {
        byte[] dictionary = RandomBytes(512 * 1024, 0xBA5Eu);
        byte[] chunk = dictionary.AsSpan(300 * 1024, 64 * 1024).ToArray();
        chunk[1000] ^= 0x5A;
        chunk[40_000] ^= 0xA5;

        using var encoder = new CspPayloadEncoder(level, (CspDictionaryLoad)load, hashLog, chainLog);
        using var decoder = new CspPayloadDecoder();
        byte[] destination = new byte[chunk.Length];

        // The encoder is reused across entries with and without a dictionary,
        // as the builder uses it.
        for (int round = 0; round < 2; round++)
        {
            byte[] frame = encoder.EncodeZstd(chunk, dictionary).ToArray();
            ZstdFrameEnvelope.Validate(frame, chunk.Length);
            Assert.InRange(frame.Length, 1, 1024);
            decoder.Decode(CspFormat.EncodingZstd, frame, dictionary, destination);
            Assert.Equal(chunk, destination);

            byte[] plain = encoder.EncodeZstd(chunk, []).ToArray();
            Assert.True(plain.Length > chunk.Length / 2, "A frame without a dictionary kept the previous one.");
            decoder.Decode(CspFormat.EncodingZstd, plain, [], destination);
            Assert.Equal(chunk, destination);
        }
    }

    // The load mode and the table caps apply to dictionary entries only: an
    // entry without a dictionary gets the default policy's frame.
    [Theory]
    [InlineData(1, 0, 0)]
    [InlineData(2, 0, 0)]
    [InlineData(0, 18, 19)]
    [InlineData(2, 18, 19)]
    public void DictionaryLoadModes_WithoutADictionary_MatchTheDefaultFrame(int load, int hashLog, int chainLog)
    {
        byte[] chunk = Compressible(64 * 1024);
        chunk[100] = 0;

        using var reference = new CspPayloadEncoder(19);
        using var encoder = new CspPayloadEncoder(19, (CspDictionaryLoad)load, hashLog, chainLog);

        Assert.Equal(
            reference.EncodeZstd(chunk, []).ToArray(),
            encoder.EncodeZstd(chunk, []).ToArray());
    }

    [Fact]
    public void ReusingOneDecoder_ClearsThePreviousDictionary()
    {
        byte[] chunk = Compressible(8 * 1024);
        byte[] dictionary = DictionaryFor(compressible: true);

        using var encoder = new CspPayloadEncoder(3);
        byte[] withDictionary = encoder.EncodeZstd(chunk, dictionary).ToArray();
        byte[] withoutDictionary = encoder.EncodeZstd(chunk, []).ToArray();

        using var decoder = new CspPayloadDecoder();
        byte[] destination = new byte[chunk.Length];

        decoder.Decode(CspFormat.EncodingZstd, withDictionary, dictionary, destination);
        Assert.Equal(chunk, destination);

        decoder.Decode(CspFormat.EncodingZstd, withoutDictionary, [], destination);
        Assert.Equal(chunk, destination);
    }

    [Fact]
    public void RawEncoding_CopiesTheStoredBytes()
    {
        byte[] stored = RandomBytes(256, 0x5EEDu);
        byte[] destination = new byte[stored.Length];

        using var decoder = new CspPayloadDecoder();
        decoder.Decode(CspFormat.EncodingRaw, stored, [], destination);

        Assert.Equal(stored, destination);
    }

    [Fact]
    public void RawEncoding_WrongStoredLength_ThrowsInvalidOperationException()
    {
        using var decoder = new CspPayloadDecoder();

        Assert.Throws<InvalidOperationException>(
            () => decoder.Decode(CspFormat.EncodingRaw, [1, 2, 3], [], new byte[4]));
    }

    [Fact]
    public void RawEncoding_WithDictionary_ThrowsInvalidOperationException()
    {
        using var decoder = new CspPayloadDecoder();

        Assert.Throws<InvalidOperationException>(
            () => decoder.Decode(CspFormat.EncodingRaw, [1, 2, 3], [4, 5, 6], new byte[3]));
    }

    [Fact]
    public void MagicPrefixedDictionary_IsNotUsable()
    {
        byte[] dictionary = [0x37, 0xA4, 0x30, 0xEC, 0x00, 0x01];

        Assert.False(CspDictionary.IsUsable(dictionary));

        using var encoder = new CspPayloadEncoder(3);
        Assert.Throws<ArgumentException>(() =>
        {
            _ = encoder.EncodeZstd([1, 2, 3], dictionary);
        });

        using var decoder = new CspPayloadDecoder();
        Assert.Throws<InvalidOperationException>(
            () => decoder.Decode(
                CspFormat.EncodingZstd,
                [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x01, 0x00, 0x00],
                dictionary,
                new byte[1]));
    }

    [Fact]
    public void DictionaryAtTheLimit_IsUsable_AndOneByteMoreIsNot()
    {
        Assert.True(CspDictionary.IsUsable(new byte[CspDictionary.MaximumBytes]));
        Assert.False(CspDictionary.IsUsable(new byte[CspDictionary.MaximumBytes + 1]));
        Assert.True(CspDictionary.IsUsable([]));
    }

    [Fact]
    public void UnknownEncoding_ThrowsNotSupportedException()
    {
        using var decoder = new CspPayloadDecoder();

        Assert.Throws<NotSupportedException>(
            () => decoder.Decode(2, [1, 2, 3], [], new byte[3]));
    }

    [Fact]
    public void DecodeAfterDispose_ThrowsObjectDisposedException()
    {
        var decoder = new CspPayloadDecoder();
        decoder.Dispose();

        Assert.Throws<ObjectDisposedException>(
            () => decoder.Decode(CspFormat.EncodingRaw, [1], [], new byte[1]));
    }

    [Fact]
    public void EncodeAfterDispose_ThrowsObjectDisposedException()
    {
        var encoder = new CspPayloadEncoder(3);
        encoder.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
        {
            _ = encoder.EncodeZstd([1], []);
        });
    }

    private static byte[] Compressible(int length)
    {
        const string line = "ChunkShift declarative patch payload, ";
        string text = string.Concat(
            Enumerable.Repeat(line, (length / line.Length) + 1));

        return System.Text.Encoding.ASCII.GetBytes(text[..length]);
    }

    private static byte[] RandomBytes(int length, uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int index = 0; index < bytes.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[index] = (byte)state;
        }

        return bytes;
    }

    private static byte[] DictionaryFor(bool compressible) =>
        compressible ? Compressible(4096) : RandomBytes(1024, 0xD1C7u);

    /// <summary>
    /// Reads the RFC 8878 header fields a test asserts on: the declared
    /// content size and the window (the content size for a single-segment
    /// frame, otherwise the <c>Window_Descriptor</c> value).
    /// </summary>
    private static class ZstdFrameHeader
    {
        internal static (ulong ContentSize, ulong Window) Read(ReadOnlySpan<byte> frame)
        {
            Assert.Equal(0xFD2FB528u, System.Buffers.Binary.BinaryPrimitives
                .ReadUInt32LittleEndian(frame));

            byte descriptor = frame[4];
            bool singleSegment = (descriptor & 0x20) != 0;
            int contentSizeFlag = descriptor >> 6;
            int position = 5;
            ulong window = 0;

            if (!singleSegment)
            {
                byte windowDescriptor = frame[position];
                position++;

                int windowLog = 10 + (windowDescriptor >> 3);
                ulong windowBase = 1UL << windowLog;
                window = windowBase
                    + ((windowBase >> 3) * (ulong)(windowDescriptor & 0x07));
            }

            position += (descriptor & 0x03) switch
            {
                0 => 0,
                1 => 1,
                2 => 2,
                _ => 4,
            };

            int contentSizeSize = (singleSegment
                ? new[] { 1, 2, 4, 8 }
                : new[] { 0, 2, 4, 8 })[contentSizeFlag];
            ulong contentSize = 0;

            for (int index = 0; index < contentSizeSize; index++)
            {
                contentSize |= (ulong)frame[position + index] << (8 * index);
            }

            if (contentSizeSize == 2)
            {
                contentSize += 256;
            }

            return (contentSize, singleSegment ? contentSize : window);
        }
    }
}
