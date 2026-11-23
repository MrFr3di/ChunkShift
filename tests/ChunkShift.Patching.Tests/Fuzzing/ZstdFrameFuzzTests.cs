using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ChunkShift.Patching.Creation;
using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Format;
using Xunit.Abstractions;
using ZstdSharp;
using ZstdSharp.Unsafe;

namespace ChunkShift.Patching.Tests.Fuzzing;

/// <summary>
/// Deterministic mutational fuzzing of encoding-1 stored bytes: the zstd frame
/// alone, without the CSP container around it.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CspApplyFuzzTests"/> reaches a frame only through a patch whose
/// CRCs and digest survive the mutation, so few of its cases exercise the
/// frame decoder. Here every case is a valid frame of the corpus mutated at the
/// byte, block-header or frame-header level and decoded with
/// <see cref="CspPayloadDecoder"/> for the corpus entry's chunk length and
/// dictionary. Oracles: only <see cref="InvalidDataException"/> escapes, and
/// nothing is written beyond the destination span.
/// </para>
/// <para>
/// With <c>CHUNKSHIFT_FUZZ_DUMP</c> set, small cases, their dictionaries and a
/// <c>frames-&lt;seed&gt;.jsonl</c> with the .NET verdict (<c>ok:&lt;SHA-256&gt;</c>
/// or <c>malformed</c>) are written for
/// <c>tools/conformance/csp/decode.py --compare-frames</c>, which decodes each with
/// libzstd and its own frame and block checks. That compares ZstdSharp with
/// libzstd on inputs neither encoder produces. <c>CHUNKSHIFT_FRAME_FUZZ_ITERATIONS</c>
/// sets the cases per seed (default 1000) and <c>CHUNKSHIFT_FUZZ_SEEDS</c> the seeds.
/// </para>
/// </remarks>
public sealed class ZstdFrameFuzzTests(ITestOutputHelper output)
{
    private const int DefaultIterationsPerSeed = 1000;
    private const int MaximumDumpedFrameBytes = 16 * 1024;
    private const int MaximumReportedFailures = 5;
    private const byte Untouched = 0xCC;

    private static readonly Lazy<List<FrameEntry>> Corpus = new(BuildCorpus);

    public static TheoryData<ulong> Seeds()
    {
        var seeds = new TheoryData<ulong>();
        string? configured = Environment.GetEnvironmentVariable("CHUNKSHIFT_FUZZ_SEEDS");

        if (string.IsNullOrWhiteSpace(configured))
        {
            seeds.Add(0x5EED_2001UL);
            seeds.Add(0x5EED_2002UL);
            return seeds;
        }

        foreach (string value in configured.Split(
            ',',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            seeds.Add(ulong.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture));
        }

        return seeds;
    }

    [Fact]
    public void CorpusFrames_DecodeToTheirChunks()
    {
        using var decoder = new CspPayloadDecoder();

        foreach (FrameEntry entry in Corpus.Value)
        {
            byte[] destination = new byte[entry.Chunk.Length];
            decoder.Decode(CspFormat.EncodingZstd, entry.Frame, entry.Dictionary, destination);
            Assert.Equal(entry.Chunk, destination);
            output.WriteLine(
                $"{entry.Name}: chunk={entry.Chunk.Length} frame={entry.Frame.Length} " +
                $"blocks={string.Join(",", BlockTypes(entry.Frame))}");
        }

        // Raw, RLE and compressed blocks, single and multiple blocks, with and
        // without a dictionary and a content checksum.
        Assert.Contains(Corpus.Value, entry => entry.Dictionary.Length > 0);
        Assert.Contains(Corpus.Value, entry => entry.Name.Contains("checksum", StringComparison.Ordinal));
        Assert.Contains(Corpus.Value, entry => BlockTypes(entry.Frame).Contains(0));
        Assert.Contains(Corpus.Value, entry => BlockTypes(entry.Frame).Contains(1));
        Assert.Contains(Corpus.Value, entry => BlockTypes(entry.Frame).Contains(2));
        Assert.Contains(Corpus.Value, entry => BlockTypes(entry.Frame).Count > 1);
    }

    [Theory]
    [MemberData(nameof(Seeds))]
    public void MutatedFrames_AreMalformedOrDecodeWithinTheDestination(ulong seed)
    {
        List<FrameEntry> corpus = Corpus.Value;
        int iterations = ReadIterations();
        var random = new FuzzRandom(seed);
        var failures = new List<string>();
        int decoded = 0;
        int malformed = 0;
        using var decoder = new CspPayloadDecoder();
        using DumpWriter? dump = DumpWriter.CreateFromEnvironment(seed);

        for (int iteration = 0; iteration < iterations; iteration++)
        {
            FrameEntry entry = random.Pick(corpus);
            var trace = new StringBuilder();
            byte[] frame = Mutate(entry.Frame, corpus, random, trace);
            byte[] buffer = new byte[entry.Chunk.Length + 16];
            buffer.AsSpan().Fill(Untouched);
            Span<byte> destination = buffer.AsSpan(0, entry.Chunk.Length);
            string verdict;

            try
            {
                decoder.Decode(CspFormat.EncodingZstd, frame, entry.Dictionary, destination);
                verdict = "ok:" + Convert.ToHexStringLower(SHA256.HashData(destination));
                decoded++;
            }
            catch (InvalidDataException)
            {
                verdict = "malformed";
                malformed++;
            }
            catch (Exception exception)
            {
                failures.Add(Describe(seed, iteration, entry, trace, frame, exception.ToString()));
                if (failures.Count >= MaximumReportedFailures)
                {
                    break;
                }

                continue;
            }

            if (buffer.AsSpan(entry.Chunk.Length).IndexOfAnyExcept(Untouched) >= 0)
            {
                failures.Add(Describe(seed, iteration, entry, trace, frame, "wrote beyond the destination"));
                continue;
            }

            dump?.Write(frame, entry, verdict, iteration);
        }

        output.WriteLine(
            $"seed=0x{seed:x} corpus={corpus.Count} iterations={iterations} " +
            $"decoded={decoded} malformed={malformed}");
        Assert.True(
            failures.Count == 0,
            string.Join(Environment.NewLine + Environment.NewLine, failures));
    }

    private static int ReadIterations()
    {
        string? configured = Environment.GetEnvironmentVariable("CHUNKSHIFT_FRAME_FUZZ_ITERATIONS");
        return string.IsNullOrWhiteSpace(configured)
            ? DefaultIterationsPerSeed
            : int.Parse(configured, NumberStyles.Integer, CultureInfo.InvariantCulture);
    }

    /// <summary>One to three stacked edits, blind or aimed at frame and block headers.</summary>
    private static byte[] Mutate(byte[] frame, List<FrameEntry> corpus, FuzzRandom random, StringBuilder trace)
    {
        var data = new List<byte>(frame);
        int edits = 1 + random.Next(3);

        for (int edit = 0; edit < edits; edit++)
        {
            int kind = random.Next(11);   // 10 and unmatched guards fall to the default
            int length = data.Count;
            _ = trace.Append(CultureInfo.InvariantCulture, $"{kind}");

            switch (kind)
            {
                case 0 when length > 0:
                    // Flip one bit.
                    int bit = random.Next(length * 8);
                    data[bit / 8] ^= (byte)(1 << (bit % 8));
                    break;

                case 1 when length > 0:
                    data[random.Next(length)] = (byte)random.Next(256);
                    break;

                case 2 when length > 0:
                    // Truncate at a random length.
                    int cut = random.Next(length);
                    data.RemoveRange(cut, length - cut);
                    break;

                case 3:
                    for (int count = 1 + random.Next(8); count > 0; count--)
                    {
                        data.Add((byte)random.Next(256));
                    }

                    break;

                case 4 when length > 1:
                    int start = random.Next(length);
                    data.RemoveRange(start, Math.Min(1 + random.Next(16), length - start));
                    break;

                case 5:
                    data.InsertRange(
                        random.Next(length + 1),
                        Enumerable.Range(0, 1 + random.Next(8)).Select(_ => (byte)random.Next(256)));
                    break;

                case 6:
                    EditBlockHeader(data, random, trace);
                    break;

                case 7:
                    EditFrameHeader(data, random, trace);
                    break;

                case 8 when length > 0:
                    // Splice bytes of another corpus frame over a range.
                    byte[] other = random.Pick(corpus).Frame;
                    int from = random.Next(other.Length);
                    int count8 = Math.Min(1 + random.Next(64), other.Length - from);
                    int at = random.Next(length);
                    for (int index = 0; index < count8 && at + index < data.Count; index++)
                    {
                        data[at + index] = other[from + index];
                    }

                    break;

                case 9:
                    EditBlockContentHeader(data, random, trace);
                    break;

                default:
                    // Duplicate a range at another position.
                    if (length > 0)
                    {
                        int from10 = random.Next(length);
                        byte[] copy = [.. data.GetRange(from10, Math.Min(1 + random.Next(64), length - from10))];
                        data.InsertRange(random.Next(length + 1), copy);
                    }

                    break;
            }

            _ = trace.Append(' ');
        }

        return [.. data];
    }

    /// <summary>Rewrites the type, last flag or size of one block header.</summary>
    private static void EditBlockHeader(List<byte> data, FuzzRandom random, StringBuilder trace)
    {
        List<int> headers = BlockHeaderOffsets([.. data]);

        if (headers.Count == 0)
        {
            return;
        }

        int at = random.Pick(headers);
        uint header = (uint)(data[at] | (data[at + 1] << 8) | (data[at + 2] << 16));
        uint last = header & 1;
        uint type = (header >> 1) & 3;
        uint size = header >> 3;

        switch (random.Next(4))
        {
            case 0:
                type = (uint)random.Next(4);
                break;
            case 1:
                last ^= 1;
                break;
            case 2:
                size = (uint)Math.Max(0, (int)size + random.Next(9) - 4);
                break;
            default:
                size = (uint)random.Next(1 << 21);
                break;
        }

        header = last | (type << 1) | ((size & 0x1FFFFF) << 3);
        data[at] = (byte)header;
        data[at + 1] = (byte)(header >> 8);
        data[at + 2] = (byte)(header >> 16);
        _ = trace.Append(CultureInfo.InvariantCulture, $"@{at}");
    }

    /// <summary>Rewrites the descriptor, window descriptor or content size.</summary>
    private static void EditFrameHeader(List<byte> data, FuzzRandom random, StringBuilder trace)
    {
        if (data.Count < 6)
        {
            return;
        }

        switch (random.Next(3))
        {
            case 0:
                data[4] ^= (byte)(1 << random.Next(8));
                _ = trace.Append("descriptor");
                break;
            case 1:
                data[5] = (byte)random.Next(256);
                _ = trace.Append("byte5");
                break;
            default:
                // The content size follows the descriptor (and window
                // descriptor); nudging those bytes moves it by small amounts.
                int at = 5 + random.Next(Math.Min(5, data.Count - 5));
                data[at] = (byte)(data[at] + random.Next(3) - 1);
                _ = trace.Append(CultureInfo.InvariantCulture, $"fcs@{at}");
                break;
        }
    }

    /// <summary>Edits the first bytes of a compressed block: literals and sequences headers.</summary>
    private static void EditBlockContentHeader(List<byte> data, FuzzRandom random, StringBuilder trace)
    {
        byte[] bytes = [.. data];
        List<int> compressed = BlockHeaderOffsets(bytes)
            .Where(at => ((bytes[at] >> 1) & 3) == 2 && at + 3 < bytes.Length)
            .ToList();

        if (compressed.Count == 0)
        {
            return;
        }

        int start = random.Pick(compressed) + 3;
        int offset = start + random.Next(Math.Min(8, data.Count - start));
        data[offset] = (byte)random.Next(256);
        _ = trace.Append(CultureInfo.InvariantCulture, $"content@{offset}");
    }

    /// <summary>Offsets of the block headers of a well-formed frame prefix.</summary>
    private static List<int> BlockHeaderOffsets(byte[] frame)
    {
        var offsets = new List<int>();

        if (frame.Length < 6)
        {
            return offsets;
        }

        byte descriptor = frame[4];
        int fcsFlag = descriptor >> 6;
        bool singleSegment = (descriptor & 0x20) != 0;
        int dictionaryIdSize = (descriptor & 3) switch { 0 => 0, 1 => 1, 2 => 2, _ => 4 };
        int contentSizeSize = fcsFlag switch { 0 => singleSegment ? 1 : 0, 1 => 2, 2 => 4, _ => 8 };
        int position = 5 + (singleSegment ? 0 : 1) + dictionaryIdSize + contentSizeSize;

        while (position + 3 <= frame.Length)
        {
            offsets.Add(position);
            uint header = (uint)(frame[position] | (frame[position + 1] << 8) | (frame[position + 2] << 16));
            uint type = (header >> 1) & 3;
            int size = (int)(header >> 3);
            position += 3 + (type == 1 ? 1 : size);

            if ((header & 1) != 0)
            {
                break;
            }
        }

        return offsets;
    }

    private static List<int> BlockTypes(byte[] frame) =>
        BlockHeaderOffsets(frame).Select(at => (frame[at] >> 1) & 3).ToList();

    private static List<FrameEntry> BuildCorpus()
    {
        var corpus = new List<FrameEntry>();
        byte[] random = CspBytes.CreateXorShiftBytes(12 * 1024, 0x5EED2101u);
        byte[] text = RepeatedText(40 * 1024);
        byte[] longText = RepeatedText(300 * 1024);
        byte[] zeros = new byte[20 * 1024];
        byte[] edited = (byte[])random.Clone();

        foreach (int offset in (int[])[100, 5_000, 11_000])
        {
            edited[offset] ^= 0x5A;
        }

        byte[] mixed = [.. random.AsSpan(0, 8 * 1024), .. text.AsSpan(0, 8 * 1024), .. zeros.AsSpan(0, 4096)];

        foreach (int level in (int[])[1, 3, 19])
        {
            using var encoder = new CspPayloadEncoder(level);

            Add(corpus, encoder, $"random-L{level}", random, []);
            Add(corpus, encoder, $"text-L{level}", text, []);
            Add(corpus, encoder, $"long-text-L{level}", longText, []);
            Add(corpus, encoder, $"zeros-L{level}", zeros, []);
            Add(corpus, encoder, $"mixed-L{level}", mixed, []);
            Add(corpus, encoder, $"edited-dictionary-L{level}", edited, random);
            Add(corpus, encoder, $"text-dictionary-L{level}", text, longText.AsSpan(1000, 64 * 1024).ToArray());
            Add(corpus, encoder, $"tiny-L{level}", text.AsSpan(0, 37).ToArray(), []);
        }

        // Frames of the default policy's dictionary handling (a raw prefix on the
        // static context, capped table logs). The 512 KiB
        // dictionary is large enough for the caps to replace zstd's choice.
        CspEncoderPolicy policy = CspEncoderPolicy.Default;
        byte[] largeDictionary = CspBytes.CreateXorShiftBytes(512 * 1024, 0x5EED2102u);
        byte[] largeEdited = largeDictionary.AsSpan(300 * 1024, 64 * 1024).ToArray();

        foreach (int offset in (int[])[10, 20_000, 60_000])
        {
            largeEdited[offset] ^= 0xA5;
        }

        using (var encoder = new CspPayloadEncoder(
            policy.Level, policy.DictionaryLoad, policy.DictionaryHashLog, policy.DictionaryChainLog))
        {
            Add(corpus, encoder, "edited-dictionary-default", edited, random);
            Add(corpus, encoder, "text-dictionary-default", text, longText.AsSpan(1000, 64 * 1024).ToArray());
            Add(corpus, encoder, "large-dictionary-default", largeEdited, largeDictionary);
            Add(corpus, encoder, "text-default", text, []);
        }

        // The CSP encoder writes no checksum; a decoder must still verify one.
        using (var compressor = new Compressor(3))
        {
            compressor.SetParameter(ZSTD_cParameter.ZSTD_c_checksumFlag, 1);
            corpus.Add(new FrameEntry("text-checksum", text, [], compressor.Wrap(text).ToArray()));
            corpus.Add(new FrameEntry("mixed-checksum", mixed, [], compressor.Wrap(mixed).ToArray()));
        }

        // No encoder here emits an RLE block; these frames are assembled from
        // RFC 8878 fields: one RLE block, and raw, RLE and raw blocks in one frame.
        byte[] rle = new byte[3000];
        rle.AsSpan().Fill((byte)'A');
        corpus.Add(new FrameEntry("rle", rle, [], AssembleFrame(rle.Length, [(1, 3000, (byte)'A', [])])));
        byte[] head = text.AsSpan(0, 500).ToArray();
        byte[] tail = random.AsSpan(0, 700).ToArray();
        byte[] blocks = [.. head, .. Enumerable.Repeat((byte)0x2A, 2000), .. tail];
        corpus.Add(new FrameEntry(
            "raw-rle-raw",
            blocks,
            [],
            AssembleFrame(blocks.Length, [(0, head.Length, 0, head), (1, 2000, 0x2A, []), (0, tail.Length, 0, tail)])));

        return corpus;
    }

    /// <summary>
    /// One single-segment frame with a 4-byte content size and the given
    /// blocks (type 0 raw with its bytes, type 1 RLE of one byte), the last
    /// one flagged.
    /// </summary>
    private static byte[] AssembleFrame(int contentSize, (int Type, int Size, byte Value, byte[] Raw)[] blocks)
    {
        var frame = new List<byte> { 0x28, 0xB5, 0x2F, 0xFD, 0xA0 };
        Span<byte> size = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(size, contentSize);
        frame.AddRange(size.ToArray());

        for (int index = 0; index < blocks.Length; index++)
        {
            (int type, int blockSize, byte value, byte[] raw) = blocks[index];
            int header = (index == blocks.Length - 1 ? 1 : 0) | (type << 1) | (blockSize << 3);
            frame.Add((byte)header);
            frame.Add((byte)(header >> 8));
            frame.Add((byte)(header >> 16));

            if (type == 1)
            {
                frame.Add(value);
            }
            else
            {
                frame.AddRange(raw);
            }
        }

        return [.. frame];
    }

    private static void Add(List<FrameEntry> corpus, CspPayloadEncoder encoder, string name, byte[] chunk, byte[] dictionary) =>
        corpus.Add(new FrameEntry(name, chunk, dictionary, encoder.EncodeZstd(chunk, dictionary).ToArray()));

    private static byte[] RepeatedText(int length)
    {
        var text = new StringBuilder();
        int line = 0;

        while (text.Length < length)
        {
            _ = text.Append(CultureInfo.InvariantCulture, $"line {line++ % 97}: ChunkShift frame fuzz corpus text.\n");
        }

        return System.Text.Encoding.ASCII.GetBytes(text.ToString(0, length));
    }

    private static string Describe(
        ulong seed,
        int iteration,
        FrameEntry entry,
        StringBuilder trace,
        byte[] frame,
        string problem) =>
        $"seed=0x{seed:x} iteration={iteration} entry={entry.Name} mutations={trace}: {problem}" +
        Environment.NewLine +
        (frame.Length <= 4096
            ? $"frame ({frame.Length} bytes, base64): {Convert.ToBase64String(frame)}"
            : $"frame: {frame.Length} bytes (replay with the seed and iteration above)");

    private sealed record FrameEntry(string Name, byte[] Chunk, byte[] Dictionary, byte[] Frame);

    /// <summary>Writes small mutated frames and their .NET verdicts for decode.py.</summary>
    private sealed class DumpWriter : IDisposable
    {
        private readonly string _directory;
        private readonly StreamWriter _verdicts;
        private readonly ulong _seed;
        private readonly Dictionary<FrameEntry, string?> _dictionaries = [];

        private DumpWriter(string directory, ulong seed)
        {
            _directory = directory;
            _seed = seed;
            Directory.CreateDirectory(directory);
            _verdicts = new StreamWriter(
                Path.Combine(directory, $"frames-{seed:x}.jsonl"),
                append: false,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
            {
                NewLine = "\n",
            };
        }

        internal static DumpWriter? CreateFromEnvironment(ulong seed)
        {
            string? directory = Environment.GetEnvironmentVariable("CHUNKSHIFT_FUZZ_DUMP");
            return string.IsNullOrWhiteSpace(directory) ? null : new DumpWriter(directory, seed);
        }

        internal void Write(byte[] frame, FrameEntry entry, string verdict, int iteration)
        {
            if (frame.Length > MaximumDumpedFrameBytes)
            {
                return;
            }

            if (!_dictionaries.TryGetValue(entry, out string? dictionary))
            {
                dictionary = null;

                if (entry.Dictionary.Length > 0)
                {
                    dictionary = $"frame-dictionary-{entry.Name}.bin";
                    File.WriteAllBytes(Path.Combine(_directory, dictionary), entry.Dictionary);
                }

                _dictionaries.Add(entry, dictionary);
            }

            string name = $"frame-{_seed:x}-{iteration}.zst";
            File.WriteAllBytes(Path.Combine(_directory, name), frame);
            _verdicts.WriteLine(JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["file"] = name,
                ["dictionary"] = dictionary,
                ["length"] = entry.Chunk.Length,
                ["verdict"] = verdict,
            }));
        }

        public void Dispose() => _verdicts.Dispose();
    }
}
