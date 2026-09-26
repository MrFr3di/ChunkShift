using System.Globalization;
using System.Text;
using System.Text.Json;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Fuzzing;

/// <summary>
/// Deterministic mutational fuzzing of the CSM reader. Fuzzing is part of the
/// reader conformance evidence for the persisted CSM v1 format.
/// </summary>
/// <remarks>
/// <para>
/// Every mutated input is checked against these oracles:
/// </para>
/// <list type="number">
/// <item>the only exceptions are <see cref="InvalidDataException"/> (malformed)
/// and <see cref="NotSupportedException"/> (unknown HashSuite); anything else,
/// such as an index, overflow or null-reference exception, is a reader bug;</item>
/// <item>the reader allocates at most <see cref="AllocationBudgetBytes"/> per
/// input, whatever lengths the input declares;</item>
/// <item><see cref="ChunkManifest.VerifyManifestAsync"/> over a seekable stream
/// and <see cref="ManifestReader"/> over a forward-only stream with random read
/// sizes and random batch sizes reach the same verdict.</item>
/// </list>
/// <para>
/// The default run is small enough for every CI build. The conformance workflow runs
/// more iterations through the environment variables below and also dumps
/// small cases for a differential check against the independent Python decoder
/// (<c>tools/conformance/csm/decode.py --compare</c>).
/// </para>
/// <list type="bullet">
/// <item><c>CHUNKSHIFT_FUZZ_ITERATIONS</c>: iterations per seed (default 400);</item>
/// <item><c>CHUNKSHIFT_FUZZ_SEEDS</c>: comma-separated seeds replacing the defaults;</item>
/// <item><c>CHUNKSHIFT_FUZZ_DUMP</c>: directory that receives small SHA-256 cases
/// and a <c>verdicts.jsonl</c> with the .NET verdict of each.</item>
/// </list>
/// </remarks>
public sealed class CsmReaderFuzzTests
{
    // The reader's fixed buffers are about 150 KiB; optional BIDX tracking can
    // grow to 262,144 entries of 16 bytes. Nothing may scale with a length
    // declared by the input beyond that.
    internal const long AllocationBudgetBytes = 16L * 1024 * 1024;

    private const int DefaultIterationsPerSeed = 400;
    private const int MaximumDumpedCaseBytes = 16 * 1024;
    private const int MaximumReportedFailures = 5;

    private static readonly Lazy<List<byte[]>> Corpus = new(BuildCorpus);

    public static TheoryData<ulong> Seeds()
    {
        var seeds = new TheoryData<ulong>();
        string? configured = Environment.GetEnvironmentVariable("CHUNKSHIFT_FUZZ_SEEDS");

        if (string.IsNullOrWhiteSpace(configured))
        {
            seeds.Add(0x5EED_0001UL);
            seeds.Add(0x5EED_0002UL);
            seeds.Add(0x5EED_0003UL);
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

    [Theory]
    [MemberData(nameof(Seeds))]
    public async Task MutatedManifests_AreClassifiedWithinBoundsAndConsistently(ulong seed)
    {
        IReadOnlyList<byte[]> corpus = Corpus.Value;
        int iterations = ReadIterations();
        var random = new FuzzRandom(seed);
        var failures = new List<string>();
        var outcomes = new Dictionary<string, int>(StringComparer.Ordinal);
        using DumpWriter? dump = DumpWriter.CreateFromEnvironment(seed);

        for (int iteration = 0; iteration < iterations; iteration++)
        {
            var trace = new StringBuilder();
            byte[] seedInput = random.Pick(corpus);
            byte[] input = CsmMutator.Mutate(seedInput, corpus, random, trace);

            (Verdict seekable, long allocated) = VerifySeekable(input);
            Verdict forward = await VerifyForwardOnlyAsync(input, random);

            string? problem = null;

            if (seekable.IsBug)
            {
                problem = $"VerifyManifestAsync threw {seekable.Text}";
            }
            else if (forward.IsBug)
            {
                problem = $"ManifestReader threw {forward.Text}";
            }
            else if (seekable.Text != forward.Text)
            {
                problem = $"seekable verdict {seekable.Text} != forward-only verdict {forward.Text}";
            }
            else if (allocated > AllocationBudgetBytes)
            {
                problem = $"allocated {allocated} bytes (budget {AllocationBudgetBytes})";
            }

            if (problem is not null)
            {
                failures.Add(Describe(seed, iteration, trace, input, problem, seekable.Detail));
                if (failures.Count >= MaximumReportedFailures)
                {
                    break;
                }

                continue;
            }

            string bucket = seekable.Text.Split(':')[0];
            outcomes[bucket] = outcomes.GetValueOrDefault(bucket) + 1;
            dump?.Write(input, seekable.Text);
        }

        Assert.True(
            failures.Count == 0,
            string.Join(Environment.NewLine + Environment.NewLine, failures));

        // Guard against a mutator regression that stops producing variety:
        // a useful run must reach acceptance, integrity failures and rejection.
        Assert.True(outcomes.GetValueOrDefault("reject") > 0, Summary(outcomes));
        Assert.True(outcomes.GetValueOrDefault("integrity") > 0, Summary(outcomes));
        Assert.True(outcomes.GetValueOrDefault("valid") > 0, Summary(outcomes));
    }

    private static (Verdict Verdict, long Allocated) VerifySeekable(byte[] input)
    {
        // MemoryStream completes every read synchronously, so the whole
        // verification runs on this thread and the per-thread allocation
        // counter measures exactly what the reader allocated.
        long before = GC.GetAllocatedBytesForCurrentThread();
        Task<ManifestVerificationResult> task;

        try
        {
            task = ChunkManifest.VerifyManifestAsync(new MemoryStream(input, writable: false));
        }
        catch (Exception exception)
        {
            return (Verdict.FromException(exception), 0);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        if (!task.IsCompleted)
        {
            return (Verdict.Bug("verification did not complete synchronously over a MemoryStream"), allocated);
        }

        try
        {
            return (Verdict.FromResult(task.GetAwaiter().GetResult()), allocated);
        }
        catch (Exception exception)
        {
            return (Verdict.FromException(exception), allocated);
        }
    }

    private static async Task<Verdict> VerifyForwardOnlyAsync(byte[] input, FuzzRandom random)
    {
        int maximumRead = random.Chance(20) ? 1 : 1 + random.Next(4096);
        int batchSize = 1 + random.Next(random.Chance(50) ? 8 : 1024);
        var source = new RandomReadStream(input, new FuzzRandom(random.NextUInt64()), maximumRead);

        try
        {
            await using ManifestReader reader = await ManifestReader.OpenAsync(source);
            var batch = new ChunkInfo[batchSize];

            while (await reader.ReadAsync(batch) != 0)
            {
            }

            return Verdict.FromResult(reader.VerificationResult!);
        }
        catch (Exception exception)
        {
            return Verdict.FromException(exception);
        }
    }

    private static int ReadIterations()
    {
        string? configured = Environment.GetEnvironmentVariable("CHUNKSHIFT_FUZZ_ITERATIONS");
        return string.IsNullOrWhiteSpace(configured)
            ? DefaultIterationsPerSeed
            : int.Parse(configured, NumberStyles.Integer, CultureInfo.InvariantCulture);
    }

    private static List<byte[]> BuildCorpus()
    {
        var corpus = new List<byte[]>();
        string fixtures = Path.Combine(AppContext.BaseDirectory, "Fixtures", "CsmV1");

        foreach (string path in Directory.GetFiles(fixtures, "*.csm").Order(StringComparer.Ordinal))
        {
            corpus.Add(File.ReadAllBytes(path));
        }

        // Production-encoded manifests with both HashSuites, with and without
        // BIDX, from empty to a few chunks.
        foreach (HashSuiteId hashSuite in new[] { HashSuiteIds.Blake3256V1, HashSuiteIds.Sha256V1 })
        {
            foreach (int length in new[] { 0, 1, 777, 200_000 })
            {
                foreach (bool includeBlockIndex in new[] { false, true })
                {
                    byte[] content = ChunkShift.Tests.Manifest.CsmBytes.CreateXorShiftBytes(length, 0xF022u + (uint)length);
                    using var encoded = new MemoryStream();

                    ChunkManifest.CreateAsync(
                        new MemoryStream(content, writable: false),
                        encoded,
                        new ManifestCreationOptions
                        {
                            HashSuite = hashSuite,
                            IncludeBlockIndex = includeBlockIndex,
                        }).GetAwaiter().GetResult();

                    corpus.Add(encoded.ToArray());
                }
            }
        }

        return corpus;
    }

    private static string Describe(
        ulong seed,
        int iteration,
        StringBuilder trace,
        byte[] input,
        string problem,
        string? detail)
    {
        var message = new StringBuilder()
            .Append(CultureInfo.InvariantCulture, $"seed=0x{seed:x} iteration={iteration}: {problem}")
            .AppendLine()
            .Append(CultureInfo.InvariantCulture, $"mutations: {trace}")
            .AppendLine();

        if (detail is not null)
        {
            message.AppendLine(detail);
        }

        message.Append(
            input.Length <= 4096
                ? $"input ({input.Length} bytes, base64): {Convert.ToBase64String(input)}"
                : $"input: {input.Length} bytes (replay with the seed and iteration above)");

        return message.ToString();
    }

    private static string Summary(Dictionary<string, int> outcomes) =>
        "outcomes: " + string.Join(", ", outcomes.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => $"{pair.Key}={pair.Value}"));

    private readonly record struct Verdict(string Text, bool IsBug, string? Detail)
    {
        internal static Verdict FromResult(ManifestVerificationResult result)
        {
            if (result.IsValid)
            {
                return new Verdict("valid", false, null);
            }

            var names = new List<string>();
            foreach (ManifestVerificationFailure flag in Enum.GetValues<ManifestVerificationFailure>())
            {
                if (flag != ManifestVerificationFailure.None && result.Failures.HasFlag(flag))
                {
                    names.Add(flag.ToString());
                }
            }

            names.Sort(StringComparer.Ordinal);
            return new Verdict("integrity:" + string.Join(",", names), false, null);
        }

        internal static Verdict FromException(Exception exception) => exception switch
        {
            InvalidDataException => new Verdict("reject", false, null),
            NotSupportedException => new Verdict("unsupported", false, null),
            _ => new Verdict(exception.GetType().FullName!, true, exception.ToString()),
        };

        internal static Verdict Bug(string description) => new(description, true, null);
    }

    /// <summary>
    /// Forward-only stream returning a random number of bytes per read, never
    /// more than requested and never zero before the end.
    /// </summary>
    private sealed class RandomReadStream(byte[] data, FuzzRandom random, int maximumRead) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadCore(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ReadCore(buffer.Span));

        private int ReadCore(Span<byte> destination)
        {
            int available = data.Length - _position;
            if (available == 0 || destination.IsEmpty)
            {
                return 0;
            }

            int count = Math.Min(
                Math.Min(destination.Length, available),
                1 + random.Next(maximumRead));
            data.AsSpan(_position, count).CopyTo(destination);
            _position += count;
            return count;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// Writes small SHA-256 cases and their .NET verdicts for the Python
    /// differential check.
    /// </summary>
    private sealed class DumpWriter : IDisposable
    {
        private readonly string _directory;
        private readonly StreamWriter _verdicts;
        private readonly ulong _seed;
        private int _written;

        private DumpWriter(string directory, ulong seed)
        {
            _directory = directory;
            _seed = seed;
            Directory.CreateDirectory(directory);
            _verdicts = new StreamWriter(
                Path.Combine(directory, $"verdicts-{seed:x}.jsonl"),
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

        internal void Write(byte[] input, string verdict)
        {
            // The Python decoder implements SHA-256 only.
            if (input.Length > MaximumDumpedCaseBytes ||
                !CsmMutator.TryReadHashSuite(input, out HashSuiteId? suite) ||
                suite != HashSuiteIds.Sha256V1)
            {
                return;
            }

            string name = $"case-{_seed:x}-{_written++:d6}.csm";
            File.WriteAllBytes(Path.Combine(_directory, name), input);
            _verdicts.WriteLine(JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["file"] = name,
                ["verdict"] = verdict,
            }));
        }

        public void Dispose() => _verdicts.Dispose();
    }
}
