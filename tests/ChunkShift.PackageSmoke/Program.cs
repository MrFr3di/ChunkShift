// Package-consumer smoke for the packed ChunkShift NuGet package.
//
// The same program runs under JIT (CI package-smoke), under NativeAOT on x64
// and ARM64 (conformance) and in the release workflow, so every lane
// exercises the real public paths instead of a primitive-only placeholder:
//
//   * ChunkScanner over both HashSuites;
//   * ChunkManifest.CreateAsync / VerifyManifestAsync / VerifyAsync and
//     ManifestReader, with and without BIDX, including a content mismatch;
//   * a 32 MiB generated non-seekable source through the scanner and the
//     manifest create/verify path, each under a managed-allocation budget.
//
// A second mode proves the larger-than-memory claim in an isolated process:
// the conformance workflow generates a file several
// times larger than a cgroup memory limit (swap disabled) and runs
// --large-source inside that limit, so any full materialization of the source
// gets the process OOM-killed instead of passing quietly:
//
//   ChunkShift.PackageSmoke --generate <file> <bytes>
//   ChunkShift.PackageSmoke --large-source <file> --manifest <file> [--evidence <path>]
//
// Deterministic results are written as evidence lines (--evidence <path>) so
// JIT vs AOT and x64 vs ARM64 runs can be compared byte-for-byte. Allocation
// figures are printed to stdout only, because they are not deterministic.

using System.Globalization;
using System.Security.Cryptography;
using ChunkShift;
using ChunkShift.Primitives;

const long GeneratedLength = 32L * 1024 * 1024;
const uint GeneratedSeed = 0x51A6E55u;

// A full-source materialization alone would allocate at least 32 MiB. Leave
// substantial runtime headroom while still detecting that class of regression.
const long AllocationBudget = 16L * 1024 * 1024;

if (args is ["--generate", string generatePath, string generateLength])
{
    await LargeSource.GenerateAsync(
        Path.GetFullPath(generatePath),
        long.Parse(generateLength, NumberStyles.None, CultureInfo.InvariantCulture));
    return 0;
}

if (args is ["--large-source", string largePath, "--manifest", string largeManifestPath, .. string[] largeRest])
{
    string? largeEvidencePath = ParseEvidencePath(largeRest);
    string line = await LargeSource.RunAsync(
        Path.GetFullPath(largePath),
        Path.GetFullPath(largeManifestPath));

    Console.WriteLine(line);
    if (largeEvidencePath is not null)
    {
        await File.WriteAllLinesAsync(largeEvidencePath, [line]);
    }

    Console.WriteLine("large-source smoke: OK");
    return 0;
}

string? evidencePath = ParseEvidencePath(args);
var evidence = new List<string>();

byte[] bytes = XorShift.Create(768 * 1024, 0xC0FFEE42u);
byte[] tampered = (byte[])bytes.Clone();
tampered[tampered.Length / 2] ^= 0x80;

foreach (HashSuiteId suite in new[] { HashSuiteIds.Blake3256V1, HashSuiteIds.Sha256V1 })
{
    ScanResult scan = await ScanAsync(
        new MemoryStream(bytes, writable: false),
        suite);

    Check(
        scan.Covered == bytes.LongLength && scan.Ids.Count > 0,
        "scanner did not cover the complete source");

    evidence.Add(Invariant(
        $"scan suite={suite} chunks={scan.Ids.Count} bytes={scan.Covered} ids-sha256={scan.IdsDigest}"));

    foreach (bool includeBlockIndex in new[] { false, true })
    {
        using var manifest = new MemoryStream();

        ManifestInfo created = await ChunkManifest.CreateAsync(
            new MemoryStream(bytes, writable: false),
            manifest,
            new ManifestCreationOptions
            {
                HashSuite = suite,
                IncludeBlockIndex = includeBlockIndex,
            });

        Check(
            created.HashSuite == suite &&
            created.HasBlockIndex == includeBlockIndex &&
            created.ChunkCount == scan.Ids.Count &&
            created.ContentLength == bytes.LongLength &&
            created.PhysicalLength == manifest.Length,
            "CreateAsync summary disagrees with the scanner or the written bytes");

        manifest.Position = 0;
        ManifestVerificationResult structural =
            await ChunkManifest.VerifyManifestAsync(manifest);

        Check(
            structural.IsValid &&
            structural.Manifest.ManifestId == created.ManifestId &&
            structural.Manifest.FileDigest == created.FileDigest,
            "VerifyManifestAsync rejected or misreported a fresh manifest");

        manifest.Position = 0;
        ManifestVerificationResult withContent =
            await ChunkManifest.VerifyAsync(
                new MemoryStream(bytes, writable: false),
                manifest);

        Check(withContent.IsValid, "VerifyAsync rejected the original content");

        manifest.Position = 0;
        await CheckReaderMatchesScanAsync(manifest, scan);

        manifest.Position = 0;
        ManifestVerificationResult mismatch =
            await ChunkManifest.VerifyAsync(
                new MemoryStream(tampered, writable: false),
                manifest);

        Check(
            !mismatch.IsValid &&
            mismatch.Failures == ManifestVerificationFailure.Content,
            "VerifyAsync did not report changed content as a Content mismatch");

        evidence.Add(Invariant(
            $"manifest suite={suite} bidx={includeBlockIndex} manifest-id={created.ManifestId} file-digest={created.FileDigest.ToHexLower()} physical-bytes={created.PhysicalLength} cblk={created.ChunkBlockCount}"));
    }
}

// Large forward-only source: scanner.
{
    using var generated = new GeneratedStream(GeneratedLength, GeneratedSeed);
    long before = GC.GetTotalAllocatedBytes(precise: true);
    ScanResult scan = await ScanAsync(generated, HashSuiteIds.Default);
    long allocated = GC.GetTotalAllocatedBytes(precise: true) - before;

    Check(
        scan.Covered == GeneratedLength &&
        generated.BytesRead == GeneratedLength &&
        generated.MaxRequestedReadLength is > 0 and <= 1024 * 1024,
        "scanner did not preserve bounded generated-stream semantics");
    CheckBudget("generated scan", allocated);

    evidence.Add(Invariant(
        $"generated-scan chunks={scan.Ids.Count} bytes={scan.Covered} ids-sha256={scan.IdsDigest}"));
    Console.WriteLine(Invariant($"generated-scan allocated={allocated}"));
}

// Large forward-only source: manifest create and content verification.
{
    using var manifest = new MemoryStream();
    ManifestInfo created;
    long allocated;

    using (var generated = new GeneratedStream(GeneratedLength, GeneratedSeed))
    {
        long before = GC.GetTotalAllocatedBytes(precise: true);
        created = await ChunkManifest.CreateAsync(
            generated,
            new ForwardOnlyWriteStream(manifest),
            new ManifestCreationOptions { IncludeBlockIndex = true });
        allocated = GC.GetTotalAllocatedBytes(precise: true) - before;

        Check(
            created.ContentLength == GeneratedLength &&
            generated.BytesRead == GeneratedLength,
            "CreateAsync did not consume the complete generated stream");
    }

    CheckBudget("generated create", allocated);
    Console.WriteLine(Invariant($"generated-create allocated={allocated}"));

    using (var generated = new GeneratedStream(GeneratedLength, GeneratedSeed))
    {
        manifest.Position = 0;
        long before = GC.GetTotalAllocatedBytes(precise: true);
        ManifestVerificationResult verified =
            await ChunkManifest.VerifyAsync(generated, manifest);
        allocated = GC.GetTotalAllocatedBytes(precise: true) - before;

        Check(
            verified.IsValid && verified.Manifest.ManifestId == created.ManifestId,
            "VerifyAsync rejected the generated content");
    }

    CheckBudget("generated verify", allocated);
    Console.WriteLine(Invariant($"generated-verify allocated={allocated}"));

    evidence.Add(Invariant(
        $"generated-manifest suite={created.HashSuite} manifest-id={created.ManifestId} file-digest={created.FileDigest.ToHexLower()} chunks={created.ChunkCount} physical-bytes={created.PhysicalLength}"));
}

foreach (string line in evidence)
{
    Console.WriteLine(line);
}

if (evidencePath is not null)
{
    await File.WriteAllLinesAsync(evidencePath, evidence);
}

Console.WriteLine("package smoke: OK");
return 0;

static string? ParseEvidencePath(string[] arguments)
{
    if (arguments.Length == 0)
    {
        return null;
    }

    if (arguments.Length == 2 && arguments[0] == "--evidence")
    {
        return Path.GetFullPath(arguments[1]);
    }

    throw new ArgumentException(
        "Usage: ChunkShift.PackageSmoke [--evidence <path>] | " +
        "--generate <file> <bytes> | " +
        "--large-source <file> --manifest <file> [--evidence <path>]");
}

static string Invariant(FormattableString value) =>
    FormattableString.Invariant(value);

static void Check(bool condition, string failure)
{
    if (!condition)
    {
        throw new InvalidOperationException($"ChunkShift package smoke failed: {failure}.");
    }
}

static void CheckBudget(string operation, long allocated)
{
    Check(
        allocated < AllocationBudget,
        string.Create(
            CultureInfo.InvariantCulture,
            $"{operation} allocated {allocated} bytes; bounded streaming regressed"));
}

static async Task<ScanResult> ScanAsync(Stream source, HashSuiteId suite)
{
    var ids = new List<ChunkId>();
    var lengths = new List<int>();
    long covered = 0;

    await ChunkScanner.ScanAsync(
        source,
        (chunk, content, _) =>
        {
            if (chunk.Index != ids.Count ||
                chunk.Offset != covered ||
                chunk.Length != content.Length ||
                chunk.Length <= 0)
            {
                throw new InvalidOperationException(
                    "ChunkShift package smoke failed: scanner chunk invariant.");
            }

            ids.Add(chunk.Id);
            lengths.Add(chunk.Length);
            covered += chunk.Length;
            return ValueTask.CompletedTask;
        },
        new ChunkScanOptions { HashSuite = suite });

    return new ScanResult(ids, lengths, covered, DigestIds(ids));
}

static async Task CheckReaderMatchesScanAsync(Stream manifest, ScanResult scan)
{
    await using ManifestReader reader = await ManifestReader.OpenAsync(manifest);
    var batch = new ChunkInfo[5];
    int index = 0;
    long offset = 0;
    int read;

    while ((read = await reader.ReadAsync(batch)) != 0)
    {
        for (int item = 0; item < read; item++, index++)
        {
            ChunkInfo entry = batch[item];
            Check(
                index < scan.Ids.Count &&
                entry.Index == index &&
                entry.Offset == offset &&
                entry.Length == scan.Lengths[index] &&
                entry.Id == scan.Ids[index],
                "ManifestReader entries disagree with the scanner");
            offset += entry.Length;
        }
    }

    Check(
        index == scan.Ids.Count &&
        reader.IsCompleted &&
        reader.VerificationResult is { IsValid: true },
        "ManifestReader did not complete as valid");
}

static string DigestIds(List<ChunkId> ids)
{
    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    Span<byte> buffer = stackalloc byte[32];

    foreach (ChunkId id in ids)
    {
        id.Value.CopyTo(buffer);
        hash.AppendData(buffer);
    }

    return Convert.ToHexStringLower(hash.GetHashAndReset());
}

// Larger-than-memory scenario over a real file. The memory limit itself is
// enforced by the caller (a cgroup); this code refuses to report success
// unless that limit is present and the source is clearly larger than it.
internal static class LargeSource
{
    private const uint Seed = 0x1A26E5EEu;
    private const int MinimumSourceToLimitRatio = 8;

    internal static async Task GenerateAsync(string path, long length)
    {
        using var generated = new GeneratedStream(length, Seed);
        await using var file = new FileStream(
            path,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 0,
            FileOptions.Asynchronous);

        await generated.CopyToAsync(file, 1024 * 1024);
        Console.WriteLine(FormattableString.Invariant($"generated {length} bytes at {path}"));
    }

    internal static async Task<string> RunAsync(string sourcePath, string manifestPath)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("--large-source reads its limit from Linux cgroup v2.");
        }

        long sourceLength = new FileInfo(sourcePath).Length;
        (long memoryLimit, string swapLimit) = ReadCgroupLimits();

        Console.WriteLine(FormattableString.Invariant(
            $"large-source bytes={sourceLength} cgroup memory.max={memoryLimit} memory.swap.max={swapLimit}"));

        Require(
            swapLimit == "0",
            "run inside a cgroup with swap disabled (memory.swap.max=0)");
        Require(
            memoryLimit > 0 && sourceLength >= memoryLimit * MinimumSourceToLimitRatio,
            FormattableString.Invariant(
                $"the source must be at least {MinimumSourceToLimitRatio}x the cgroup memory limit"));

        ManifestInfo created;
        await using (FileStream source = OpenSequential(sourcePath))
        await using (var manifest = new FileStream(
            manifestPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 0,
            FileOptions.Asynchronous))
        {
            created = await ChunkManifest.CreateAsync(
                source,
                manifest,
                new ManifestCreationOptions { IncludeBlockIndex = true });
        }

        Require(created.ContentLength == sourceLength, "CreateAsync did not cover the whole file");

        await using (FileStream manifest = OpenSequential(manifestPath))
        {
            ManifestVerificationResult structural = await ChunkManifest.VerifyManifestAsync(manifest);
            Require(
                structural.IsValid && structural.Manifest.ManifestId == created.ManifestId,
                "VerifyManifestAsync rejected the large manifest");
        }

        long entries = 0;
        long covered = 0;
        await using (FileStream manifest = OpenSequential(manifestPath))
        await using (ManifestReader reader = await ManifestReader.OpenAsync(manifest))
        {
            var batch = new ChunkInfo[4096];
            int read;

            while ((read = await reader.ReadAsync(batch)) != 0)
            {
                for (int item = 0; item < read; item++)
                {
                    Require(batch[item].Offset == covered, "ManifestReader entries are not contiguous");
                    covered += batch[item].Length;
                }

                entries += read;
            }

            Require(
                reader.VerificationResult is { IsValid: true } &&
                entries == created.ChunkCount &&
                covered == created.ContentLength,
                "ManifestReader did not stream the large manifest as valid");
        }

        await using (FileStream source = OpenSequential(sourcePath))
        await using (FileStream manifest = OpenSequential(manifestPath))
        {
            ManifestVerificationResult verified = await ChunkManifest.VerifyAsync(source, manifest);
            Require(verified.IsValid, "VerifyAsync rejected the large source");
        }

        long peakResident = ReadPeakResidentBytes();
        Console.WriteLine(FormattableString.Invariant(
            $"large-source peak-rss={peakResident} source/peak={(double)sourceLength / peakResident:F1}x"));
        Require(peakResident < memoryLimit, "peak RSS reached the cgroup memory limit");

        // Deterministic: compared across architectures, unlike the memory figures.
        return FormattableString.Invariant(
            $"large-source bytes={sourceLength} manifest-id={created.ManifestId} file-digest={created.FileDigest.ToHexLower()} chunks={created.ChunkCount} physical-bytes={created.PhysicalLength}");
    }

    private static FileStream OpenSequential(string path) => new(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        bufferSize: 0,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static (long MemoryLimit, string SwapLimit) ReadCgroupLimits()
    {
        // cgroup v2: a single "0::/path" line.
        string? relative = File.ReadLines("/proc/self/cgroup")
            .Where(line => line.StartsWith("0::", StringComparison.Ordinal))
            .Select(line => line[3..])
            .FirstOrDefault();
        Require(relative is not null, "no cgroup v2 membership in /proc/self/cgroup");

        string directory = "/sys/fs/cgroup" + relative;
        string memory = File.ReadAllText(Path.Combine(directory, "memory.max")).Trim();
        string swapFile = Path.Combine(directory, "memory.swap.max");
        string swap = File.Exists(swapFile) ? File.ReadAllText(swapFile).Trim() : "unavailable";

        return (
            memory == "max" ? 0 : long.Parse(memory, NumberStyles.None, CultureInfo.InvariantCulture),
            swap);
    }

    private static long ReadPeakResidentBytes()
    {
        // VmHWM is the process's peak resident set size, in kB.
        string line = File.ReadLines("/proc/self/status")
            .First(value => value.StartsWith("VmHWM:", StringComparison.Ordinal));
        string kilobytes = line["VmHWM:".Length..].Trim().Split(' ')[0];

        return long.Parse(kilobytes, NumberStyles.None, CultureInfo.InvariantCulture) * 1024;
    }

    private static void Require(bool condition, string failure)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"ChunkShift large-source smoke failed: {failure}.");
        }
    }
}

internal sealed record ScanResult(
    List<ChunkId> Ids,
    List<int> Lengths,
    long Covered,
    string IdsDigest);

internal static class XorShift
{
    internal static byte[] Create(int length, uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int index = 0; index < bytes.Length; index++)
        {
            state = Next(state);
            bytes[index] = (byte)state;
        }

        return bytes;
    }

    internal static uint Next(uint state)
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }
}

// Non-seekable, generated-on-demand source that never materializes its payload.
internal sealed class GeneratedStream : Stream
{
    private long _remaining;
    private uint _state;

    internal GeneratedStream(long length, uint seed)
    {
        _remaining = length;
        _state = seed;
    }

    internal long BytesRead { get; private set; }

    internal int MaxRequestedReadLength { get; private set; }

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
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(ReadCore(buffer.Span));
    }

    private int ReadCore(Span<byte> destination)
    {
        MaxRequestedReadLength = Math.Max(MaxRequestedReadLength, destination.Length);

        int count = (int)Math.Min(destination.Length, _remaining);

        for (int index = 0; index < count; index++)
        {
            _state = XorShift.Next(_state);
            destination[index] = (byte)_state;
        }

        _remaining -= count;
        BytesRead += count;
        return count;
    }

    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

// Write-only, non-seekable view of a caller-owned stream: CreateAsync must
// produce the CSM strictly forward.
internal sealed class ForwardOnlyWriteStream(Stream inner) : Stream
{
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        inner.Write(buffer, offset, count);

    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default) =>
        inner.WriteAsync(buffer, cancellationToken);

    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) =>
        inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
