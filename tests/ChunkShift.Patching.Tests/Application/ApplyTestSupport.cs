using System.Text.Json;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Format;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// One committed CSP v1 vector as apply needs it: the expected verdict, the
/// base files it names and, for a valid vector, the pinned target bytes.
/// </summary>
internal sealed record CspApplyVector(
    string Name,
    string Verdict,
    string[] Failures,
    string? BaseName,
    string? BaseManifestFile,
    string? BaseContentFile,
    int MaximumPayloadEntries,
    string? OutputSha256,
    long OutputLength);

/// <summary>
/// Loads the committed CSP v1 vectors and their base files for the apply
/// differential test (CSP-V1 sections 6 and 10). The structure-stage
/// reader test keeps its own loader; this one adds the apply expectations.
/// </summary>
internal static class CspApplyVectors
{
    internal static IReadOnlyList<CspApplyVector> All { get; } = Load();

    internal static CspApplyVector Find(string name) =>
        All.First(vector => vector.Name == name);

    internal static byte[] ReadPatch(string name) => ReadFile(name);

    internal static byte[] ReadBaseManifest(CspApplyVector vector) =>
        ReadFile(vector.BaseManifestFile!);

    internal static byte[] ReadBaseContent(CspApplyVector vector) =>
        ReadFile(vector.BaseContentFile!);

    internal static byte[] ReadFile(string name) =>
        File.ReadAllBytes(Path.Combine(CspV1Vectors.Directory, name));

    private static List<CspApplyVector> Load()
    {
        string path = Path.Combine(CspV1Vectors.Directory, "vectors.json");
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));

        var bases = new Dictionary<string, (string Manifest, string Content)>(
            StringComparer.Ordinal);

        foreach (JsonProperty property in document.RootElement
            .GetProperty("bases")
            .EnumerateObject())
        {
            bases[property.Name] = (
                property.Value.GetProperty("manifest").GetString()!,
                property.Value.GetProperty("content").GetString()!);
        }

        var vectors = new List<CspApplyVector>();

        foreach (JsonProperty property in document.RootElement
            .GetProperty("vectors")
            .EnumerateObject())
        {
            JsonElement value = property.Value;
            JsonElement expect = value.GetProperty("expect");
            string[] failures = [];

            if (expect.TryGetProperty("failures", out JsonElement failureElement))
            {
                failures =
                [
                    .. failureElement
                        .EnumerateArray()
                        .Select(item => item.GetString()!),
                ];
            }

            string? baseName = value.TryGetProperty("base", out JsonElement baseElement)
                ? baseElement.GetString()
                : null;
            string? baseManifest = null;
            string? baseContent = null;

            if (baseName is not null)
            {
                (baseManifest, baseContent) = bases[baseName];
            }

            vectors.Add(new CspApplyVector(
                property.Name,
                expect.GetProperty("verdict").GetString()!,
                failures,
                baseName,
                baseManifest,
                baseContent,
                value.TryGetProperty("maxPayloadEntries", out JsonElement maxElement)
                    ? maxElement.GetInt32()
                    : CspFormat.DefaultMaximumPayloadEntries,
                expect.TryGetProperty("outputSha256", out JsonElement hashElement)
                    ? hashElement.GetString()
                    : null,
                expect.TryGetProperty("outputLength", out JsonElement lengthElement)
                    ? lengthElement.GetInt64()
                    : 0));
        }

        return vectors;
    }
}

/// <summary>
/// Readable, seekable wrapper over an inner stream that interrupts apply at a
/// chosen base read: it either cancels a token or throws
/// <see cref="IOException"/>. It makes cancellation and base I/O failures occur
/// between records, not only before apply starts.
/// </summary>
internal sealed class InterruptingReadStream : Stream
{
    private readonly Stream _inner;
    private readonly CancellationTokenSource? _cancellation;
    private readonly int _interruptAtRead;
    private readonly bool _throwIo;
    private int _reads;

    /// <summary>Cancels <paramref name="cancellation"/> at read number <paramref name="interruptAtRead"/>.</summary>
    internal InterruptingReadStream(
        Stream inner,
        CancellationTokenSource cancellation,
        int interruptAtRead)
    {
        _inner = inner;
        _cancellation = cancellation;
        _interruptAtRead = interruptAtRead;
    }

    /// <summary>Throws <see cref="IOException"/> at read number <paramref name="interruptAtRead"/>.</summary>
    internal InterruptingReadStream(Stream inner, int interruptAtRead)
    {
        _inner = inner;
        _interruptAtRead = interruptAtRead;
        _throwIo = true;
    }

    public override bool CanRead => _inner.CanRead;

    public override bool CanSeek => _inner.CanSeek;

    public override bool CanWrite => false;

    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        Interrupt();
        return _inner.Read(buffer, offset, count);
    }

    public override int Read(Span<byte> buffer)
    {
        Interrupt();
        return _inner.Read(buffer);
    }

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        Interrupt();

        // The inner read never observes the token: the interruption is what
        // the applier must react to at its next cancellation check.
        return _inner.ReadAsync(buffer, CancellationToken.None);
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin) =>
        _inner.Seek(offset, origin);

    public override void Flush()
    {
    }

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    private void Interrupt()
    {
        if (++_reads != _interruptAtRead)
        {
            return;
        }

        if (_throwIo)
        {
            throw new IOException("Injected base stream read failure.");
        }

        _cancellation!.Cancel();
    }
}
