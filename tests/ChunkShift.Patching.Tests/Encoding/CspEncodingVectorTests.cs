using System.Text.Json;
using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Encoding;

/// <summary>
/// Decodes every committed apply-stage <c>zstd-</c> CSP vector with the
/// production payload codec and checks it against the vector's verdict. The
/// vectors were made by the independent generator; their stored bytes pin the
/// frame envelope, so this is the codec's side of the differential test
/// (CSP-V1 section 10).
/// </summary>
public sealed class CspEncodingVectorTests
{
    public static TheoryData<string> ZstdVectorNames
    {
        get
        {
            var names = new TheoryData<string>();

            foreach (CspZstdVector vector in CspZstdVectors.All)
            {
                names.Add(vector.Name);
            }

            return names;
        }
    }

    [Theory]
    [MemberData(nameof(ZstdVectorNames))]
    public async Task ZstdVector_DecodesToTheExpectedVerdict(string name)
    {
        CspZstdVector vector = CspZstdVectors.Find(name);
        byte[] patch = File.ReadAllBytes(Path.Combine(CspZstdVectors.Directory, name));
        using var stream = new MemoryStream(patch, writable: false);
        CspReader reader = await CspReader.OpenAsync(stream);

        Assert.Equal(CspVerificationFailure.None, reader.Failures);
        Assert.Single(reader.Index);
        Assert.Single(reader.PayloadChunkIds);

        CspEntry entry = await reader.ReadEntryAsync(0);
        Assert.Equal(CspFormat.EncodingZstd, entry.Encoding);

        int targetLength = await FindTargetLengthAsync(reader, entry.ChunkId);
        byte[] dictionary = await LoadDictionaryAsync(vector.Base, entry.DictionaryChunkIds);
        byte[] destination = new byte[targetLength];

        using var decoder = new CspPayloadDecoder();

        try
        {
            decoder.Decode(entry.Encoding, entry.StoredBytes, dictionary, destination);
        }
        catch (InvalidDataException)
        {
            Assert.Equal("malformed", vector.Verdict);
            return;
        }

        var decoded = new ChunkId(
            PatchHashing.Hash(reader.TargetManifest.Manifest.HashSuite, destination));

        if (vector.Verdict == "valid")
        {
            Assert.Equal(entry.ChunkId, decoded);
            return;
        }

        // The only accepted non-valid verdict here is a frame that decodes to
        // other bytes; the caller's ChunkId check rejects it (rule 19).
        Assert.Equal("verification", vector.Verdict);
        Assert.Contains("PayloadChunk", vector.Failures);
        Assert.NotEqual(entry.ChunkId, decoded);
    }

    [Fact]
    public void TheoryCoversAtLeastFifteenApplyStageZstdVectors()
    {
        Assert.True(
            CspZstdVectors.All.Count >= 15,
            $"Only {CspZstdVectors.All.Count} apply-stage zstd vectors are covered.");
    }

    private static async Task<int> FindTargetLengthAsync(CspReader reader, ChunkId chunkId)
    {
        using Stream manifest = reader.OpenTargetManifest();
        using ManifestReader manifestReader = await ManifestReader.OpenAsync(manifest);
        var batch = new ChunkInfo[16];

        while (true)
        {
            int count = await manifestReader.ReadAsync(batch);

            if (count == 0)
            {
                break;
            }

            for (int index = 0; index < count; index++)
            {
                if (batch[index].Id == chunkId)
                {
                    return batch[index].Length;
                }
            }
        }

        throw new InvalidOperationException(
            $"The embedded target manifest does not hold chunk {chunkId}.");
    }

    private static async Task<byte[]> LoadDictionaryAsync(
        string? baseName,
        ChunkId[] references)
    {
        if (references.Length == 0)
        {
            return [];
        }

        if (baseName is null)
        {
            throw new InvalidOperationException(
                "The vector names dictionary chunks but no base.");
        }

        IReadOnlyList<ChunkInfo> records = await ReadManifestAsync(
            Path.Combine(CspZstdVectors.Directory, baseName + ".csm"));
        byte[] content = File.ReadAllBytes(
            Path.Combine(CspZstdVectors.Directory, baseName + ".bin"));
        using var dictionary = new MemoryStream();

        foreach (ChunkId reference in references)
        {
            ChunkInfo record = records.First(record => record.Id == reference);
            dictionary.Write(content, checked((int)record.Offset), record.Length);
        }

        return dictionary.ToArray();
    }

    private static async Task<IReadOnlyList<ChunkInfo>> ReadManifestAsync(string path)
    {
        using var stream = new MemoryStream(File.ReadAllBytes(path), writable: false);
        using ManifestReader reader = await ManifestReader.OpenAsync(stream);
        var records = new List<ChunkInfo>();
        var batch = new ChunkInfo[16];

        while (true)
        {
            int count = await reader.ReadAsync(batch);

            if (count == 0)
            {
                break;
            }

            for (int index = 0; index < count; index++)
            {
                records.Add(batch[index]);
            }
        }

        Assert.NotNull(reader.VerificationResult);
        Assert.True(reader.VerificationResult!.IsValid);
        return records;
    }
}

/// <summary>One apply-stage <c>zstd-</c> vector of the committed fixture set.</summary>
internal sealed record CspZstdVector(
    string Name,
    string Verdict,
    string[] Failures,
    string? Base);

/// <summary>
/// Selects from <c>vectors.json</c> the apply-stage zstd vectors this codec can
/// decide: valid frames, malformed frames and frames that decode to other
/// bytes. Dictionary failures (rule 28) belong to the caller's base checks.
/// </summary>
internal static class CspZstdVectors
{
    private static readonly Dictionary<string, CspZstdVector> ByName =
        Load().ToDictionary(vector => vector.Name, StringComparer.Ordinal);

    internal static string Directory =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "CspV1");

    internal static IReadOnlyList<CspZstdVector> All { get; } = [.. ByName.Values];

    internal static CspZstdVector Find(string name) => ByName[name];

    private static List<CspZstdVector> Load()
    {
        string path = Path.Combine(Directory, "vectors.json");
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
        var vectors = new List<CspZstdVector>();

        foreach (JsonProperty property in document.RootElement
            .GetProperty("vectors")
            .EnumerateObject())
        {
            if (!property.Name.StartsWith("zstd-", StringComparison.Ordinal) ||
                property.Value.GetProperty("stage").GetString() != "apply")
            {
                continue;
            }

            JsonElement expect = property.Value.GetProperty("expect");
            string verdict = expect.GetProperty("verdict").GetString()!;
            string[] failures = expect.TryGetProperty(
                "failures",
                out JsonElement failureElement)
                ? [.. failureElement
                    .EnumerateArray()
                    .Select(item => item.GetString()!)]
                : [];

            bool covers = verdict == "valid"
                || verdict == "malformed"
                || (verdict == "verification" && failures.Contains("PayloadChunk"));

            if (!covers)
            {
                continue;
            }

            vectors.Add(new CspZstdVector(
                property.Name,
                verdict,
                failures,
                property.Value.TryGetProperty("base", out JsonElement baseElement)
                    ? baseElement.GetString()
                    : null));
        }

        return vectors;
    }
}
