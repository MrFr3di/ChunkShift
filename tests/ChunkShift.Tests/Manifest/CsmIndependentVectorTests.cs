using System.Text;
using System.Text.Json;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

/// <summary>
/// Runs every vector from <c>tools/csm-fixtures/generate.py</c> through the
/// public verification API and checks the verdict recorded in
/// <c>Fixtures/CsmV1/vectors.json</c>.
/// </summary>
/// <remarks>
/// The expectations come from the Python generator's definitions, and CI checks
/// the same file with the independent Python decoder
/// (<c>generate.py --verify</c>). A vector therefore passes only when both
/// implementations reach the verdict the specification prescribes.
/// </remarks>
public sealed class CsmIndependentVectorTests
{
    private const string FixtureDirectory = "Fixtures/CsmV1";

    private static readonly Lazy<JsonElement> VectorManifest = new(() =>
        JsonDocument.Parse(File.ReadAllBytes(FixturePath("vectors.json")))
            .RootElement
            .Clone());

    public static TheoryData<string> VectorNames()
    {
        var names = new TheoryData<string>();

        foreach (JsonProperty vector in Vectors().EnumerateObject())
        {
            names.Add(vector.Name);
        }

        return names;
    }

    [Theory]
    [MemberData(nameof(VectorNames))]
    public async Task Vector_ReachesTheIndependentlyExpectedVerdict(string name)
    {
        JsonElement vector = Vectors().GetProperty(name);
        JsonElement expect = vector.GetProperty("expect");
        string outcome = expect.GetProperty("outcome").GetString()!;
        byte[] bytes = File.ReadAllBytes(FixturePath(name));

        Assert.Equal(
            vector.GetProperty("physicalLength").GetInt64(),
            bytes.LongLength);

        Task<ManifestVerificationResult> verification =
            ChunkManifest.VerifyManifestAsync(
                new MemoryStream(bytes, writable: false));

        switch (outcome)
        {
            case "reject":
                await Assert.ThrowsAsync<InvalidDataException>(() => verification);
                return;

            case "unsupported":
                await Assert.ThrowsAsync<NotSupportedException>(() => verification);
                return;

            case "valid":
            case "integrity":
                break;

            default:
                Assert.Fail($"Unknown expected outcome '{outcome}' for {name}.");
                return;
        }

        ManifestVerificationResult result = await verification;

        Assert.Equal(
            ExpectedFailures(expect.GetProperty("failures")),
            result.Failures);
        Assert.Equal(outcome == "valid", result.IsValid);

        ManifestInfo manifest = result.Manifest;
        Assert.Equal(
            vector.GetProperty("chunkCount").GetInt64(),
            manifest.ChunkCount);
        Assert.Equal(
            vector.GetProperty("contentLength").GetInt64(),
            manifest.ContentLength);
        Assert.Equal(
            vector.GetProperty("cblkCount").GetInt64(),
            manifest.ChunkBlockCount);
        Assert.Equal(
            vector.GetProperty("hasBidx").GetBoolean(),
            manifest.HasBlockIndex);
        Assert.Equal(
            vector.GetProperty("physicalLength").GetInt64(),
            manifest.PhysicalLength);

        if (outcome == "valid")
        {
            Assert.Equal(
                vector.GetProperty("manifestId").GetString(),
                manifest.ManifestId.ToString());
            Assert.Equal(
                vector.GetProperty("fileDigest").GetString(),
                manifest.FileDigest.ToHexLower());
        }
    }

    [Fact]
    public void EveryCheckedInVector_IsListedWithAnExpectation()
    {
        string directory = FixturePath(string.Empty);
        string[] files = Directory
            .GetFiles(directory, "*.csm")
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray()!;
        string[] listed = Vectors()
            .EnumerateObject()
            .Select(vector => vector.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(listed, files);
    }

    [Fact]
    public void PermittedPhysicalDifferences_KeepTheLogicalIdentity()
    {
        string baseline = Vectors()
            .GetProperty("valid-small-sha256-no-bidx.csm")
            .GetProperty("manifestId")
            .GetString()!;

        string[] physicalVariants =
        [
            "valid-small-sha256-bidx.csm",
            "valid-aux0-optional-skipped.csm",
            "valid-unknown-optional-tail-section-skipped.csm",
            "valid-optional-physical-feature-ignored.csm",
        ];

        var digests = new HashSet<string>(StringComparer.Ordinal)
        {
            Vectors()
                .GetProperty("valid-small-sha256-no-bidx.csm")
                .GetProperty("fileDigest")
                .GetString()!,
        };

        foreach (string name in physicalVariants)
        {
            JsonElement vector = Vectors().GetProperty(name);
            Assert.Equal(baseline, vector.GetProperty("manifestId").GetString());
            Assert.True(
                digests.Add(vector.GetProperty("fileDigest").GetString()!),
                $"{name} should differ physically from the other variants.");
        }
    }

    [Theory]
    [InlineData("valid-small-sha256-no-bidx.csm", false)]
    [InlineData("valid-small-sha256-bidx.csm", true)]
    public async Task ProductionEncoder_IsByteExactWithSmallIndependentVectors(
        string name,
        bool includeBlockIndex)
    {
        using var destination = new MemoryStream();

        using (CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                destination,
                HashSuiteIds.Sha256V1,
                new ChunkingProfileId("fixture.csm.synthetic.v1"),
                new ProfileFingerprint(
                    HashSuiteHasher.Hash(
                        HashSuiteIds.Sha256V1,
                        "chunkshift.csm.fixture.profile.v1"u8)),
                includeBlockIndex,
                CancellationToken.None))
        {
            uint[] lengths = [5, 7, 11];

            for (int index = 0; index < lengths.Length; index++)
            {
                await encoder.AppendAsync(
                    new ChunkId(
                        HashSuiteHasher.Hash(
                            HashSuiteIds.Sha256V1,
                            Encoding.ASCII.GetBytes($"small-{index}"))),
                    lengths[index],
                    CancellationToken.None);
            }

            _ = await encoder.CompleteAsync(CancellationToken.None);
        }

        Assert.Equal(
            File.ReadAllBytes(FixturePath(name)),
            destination.ToArray());
    }

    private static JsonElement Vectors() =>
        VectorManifest.Value.GetProperty("vectors");

    private static ManifestVerificationFailure ExpectedFailures(
        JsonElement failures)
    {
        ManifestVerificationFailure expected = ManifestVerificationFailure.None;

        foreach (JsonElement failure in failures.EnumerateArray())
        {
            expected |= failure.GetString() switch
            {
                "BlockCrc" => ManifestVerificationFailure.BlockCrc,
                "LogicalTotals" => ManifestVerificationFailure.LogicalTotals,
                "ManifestId" => ManifestVerificationFailure.ManifestId,
                "FileDigest" => ManifestVerificationFailure.FileDigest,
                "ProfileSemantics" => ManifestVerificationFailure.ProfileSemantics,
                string other => throw new InvalidOperationException(
                    $"Unknown failure name '{other}' in vectors.json."),
                null => throw new InvalidOperationException(
                    "Null failure name in vectors.json."),
            };
        }

        return expected;
    }

    private static string FixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, FixtureDirectory, fileName);
}
