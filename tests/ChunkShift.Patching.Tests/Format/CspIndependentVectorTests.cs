using System.Text.Json;
using ChunkShift.Patching.Format;

namespace ChunkShift.Patching.Tests.Format;

/// <summary>
/// Differential test against the independent decoder of
/// <c>tools/conformance/csp/decode.py</c>: every committed vector's verdict and,
/// for the structure stage, its failure kinds must match
/// (CSP-V1 sections 6 and 10).
/// </summary>
public sealed class CspIndependentVectorTests
{
    /// <summary>Gets every vector name in <c>vectors.json</c>.</summary>
    public static TheoryData<string> Names
    {
        get
        {
            var names = new TheoryData<string>();

            foreach (CspV1Vector vector in CspV1Vectors.All)
            {
                names.Add(vector.Name);
            }

            return names;
        }
    }

    [Theory]
    [MemberData(nameof(Names))]
    public async Task Vector_MatchesTheIndependentVerdict(string name)
    {
        CspV1Vector vector = CspV1Vectors.Find(name);
        byte[] patch = CspV1Vectors.Read(name);
        using var stream = new MemoryStream(patch, writable: false);
        CspReader? reader = null;
        string verdict;
        string[] failures = [];

        try
        {
            reader = await CspReader.OpenAsync(stream, vector.MaximumPayloadEntries);

            if (reader.Failures == CspVerificationFailure.None)
            {
                verdict = "accepted";
            }
            else
            {
                verdict = "verification";
                failures = FailureNames(reader.Failures);
            }
        }
        catch (InvalidDataException)
        {
            verdict = "malformed";
        }
        catch (NotSupportedException)
        {
            verdict = "unsupported";
        }
        catch (CspResourceLimitException)
        {
            verdict = "limit";
        }

        if (vector.Stage == "structure")
        {
            Assert.Equal(vector.Verdict, verdict);

            if (vector.Verdict == "verification")
            {
                Assert.Equal(
                    vector.Failures.Order(StringComparer.Ordinal),
                    failures.Order(StringComparer.Ordinal));
            }

            return;
        }

        // Apply-stage failures need the base or the reconstruction, which this
        // reader deliberately does not perform; every apply vector must open.
        Assert.Equal("accepted", verdict);

        if (vector.Verdict == "valid")
        {
            Assert.NotNull(reader);
            Assert.Equal(vector.DependsOnBase, reader!.DependsOnBase);
            Assert.True(reader.TargetManifest.IsValid);
        }
    }

    [Fact]
    public void TheoryCoversEveryCommittedVectorAndTheStructureStage()
    {
        string path = Path.Combine(CspV1Vectors.Directory, "vectors.json");
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));

        var jsonNames = document.RootElement
            .GetProperty("vectors")
            .EnumerateObject()
            .Select(property => property.Name)
            .ToList();
        var theoryNames = CspV1Vectors.All
            .Select(vector => vector.Name)
            .ToList();

        Assert.Equal(jsonNames.Count, theoryNames.Count);
        Assert.Empty(jsonNames.Except(theoryNames, StringComparer.Ordinal));
        Assert.Empty(theoryNames.Except(jsonNames, StringComparer.Ordinal));

        int structureVectors = CspV1Vectors.All.Count(
            vector => vector.Stage == "structure");
        Assert.True(
            structureVectors >= 76,
            $"Only {structureVectors} structure vectors are committed.");

        foreach (CspV1Vector vector in CspV1Vectors.All)
        {
            Assert.True(
                File.Exists(Path.Combine(CspV1Vectors.Directory, vector.Name)),
                $"The vector file for '{vector.Name}' is missing from the test output.");
        }
    }

    private static string[] FailureNames(CspVerificationFailure failures)
    {
        var names = new List<string>();

        if ((failures & CspVerificationFailure.FileDigest) != 0)
        {
            names.Add("FileDigest");
        }

        if ((failures & CspVerificationFailure.EmbeddedManifest) != 0)
        {
            names.Add("EmbeddedManifest");
        }

        if ((failures & CspVerificationFailure.ProfileSemantics) != 0)
        {
            names.Add("ProfileSemantics");
        }

        if ((failures & CspVerificationFailure.DuplicatePayload) != 0)
        {
            names.Add("DuplicatePayload");
        }

        if ((failures & CspVerificationFailure.PayloadNotInTarget) != 0)
        {
            names.Add("PayloadNotInTarget");
        }

        if ((failures & CspVerificationFailure.PayloadLength) != 0)
        {
            names.Add("PayloadLength");
        }

        return [.. names];
    }
}

/// <summary>One entry of the committed <c>vectors.json</c>.</summary>
/// <param name="Name">Vector file name, relative to the fixture directory.</param>
/// <param name="Stage">The independent decoder stage that decides the vector.</param>
/// <param name="Verdict">Expected verdict: valid, malformed, unsupported, verification or limit.</param>
/// <param name="Failures">Expected failure names of a verification verdict.</param>
/// <param name="DependsOnBase">Expected base dependence of a valid apply vector.</param>
/// <param name="MaximumPayloadEntries">Configured payload-entry limit for the vector.</param>
internal sealed record CspV1Vector(
    string Name,
    string Stage,
    string Verdict,
    string[] Failures,
    bool DependsOnBase,
    int MaximumPayloadEntries);

/// <summary>Loads the committed CSP v1 vectors and their expected verdicts.</summary>
internal static class CspV1Vectors
{
    private static readonly Dictionary<string, CspV1Vector> ByName =
        Load().ToDictionary(vector => vector.Name, StringComparer.Ordinal);

    /// <summary>Gets the directory that holds the copied fixtures.</summary>
    internal static string Directory =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "CspV1");

    /// <summary>Gets every vector in the order of <c>vectors.json</c>.</summary>
    internal static IReadOnlyList<CspV1Vector> All { get; } = [.. ByName.Values];

    internal static CspV1Vector Find(string name) => ByName[name];

    internal static byte[] Read(string name) =>
        File.ReadAllBytes(Path.Combine(Directory, name));

    private static List<CspV1Vector> Load()
    {
        string path = Path.Combine(Directory, "vectors.json");
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(path));
        var vectors = new List<CspV1Vector>();

        foreach (JsonProperty property in document.RootElement
            .GetProperty("vectors")
            .EnumerateObject())
        {
            JsonElement expect = property.Value.GetProperty("expect");
            string[] failures = [];

            if (expect.TryGetProperty("failures", out JsonElement failureElement))
            {
                failures = [.. failureElement
                    .EnumerateArray()
                    .Select(item => item.GetString()!)];
            }

            vectors.Add(new CspV1Vector(
                property.Name,
                property.Value.GetProperty("stage").GetString()!,
                expect.GetProperty("verdict").GetString()!,
                failures,
                expect.TryGetProperty("dependsOnBase", out JsonElement dependsElement) &&
                    dependsElement.GetBoolean(),
                property.Value.TryGetProperty("maxPayloadEntries", out JsonElement maxElement)
                    ? maxElement.GetInt32()
                    : CspFormat.DefaultMaximumPayloadEntries));
        }

        return vectors;
    }
}
