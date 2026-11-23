using System.Security.Cryptography;
using ChunkShift.Patching.Application;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Tests.Format;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// The apply half of the differential test against the independent decoder of
/// <c>tools/conformance/csp/decode.py</c>: every committed vector's verdict and,
/// for verification outcomes, its failure kinds must match, and a valid vector
/// must reconstruct the pinned target bytes (CSP-V1 sections 6 and 10).
/// </summary>
public sealed class ApplyVectorTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-apply-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    /// <summary>
    /// Gets every vector name in <c>vectors.json</c> with every way of running
    /// the re-chunk check: the check must never change a verdict.
    /// </summary>
    public static TheoryData<string, string> Names
    {
        get
        {
            var names = new TheoryData<string, string>();

            foreach (CspApplyVector vector in CspApplyVectors.All)
            {
                foreach (ChunkingCheck check in Enum.GetValues<ChunkingCheck>())
                {
                    names.Add(vector.Name, check.ToString());
                }
            }

            return names;
        }
    }

    [Theory]
    [MemberData(nameof(Names))]
    public async Task Vector_MatchesTheIndependentVerdict(string name, string checkName)
    {
        ChunkingCheck check = Enum.Parse<ChunkingCheck>(checkName);
        CspApplyVector vector = CspApplyVectors.Find(name);
        byte[] patch = CspApplyVectors.ReadPatch(name);
        string destination = Path.Combine(_directory, "output.bin");
        PatchApplyResult? result = null;
        string verdict;
        string[] failures = [];

        using (var patchStream = new MemoryStream(patch, writable: false))
        {
            try
            {
                using MemoryStream? baseManifest = vector.BaseName is null
                    ? null
                    : new MemoryStream(CspApplyVectors.ReadBaseManifest(vector), writable: false);
                using MemoryStream? baseContent = vector.BaseName is null
                    ? null
                    : new MemoryStream(CspApplyVectors.ReadBaseContent(vector), writable: false);

                result = await CspApplier.ApplyAsync(
                    patchStream,
                    baseManifest,
                    baseContent,
                    destination,
                    vector.MaximumPayloadEntries,
                    check,
                    CancellationToken.None);

                verdict = result.IsApplied
                    ? "valid"
                    : (result.Failures & PatchApplyFailure.ResourceLimit) != 0
                        ? "limit"
                        : "verification";
                failures = result.IsApplied ? [] : FailureNames(result.Failures);
            }
            catch (InvalidDataException)
            {
                verdict = "malformed";
            }
            catch (NotSupportedException)
            {
                verdict = "unsupported";
            }
        }

        Assert.Equal(vector.Verdict, verdict);

        if (vector.Verdict == "verification")
        {
            Assert.Equal(
                vector.Failures.Order(StringComparer.Ordinal),
                failures.Order(StringComparer.Ordinal));
        }

        if (vector.Verdict == "valid")
        {
            Assert.NotNull(result);
            Assert.True(result!.IsApplied);
            Assert.NotNull(result.Target);
            Assert.Equal(vector.OutputLength, result.Target!.ContentLength);

            // The returned manifest is the one the reader saw in the patch.
            using var readerStream = new MemoryStream(patch, writable: false);
            CspReader reader = await CspReader.OpenAsync(readerStream);
            Assert.Equal(reader.TargetManifest.Manifest.ManifestId, result.Target.ManifestId);

            byte[] output = File.ReadAllBytes(destination);
            Assert.Equal(vector.OutputLength, output.Length);
            Assert.Equal(
                vector.OutputSha256,
                Convert.ToHexStringLower(SHA256.HashData(output)));

            // The applied target is the only file the operation left behind.
            Assert.Equal([destination], Directory.GetFiles(_directory));
            return;
        }

        // Malformed, unsupported, limit and verification never publish and
        // never leave a temporary file.
        Assert.Empty(Directory.GetFileSystemEntries(_directory));
    }

    [Fact]
    public void TheoryCoversEveryCommittedVector()
    {
        Assert.True(
            CspApplyVectors.All.Count >= 116,
            $"Only {CspApplyVectors.All.Count} vectors were loaded.");

        foreach (CspApplyVector vector in CspApplyVectors.All)
        {
            Assert.True(
                File.Exists(Path.Combine(CspV1Vectors.Directory, vector.Name)),
                $"The vector file for '{vector.Name}' is missing from the test output.");
        }
    }

    private static string[] FailureNames(PatchApplyFailure failures)
    {
        var names = new List<string>();

        // The .NET surface names the patch TRAILER digest PatchFileDigest; the
        // independent decoder calls it FileDigest.
        if ((failures & PatchApplyFailure.PatchFileDigest) != 0)
        {
            names.Add("FileDigest");
        }

        if ((failures & PatchApplyFailure.EmbeddedManifest) != 0)
        {
            names.Add("EmbeddedManifest");
        }

        if ((failures & PatchApplyFailure.ProfileSemantics) != 0)
        {
            names.Add("ProfileSemantics");
        }

        if ((failures & PatchApplyFailure.DuplicatePayload) != 0)
        {
            names.Add("DuplicatePayload");
        }

        if ((failures & PatchApplyFailure.PayloadNotInTarget) != 0)
        {
            names.Add("PayloadNotInTarget");
        }

        if ((failures & PatchApplyFailure.PayloadLength) != 0)
        {
            names.Add("PayloadLength");
        }

        if ((failures & PatchApplyFailure.BaseMismatch) != 0)
        {
            names.Add("BaseMismatch");
        }

        if ((failures & PatchApplyFailure.BaseManifest) != 0)
        {
            names.Add("BaseManifest");
        }

        if ((failures & PatchApplyFailure.BaseChunk) != 0)
        {
            names.Add("BaseChunk");
        }

        if ((failures & PatchApplyFailure.DictionaryChunk) != 0)
        {
            names.Add("DictionaryChunk");
        }

        if ((failures & PatchApplyFailure.PayloadChunk) != 0)
        {
            names.Add("PayloadChunk");
        }

        if ((failures & PatchApplyFailure.MissingPayload) != 0)
        {
            names.Add("MissingPayload");
        }

        if ((failures & PatchApplyFailure.ContentLength) != 0)
        {
            names.Add("ContentLength");
        }

        if ((failures & PatchApplyFailure.ProfileContent) != 0)
        {
            names.Add("ProfileContent");
        }

        if ((failures & PatchApplyFailure.ResourceLimit) != 0)
        {
            names.Add("ResourceLimit");
        }

        return [.. names];
    }
}
