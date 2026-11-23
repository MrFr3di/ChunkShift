using ChunkShift.Patching.Tests.Creation;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// In-place updates, where the destination path is the base file itself
/// (CSP-V1 section 6, step 8).
/// </summary>
public sealed class ApplyInPlaceTests : IDisposable
{
    private readonly string _directory =
        Directory.CreateTempSubdirectory("chunkshift-apply-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task InPlaceUpdate_WithDeleteSharing_ReplacesTheOpenBaseFile()
    {
        (PatchScenario scenario, byte[] baseManifest, byte[] patch) =
            await CreatePatchAsync();
        string path = Path.Combine(_directory, "in-place.bin");
        File.WriteAllBytes(path, scenario.BaseContent);

        using (var baseContent = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete))
        {
            PatchApplyResult result = await ChunkPatch.ApplyAsync(
                new MemoryStream(patch, writable: false),
                new MemoryStream(baseManifest, writable: false),
                baseContent,
                path);

            Assert.True(result.IsApplied);
        }

        Assert.Equal(scenario.TargetContent, File.ReadAllBytes(path));
        Assert.Equal([path], Directory.GetFiles(_directory));
    }

    [Fact]
    public async Task InPlaceUpdate_WithoutDeleteSharing_KeepsTheBaseOnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Sharing modes are Windows-only; a rename replaces an open file elsewhere.
            return;
        }

        (PatchScenario scenario, byte[] baseManifest, byte[] patch) =
            await CreatePatchAsync();
        string path = Path.Combine(_directory, "locked.bin");
        File.WriteAllBytes(path, scenario.BaseContent);

        using (var baseContent = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read))
        {
            Exception? error = await Record.ExceptionAsync(() => ChunkPatch.ApplyAsync(
                new MemoryStream(patch, writable: false),
                new MemoryStream(baseManifest, writable: false),
                baseContent,
                path));

            Assert.True(
                error is IOException or UnauthorizedAccessException,
                $"The publication threw {error?.GetType().FullName ?? "nothing"}.");
        }

        Assert.Equal(scenario.BaseContent, File.ReadAllBytes(path));
        Assert.Equal([path], Directory.GetFiles(_directory));
    }

    private static async Task<(PatchScenario Scenario, byte[] BaseManifest, byte[] Patch)>
        CreatePatchAsync()
    {
        PatchScenario scenario = PatchScenarios.Find(PatchScenarios.Inserted);
        byte[] baseManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.BaseContent,
            HashSuiteIds.Sha256V1);
        byte[] targetManifest = await CreationTestSupport.CreateManifestAsync(
            scenario.TargetContent,
            HashSuiteIds.Sha256V1);
        (byte[] patch, _) = await CreationTestSupport.CreatePatchAsync(
            scenario,
            baseManifest,
            targetManifest);

        return (scenario, baseManifest, patch);
    }
}
