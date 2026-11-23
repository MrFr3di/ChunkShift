using System.Reflection;
using ChunkShift.Patching.Hashing;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// Builds the negative case of the re-chunk check (CSP-V1 section 9.5):
/// a valid manifest of the registered profile whose record lengths are not
/// the cuts that profile makes. Every record still hashes to its content, so
/// only the re-chunk check can reject it.
/// </summary>
/// <remarks>
/// No public Core API writes a manifest with chosen boundaries, and the
/// committed CSP vectors are frozen, so the helper drives Core's internal
/// CSM encoder by reflection, the way a producer with its own chunker would
/// write the same bytes.
/// </remarks>
internal static class RecutManifests
{
    private const BindingFlags Internal =
        BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance;

    /// <summary>
    /// Returns a manifest of <paramref name="content"/> that is the profile's
    /// own manifest except that its first record is cut in two halves.
    /// </summary>
    internal static async Task<byte[]> SplitFirstRecordAsync(byte[] content, HashSuiteId hashSuite)
    {
        byte[] canonical = await Creation.CreationTestSupport.CreateManifestAsync(content, hashSuite);
        ManifestVerificationResult verified = await ChunkManifest.VerifyManifestAsync(
            new MemoryStream(canonical, writable: false));
        Assert.True(verified.IsValid);
        List<ChunkInfo> records = await Creation.CreationTestSupport.ReadRecordsAsync(canonical);
        Assert.True(records[0].Length >= 2, "The first record cannot be split.");

        var cuts = new List<int> { records[0].Length / 2, records[0].Length - (records[0].Length / 2) };
        cuts.AddRange(records.Skip(1).Select(static record => record.Length));

        byte[] recut = await WriteAsync(
            content,
            cuts,
            hashSuite,
            verified.Manifest.ProfileId,
            verified.Manifest.ProfileFingerprint);

        // The manifest is well formed and of the registered profile; only
        // re-chunking the content tells it apart.
        Assert.True((await ChunkManifest.VerifyManifestAsync(
            new MemoryStream(recut, writable: false))).IsValid);
        Assert.Equal(
            ManifestVerificationFailure.Content,
            (await ChunkManifest.VerifyAsync(
                new MemoryStream(content, writable: false),
                new MemoryStream(recut, writable: false))).Failures);

        return recut;
    }

    /// <summary>
    /// Writes a manifest of <paramref name="content"/> with the given record
    /// lengths, profile and fingerprint; every record hashes to its content.
    /// </summary>
    internal static Task<byte[]> WriteAsync(
        byte[] content,
        IReadOnlyList<int> cuts,
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint fingerprint)
    {
        var records = new List<(ChunkId Id, int Length)>(cuts.Count);
        int offset = 0;

        foreach (int length in cuts)
        {
            records.Add((new ChunkId(PatchHashing.Hash(hashSuite, content.AsSpan(offset, length))), length));
            offset += length;
        }

        Assert.Equal(content.Length, offset);
        return WriteRecordsAsync(records, hashSuite, profileId, fingerprint);
    }

    /// <summary>
    /// Writes a manifest of exactly the given records. Nothing ties them to
    /// any content, so a test can describe content that cannot exist, such as
    /// one <see cref="ChunkId"/> with two lengths.
    /// </summary>
    internal static async Task<byte[]> WriteRecordsAsync(
        IReadOnlyList<(ChunkId Id, int Length)> records,
        HashSuiteId hashSuite,
        ChunkingProfileId profileId,
        ProfileFingerprint fingerprint)
    {
        Type session = typeof(ChunkManifest).Assembly.GetType(
            "ChunkShift.Manifest.CsmEncoderSession",
            throwOnError: true)!;
        using var destination = new MemoryStream();

        var createTask = (Task)session.GetMethod("CreateAsync", Internal)!.Invoke(
            null,
            [
                destination,
                hashSuite,
                profileId,
                fingerprint,
                false,
                CancellationToken.None,
            ])!;
        await createTask;
        object encoder = createTask.GetType().GetProperty("Result")!.GetValue(createTask)!;

        try
        {
            MethodInfo append = session.GetMethod("AppendAsync", Internal)!;

            foreach ((ChunkId id, int length) in records)
            {
                await (ValueTask)append.Invoke(encoder, [id, (uint)length, CancellationToken.None])!;
            }

            await (Task)session.GetMethod("CompleteAsync", Internal)!.Invoke(
                encoder,
                [CancellationToken.None])!;
        }
        finally
        {
            ((IDisposable)encoder).Dispose();
        }

        return destination.ToArray();
    }
}
