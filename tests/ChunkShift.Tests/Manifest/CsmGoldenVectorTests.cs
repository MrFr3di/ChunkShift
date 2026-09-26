using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class CsmGoldenVectorTests
{
    private static readonly GoldenVector[] GoldenVectors =
    [
        new(
            "empty-sha256-no-bidx.csm",
            "ab0c32c4052ea59a35569b20b23f8d3d0156d3aca59c431a70ba5f365f66a12c",
            "7b7fbf21a433c37590b6b9273a6249341a04226174369e685bd6557ecffa32ab",
            0,
            0,
            340,
            0,
            false),
        new(
            "one-entry-sha256-no-bidx.csm",
            "7add187663e900912f9438fcf3a3fc13a826937a188cd377e32aa145ed9b3606",
            "2339a525f39e5959d8855fb746e2930cd1dffc8ddc742b0d5626aad691de8cd4",
            1,
            28,
            420,
            1,
            false),
        new(
            "multiblock-sha256-no-bidx.csm",
            "b93a7868fd0714e2ecde57303f9df466e7695677d3d79e88f443d49b55cd82e6",
            "abba97ae65253ee7e6b42dd6ca82da3b170d5822e3bdf8feaf682e80f9b2580c",
            4097,
            8_390_657,
            147_920,
            2,
            false),
        new(
            "multiblock-sha256-bidx.csm",
            "b93a7868fd0714e2ecde57303f9df466e7695677d3d79e88f443d49b55cd82e6",
            "9a4ca2a47086c5de0e6556fbe61ad33f1b4127e6079eb9121dae340e9c9b3d25",
            4097,
            8_390_657,
            147_976,
            2,
            true),
    ];

    [Fact]
    public async Task IndependentGoldenVectors_AreAcceptedWithExpectedIdentity()
    {
        foreach (GoldenVector vector in GoldenVectors)
        {
            byte[] bytes = File.ReadAllBytes(
                GetFixturePath(vector.FileName));

            CsmReadResult result = await CsmReader.ReadAndVerifyAsync(
                new MemoryStream(bytes, writable: false));

            Assert.True(result.IsValid);
            Assert.Equal(
                vector.ManifestId,
                result.StoredManifestId.ToString());
            Assert.Equal(
                vector.ManifestId,
                result.ComputedManifestId.ToString());
            Assert.Equal(
                vector.FileDigest,
                result.StoredFileDigest.ToHexLower());
            Assert.Equal(
                vector.FileDigest,
                result.ComputedFileDigest.ToHexLower());
            Assert.Equal(vector.ChunkCount, result.ChunkCount);
            Assert.Equal(vector.ContentLength, result.ContentLength);
            Assert.Equal(vector.PhysicalLength, result.PhysicalLength);
            Assert.Equal(vector.ChunkBlockCount, result.ChunkBlockCount);
            Assert.Equal(vector.HasBlockIndex, result.HasBlockIndex);
        }
    }

    [Fact]
    public async Task ProductionEncoder_IsByteExactWithIndependentGoldenVectors()
    {
        foreach (GoldenVector vector in GoldenVectors)
        {
            byte[] expected = File.ReadAllBytes(
                GetFixturePath(vector.FileName));
            byte[] actual = await EncodeWithProductionAsync(
                vector.FileName);

            Assert.Equal(expected, actual);
        }
    }

    private static async Task<byte[]> EncodeWithProductionAsync(
        string fileName)
    {
        using var destination = new MemoryStream();

        var profileId =
            new ChunkingProfileId("fixture.csm.synthetic.v1");
        ProfileFingerprint fingerprint = new(
            HashSuiteHasher.Hash(
                HashSuiteIds.Sha256V1,
                "chunkshift.csm.fixture.profile.v1"u8));

        using CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                destination,
                HashSuiteIds.Sha256V1,
                profileId,
                fingerprint,
                includeBlockIndex:
                    fileName == "multiblock-sha256-bidx.csm",
                CancellationToken.None);

        if (fileName == "one-entry-sha256-no-bidx.csm")
        {
            byte[] payload =
                "hello chunkshift csm fixture"u8.ToArray();
            ChunkId chunkId = new(
                HashSuiteHasher.Hash(
                    HashSuiteIds.Sha256V1,
                    payload));

            await encoder.AppendAsync(
                chunkId,
                checked((uint)payload.Length),
                CancellationToken.None);
        }
        else if (fileName.StartsWith(
            "multiblock-sha256-",
            StringComparison.Ordinal))
        {
            for (int index = 0; index < 4097; index++)
            {
                byte[] payload = Encoding.ASCII.GetBytes(
                    $"chunk-{index}");
                ChunkId chunkId = new(
                    HashSuiteHasher.Hash(
                        HashSuiteIds.Sha256V1,
                        payload));

                await encoder.AppendAsync(
                    chunkId,
                    checked((uint)((index % 4096) + 1)),
                    CancellationToken.None);
            }
        }

        _ = await encoder.CompleteAsync(
            CancellationToken.None);

        return destination.ToArray();
    }

    private static string GetFixturePath(string fileName) =>
        Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "CsmV1",
            fileName);

    private readonly record struct GoldenVector(
        string FileName,
        string ManifestId,
        string FileDigest,
        ulong ChunkCount,
        ulong ContentLength,
        ulong PhysicalLength,
        ulong ChunkBlockCount,
        bool HasBlockIndex);
}
