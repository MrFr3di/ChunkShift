using ChunkShift.Patching.Hashing;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Hashing;

public sealed class PatchHashingTests
{
    // Five entries of Blake3OfficialVectors copied verbatim from
    // tests/ChunkShift.Tests/Hashing/HashVectors.cs.
    public static TheoryData<int, string> Blake3Data { get; } = CreateBlake3Data();

    [Theory]
    [MemberData(nameof(Blake3Data))]
    public void Blake3_OfficialVectors_MatchOneShotAndIncremental(int length, string expected)
    {
        byte[] input = CreateInput(length);

        Assert.Equal(
            expected,
            PatchHashing.Hash(HashSuiteIds.Blake3256V1, input).ToHexLower());

        using IncrementalPatchHash incremental =
            PatchHashing.CreateIncremental(HashSuiteIds.Blake3256V1);
        incremental.Append(input);

        Assert.Equal(expected, incremental.FinalizeHash().ToHexLower());
    }

    [Fact]
    public void Sha256_Abc_MatchesStandardVector()
    {
        byte[] input = System.Text.Encoding.ASCII.GetBytes("abc");

        Assert.Equal(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            PatchHashing.Hash(HashSuiteIds.Sha256V1, input).ToHexLower());
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task ScannedChunkIds_MatchPatchHashing(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] input = CspBytes.CreateXorShiftBytes(3 * 1024 * 1024, 0x5CA11E5u);
        var chunks = new List<(ChunkInfo Info, byte[] Content)>();

        await ChunkScanner.ScanAsync(
            new MemoryStream(input, writable: false),
            (chunk, content, _) =>
            {
                chunks.Add((chunk, content.ToArray()));
                return ValueTask.CompletedTask;
            },
            new ChunkScanOptions { HashSuite = suite });

        Assert.NotEmpty(chunks);

        foreach ((ChunkInfo info, byte[] content) in chunks)
        {
            Assert.Equal(info.Id.Value, PatchHashing.Hash(suite, content));
        }
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task CsmFileDigest_MatchesPatchHashing(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] input = CspBytes.CreateXorShiftBytes(1024 * 1024, 0xC5A5EEDu);
        using var destination = new MemoryStream();

        ManifestInfo info = await ChunkManifest.CreateAsync(
            new MemoryStream(input, writable: false),
            destination,
            new ManifestCreationOptions { HashSuite = suite });

        byte[] csm = destination.ToArray();

        Assert.Equal(
            info.FileDigest,
            PatchHashing.Hash(suite, csm.AsSpan(0, csm.Length - 64)));
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public void IncrementalRandomPieces_MatchOneShot(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        byte[] input = CspBytes.CreateXorShiftBytes(256 * 1024, 0x1EC0DEu);
        Hash256 expected = PatchHashing.Hash(suite, input);
        var random = new Random(0x5EED);

        using IncrementalPatchHash incremental = PatchHashing.CreateIncremental(suite);
        int offset = 0;

        while (offset < input.Length)
        {
            int length = Math.Min(input.Length - offset, random.Next(1, 8192));
            incremental.Append(input.AsSpan(offset, length));
            offset += length;
        }

        Assert.Equal(expected, incremental.FinalizeHash());
    }

    [Fact]
    public void UnsupportedSuite_IsRejected()
    {
        var unsupported = new HashSuiteId("test.unsupported.v1");

        Assert.False(PatchHashing.IsSupported(unsupported));
        Assert.Throws<NotSupportedException>(
            () => PatchHashing.Hash(unsupported, ReadOnlySpan<byte>.Empty));
        Assert.Throws<NotSupportedException>(
            () => PatchHashing.CreateIncremental(unsupported));
    }

    [Fact]
    public void NullSuite_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => PatchHashing.IsSupported(null!));
        Assert.Throws<ArgumentNullException>(
            () => PatchHashing.Hash(null!, ReadOnlySpan<byte>.Empty));
        Assert.Throws<ArgumentNullException>(
            () => PatchHashing.CreateIncremental(null!));
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public void IncrementalMisuse_Throws(string hashSuite)
    {
        var suite = new HashSuiteId(hashSuite);
        var probe = new byte[] { 1, 2, 3 };
        IncrementalPatchHash incremental = PatchHashing.CreateIncremental(suite);
        incremental.Append(probe);
        _ = incremental.FinalizeHash();

        Assert.Throws<InvalidOperationException>(() => incremental.Append(probe));
        Assert.Throws<InvalidOperationException>(() => incremental.FinalizeHash());

        incremental.Dispose();

        Assert.Throws<ObjectDisposedException>(() => incremental.Append(probe));
        Assert.Throws<ObjectDisposedException>(() => incremental.FinalizeHash());
    }

    // The input generator of tests/ChunkShift.Tests/Hashing/HashVectors.cs.
    private static byte[] CreateInput(int length)
    {
        var input = new byte[length];

        for (int i = 0; i < input.Length; i++)
        {
            input[i] = (byte)(i % 251);
        }

        return input;
    }

    private static TheoryData<int, string> CreateBlake3Data()
    {
        var data = new TheoryData<int, string>
        {
            { 0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" },
            { 1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213" },
            { 1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11" },
            { 1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7" },
            { 1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444" },
        };

        return data;
    }
}
