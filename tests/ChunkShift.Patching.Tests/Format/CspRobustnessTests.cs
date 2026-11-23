using System.Buffers.Binary;
using ChunkShift.Patching.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Format;

/// <summary>
/// Exception discipline for hostile input: whatever a mutated CSP artifact
/// declares, <see cref="CspReader.OpenAsync(Stream, CancellationToken)"/>
/// either opens or throws malformed, unsupported or limit — never an index,
/// overflow, end-of-stream or null-reference exception.
/// </summary>
public sealed class CspRobustnessTests
{
    [Fact]
    public async Task EveryPrefix_OpensOrThrowsADocumentedException()
    {
        byte[] patch = await CreateRobustnessPatchAsync();

        CspReader pristine = await OpenAsync(patch);
        Assert.Equal(CspVerificationFailure.DuplicatePayload, pristine.Failures);

        for (int length = 0; length < patch.Length; length++)
        {
            await OpenExpectingDisciplineAsync(patch.AsSpan(0, length).ToArray());
        }
    }

    [Fact]
    public async Task EverySingleByteFlip_OpensOrThrowsADocumentedException()
    {
        byte[] patch = await CreateRobustnessPatchAsync();

        for (int position = 0; position < patch.Length; position++)
        {
            byte[] mutated = (byte[])patch.Clone();
            mutated[position] ^= 0x5A;
            await OpenExpectingDisciplineAsync(mutated);
        }
    }

    [Fact]
    public async Task PaylPayloadLengthClaimingTwoGiB_FailsTheFitCheck()
    {
        byte[] patch = await CreateRobustnessPatchAsync();
        CspSectionInfo payl = CspBytes.FindSection(patch, CspFormat.Payload);

        BinaryPrimitives.WriteUInt64LittleEndian(
            patch.AsSpan(payl.Offset + 8, sizeof(ulong)),
            2UL * 1024 * 1024 * 1024);

        using var stream = new MemoryStream(patch, writable: false);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => CspReader.OpenAsync(stream));
    }

    [Fact]
    public async Task TcsmPayloadLengthZero_IsMalformed()
    {
        byte[] patch = new CspPatchBuilder
        {
            HashSuite = HashSuiteIds.Sha256V1,
            TargetManifest = [],
        }.Build();

        using var stream = new MemoryStream(patch, writable: false);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => CspReader.OpenAsync(stream));
    }

    /// <summary>
    /// A structurally complete, small patch: a real one-record target, a
    /// <c>BASE</c> and three raw entries. The three entries name one target
    /// chunk, so the reader reports <c>DuplicatePayload</c>; the tests care
    /// about the exception discipline over every byte, not about that verdict.
    /// </summary>
    private static async Task<byte[]> CreateRobustnessPatchAsync()
    {
        HashSuiteId suite = HashSuiteIds.Sha256V1;
        byte[] content = CspBytes.CreateXorShiftBytes(256, 0x0B05u);
        byte[] targetManifest = await CspBytes.CreateCsmAsync(
            suite,
            content.Length,
            0x0B05u);
        IReadOnlyList<ChunkInfo> records = await ReadRecordsAsync(targetManifest);
        Assert.Single(records);
        ChunkInfo record = records[0];
        byte[] stored = content.AsSpan(
            checked((int)record.Offset),
            record.Length).ToArray();

        CspPatchEntry[] entries =
        [
            new(record.Id, 0, CspFormat.EncodingRaw, stored, []),
            new(record.Id, 1, CspFormat.EncodingRaw, stored, []),
            new(record.Id, 2, CspFormat.EncodingRaw, stored, []),
        ];

        return new CspPatchBuilder
        {
            HashSuite = suite,
            TargetManifest = targetManifest,
            ExpectedBase = new ManifestId(
                Hash256.FromBytes(CspBytes.CreateXorShiftBytes(32, 0xBA5E04u))),
        }.AddEntries(entries).Build();
    }

    private static async Task<CspReader> OpenAsync(byte[] patch)
    {
        var stream = new MemoryStream(patch, writable: false);
        return await CspReader.OpenAsync(stream);
    }

    private static async Task OpenExpectingDisciplineAsync(byte[] patch)
    {
        using var stream = new MemoryStream(patch, writable: false);

        try
        {
            CspReader reader = await CspReader.OpenAsync(stream);

            _ = reader.IsValid;
            _ = reader.Index.Count;
            _ = reader.PayloadChunkIds.Count;
            _ = reader.TargetManifest.Manifest.ManifestId;
        }
        catch (InvalidDataException)
        {
        }
        catch (NotSupportedException)
        {
        }
        catch (CspResourceLimitException)
        {
        }
    }

    private static async Task<IReadOnlyList<ChunkInfo>> ReadRecordsAsync(
        byte[] targetManifest)
    {
        using var stream = new MemoryStream(targetManifest, writable: false);
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
