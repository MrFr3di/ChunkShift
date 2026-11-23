using ChunkShift.Patching.Creation;
using ChunkShift.Patching.Encoding;
using ChunkShift.Patching.Format;
using ChunkShift.Patching.Hashing;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;
using CreationBuilder = ChunkShift.Patching.Creation.CspPatchBuilder;

namespace ChunkShift.Patching.Tests.Creation;

/// <summary>
/// One creation scenario: the base and target content a patch is created for,
/// and whether creation uses the self-contained overload.
/// </summary>
internal sealed record PatchScenario(
    string Name,
    byte[] BaseContent,
    byte[] TargetContent,
    bool SelfContained);

/// <summary>
/// Deterministic creation scenarios shared by the end-to-end tests and the
/// independent-decoder dump.
/// </summary>
internal static class PatchScenarios
{
    private const int Mebibyte = 1024 * 1024;

    internal const string Identical = "identical";
    internal const string Inserted = "inserted";
    internal const string XorRegion = "xor-region";
    internal const string Different = "different";
    internal const string RepeatedBlock = "repeated-block";
    internal const string CompressibleText = "compressible-text";
    internal const string EditedChunks = "edited-chunks";
    internal const string SelfContainedInserted = "self-contained-inserted";

    internal static IReadOnlyList<PatchScenario> All { get; } = Create();

    internal static PatchScenario Find(string name) =>
        All.First(scenario => scenario.Name == name);

    private static PatchScenario[] Create()
    {
        // A 4 KiB insertion in the middle of 3 MiB of xorshift bytes.
        byte[] insertedBase = CspBytes.CreateXorShiftBytes(3 * Mebibyte, 0x5EED1001u);
        byte[] insertedTarget = Insert(
            insertedBase,
            (3 * Mebibyte) / 2,
            CspBytes.CreateXorShiftBytes(4096, 0x5EED1002u));

        // A 50 KiB region of 3 MiB XOR-ed with 0x5A.
        byte[] xorBase = CspBytes.CreateXorShiftBytes(3 * Mebibyte, 0x5EED1003u);
        byte[] xorTarget = (byte[])xorBase.Clone();
        ApplyXorRegion(xorTarget, Mebibyte, 50 * 1024, 0x5A);

        // Completely different content.
        byte[] differentBase = CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED1004u);
        byte[] differentTarget = CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED1005u);

        // The same 64 KiB block repeated.
        byte[] repeatedBlock = CspBytes.CreateXorShiftBytes(64 * 1024, 0x5EED1006u);
        byte[] repeatedBase = CspBytes.CreateXorShiftBytes(512 * 1024, 0x5EED1007u);
        byte[] repeatedTarget = Repeat(repeatedBlock, 8);

        // A compressible target of repeated text.
        byte[] textBase = CspBytes.CreateXorShiftBytes(512 * 1024, 0x5EED1008u);
        byte[] textTarget = RepeatedText();

        // Small edits inside chunks of 1 MiB: one byte each at four offsets.
        byte[] editedBase = CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED1009u);
        byte[] editedTarget = (byte[])editedBase.Clone();

        foreach (int offset in (int[])[30_000, 300_000, 700_000, 900_000])
        {
            editedTarget[offset] ^= 0x5A;
        }

        byte[] identical = CspBytes.CreateXorShiftBytes(Mebibyte, 0x5EED100Au);

        return
        [
            new PatchScenario(Identical, identical, (byte[])identical.Clone(), SelfContained: false),
            new PatchScenario(Inserted, insertedBase, insertedTarget, SelfContained: false),
            new PatchScenario(XorRegion, xorBase, xorTarget, SelfContained: false),
            new PatchScenario(Different, differentBase, differentTarget, SelfContained: false),
            new PatchScenario(RepeatedBlock, repeatedBase, repeatedTarget, SelfContained: false),
            new PatchScenario(CompressibleText, textBase, textTarget, SelfContained: false),
            new PatchScenario(EditedChunks, editedBase, editedTarget, SelfContained: false),
            new PatchScenario(SelfContainedInserted, insertedBase, insertedTarget, SelfContained: true),
        ];
    }

    private static byte[] Insert(byte[] content, int offset, byte[] inserted)
    {
        var result = new byte[content.Length + inserted.Length];
        content.AsSpan(0, offset).CopyTo(result);
        inserted.CopyTo(result, offset);
        content.AsSpan(offset).CopyTo(result.AsSpan(offset + inserted.Length));
        return result;
    }

    private static void ApplyXorRegion(byte[] content, int offset, int length, byte value)
    {
        for (int index = offset; index < offset + length; index++)
        {
            content[index] ^= value;
        }
    }

    private static byte[] Repeat(byte[] block, int count)
    {
        var result = new byte[block.Length * count];

        for (int index = 0; index < count; index++)
        {
            block.CopyTo(result, index * block.Length);
        }

        return result;
    }

    private static byte[] RepeatedText()
    {
        var text = new System.Text.StringBuilder();
        const string Line =
            "ChunkShift CSP patch creation scenario: repeated text compresses well with zstd.\n";

        while (text.Length < 512 * 1024)
        {
            _ = text.Append(Line);
        }

        return System.Text.Encoding.UTF8.GetBytes(text.ToString());
    }
}

/// <summary>
/// Shared helpers for the creation tests: Core manifest creation, record reads,
/// public and internal patch creation, and an independent in-test applier.
/// </summary>
internal static class CreationTestSupport
{
    internal static async Task<byte[]> CreateManifestAsync(
        byte[] content,
        HashSuiteId hashSuite)
    {
        using var destination = new MemoryStream();

        await ChunkManifest.CreateAsync(
            new MemoryStream(content, writable: false),
            destination,
            new ManifestCreationOptions { HashSuite = hashSuite },
            CancellationToken.None);

        return destination.ToArray();
    }

    internal static async Task<List<ChunkInfo>> ReadRecordsAsync(byte[] manifest)
    {
        using var stream = new MemoryStream(manifest, writable: false);
        return await ReadRecordsAsync(stream);
    }

    internal static async Task<List<ChunkInfo>> ReadRecordsAsync(Stream manifest)
    {
        await using ManifestReader reader = await ManifestReader.OpenAsync(manifest);
        var records = new List<ChunkInfo>();
        var batch = new ChunkInfo[256];
        int count;

        while ((count = await reader.ReadAsync(batch)) != 0)
        {
            for (int index = 0; index < count; index++)
            {
                records.Add(batch[index]);
            }
        }

        Assert.NotNull(reader.VerificationResult);
        return records;
    }

    /// <summary>
    /// Creates a patch through the public API and returns its bytes, leaving the
    /// destination owned by this helper.
    /// </summary>
    internal static async Task<(byte[] Patch, PatchInfo Info)> CreatePatchAsync(
        PatchScenario scenario,
        byte[] baseManifest,
        byte[] targetManifest)
    {
        using var destination = new MemoryStream();
        PatchInfo info;

        if (scenario.SelfContained)
        {
            info = await ChunkPatch.CreateAsync(
                new MemoryStream(targetManifest, writable: false),
                new MemoryStream(scenario.TargetContent, writable: false),
                destination);
        }
        else
        {
            info = await ChunkPatch.CreateAsync(
                new MemoryStream(baseManifest, writable: false),
                new MemoryStream(scenario.BaseContent, writable: false),
                new MemoryStream(targetManifest, writable: false),
                new MemoryStream(scenario.TargetContent, writable: false),
                destination);
        }

        return (destination.ToArray(), info);
    }

    /// <summary>
    /// Creates a patch through the internal builder with an explicit policy.
    /// </summary>
    internal static async Task<byte[]> CreatePatchWithPolicyAsync(
        PatchScenario scenario,
        byte[] baseManifest,
        byte[] targetManifest,
        CspEncoderPolicy policy)
    {
        using var destination = new MemoryStream();
        _ = await CreationBuilder.CreateAsync(
            new MemoryStream(baseManifest, writable: false),
            new MemoryStream(scenario.BaseContent, writable: false),
            new MemoryStream(targetManifest, writable: false),
            new MemoryStream(scenario.TargetContent, writable: false),
            destination,
            policy,
            CancellationToken.None);

        return destination.ToArray();
    }

    internal static async Task<CspReader> OpenAsync(byte[] patch)
    {
        var stream = new MemoryStream(patch, writable: false);
        CspReader reader = await CspReader.OpenAsync(stream);
        Assert.Equal(CspVerificationFailure.None, reader.Failures);
        return reader;
    }

    internal static async Task<List<ChunkInfo>> ReadTargetRecordsAsync(CspReader reader)
    {
        using Stream manifest = reader.OpenTargetManifest();
        return await ReadRecordsAsync(manifest);
    }

    /// <summary>
    /// Independent in-test applier: resolves every target record from the base by
    /// <see cref="ChunkId"/> or from a payload entry decoded with
    /// <see cref="CspPayloadDecoder"/> and the named dictionary chunks read from
    /// the base content.
    /// </summary>
    internal static async Task<byte[]> ReconstructAsync(
        byte[] patch,
        byte[]? baseManifest,
        byte[]? baseContent)
    {
        CspReader reader = await OpenAsync(patch);
        List<ChunkInfo> targetRecords = await ReadTargetRecordsAsync(reader);
        HashSuiteId hashSuite = reader.TargetManifest.Manifest.HashSuite;

        var ordinals = new Dictionary<ChunkId, int>();

        for (int index = 0; index < reader.PayloadChunkIds.Count; index++)
        {
            _ = ordinals.TryAdd(reader.PayloadChunkIds[index], index);
        }

        var baseChunks = new Dictionary<ChunkId, ChunkInfo>();

        if (baseManifest is not null)
        {
            foreach (ChunkInfo record in await ReadRecordsAsync(baseManifest))
            {
                _ = baseChunks.TryAdd(record.Id, record);
            }
        }

        using var decoder = new CspPayloadDecoder();
        using var output = new MemoryStream();
        byte[] decoded = [];

        foreach (ChunkInfo record in targetRecords)
        {
            byte[] chunk;

            if (ordinals.TryGetValue(record.Id, out int ordinal))
            {
                CspEntry entry = await reader.ReadEntryAsync(ordinal);
                byte[] dictionary = entry.DictionaryChunkIds.Length == 0
                    ? []
                    : ReadDictionary(entry.DictionaryChunkIds, baseChunks, baseContent!);

                if (decoded.Length < record.Length)
                {
                    decoded = new byte[record.Length];
                }

                decoder.Decode(
                    entry.Encoding,
                    entry.StoredBytes,
                    dictionary,
                    decoded.AsSpan(0, record.Length));
                chunk = decoded.AsSpan(0, record.Length).ToArray();
            }
            else
            {
                ChunkInfo baseRecord = baseChunks[record.Id];
                chunk = baseContent!
                    .AsSpan(checked((int)baseRecord.Offset), baseRecord.Length)
                    .ToArray();
            }

            Assert.Equal(record.Length, chunk.Length);
            Assert.Equal(record.Id.Value, PatchHashing.Hash(hashSuite, chunk));
            output.Write(chunk, 0, chunk.Length);
        }

        return output.ToArray();
    }

    internal static byte[] ReadDictionary(
        ChunkId[] dictionaryIds,
        Dictionary<ChunkId, ChunkInfo> baseChunks,
        byte[] baseContent)
    {
        int length = 0;

        foreach (ChunkId id in dictionaryIds)
        {
            length = checked(length + baseChunks[id].Length);
        }

        var dictionary = new byte[length];
        int offset = 0;

        foreach (ChunkId id in dictionaryIds)
        {
            ChunkInfo record = baseChunks[id];
            baseContent
                .AsSpan(checked((int)record.Offset), record.Length)
                .CopyTo(dictionary.AsSpan(offset));
            offset += record.Length;
        }

        return dictionary;
    }
}
