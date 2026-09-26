using System.Buffers.Binary;
using ChunkShift.Hashing;
using ChunkShift.Manifest;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Manifest;

public sealed class ManifestReaderTests
{
    [Fact]
    public async Task SmallBatches_TraverseAcrossChunkBlockBoundary()
    {
        const int entryCount = 4097;
        using var manifest = new MemoryStream();
        await EncodeSyntheticManifestAsync(manifest, entryCount);
        manifest.Position = 0;

        await using ManifestReader reader =
            await ManifestReader.OpenAsync(manifest);

        var batch = new ChunkInfo[7];
        long count = 0;
        long offset = 0;

        while (true)
        {
            int read = await reader.ReadAsync(batch);
            if (read == 0)
            {
                break;
            }

            for (int index = 0; index < read; index++)
            {
                Assert.Equal(count, batch[index].Index);
                Assert.Equal(offset, batch[index].Offset);
                Assert.True(batch[index].Length > 0);

                count++;
                offset = checked(
                    offset + batch[index].Length);
            }
        }

        Assert.Equal((long)entryCount, count);
        Assert.True(reader.IsCompleted);
        Assert.NotNull(reader.VerificationResult);
        Assert.True(reader.VerificationResult.IsValid);
        Assert.Equal(
            (long)entryCount,
            reader.VerificationResult.Manifest.ChunkCount);
        Assert.Equal(
            offset,
            reader.VerificationResult.Manifest.ContentLength);

        Assert.Equal(0, await reader.ReadAsync(batch));
    }

    [Fact]
    public async Task BadFirstBlockCrc_IsFailClosedAndReportedAsResult()
    {
        byte[] source = CreateXorShiftBytes(
            1024 * 1024,
            0xA11CE55u);
        using var encoded = new MemoryStream();

        _ = await ChunkManifest.CreateAsync(
            new MemoryStream(source, writable: false),
            encoded);

        byte[] bytes = encoded.ToArray();
        int blockOffset = FindFirstChunkBlockOffset(bytes);
        int blockLength =
            GetSectionRecordLength(bytes, blockOffset);
        bytes[blockOffset + blockLength - 1] ^= 0x80;

        using var corrupted =
            new MemoryStream(bytes, writable: false);
        await using ManifestReader reader =
            await ManifestReader.OpenAsync(corrupted);

        var destination = new ChunkInfo[16];
        int read = await reader.ReadAsync(destination);

        Assert.Equal(0, read);
        Assert.True(reader.IsCompleted);
        Assert.NotNull(reader.VerificationResult);
        Assert.False(reader.VerificationResult.IsValid);
        Assert.True(
            reader.VerificationResult.Failures.HasFlag(
                ManifestVerificationFailure.BlockCrc));
        Assert.True(
            reader.VerificationResult.Failures.HasFlag(
                ManifestVerificationFailure.FileDigest));
    }

    [Fact]
    public async Task BadMiddleBlockCrc_ExposesOnlyPrecedingBlocks_AndStaysFailClosed()
    {
        // Three CBLKs; only the CRC field of the middle one is damaged, so its
        // entries and the third block are intact. The reader must not resume
        // after the damaged block: a consumer would otherwise see a gap in an
        // apparently contiguous logical stream.
        const int entryCount = (2 * 4096) + 1;
        byte[] bytes = await CsmBytes.CreateSyntheticAsync(
            entryCount,
            includeBlockIndex: true);
        int middle = CsmBytes.FindSection(
            bytes,
            CsmFormat.ChunkBlock,
            occurrence: 1);
        int middleLength = CsmBytes.GetSectionRecordLength(bytes, middle);
        bytes[middle + middleLength - 1] ^= 0x80;
        CsmBytes.RewritePhysicalDigest(bytes);

        await using ManifestReader reader =
            await ManifestReader.OpenAsync(
                new MemoryStream(bytes, writable: false));

        var batch = new ChunkInfo[1000];
        long exposed = 0;
        int read;

        while ((read = await reader.ReadAsync(batch)) != 0)
        {
            for (int index = 0; index < read; index++)
            {
                Assert.Equal(exposed, batch[index].Index);
                exposed++;
            }
        }

        Assert.Equal(4096L, exposed);
        Assert.True(reader.IsCompleted);
        Assert.NotNull(reader.VerificationResult);
        Assert.Equal(
            ManifestVerificationFailure.BlockCrc,
            reader.VerificationResult.Failures);
        Assert.Equal(
            (long)entryCount,
            reader.VerificationResult.Manifest.ChunkCount);
        Assert.Equal(0, await reader.ReadAsync(batch));
    }

    [Fact]
    public async Task EmptyDestination_IsRejectedWithoutConsumingEntries()
    {
        using var manifest = new MemoryStream();
        await EncodeSyntheticManifestAsync(manifest, 3);
        manifest.Position = 0;

        await using ManifestReader reader =
            await ManifestReader.OpenAsync(manifest);

        await Assert.ThrowsAsync<ArgumentException>(
            async () => await reader.ReadAsync(
                Memory<ChunkInfo>.Empty));

        var one = new ChunkInfo[1];
        Assert.Equal(1, await reader.ReadAsync(one));
        Assert.Equal(0L, one[0].Index);
    }

    [Fact]
    public async Task ReaderNeverDisposesCallerOwnedStream()
    {
        byte[] bytes;
        using (var encoded = new MemoryStream())
        {
            await EncodeSyntheticManifestAsync(encoded, 32);
            bytes = encoded.ToArray();
        }

        var stream =
            new TrackingMemoryStream(bytes, writable: false);

        try
        {
            ManifestReader reader =
                await ManifestReader.OpenAsync(stream);

            try
            {
                var buffer = new ChunkInfo[8];
                while (await reader.ReadAsync(buffer) != 0)
                {
                }
            }
            finally
            {
                await reader.DisposeAsync();
            }

            Assert.False(stream.WasDisposed);
        }
        finally
        {
            stream.Dispose();
        }
    }

    private static async Task EncodeSyntheticManifestAsync(
        Stream destination,
        int entryCount)
    {
        var profileId =
            new ChunkingProfileId("test.manifest-reader.v1");
        ProfileFingerprint fingerprint = new(
            HashSuiteHasher.Hash(
                HashSuiteIds.Sha256V1,
                "test.manifest-reader.profile.v1"u8));

        using CsmEncoderSession encoder =
            await CsmEncoderSession.CreateAsync(
                destination,
                HashSuiteIds.Default,
                profileId,
                fingerprint,
                includeBlockIndex: true,
                CancellationToken.None);

        var bytes = new byte[CsmFormat.HashSize];

        for (int index = 0; index < entryCount; index++)
        {
            Array.Clear(bytes);
            BinaryPrimitives.WriteUInt64LittleEndian(
                bytes.AsSpan(0, 8),
                checked((ulong)index + 1));

            await encoder.AppendAsync(
                new ChunkId(Hash256.FromBytes(bytes)),
                checked((uint)((index % 97) + 1)),
                CancellationToken.None);
        }

        _ = await encoder.CompleteAsync(
            CancellationToken.None);
    }

    private static int FindFirstChunkBlockOffset(
        byte[] bytes)
    {
        int offset = CsmFormat.PreambleSize;

        while (offset
            < bytes.Length - CsmFormat.TrailerSize)
        {
            uint type =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    bytes.AsSpan(offset, 4));

            if (type == CsmFormat.ChunkBlock)
            {
                return offset;
            }

            offset += GetSectionRecordLength(
                bytes,
                offset);
        }

        throw new InvalidOperationException(
            "CBLK was not found.");
    }

    private static int GetSectionRecordLength(
        byte[] bytes,
        int sectionOffset)
    {
        ulong payloadLength =
            BinaryPrimitives.ReadUInt64LittleEndian(
                bytes.AsSpan(
                    sectionOffset + 8,
                    8));

        return checked(
            CsmFormat.SectionHeaderSize
            + (int)payloadLength);
    }

    private static byte[] CreateXorShiftBytes(
        int length,
        uint seed)
    {
        var bytes = new byte[length];
        uint state = seed;

        for (int index = 0; index < bytes.Length; index++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes[index] = (byte)state;
        }

        return bytes;
    }

    private sealed class TrackingMemoryStream : MemoryStream
    {
        internal TrackingMemoryStream(
            byte[] buffer,
            bool writable)
            : base(buffer, writable)
        {
        }

        internal bool WasDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }
}
