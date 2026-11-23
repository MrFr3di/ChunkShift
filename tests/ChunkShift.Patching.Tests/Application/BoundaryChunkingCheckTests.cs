using System.Buffers.Binary;
using System.Security.Cryptography;
using ChunkShift.Patching.Application;
using ChunkShift.Patching.Tests.Creation;
using ChunkShift.Patching.Tests.Format;
using ChunkShift.Primitives;

namespace ChunkShift.Patching.Tests.Application;

/// <summary>
/// The boundary-only check duplicates Core's frozen FastCDC semantics
/// (docs/architecture/FASTCDC-V1.md). These tests cross-check
/// it against Core's <see cref="ChunkScanner"/> output and the independent
/// FastCDC vectors of <c>tools/conformance/fastcdc_reference.py</c>: it accepts exactly the cuts the
/// profile makes and rejects every neighbouring cut.
/// </summary>
public sealed class BoundaryChunkingCheckTests
{
    private const int Minimum = 16 * 1024;
    private const int Target = 64 * 1024;
    private const int Maximum = 256 * 1024;

    /// <summary>
    /// fastcdc-rs 5.0.0 v2016 cut list of 1 MiB of xorshift bytes, seed
    /// 0x12345678, at 16/64/256 KiB, recorded from the fastcdc crate.
    /// </summary>
    private static readonly (long Offset, int Length)[] ExternalCuts =
    [
        (0, 100081),
        (100081, 33106),
        (133187, 69903),
        (203090, 49442),
        (252532, 103705),
        (356237, 144977),
        (501214, 214287),
        (715501, 145480),
        (860981, 50981),
        (911962, 37677),
        (949639, 79457),
        (1029096, 19480),
    ];

    /// <summary>
    /// FNV-1a 64 digests of the cut lists of the reference fixtures at target
    /// 64 KiB, from tools/conformance/fastcdc_reference.py.
    /// </summary>
    private static readonly Dictionary<string, ulong> FixtureDigests = new()
    {
        ["xorshift-1m"] = 0x259bdfaf8c068fd9,
        ["xorshift-1m-minus-1"] = 0x27978d2329d4f2ee,
        ["zero-1m"] = 0xd9d0423596bbe425,
        ["pattern7-1m"] = 0xd9d0423596bbe425,
        ["low-entropy-1m"] = 0x06efcccd64876221,
        ["alternating-1m"] = 0x916a6a99875bf022,
        ["odd-eof-transient"] = 0x5746b5ee65e8c544,
        ["edge-minimum-1"] = 0xb03cf1b9a107f86b,
        ["edge-minimum+0"] = 0xdcbf024dd5f41b25,
        ["edge-minimum+1"] = 0xbdc43b44cb04d104,
        ["edge-target-1"] = 0x5b9e0f252c1341ab,
        ["edge-target+0"] = 0xab89bb86730d9e2c,
        ["edge-target+1"] = 0x45bbbce34401e07d,
        ["edge-maximum-1"] = 0x060282e0655707de,
        ["edge-maximum+0"] = 0xb21353787c45bca7,
        ["edge-maximum+1"] = 0xda0f4034bef199f4,
    };

    /// <summary>Gets the names of the reference fixtures.</summary>
    public static TheoryData<string> Fixtures => new(FixtureDigests.Keys);

    [Fact]
    public void GearTable_MatchesTheNormativeDigest()
    {
        byte[] serialized = new byte[256 * sizeof(ulong)];

        for (int index = 0; index < 256; index++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(
                serialized.AsSpan(index * sizeof(ulong)),
                BoundaryChunkingCheck.GearTable[index]);
        }

        // docs/architecture/FASTCDC-GEAR-V1.txt, chunkshift.fastcdc.gear.v1.
        Assert.Equal(
            "91a3061015ae351cd3701852712bcd6aa4a1ce26c8a231d3969432b00f028f88",
            Convert.ToHexStringLower(SHA256.HashData(serialized)));
    }

    [Theory]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    public async Task PinnedProfile_IsTheOneCoreRecords(string hashSuite)
    {
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(
            CspBytes.CreateXorShiftBytes(1000, 1),
            new HashSuiteId(hashSuite));
        ManifestVerificationResult verified = await ChunkManifest.VerifyManifestAsync(
            new MemoryStream(manifest, writable: false));

        Assert.Equal(BoundaryChunkingCheck.ProfileId, verified.Manifest.ProfileId);
        Assert.Equal(BoundaryChunkingCheck.Fingerprint, verified.Manifest.ProfileFingerprint);
        Assert.True(BoundaryChunkingCheck.AppliesTo(verified.Manifest));
    }

    [Fact]
    public async Task ExternalVector_IsCoresCutListAndIsAccepted()
    {
        byte[] content = CspBytes.CreateXorShiftBytes(1024 * 1024, 0x12345678);
        int[] cuts = await CoreCutsAsync(content);

        Assert.Equal(ExternalCuts.Select(static cut => cut.Length), cuts);
        Assert.True(Check(content, cuts));
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public async Task ReferenceFixture_IsAcceptedAndEveryNeighbourRejected(string name)
    {
        byte[] content = CreateFixture(name);
        int[] cuts = await CoreCutsAsync(content);

        Assert.Equal(FixtureDigests[name], Fnv1a64(cuts));
        Assert.True(Check(content, cuts));
        AssertNeighboursRejected(content, cuts);
    }

    [Theory]
    [InlineData(0x0000_0001u, 3 * 1024 * 1024 + 17)]
    [InlineData(0x5EED_A1A0u, 2 * 1024 * 1024)]
    [InlineData(0xC0FF_EE01u, Maximum * 3)]
    [InlineData(0x0BAD_F00Du, Minimum)]
    [InlineData(0x0BAD_F00Eu, 1)]
    public async Task MixedEntropyContent_IsAcceptedAndEveryNeighbourRejected(uint seed, int length)
    {
        byte[] content = CreateMixed(length, seed);
        int[] cuts = await CoreCutsAsync(content);

        Assert.True(Check(content, cuts));
        AssertNeighboursRejected(content, cuts);
    }

    [Fact]
    public async Task RecordEndingAtTheTarget_IsCutByTheRelaxedMask()
    {
        // The position equal to the target belongs to the relaxed range: Core
        // cuts a record of exactly the target length where only the relaxed
        // mask hits.
        byte[] content = CreateCutAtTarget();
        int[] cuts = await CoreCutsAsync(content);

        Assert.Equal(Target, cuts[0]);
        Assert.True(Check(content, cuts));
        AssertNeighboursRejected(content, cuts);
    }

    [Fact]
    public void EmptyContent_HasNoRecordsAndIsAccepted() =>
        Assert.True(new BoundaryChunkingCheck().Complete());

    [Fact]
    public void RecordAboveTheMaximum_IsRejected()
    {
        byte[] content = new byte[Maximum + 1];
        Assert.False(Check(content, [Maximum + 1]));
    }

    [Fact]
    public void RecordAfterAShortRecord_IsRejected()
    {
        // Only the last record may be shorter than the minimum.
        byte[] content = CspBytes.CreateXorShiftBytes(Minimum, 7);
        Assert.False(Check(content, [Minimum - 1, 1]));
    }

    /// <summary>
    /// Each boundary moved one byte either way, two neighbours merged, and
    /// every record split in half: the check must reject all of them.
    /// </summary>
    private static void AssertNeighboursRejected(byte[] content, int[] cuts)
    {
        for (int index = 0; index < cuts.Length; index++)
        {
            if (index + 1 < cuts.Length)
            {
                foreach (int delta in (int[])[-1, 1])
                {
                    int[] moved = (int[])cuts.Clone();
                    moved[index] += delta;
                    moved[index + 1] -= delta;

                    if (moved[index] > 0 && moved[index + 1] > 0)
                    {
                        Assert.False(Check(content, moved), $"boundary {index} moved by {delta} was accepted");
                    }
                }

                int[] merged = [.. cuts[..index], cuts[index] + cuts[index + 1], .. cuts[(index + 2)..]];
                Assert.False(Check(content, merged), $"records {index} and {index + 1} merged were accepted");
            }

            if (cuts[index] >= 2)
            {
                int half = cuts[index] / 2;
                int[] split = [.. cuts[..index], half, cuts[index] - half, .. cuts[(index + 1)..]];
                Assert.False(Check(content, split), $"record {index} split in half was accepted");
            }
        }
    }

    private static bool Check(byte[] content, IEnumerable<int> cuts)
    {
        var check = new BoundaryChunkingCheck();
        int offset = 0;

        foreach (int length in cuts)
        {
            check.Append(content.AsSpan(offset, length));
            offset += length;
        }

        Assert.Equal(content.Length, offset);
        return check.Complete();
    }

    private static async Task<int[]> CoreCutsAsync(byte[] content)
    {
        byte[] manifest = await CreationTestSupport.CreateManifestAsync(content, HashSuiteIds.Sha256V1);
        List<ChunkInfo> records = await CreationTestSupport.ReadRecordsAsync(manifest);
        return [.. records.Select(static record => record.Length)];
    }

    private static ulong Fnv1a64(int[] cuts)
    {
        ulong value = 0xcbf29ce484222325;
        Span<byte> field = stackalloc byte[sizeof(ulong)];
        long offset = 0;

        foreach (int length in cuts)
        {
            foreach (long number in (long[])[offset, length])
            {
                BinaryPrimitives.WriteUInt64LittleEndian(field, (ulong)number);

                foreach (byte b in field)
                {
                    value ^= b;
                    value = unchecked(value * 0x100000001b3);
                }
            }

            offset += length;
        }

        return value;
    }

    /// <summary>
    /// The fixtures of fastcdc_reference.py <c>fixtures</c> at 16/64/256 KiB.
    /// </summary>
    private static byte[] CreateFixture(string name)
    {
        byte[] random = CspBytes.CreateXorShiftBytes(1024 * 1024, 0x12345678);
        byte[] edges = CspBytes.CreateXorShiftBytes(Maximum + 1, 0x9E3779B9);

        switch (name)
        {
            case "xorshift-1m":
                return random;
            case "xorshift-1m-minus-1":
                return random[..^1];
            case "zero-1m":
                return new byte[1024 * 1024];
            case "pattern7-1m":
                return [.. Enumerable.Range(0, 1024 * 1024).Select(index => random[index % 7])];
            case "low-entropy-1m":
                return [.. random.Select(static b => (byte)(b & 0x03))];
            case "alternating-1m":
            {
                byte[] alternating = new byte[1024 * 1024];

                for (int block = 0; block < alternating.Length; block += 128 * 1024)
                {
                    random.AsSpan(block, 64 * 1024).CopyTo(alternating.AsSpan(block));
                }

                return alternating;
            }

            case "odd-eof-transient":
                return [.. new byte[16 * 1024], 2, 255, 65];
        }

        // edge-<minimum|target|maximum><-1|+0|+1>
        string edge = name["edge-".Length..^2];
        int size = edge switch
        {
            "minimum" => Minimum,
            "target" => Target,
            "maximum" => Maximum,
            _ => throw new ArgumentException(name, nameof(name)),
        };
        int delta = int.Parse(name[^2..], System.Globalization.CultureInfo.InvariantCulture);
        return edges[..(size + delta)];
    }

    /// <summary>
    /// Finds random content whose gear hash does not hit in [minimum, target)
    /// and whose byte at the target makes the relaxed mask hit there but not
    /// the strict one. Core, not this search, decides the cut in the test.
    /// </summary>
    private static byte[] CreateCutAtTarget()
    {
        ReadOnlySpan<ulong> gear = BoundaryChunkingCheck.GearTable;

        for (uint seed = 1; ; seed++)
        {
            byte[] prefix = CspBytes.CreateXorShiftBytes(Target, seed);
            ulong hash = 0;
            bool hit = false;

            for (int index = Minimum; index < Target && !hit; index++)
            {
                hash = unchecked((hash << 1) + gear[prefix[index]]);
                hit = (hash & BoundaryChunkingCheck.StrictMask) == 0;
            }

            if (hit)
            {
                continue;
            }

            for (int value = 0; value < 256; value++)
            {
                ulong next = unchecked((hash << 1) + gear[value]);

                if ((next & BoundaryChunkingCheck.RelaxedMask) == 0 &&
                    (next & BoundaryChunkingCheck.StrictMask) != 0)
                {
                    return [.. prefix, (byte)value, .. CspBytes.CreateXorShiftBytes(2 * Minimum, seed + 1)];
                }
            }
        }
    }

    /// <summary>
    /// Random bytes interleaved with zero, repeated-pattern and low-entropy
    /// runs, so records end by the strict mask, the relaxed mask, the
    /// maximum and end of content.
    /// </summary>
    private static byte[] CreateMixed(int length, uint seed)
    {
        byte[] content = CspBytes.CreateXorShiftBytes(length, seed);
        var random = new Random(unchecked((int)seed));
        int offset = 0;

        while (offset < length)
        {
            int run = Math.Min(length - offset, random.Next(1, Maximum + Minimum));

            switch (random.Next(4))
            {
                case 0:
                    content.AsSpan(offset, run).Clear();
                    break;
                case 1:
                    for (int index = 0; index < run; index++)
                    {
                        content[offset + index] = (byte)(index % 5);
                    }

                    break;
                case 2:
                    for (int index = 0; index < run; index++)
                    {
                        content[offset + index] &= 0x01;
                    }

                    break;
            }

            offset += run;
        }

        return content;
    }
}
