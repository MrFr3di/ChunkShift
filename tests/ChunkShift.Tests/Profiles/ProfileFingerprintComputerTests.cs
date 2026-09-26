using System;
using System.Security.Cryptography;
using System.Text;
using ChunkShift.Hashing;
using ChunkShift.Primitives;
using ChunkShift.Profiles;

namespace ChunkShift.Tests.Profiles;

public class ProfileFingerprintComputerTests
{
    [Fact]
    public void CosmeticArtifactChanges_DoNotChangeFingerprint()
    {
        const string first = """
            {
              "id": "fastcdc.example",
              "description": "first prose",
              "semantics": {
                "algorithm": "fastcdc.gear",
                "version": 1,
                "sizes": { "min": 32768, "target": 65536, "max": 262144 },
                "masks": [ 65535, 131071 ],
                "overflow": "uint64-wrap"
              }
            }
            """;

        const string second = """{"documentation":"different prose","semantics":{"overflow":"uint64-wrap","masks":[65535,131071],"sizes":{"max":262144,"target":65536,"min":32768},"version":1.0,"algorithm":"fastcdc.gear"},"id":"renamed-authoring-file"}""";

        ProfileFingerprint a = Compute(first);
        ProfileFingerprint b = Compute(second);

        Assert.Equal(a, b);
    }

    [Fact]
    public void SemanticParameterChange_ChangesFingerprint()
    {
        const string first = """{"semantics":{"algorithm":"fastcdc.gear","version":1,"target":65536}}""";
        const string second = """{"semantics":{"algorithm":"fastcdc.gear","version":1,"target":131072}}""";

        Assert.NotEqual(Compute(first), Compute(second));
    }

    [Fact]
    public void ArrayOrder_IsSemantic()
    {
        const string first = """{"semantics":{"thresholds":[1,2,3]}}""";
        const string second = """{"semantics":{"thresholds":[3,2,1]}}""";

        Assert.NotEqual(Compute(first), Compute(second));
    }

    [Theory]
    [InlineData("1", "1.0")]
    [InlineData("1", "1e0")]
    [InlineData("1", "0.001e3")]
    [InlineData("12", "1.20e1")]
    [InlineData("1000", "1e3")]
    [InlineData("0", "-0.000e100")]
    public void EquivalentIntegerSpellings_AreCanonical(string firstNumber, string secondNumber)
    {
        string first = "{\"semantics\":{\"value\":" + firstNumber + "}}";
        string second = "{\"semantics\":{\"value\":" + secondNumber + "}}";

        Assert.Equal(Compute(first), Compute(second));
    }

    [Theory]
    [InlineData("1.5")]
    [InlineData("1.00000000000000000000000000001")]
    [InlineData("1e-1000")]
    [InlineData("100e-3")]
    [InlineData("-0.00000000000000000000000000001")]
    public void FractionalValuesBeyondDecimalPrecision_AreRejected(string number)
    {
        string artifact = "{\"semantics\":{\"value\":" + number + "}}";

        Assert.Throws<FormatException>(() => Compute(artifact));
    }

    [Theory]
    [InlineData("1e1025")]
    [InlineData("1e-1025")]
    public void ExponentsOutsideResourceBound_AreRejected(string number)
    {
        string artifact = "{\"semantics\":{\"value\":" + number + "}}";

        Assert.Throws<FormatException>(() => Compute(artifact));
    }

    [Fact]
    public void CanonicalIntegerOutsideDigitBound_IsRejected()
    {
        string artifact = """{"semantics":{"value":1e128}}""";

        Assert.Throws<FormatException>(() => Compute(artifact));
    }

    [Fact]
    public void FractionalSemanticNumbers_AreRejected()
    {
        const string artifact = """{"semantics":{"threshold":1.5}}""";

        Assert.Throws<FormatException>(() => Compute(artifact));
    }

    [Fact]
    public void DuplicateSemanticProperties_AreRejected()
    {
        const string artifact = """{"semantics":{"target":65536,"target":131072}}""";

        Assert.Throws<FormatException>(() => Compute(artifact));
    }

    [Fact]
    public void MissingSemanticsObject_IsRejected()
    {
        const string artifact = """{"description":"not a semantic profile"}""";

        Assert.Throws<FormatException>(() => Compute(artifact));
    }

    [Fact]
    public void ProfileFingerprint_IsFixedSha256OfCanonicalSemantics_IndependentOfContentHashSuite()
    {
        const string artifact = """{"semantics":{"algorithm":"fixed","version":1,"size":65536}}""";

        // Independent oracle: the PROFILE-FINGERPRINT-V1 canonical encoding of the
        // semantics object written out by hand (tag 06, UInt32 LE property count,
        // properties in ordinal name order, each name as UInt32 LE length + UTF-8,
        // strings tag 04, integers tag 03 with canonical decimal text).
        byte[] canonical = Convert.FromHexString(
            "06" + "03000000"
            + "09000000" + "616c676f726974686d" + "04" + "05000000" + "6669786564"
            + "04000000" + "73697a65" + "03" + "05000000" + "3635353336"
            + "07000000" + "76657273696f6e" + "03" + "01000000" + "31");
        byte[] domain = Encoding.UTF8.GetBytes("chunkshift.profile-fingerprint.v1\0");
        byte[] identityInput = [.. domain, .. canonical];

        ProfileFingerprint fingerprint = Compute(artifact);

        // Pinned value (computed outside .NET) and the SHA-256 definition must agree.
        Assert.Equal(
            "c0d37899e24e151b689f5b1fece9ce754a1246d69d3d4674f5efcd67be29ae48",
            fingerprint.ToString());
        Assert.Equal(
            Hash256.FromBytes(SHA256.HashData(identityInput)),
            fingerprint.Value);

        // The default content HashSuite (BLAKE3-256) must not be what is used.
        Assert.NotEqual(
            HashSuiteHasher.Hash(HashSuiteIds.Default, identityInput),
            fingerprint.Value);
    }

    private static ProfileFingerprint Compute(string artifact)
    {
        return ProfileFingerprintComputer.Compute(Encoding.UTF8.GetBytes(artifact));
    }
}
