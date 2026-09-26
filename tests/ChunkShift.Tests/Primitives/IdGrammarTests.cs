using System;
using Xunit;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Primitives;

/// <summary>
/// Tests for the internal IdGrammar validation rules.
/// </summary>
public class IdGrammarTests
{
    [Theory]
    [InlineData("sha256")]
    [InlineData("fastcdc.gear")]
    [InlineData("fastcdc.gear.candidate1.64k")]
    [InlineData("fixed.v1.64k")]
    [InlineData("chunkshift.manifest.v1")]
    [InlineData("blake3-256")]
    [InlineData("chunkshift.blake3-256.v1")]
    [InlineData("chunkshift.sha256.v1")]
    [InlineData("test_profile_1")]
    [InlineData("a")]
    [InlineData("a.b-c_d")]
    [InlineData("0start")]
    public void IsValid_ReturnsTrue_ForValidIds(string id)
    {
        Assert.True(IdGrammar.IsValid(id.AsSpan()));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData(".abc")]
    [InlineData("-abc")]
    [InlineData("_abc")]
    [InlineData("SHA256")]
    [InlineData("FastCDC")]
    [InlineData("fastcdc/Gear")]
    [InlineData("fastcdc gear")]
    [InlineData("fastcdc:gear")]
    [InlineData("тест")]
    [InlineData("id@extra")]
    [InlineData("id!extra")]
    public void IsValid_ReturnsFalse_ForInvalidIds(string id)
    {
        Assert.False(IdGrammar.IsValid(id.AsSpan()));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".abc")]
    [InlineData("-abc")]
    [InlineData("SHA256")]
    [InlineData("тест")]
    public void Validate_Throws_ForInvalidIds(string id)
    {
        var ex = Assert.Throws<ArgumentException>(() => IdGrammar.Validate(id, "param"));
        Assert.Contains("param", ex.Message);
    }

    [Theory]
    [InlineData("sha256")]
    [InlineData("fastcdc.gear")]
    [InlineData("chunkshift.manifest.v1")]
    public void Validate_DoesNotThrow_ForValidIds(string id)
    {
        // Should not throw
        IdGrammar.Validate(id, "param");
    }

    [Fact]
    public void Validate_Throws_ForNull()
    {
        var ex = Assert.Throws<ArgumentException>(() => IdGrammar.Validate(null, "param"));
        Assert.Contains("param", ex.Message);
    }

    [Fact]
    public void IsValid_ReturnsFalse_ForTooLongId()
    {
        var tooLong = new string('a', IdGrammar.MaxLength + 1);
        Assert.False(IdGrammar.IsValid(tooLong.AsSpan()));
    }

    [Fact]
    public void IsValid_ReturnsTrue_ForMaxLengthId()
    {
        var maxLength = new string('a', IdGrammar.MaxLength);
        Assert.True(IdGrammar.IsValid(maxLength.AsSpan()));
    }

    [Theory]
    [InlineData("SHA256")]
    [InlineData("Sha256")]
    [InlineData("HELLO")]
    public void IsValid_ReturnsFalse_ForUppercase(string id)
    {
        Assert.False(IdGrammar.IsValid(id.AsSpan()));
    }

    [Theory]
    [InlineData("тест")]
    [InlineData("caf\u00e9")]
    [InlineData("日本語")]
    [InlineData("id\u00d7extra")]
    public void IsValid_ReturnsFalse_ForUnicode(string id)
    {
        Assert.False(IdGrammar.IsValid(id.AsSpan()));
    }

    [Theory]
    [InlineData(".abc")]
    [InlineData("-abc")]
    [InlineData("_abc")]
    public void IsValid_ReturnsFalse_ForLeadingDotDashUnderscore(string id)
    {
        Assert.False(IdGrammar.IsValid(id.AsSpan()));
    }
}