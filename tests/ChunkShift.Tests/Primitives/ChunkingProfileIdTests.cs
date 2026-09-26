using System;
using Xunit;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Primitives;

/// <summary>
/// Tests for the ChunkingProfileId value object.
/// </summary>
public class ChunkingProfileIdTests
{
    [Fact]
    public void Constructor_Accepts_ValidValue()
    {
        var id = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        Assert.Equal("fastcdc.gear.candidate1.64k", id.Value);
    }

    [Fact]
    public void Constructor_Rejects_Null_WithPublicParameterName()
    {
        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(() => new ChunkingProfileId(null!));

        Assert.Equal("value", exception.ParamName);
    }

    [Theory]
    [InlineData("FASTCDC.GEAR.CANDIDATE1.64K")]
    [InlineData("")]
    [InlineData(".profile")]
    [InlineData("fastcdc gear")]
    [InlineData("fastcdc/gear")]
    public void Constructor_Rejects_InvalidValue(string invalid)
    {
        Assert.Throws<ArgumentException>(() => new ChunkingProfileId(invalid));
    }

    [Fact]
    public void Type_HasNoInstanceWithoutAValidatedValue()
    {
        // A sealed reference type with only the validating constructor: there is
        // no default(T) instance whose Value could be null.
        Type type = typeof(ChunkingProfileId);

        Assert.True(type.IsClass);
        Assert.True(type.IsSealed);
        Assert.Null(type.GetConstructor(Type.EmptyTypes));
        Assert.Null(default(ChunkingProfileId));
    }

    [Fact]
    public void ToString_Returns_Value()
    {
        var id = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        Assert.Equal("fastcdc.gear.candidate1.64k", id.ToString());
    }

    [Fact]
    public void Equality_Works_ForSameValue()
    {
        var id1 = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        var id2 = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        Assert.True(id1.Equals(id2));
        Assert.Equal(id1, id2);
    }

    [Fact]
    public void Inequality_Works_ForDifferentValue()
    {
        var id1 = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        var id2 = new ChunkingProfileId("fixed.v1.64k");
        Assert.False(id1.Equals(id2));
        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void Operators_Work()
    {
        var id1 = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        var id2 = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        var id3 = new ChunkingProfileId("fixed.v1.64k");

        Assert.True(id1 == id2);
        Assert.True(id1 != id3);
        Assert.False(id1 == null);
        Assert.False(null == id1);
        Assert.True((ChunkingProfileId?)null == null);
    }

    [Fact]
    public void Equality_IsOrdinalOverTheValue()
    {
        var id = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        var copy = new ChunkingProfileId(new string("fastcdc.gear.candidate1.64k".AsSpan()));

        Assert.NotSame(id.Value, copy.Value);
        Assert.True(id.Equals(copy));
        Assert.Equal(
            StringComparer.Ordinal.GetHashCode(id.Value),
            id.GetHashCode());
        Assert.False(id.Equals((ChunkingProfileId?)null));
    }

    [Fact]
    public void Equals_Object_ReturnsFalse_ForNull()
    {
        var id = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        Assert.False(id.Equals((object?)null));
    }

    [Fact]
    public void Equals_Object_ReturnsFalse_ForDifferentType()
    {
        var id = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        Assert.False(id.Equals("fastcdc.gear.candidate1.64k"));
    }

    [Fact]
    public void GetHashCode_IsSame_ForSameValue()
    {
        var id1 = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        var id2 = new ChunkingProfileId("fastcdc.gear.candidate1.64k");
        Assert.Equal(id1.GetHashCode(), id2.GetHashCode());
    }
}