using System;
using ChunkShift.Primitives;

namespace ChunkShift.Tests.Primitives;

public class HashSuiteIdTests
{
    [Fact]
    public void KnownSuites_HaveNormativeIdentifiers()
    {
        Assert.Equal("chunkshift.blake3-256.v1", HashSuiteIds.Blake3256V1.Value);
        Assert.Equal("chunkshift.sha256.v1", HashSuiteIds.Sha256V1.Value);
        Assert.Equal(HashSuiteIds.Blake3256V1, HashSuiteIds.Default);
    }

    [Fact]
    public void Constructor_UsesStableIdGrammar()
    {
        var id = new HashSuiteId("chunkshift.example.v1");

        Assert.Equal("chunkshift.example.v1", id.Value);
        Assert.Equal(id, new HashSuiteId("chunkshift.example.v1"));
        Assert.True(id == new HashSuiteId("chunkshift.example.v1"));
        Assert.False(id == null);
        Assert.Equal("chunkshift.example.v1", id.ToString());
    }

    [Fact]
    public void Constructor_RejectsNull_WithPublicParameterName()
    {
        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(() => new HashSuiteId(null!));

        Assert.Equal("value", exception.ParamName);
    }

    [Fact]
    public void Type_HasNoInstanceWithoutAValidatedValue()
    {
        Type type = typeof(HashSuiteId);

        Assert.True(type.IsClass);
        Assert.True(type.IsSealed);
        Assert.Null(type.GetConstructor(Type.EmptyTypes));
        Assert.Null(default(HashSuiteId));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ChunkShift.SHA256.V1")]
    [InlineData(".chunkshift.sha256.v1")]
    [InlineData("chunkshift/sha256/v1")]
    public void Constructor_RejectsInvalidIds(string value)
    {
        Assert.Throws<ArgumentException>(() => new HashSuiteId(value));
    }
}
