using ChunkShift.Primitives;

namespace ChunkShift.Tests.Primitives;

public class LogicalIdentityTests
{
    [Fact]
    public void LogicalIdentities_PreserveTheFull256BitValueSpace()
    {
        Hash256 zero = default;

        Assert.Equal(zero, new ChunkId(zero).Value);
        Assert.Equal(zero, new ManifestId(zero).Value);
        Assert.Equal(zero, new ProfileFingerprint(zero).Value);

        Assert.Equal(new string('0', 64), new ChunkId(zero).ToString());
        Assert.Equal(new string('0', 64), new ManifestId(zero).ToString());
        Assert.Equal(new string('0', 64), new ProfileFingerprint(zero).ToString());
    }
}
