using ChunkShift.Patching.Encoding;

namespace ChunkShift.Patching.Tests.Encoding;

/// <summary>
/// Non-normative regression (CSP-V1 section 3.5): the stored bytes of a
/// patch are a physical representation, not a contract, so this test is not a
/// compatibility gate. It pins one frame the current backend writes, so that a
/// change in the backend's defaults or in the encoder's parameters is noticed;
/// the committed CSP vectors pin the format itself.
/// </summary>
public sealed class ZstdEncoderRegressionTests
{
    [Fact]
    public void Level19Frame_MatchesTheRecordedBackendBytes()
    {
        const string line = "ChunkShift declarative patch payload, ";
        byte[] chunk = System.Text.Encoding.ASCII.GetBytes(
            string.Concat(Enumerable.Repeat(line, 40))[..900]);

        using var encoder = new CspPayloadEncoder(19);
        byte[] frame = encoder.EncodeZstd(chunk, []).ToArray();

        Assert.Equal(
            Convert.FromHexString(
                "28b52ffd6084027d010064024368756e6b5368696674206465636c61726174697665207061746368207061796c6f61642c200100de9a2af504"),
            frame);
    }
}
