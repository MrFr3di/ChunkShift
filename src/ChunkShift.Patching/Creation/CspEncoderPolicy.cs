using ChunkShift.Patching.Encoding;

namespace ChunkShift.Patching.Creation;

/// <summary>
/// Encoder policy for patch creation: the zstd level and the dictionary search
/// that decide the stored form of one target chunk.
/// </summary>
/// <param name="Level">
/// Zstd compression level, 0..22. Level zero stores every entry raw and never
/// calls the encoder, so the remaining fields do not matter.
/// </param>
/// <param name="DictionaryChunks">
/// Number of contiguous base chunks concatenated into one dictionary candidate,
/// 0..4; zero disables dictionary entries.
/// </param>
/// <param name="MaxCandidates">Maximum number of dictionary candidate runs per target record.</param>
/// <param name="SearchRadius">
/// Maximum distance in bytes between a candidate's first base record offset and
/// the target record offset.
/// </param>
/// <remarks>
/// <see cref="Default"/> balances patch size against create time, with the
/// dictionary handling that bounds the create peak. Policies built from the
/// constructor alone keep <see cref="CspDictionaryLoad.Copy"/> and zstd's own
/// table sizes. The public <see cref="ChunkPatch"/> API always uses
/// <see cref="Default"/>; the raw-only level exists for tests.
/// </remarks>
internal sealed record CspEncoderPolicy(
    int Level,
    int DictionaryChunks,
    int MaxCandidates,
    int SearchRadius)
{
    /// <summary>Gets how a dictionary is handed to zstd.</summary>
    internal CspDictionaryLoad DictionaryLoad { get; init; } = CspDictionaryLoad.Copy;

    /// <summary>
    /// Gets the zstd hash log of entries with a dictionary, or zero for zstd's
    /// choice from the level, chunk and dictionary sizes.
    /// </summary>
    internal int DictionaryHashLog { get; init; }

    /// <summary>
    /// Gets the zstd chain log of entries with a dictionary, or zero for zstd's
    /// choice.
    /// </summary>
    internal int DictionaryChainLog { get; init; }

    /// <summary>
    /// Gets zstd level 19, four contiguous base chunks per dictionary, up to
    /// eight candidates within 256 KiB of the target offset; each dictionary
    /// is a raw prefix on the encoder's static context, with the hash and
    /// chain logs of dictionary entries at most 20.
    /// </summary>
    internal static CspEncoderPolicy Default { get; } =
        new(Level: 19, DictionaryChunks: 4, MaxCandidates: 8, SearchRadius: 256 * 1024)
        {
            DictionaryLoad = CspDictionaryLoad.Prefix,
            DictionaryHashLog = 20,
            DictionaryChainLog = 20,
        };
}
