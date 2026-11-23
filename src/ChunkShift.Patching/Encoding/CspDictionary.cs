using ChunkShift.Patching.Format;

namespace ChunkShift.Patching.Encoding;

/// <summary>
/// The CSP dictionary rule of docs/architecture/CSP-V1.md section 5.2:
/// the concatenated bytes of the named base chunks are used as raw zstd
/// dictionary content, must be at most 1 MiB in total, and must not begin with
/// the zstd dictionary magic, which zstd implementations would otherwise
/// interpret as a trained dictionary.
/// </summary>
internal static class CspDictionary
{
    /// <summary>Maximum concatenated dictionary length CSP allows.</summary>
    internal const int MaximumBytes = 1 << 20;

    /// <summary>
    /// Gets whether <paramref name="dictionary"/> may be used as raw dictionary
    /// content. An empty dictionary is usable: it means "no dictionary".
    /// </summary>
    /// <param name="dictionary">Concatenated dictionary bytes, in listed order.</param>
    internal static bool IsUsable(ReadOnlySpan<byte> dictionary) =>
        dictionary.Length <= MaximumBytes &&
        !dictionary.StartsWith(CspFormat.ZstdDictionaryMagic);
}
