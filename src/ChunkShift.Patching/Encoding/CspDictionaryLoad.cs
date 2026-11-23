namespace ChunkShift.Patching.Encoding;

/// <summary>
/// How the encoder hands a CSP dictionary to zstd. Every mode loads the same
/// raw content (docs/architecture/CSP-V1.md section 5.2), so the
/// frames decode identically; they differ in the native memory zstd uses for
/// the dictionary's match tables.
/// </summary>
internal enum CspDictionaryLoad
{
    /// <summary>
    /// ZstdSharp's <c>LoadDictionary</c>: zstd builds a dictionary object
    /// (CDict) per dictionary and, at the strategies of the high levels, copies
    /// its tables into the context, so two dictionary-sized table sets are live.
    /// </summary>
    Copy,

    /// <summary>
    /// <c>LoadDictionary</c> with zstd's <c>forceAttachDict</c>: the context
    /// searches the CDict's tables in place instead of copying them.
    /// </summary>
    Attach,

    /// <summary>
    /// <c>ZSTD_CCtx_refPrefix</c> on a context the encoder owns: the raw content
    /// is loaded into that reused context and no CDict is built.
    /// </summary>
    Prefix,
}
