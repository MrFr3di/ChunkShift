using ChunkShift.Patching.Format;
using ZstdSharp;
using ZstdSharp.Unsafe;

namespace ChunkShift.Patching.Encoding;

/// <summary>
/// Decodes one CSP payload entry into a caller-provided destination
/// (docs/architecture/CSP-V1.md section 5).
/// </summary>
/// <remarks>
/// <para>
/// Encoding 0 copies the stored bytes; encoding 1 validates the frame envelope
/// with <see cref="ZstdFrameEnvelope"/> and decodes exactly one zstd frame,
/// optionally against raw dictionary content of named base chunks. Every other
/// encoding is unsupported (rule 16).
/// </para>
/// <para>
/// The decoder reuses one zstd context, never allocates from a size declared
/// by the stored bytes, and writes output only into the caller's destination
/// span, whose length is the target chunk length. It is not thread-safe and
/// must not be called after <see cref="Dispose"/>.
/// </para>
/// </remarks>
internal sealed class CspPayloadDecoder : IDisposable
{
    private const int MaximumWindowLog = 20;

    private readonly Decompressor _decompressor = new();
    private bool _disposed;

    internal CspPayloadDecoder() =>
        _decompressor.SetParameter(ZSTD_dParameter.ZSTD_d_windowLogMax, MaximumWindowLog);

    /// <summary>
    /// Reconstructs the entry's target chunk bytes into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <param name="encoding">Payload encoding: 0 raw, 1 one zstd frame.</param>
    /// <param name="stored">Exactly the entry's stored bytes.</param>
    /// <param name="dictionary">
    /// Concatenated raw dictionary content of the entry's named base chunks, or
    /// an empty span for no dictionary.
    /// </param>
    /// <param name="destination">Destination of exactly the target chunk length.</param>
    /// <exception cref="ObjectDisposedException">The decoder has been disposed.</exception>
    /// <exception cref="NotSupportedException">The encoding is not implemented.</exception>
    /// <exception cref="InvalidOperationException">
    /// The stored bytes and the dictionary violate the codec's input contract:
    /// a raw entry whose stored length differs from the destination length, a
    /// raw entry that names a dictionary, or a dictionary that is unusable.
    /// The caller checks the CSP rules that produce these states first
    /// (rules 18 and 28); these are guards, not format checks.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// The stored bytes are not exactly one valid zstd frame for the target
    /// chunk length (rules 29 and 30).
    /// </exception>
    internal void Decode(
        byte encoding,
        ReadOnlySpan<byte> stored,
        ReadOnlySpan<byte> dictionary,
        Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        switch (encoding)
        {
            case CspFormat.EncodingRaw:
                DecodeRaw(stored, dictionary, destination);
                return;

            case CspFormat.EncodingZstd:
                DecodeZstd(stored, dictionary, destination);
                return;

            default:
                throw new NotSupportedException(
                    $"CSP payload encoding {encoding} is not implemented.");
        }
    }

    /// <inheritdoc cref="Decode(byte, ReadOnlySpan{byte}, ReadOnlySpan{byte}, Span{byte})" />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _decompressor.Dispose();
    }

    private static void DecodeRaw(
        ReadOnlySpan<byte> stored,
        ReadOnlySpan<byte> dictionary,
        Span<byte> destination)
    {
        if (stored.Length != destination.Length)
        {
            throw new InvalidOperationException(
                "A raw CSP payload entry must store exactly the target chunk length.");
        }

        if (!dictionary.IsEmpty)
        {
            throw new InvalidOperationException(
                "A raw CSP payload entry must not use a dictionary.");
        }

        stored.CopyTo(destination);
    }

    private void DecodeZstd(
        ReadOnlySpan<byte> stored,
        ReadOnlySpan<byte> dictionary,
        Span<byte> destination)
    {
        if (!CspDictionary.IsUsable(dictionary))
        {
            throw new InvalidOperationException(
                "The CSP dictionary cannot be used: it exceeds 1 MiB or starts "
                + "with the zstd dictionary magic.");
        }

        ZstdFrameEnvelope.Validate(stored, destination.Length);
        _decompressor.LoadDictionary(dictionary);

        int written;

        try
        {
            written = _decompressor.Unwrap(stored, destination);
        }
        catch (ZstdException exception)
        {
            throw new InvalidDataException(
                "The zstd frame is corrupt or does not decode into the target chunk length.",
                exception);
        }

        if (written != destination.Length)
        {
            throw new InvalidDataException(
                "The zstd frame decoded to a length other than the target chunk length.");
        }
    }
}
