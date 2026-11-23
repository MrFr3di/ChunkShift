using System.Runtime.InteropServices;
using ZstdSharp;
using ZstdSharp.Unsafe;

namespace ChunkShift.Patching.Encoding;

/// <summary>
/// Encodes one target chunk as a single CSP encoding-1 zstd frame, optionally
/// against raw dictionary content
/// (docs/architecture/CSP-V1.md section 5.2).
/// </summary>
/// <remarks>
/// <para>
/// The encoder reuses one zstd context and its level. A dictionary must be
/// usable under <see cref="CspDictionary.IsUsable"/>; an empty span means "no
/// dictionary" and clears one loaded for an earlier entry. A chunk larger than
/// 1 MiB is compressed with a 1 MiB window so the frame satisfies the CSP
/// window bound; a content checksum is never enabled.
/// </para>
/// <para>
/// Every returned frame is checked against <see cref="ZstdFrameEnvelope"/> for
/// exactly the chunk length, so the encoder cannot emit a frame the format
/// rejects. The encoder does not choose between raw and zstd encoding: that is
/// the caller's policy. The returned frame lives in a buffer the encoder
/// reuses, so it is valid only until the next call. The encoder is not
/// thread-safe and must not be called after <see cref="Dispose"/>.
/// </para>
/// <para>
/// How a dictionary reaches zstd and the table sizes of dictionary entries
/// are encoder policy (<see cref="CspDictionaryLoad"/>). They change the frame bytes, never what a frame decodes to.
/// </para>
/// </remarks>
internal sealed unsafe class CspPayloadEncoder : IDisposable
{
    private const int MaximumWindowLog = 20;
    private const int DefaultParameter = 0;

    private readonly int _level;
    private readonly int _dictionaryHashLog;
    private readonly int _dictionaryChainLog;

    // Copy and Attach use ZstdSharp's managed compressor; Prefix owns a static
    // context, because ZSTD_CCtx_refPrefix exists only in the low-level API.
    private readonly Compressor? _compressor;
    private readonly StaticContext? _context;
    private byte[] _frameBuffer = [];
    private bool _disposed;

    /// <param name="level">Zstd compression level, 1..22.</param>
    internal CspPayloadEncoder(int level)
        : this(level, CspDictionaryLoad.Copy, dictionaryHashLog: 0, dictionaryChainLog: 0)
    {
    }

    /// <param name="level">Zstd compression level, 1..22.</param>
    /// <param name="load">How a dictionary is handed to zstd.</param>
    /// <param name="dictionaryHashLog">
    /// The largest zstd hash log of an entry with a dictionary, or zero for no
    /// cap. A cap applies only where zstd's parameters for the level, chunk and
    /// dictionary sizes exceed it.
    /// </param>
    /// <param name="dictionaryChainLog">
    /// The largest zstd chain log of an entry with a dictionary, or zero for no cap.
    /// </param>
    internal CspPayloadEncoder(
        int level,
        CspDictionaryLoad load,
        int dictionaryHashLog,
        int dictionaryChainLog)
    {
        _level = level;
        _dictionaryHashLog = dictionaryHashLog;
        _dictionaryChainLog = dictionaryChainLog;

        if (load == CspDictionaryLoad.Prefix)
        {
            _context = new StaticContext();
            return;
        }

        _compressor = new Compressor(level);

        if (load == CspDictionaryLoad.Attach)
        {
            // ZSTD_c_forceAttachDict = ZSTD_dictForceAttach.
            _compressor.SetParameter(
                ZSTD_cParameter.ZSTD_c_experimentalParam4,
                (int)ZSTD_dictAttachPref_e.ZSTD_dictForceAttach);
        }
    }

    /// <summary>
    /// Compresses <paramref name="chunk"/> into exactly one zstd frame that
    /// decodes to the chunk bytes.
    /// </summary>
    /// <param name="chunk">The target chunk bytes.</param>
    /// <param name="dictionary">
    /// Concatenated raw dictionary content of the entry's named base chunks, or
    /// an empty span for no dictionary.
    /// </param>
    /// <returns>
    /// The stored bytes of one encoding-1 payload entry, valid until the next
    /// call.
    /// </returns>
    /// <exception cref="ObjectDisposedException">The encoder has been disposed.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="dictionary"/> exceeds 1 MiB or starts with the zstd
    /// dictionary magic.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The backend produced a frame that <see cref="ZstdFrameEnvelope"/> rejects.
    /// </exception>
    internal ReadOnlySpan<byte> EncodeZstd(ReadOnlySpan<byte> chunk, ReadOnlySpan<byte> dictionary)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!CspDictionary.IsUsable(dictionary))
        {
            throw new ArgumentException(
                "The CSP dictionary cannot be used: it exceeds 1 MiB or starts "
                + "with the zstd dictionary magic.",
                nameof(dictionary));
        }

        int windowLog = chunk.Length > ZstdFrameEnvelope.MaximumWindowBytes
            ? MaximumWindowLog
            : DefaultParameter;

        // Wrap(ReadOnlySpan<byte>) allocates a compress-bound array per call;
        // the create path encodes each chunk up to nine times, so the buffer
        // is reused instead.
        int bound = Compressor.GetCompressBound(chunk.Length);

        if (_frameBuffer.Length < bound)
        {
            _frameBuffer = new byte[Math.Max(bound, _frameBuffer.Length * 2)];
        }

        (int hashLog, int chainLog) = TableLogs(chunk.Length, dictionary.Length);
        int written = _context is null
            ? CompressLoaded(chunk, dictionary, windowLog, hashLog, chainLog)
            : _context.Compress(_level, chunk, dictionary, windowLog, hashLog, chainLog, _frameBuffer);
        ReadOnlySpan<byte> frame = _frameBuffer.AsSpan(0, written);

        try
        {
            ZstdFrameEnvelope.Validate(frame, chunk.Length);
        }
        catch (InvalidDataException exception)
        {
            throw new InvalidOperationException(
                "The zstd backend produced a frame the CSP format rejects.",
                exception);
        }

        return frame;
    }

    /// <inheritdoc cref="EncodeZstd(ReadOnlySpan{byte}, ReadOnlySpan{byte})" />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _compressor?.Dispose();
        _context?.Dispose();
    }

    private static void Check(nuint result)
    {
        if (Methods.ZSTD_isError(result))
        {
            throw new InvalidOperationException(
                $"The zstd backend failed: {Methods.ZSTD_getErrorName(result)}.");
        }
    }

    /// <summary>
    /// Returns the capped hash and chain logs of an entry, zero where no cap
    /// applies: without a dictionary, without a cap, or where zstd's own choice
    /// for the level, chunk and dictionary sizes is already within the cap.
    /// </summary>
    private (int HashLog, int ChainLog) TableLogs(int chunkLength, int dictionaryLength)
    {
        if (dictionaryLength == 0 || (_dictionaryHashLog == 0 && _dictionaryChainLog == 0))
        {
            return (DefaultParameter, DefaultParameter);
        }

        ZSTD_compressionParameters chosen = Methods.ZSTD_getCParams(
            _level,
            (ulong)chunkLength,
            (nuint)dictionaryLength);

        return (
            Cap(chosen.hashLog, _dictionaryHashLog),
            Cap(chosen.chainLog, _dictionaryChainLog));

        static int Cap(uint chosen, int cap) =>
            cap != 0 && chosen > (uint)cap ? cap : DefaultParameter;
    }

    private int CompressLoaded(
        ReadOnlySpan<byte> chunk,
        ReadOnlySpan<byte> dictionary,
        int windowLog,
        int hashLog,
        int chainLog)
    {
        Compressor compressor = _compressor!;
        compressor.LoadDictionary(dictionary);
        compressor.SetParameter(ZSTD_cParameter.ZSTD_c_windowLog, windowLog);

        // Without caps the parameters are never touched, so the default policy
        // makes the frames it made before the caps existed.
        if (_dictionaryHashLog != 0 || _dictionaryChainLog != 0)
        {
            compressor.SetParameter(ZSTD_cParameter.ZSTD_c_hashLog, hashLog);
            compressor.SetParameter(ZSTD_cParameter.ZSTD_c_chainLog, chainLog);
        }

        return compressor.Wrap(chunk, _frameBuffer);
    }

    /// <summary>
    /// A zstd compression context in one native workspace the encoder owns
    /// (<c>ZSTD_initStaticCCtx</c>). zstd never allocates in it; the workspace
    /// grows when an entry needs more and never shrinks, so a create allocates
    /// it a few times at most instead of once per dictionary candidate.
    /// </summary>
    private sealed class StaticContext : SafeHandle
    {
        // Rounding keeps the few growth steps from following every size change.
        private const nuint Granularity = 1 << 20;

        private nuint _size;
        private ZSTD_CCtx_s* _context;

        internal StaticContext()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        internal int Compress(
            int level,
            ReadOnlySpan<byte> chunk,
            ReadOnlySpan<byte> dictionary,
            int windowLog,
            int hashLog,
            int chainLog,
            byte[] destination)
        {
            ZSTD_compressionParameters parameters = Methods.ZSTD_getCParams(
                level,
                (ulong)chunk.Length,
                (nuint)dictionary.Length);

            if (windowLog != DefaultParameter)
            {
                parameters.windowLog = (uint)windowLog;
            }

            if (hashLog != DefaultParameter)
            {
                parameters.hashLog = (uint)hashLog;
            }

            if (chainLog != DefaultParameter)
            {
                parameters.chainLog = (uint)chainLog;
            }

            Reserve(Methods.ZSTD_estimateCCtxSize_usingCParams(parameters));

            fixed (byte* source = chunk)
            fixed (byte* prefix = dictionary)
            fixed (byte* output = destination)
            {
                while (true)
                {
                    Check(Methods.ZSTD_CCtx_reset(_context, ZSTD_ResetDirective.ZSTD_reset_session_and_parameters));
                    Check(Methods.ZSTD_CCtx_setParameter(_context, ZSTD_cParameter.ZSTD_c_compressionLevel, level));
                    Check(Methods.ZSTD_CCtx_setParameter(_context, ZSTD_cParameter.ZSTD_c_windowLog, windowLog));
                    Check(Methods.ZSTD_CCtx_setParameter(_context, ZSTD_cParameter.ZSTD_c_hashLog, hashLog));
                    Check(Methods.ZSTD_CCtx_setParameter(_context, ZSTD_cParameter.ZSTD_c_chainLog, chainLog));

                    // A prefix is raw content and applies to the next frame
                    // only; an empty dictionary references none.
                    if (!dictionary.IsEmpty)
                    {
                        Check(Methods.ZSTD_CCtx_refPrefix(_context, prefix, (nuint)dictionary.Length));
                    }

                    nuint written = Methods.ZSTD_compress2(
                        _context,
                        output,
                        (nuint)destination.Length,
                        source,
                        (nuint)chunk.Length);

                    // The estimate is an upper bound for single-shot
                    // compression; should it fall short, grow and repeat.
                    if (Methods.ZSTD_isError(written) &&
                        Methods.ZSTD_getErrorCode(written) == ZSTD_ErrorCode.ZSTD_error_memory_allocation)
                    {
                        Reserve(_size * 2);
                        continue;
                    }

                    Check(written);
                    return checked((int)written);
                }
            }
        }

        protected override bool ReleaseHandle()
        {
            NativeMemory.Free((void*)handle);
            return true;
        }

        private void Reserve(nuint needed)
        {
            if (needed <= _size)
            {
                return;
            }

            nuint size = (needed + Granularity - 1) / Granularity * Granularity;

            // The old workspace is freed first, so the two never coexist: a
            // growth step costs no more than the workspace it produces.
            if (!IsInvalid)
            {
                NativeMemory.Free((void*)handle);
                SetHandle(IntPtr.Zero);
                _size = 0;
                _context = null;
            }

            void* workspace = NativeMemory.Alloc(size);
            SetHandle((IntPtr)workspace);
            _size = size;
            _context = Methods.ZSTD_initStaticCCtx(workspace, size);

            if (_context is null)
            {
                throw new InvalidOperationException("zstd could not place a compression context in its workspace.");
            }
        }
    }
}
