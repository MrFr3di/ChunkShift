namespace ChunkShift.Patching.IO;

/// <summary>
/// A temporary file in the destination directory that replaces the
/// destination only when <see cref="CommitAsync"/> is called
/// (CSP-V1 section 6, step 8).
/// </summary>
/// <remarks>
/// <para>
/// The temporary file lives next to the destination so the final rename stays
/// on one volume. Commit flushes it to disk and then renames it over the
/// destination; every other outcome (an exception, cancellation, disposal
/// without commit) deletes it and leaves an existing destination unchanged.
/// </para>
/// <para>
/// This guarantees that an unverified target never becomes visible at the
/// destination path. It does not promise that the new directory entry
/// survives a power loss: the directory itself is not flushed.
/// </para>
/// </remarks>
internal sealed class PendingFile : IAsyncDisposable
{
    private const int BufferSize = 64 * 1024;

    private readonly string _destinationPath;
    private FileStream? _stream;
    private bool _flushedToDisk;
    private bool _committed;

    private PendingFile(string destinationPath, string temporaryPath, FileStream stream)
    {
        _destinationPath = destinationPath;
        TemporaryPath = temporaryPath;
        _stream = stream;
    }

    /// <summary>Gets the full path of the temporary file.</summary>
    internal string TemporaryPath { get; }

    /// <summary>
    /// Gets the readable, writable and seekable temporary file.
    /// </summary>
    internal FileStream Stream =>
        _stream ?? throw new InvalidOperationException("The pending file is no longer open.");

    /// <summary>
    /// Creates a new, empty temporary file for <paramref name="destinationPath"/>.
    /// </summary>
    /// <exception cref="IOException">The destination directory does not exist or cannot be written.</exception>
    internal static PendingFile Create(string destinationPath)
    {
        string fullPath = Path.GetFullPath(destinationPath);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("The destination path has no parent directory.", nameof(destinationPath));

        // Hidden on Unix, unique per attempt, recognizably tied to its destination.
        // The name prefix is capped so the temporary name stays within the
        // 255-character file-name limit even for a long destination name.
        string name = Path.GetFileName(fullPath);
        string temporaryPath = Path.Combine(
            directory,
            $".{name[..Math.Min(name.Length, 200)]}.{Guid.NewGuid():N}.tmp");

        var stream = new FileStream(
            temporaryPath,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                BufferSize = BufferSize,
                Options = FileOptions.Asynchronous,
            });

        return new PendingFile(fullPath, temporaryPath, stream);
    }

    /// <summary>
    /// Flushes the temporary file to disk ahead of <see cref="CommitAsync"/>,
    /// which then does not flush again. Nothing may be written afterwards. This
    /// publishes nothing: the destination changes only in <see cref="CommitAsync"/>.
    /// </summary>
    internal async Task FlushToDiskAsync(CancellationToken cancellationToken)
    {
        FileStream stream = Stream;
        cancellationToken.ThrowIfCancellationRequested();

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
        _flushedToDisk = true;
    }

    /// <summary>
    /// Flushes the temporary file to disk unless <see cref="FlushToDiskAsync"/>
    /// already did, closes it and renames it over the destination, replacing an
    /// existing file.
    /// </summary>
    /// <exception cref="IOException">
    /// The rename failed, for example because the destination is open without
    /// delete sharing on Windows. The temporary file is then deleted on disposal
    /// and the destination is unchanged.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">Same as above.</exception>
    internal async Task CommitAsync(CancellationToken cancellationToken)
    {
        FileStream stream = Stream;
        cancellationToken.ThrowIfCancellationRequested();

        if (!_flushedToDisk)
        {
            await FlushToDiskAsync(cancellationToken).ConfigureAwait(false);
        }

        await stream.DisposeAsync().ConfigureAwait(false);
        _stream = null;

        // The last point where the caller can still stop publication.
        cancellationToken.ThrowIfCancellationRequested();

        if (File.Exists(_destinationPath))
        {
            // On Windows, File.Move(overwrite: true) (MoveFileEx) refuses a
            // destination that another handle keeps open, even with delete
            // sharing; File.Replace (ReplaceFile) allows it, which in-place
            // updates need. On Unix both are rename(2).
            File.Replace(
                TemporaryPath,
                _destinationPath,
                destinationBackupFileName: null,
                ignoreMetadataErrors: true);
        }
        else
        {
            // A destination created since the check is replaced as well.
            File.Move(TemporaryPath, _destinationPath, overwrite: true);
        }

        _committed = true;
    }

    /// <summary>
    /// Closes and deletes the temporary file unless it was committed.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
            _stream = null;
        }

        if (!_committed)
        {
            try
            {
                File.Delete(TemporaryPath);
            }
            catch (IOException)
            {
                // Best effort: a leftover temporary file never replaces the destination.
            }
            catch (UnauthorizedAccessException)
            {
                // Same as above.
            }
        }
    }
}
