// Minimal ASP.NET Core use of the ChunkShift Core package: the request body
// Stream goes straight into ChunkShift, forward-only, with no IFormFile, no
// EnableBuffering and no full materialization of the upload.
//
//   POST /chunks    store each new chunk in a content-addressed directory;
//                   responds "chunks=<n> bytes=<n> stored=<n>" (stored is
//                   best-effort when the same content is uploaded concurrently)
//   POST /manifest  respond with the binary CSM manifest of the request body
//
// Configuration (appsettings, environment or command line):
//   ChunkShift:MaxRequestBodyBytes  body limit for these two endpoints only
//   ChunkShift:ChunkStore           directory for /chunks
//
// ChunkShift hashes the bytes the request Stream presents. If request
// decompression middleware is added, chunk identities describe decompressed
// bytes, and its own size limits must be configured as well.

using ChunkShift;
using Microsoft.AspNetCore.Http.Features;
using static System.FormattableString;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
WebApplication app = builder.Build();

// Kestrel's default request-body limit (about 30 MB) stays in force for the
// host; only the ChunkShift endpoints raise it, to this explicit value.
long maxRequestBodyBytes = app.Configuration.GetValue("ChunkShift:MaxRequestBodyBytes", 1L << 30);
string chunkStore = Path.GetFullPath(
    app.Configuration["ChunkShift:ChunkStore"] ??
    Path.Combine(app.Environment.ContentRootPath, "chunk-store"));
Directory.CreateDirectory(chunkStore);

app.MapPost("/chunks", async (HttpContext context) =>
{
    SetRequestBodyLimit(context, maxRequestBodyBytes);

    long chunks = 0;
    long bytes = 0;
    long stored = 0;

    // The handler is awaited before ChunkShift reads further, so a slow store
    // slows the upload down instead of buffering it (backpressure).
    // RequestAborted cancels the scan when the client disconnects.
    await ChunkScanner.ScanAsync(
        context.Request.Body,
        async (chunk, content, cancellationToken) =>
        {
            chunks++;
            bytes += chunk.Length;

            if (await StoreChunkAsync(chunkStore, chunk, content, cancellationToken))
            {
                stored++;
            }
        },
        cancellationToken: context.RequestAborted);

    return Results.Text(Invariant($"chunks={chunks} bytes={bytes} stored={stored}\n"));
});

app.MapPost("/manifest", async (HttpContext context) =>
{
    SetRequestBodyLimit(context, maxRequestBodyBytes);

    // CreateAsync writes the manifest while it reads the body. Writing it to
    // a temporary file first means a failed or aborted upload never reaches
    // the client as a truncated 200 response.
    var manifest = new FileStream(
        Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()),
        FileMode.CreateNew,
        FileAccess.ReadWrite,
        FileShare.None,
        bufferSize: 4096,
        FileOptions.Asynchronous | FileOptions.DeleteOnClose);

    try
    {
        ManifestInfo info = await ChunkManifest.CreateAsync(
            context.Request.Body,
            manifest,
            new ManifestCreationOptions { IncludeBlockIndex = true },
            context.RequestAborted);

        manifest.Position = 0;
        context.Response.Headers["X-ChunkShift-Manifest-Id"] = info.ManifestId.ToString();

        // Results.Stream disposes (and so deletes) the file once it is sent.
        return Results.Stream(manifest, "application/octet-stream");
    }
    catch
    {
        await manifest.DisposeAsync();
        throw;
    }
});

app.Run();

static void SetRequestBodyLimit(HttpContext context, long limit)
{
    IHttpMaxRequestBodySizeFeature? feature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (feature is { IsReadOnly: false })
    {
        feature.MaxRequestBodySize = limit;
    }
}

// Content-addressed store: the file name is the ChunkId, so a chunk that is
// already present is not written again. `content` is borrowed and only valid
// until this method completes, which is why it is written out before returning.
// Concurrent uploads of the same content may both write a chunk: the bytes are
// identical, so the later rename harmlessly replaces the earlier copy, and the
// "stored" count is best-effort under such races. (File.Move with
// overwrite: false is a check followed by rename on Unix, not an atomic
// no-replace, so it would not prevent this anyway.)
static async ValueTask<bool> StoreChunkAsync(
    string store,
    ChunkInfo chunk,
    ReadOnlyMemory<byte> content,
    CancellationToken cancellationToken)
{
    string path = Path.Combine(store, chunk.Id.Value.ToHexLower());
    if (File.Exists(path))
    {
        return false;
    }

    string temporary = Invariant($"{path}.{Path.GetRandomFileName()}.tmp");

    try
    {
        await File.WriteAllBytesAsync(temporary, content, cancellationToken);
        File.Move(temporary, path, overwrite: true);
        return true;
    }
    catch
    {
        File.Delete(temporary);
        throw;
    }
}
