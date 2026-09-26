# Hosting ChunkShift in ASP.NET Core

Status: Supported composition for Core 0.1  
Last reviewed: 2026-09-27

ChunkShift Core has no ASP.NET Core dependency and needs none. The request body is a `Stream`, and Core consumes streams directly. This guide lists what the host owns and the rules that keep the composition correct. A runnable example is in [`samples/ChunkShift.Samples.AspNetCore`](../samples/ChunkShift.Samples.AspNetCore/Program.cs).

## 1. Recommended path

```text
HttpRequest.Body
    -> ChunkScanner.ScanAsync / ChunkManifest.CreateAsync
    -> HttpContext.RequestAborted as the cancellation token
```

```csharp
app.MapPost("/manifest", async (HttpContext context) =>
{
    // ... set the request-body limit first (§3) ...
    string temporary = Path.GetTempFileName();
    await using (FileStream manifest = File.Create(temporary))
    {
        await ChunkManifest.CreateAsync(
            context.Request.Body, manifest, cancellationToken: context.RequestAborted);
    }
    // Publish or stream `temporary` only after CreateAsync succeeded.
});
```

Real-Kestrel validation of the Core 0.1 contract confirmed:

- `HttpRequest.Body` is the preferred input. Wrapping `HttpRequest.BodyReader` in a stream gives the same chunk sequence and no reproducible throughput advantage, at a higher allocation cost, so Core has no `PipeReader` overload.
- `IFormFile` and `EnableBuffering` are not needed and defeat bounded memory for large bodies.
- Output does not depend on how Kestrel segments the body: one-byte, random and normal reads produce the same chunk identities.
- A 1 GiB body streamed through Kestrel into both `ScanAsync` and `CreateAsync` stays inside a 128 MiB memory limit.
- Concurrent requests keep independent, deterministic state.

No `ChunkShift.AspNetCore` package exists or is required. Authentication, authorization, request limits, decompression, rate limiting and caching stay host policy.

## 2. Cancellation and disconnects

Two cases are different and both are safe:

- **Disconnect during a body read.** Kestrel may fail the read with a transport exception (and a 400 response) before `RequestAborted` is observed. The scan or `CreateAsync` fails; nothing is reported as success, and an incomplete chunk is never emitted. Do not rely on seeing `RequestAborted` first.
- **Cancellation while your handler runs.** The token passed to the handler is the one you passed to Core. A handler that observes it unwinds promptly. Cancellation is cooperative: a handler that ignores the token keeps running until it returns, because Core never preempts application code.

## 3. Request-size limits and decompression

- Set `IHttpMaxRequestBodySizeFeature.MaxRequestBodySize` **before** the first body read; the feature becomes read-only afterwards. It then rejects known-length bodies above the limit and chunked bodies once the consumed bytes cross it. The sample raises the limit only for its own endpoints.
- If you add request decompression middleware, put the limit on the endpoint as metadata (for example `[RequestSizeLimit]` or `.WithMetadata(new RequestSizeLimitAttribute(...))`). The middleware reads endpoint metadata when it wraps the body, so a limit assigned inside the endpoint is too late for it.
- ChunkShift hashes the bytes the request stream presents. Behind decompression, chunk identities describe the decompressed bytes. ChunkShift does not inspect `Content-Encoding` and does not implement decompression-bomb policy.

## 4. Publishing and serving a CSM

Create manifests forward-only into a temporary file and publish only after `CreateAsync` succeeds; a failed or aborted request must not expose a truncated manifest. For a completed, immutable CSM:

- open a fresh seekable `FileStream` per response and let ASP.NET Core handle ranges (`Results.File(..., enableRangeProcessing: true)`);
- use the quoted physical `ManifestInfo.FileDigest` as the strong `ETag`;
- expose the logical `ManifestId` separately, for example in a response header, and never use it as an HTTP validator.

The same content can have several valid CSM representations (for example with and without BIDX). They share a `ManifestId` but have different `FileDigest` values and bytes, so only `FileDigest` identifies the representation a cache or range request refers to. Full responses, prefix and suffix ranges, unsatisfiable ranges, `If-Range` and `If-None-Match` all behave as standard ASP.NET Core defines when the ETag is `FileDigest`.

## 5. Stream ownership

- Core never disposes streams you pass to it.
- `Results.Stream(Stream)` disposes the stream it is given, and `Results.Stream(PipeReader)` completes its reader. Hand those APIs a fresh per-response resource, never a shared long-lived stream.
- For slow response consumers, Kestrel and socket buffering decide how far a response source is read ahead; do not depend on an exact read-ahead size.

## 6. Out of scope

This guide does not define a resumable-upload protocol, per-chunk distribution endpoints, proxy or CDN behavior, or HTTP/2- and HTTP/3-specific tuning.
