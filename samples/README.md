# ChunkShift samples

Two minimal applications that consume the **packed** `ChunkShift` package, the
way an application would:

| Sample | Shows |
|---|---|
| [`ChunkShift.Samples.Console`](ChunkShift.Samples.Console/Program.cs) | `ChunkScanner.ScanAsync` over a file; `ChunkManifest.CreateAsync` that reserves the target up front (fails at once if it exists) and publishes via a temporary file renamed over the reservation; `ChunkManifest.VerifyAsync` |
| [`ChunkShift.Samples.AspNetCore`](ChunkShift.Samples.AspNetCore/Program.cs) | `HttpRequest.Body` streamed straight into ChunkShift: per-chunk storage with backpressure, a CSM manifest response, `RequestAborted` cancellation and an explicit per-endpoint request-body limit |

They are not part of `ChunkShift.slnx`. CI (`package-smoke`) builds both
against the package it just produced and runs them end to end.

## Running locally

Until ChunkShift is on NuGet.org, pack it into a local feed first. Use a new
version for each pack; NuGet caches packages by version.

```text
dotnet pack src/ChunkShift/ChunkShift.csproj -c Release -o artifacts/packages -p:PackageVersion=0.0.0-local.1

dotnet run --project samples/ChunkShift.Samples.Console -c Release -p:ChunkShiftPackageVersion=0.0.0-local.1 -p:RestoreAdditionalProjectSources=<repo>/artifacts/packages -- scan <file>
dotnet run --project samples/ChunkShift.Samples.Console -c Release -p:ChunkShiftPackageVersion=0.0.0-local.1 -p:RestoreAdditionalProjectSources=<repo>/artifacts/packages -- create <file> <file>.csm
dotnet run --project samples/ChunkShift.Samples.Console -c Release -p:ChunkShiftPackageVersion=0.0.0-local.1 -p:RestoreAdditionalProjectSources=<repo>/artifacts/packages -- verify <file> <file>.csm
```

```text
dotnet run --project samples/ChunkShift.Samples.AspNetCore -c Release -p:ChunkShiftPackageVersion=0.0.0-local.1 -p:RestoreAdditionalProjectSources=<repo>/artifacts/packages -- --urls http://127.0.0.1:5080

curl -X POST --data-binary @<file> http://127.0.0.1:5080/chunks
curl -X POST --data-binary @<file> http://127.0.0.1:5080/manifest -o <file>.csm
```

Once a version is published, drop the `RestoreAdditionalProjectSources`
argument and set `ChunkShiftPackageVersion` to that version.

The ASP.NET Core sample raises the request-body limit only for its two
endpoints, to `ChunkShift:MaxRequestBodyBytes` (default 1 GiB); the host-wide
Kestrel limit is unchanged. Chunks go to `ChunkShift:ChunkStore` (default
`chunk-store/` under the content root).

The samples stay deliberately small. [`docs/ASPNET-CORE.md`](../docs/ASPNET-CORE.md)
covers the rest of the hosting contract: cancellation and disconnects, request
limits and decompression, and serving an immutable CSM with Range and a strong
ETag based on `ManifestInfo.FileDigest`.
