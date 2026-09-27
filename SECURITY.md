# Security Policy

ChunkShift parses untrusted binary input (CSM manifests) and processes arbitrary content streams. Security reports are handled separately from ordinary bugs.

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability that could enable exploitation, data corruption, denial of service, integrity-check bypass or unsafe parser behavior.

Report it privately through GitHub:

https://github.com/MrFr3di/ChunkShift/security/advisories/new

Include:

- affected version or commit;
- a minimal reproduction or malformed input, when safe to share;
- expected and actual behavior;
- the security impact you see;
- whether the issue is already public.

If private reporting is unavailable, contact the maintainer through GitHub without publishing exploit details.

## Supported versions

| Version | Security fixes |
| --- | --- |
| latest `0.1.Z` release | yes |
| older `0.1.Z` releases | upgrade to the latest release |

During the pre-1.0 `0.1.Z` train, fixes ship in the next patch release rather than being backported ([docs/SUPPORT.md](docs/SUPPORT.md)).

## Security boundaries

Security-sensitive areas include:

- CSM parsing: sizes, counts, offsets and section order from untrusted input;
- checked arithmetic and resource bounds before allocation or seeking;
- borrowed and pooled buffer lifetime;
- integrity semantics of `ChunkId`, `ManifestId` and `FileDigest`;
- dependency and CI/release supply-chain changes.

A cryptographic content hash proves integrity relative to a trusted expected value. It is not a signature or an authenticity proof: anyone can produce a valid manifest for content they control.

## In-process pooled-buffer residuals

ChunkShift uses pooled buffers on streaming hot paths. Returned pooled storage is an implementation resource, not a confidentiality boundary.

- Borrowed chunk memory is valid only for its documented lease and must not be used after it ends.
- ChunkShift may return backing storage to a pool without clearing every byte.
- Callers must not assume pooled memory is zeroed before or after use.
- Code running with arbitrary execution inside the same process is outside the confidentiality boundary of ordinary pooled-memory reuse.
- Secrets that need stronger in-process erasure must not rely on the default high-throughput scanner path.

ChunkShift does not scrub buffers by default. Scrubbing materially increases memory bandwidth on large streaming workloads and does not by itself create a process-isolation boundary. Changing the pooling strategy never changes chunk identity or persisted formats, provided the documented borrowed-memory lifetime holds.
