# CSM v1 binary specification

Status: Normative for CSM FormatMajor 1  
Last reviewed: 2026-09-27

CSM (ChunkShift Manifest) records the ordered chunk sequence of one content stream: each chunk's identity and length, the chunking profile and HashSuite that produced them, a logical `ManifestId` and a physical `FileDigest`. This document is the byte-level contract for writers and readers.

CSM v1 becomes a persisted compatibility contract with the first published ChunkShift package. From then on an incompatible change requires a new format version; the format version is independent from the NuGet package version.

## 1. Byte order and common rules

- all integers are little-endian;
- all offsets/counts are unsigned unless explicitly stated;
- persistent IDs are exactly 32 bytes;
- chunk lengths are UInt32;
- identifier strings are UTF-8 ASCII-compatible ChunkShift IDs and MUST be 1..128 bytes;
- checked arithmetic is mandatory before allocation, seek or length multiplication;
- reserved fields MUST be zero;
- unknown required features fail;
- unknown optional physical sections may be skipped without materialization;
- a reader MUST NOT allocate based solely on an untrusted length before validating configured/hard limits.

## 2. Physical order

```text
PREAMBLE
CORE
CBLK*
CEND
[AUX]*
[BIDX]
FOOT
TRAILER
```

The writer emits forward-only through CEND. Optional AUX/BIDX/FOOT/TRAILER finalization may follow after source scanning; no header backpatching is required.

### 2.1 Section state machine

A conforming v1 physical stream follows this exact state machine:

```text
PREAMBLE
  -> exactly one CORE
  -> zero or more CBLK
  -> exactly one CEND
  -> zero or more optional AUX*
  -> zero or one BIDX
  -> exactly one FOOT
  -> exactly one fixed TRAILER at physical EOF
```

The reader MUST reject:

- duplicate CORE, CEND, BIDX or FOOT;
- CBLK before CORE or after CEND;
- AUX before CEND or after BIDX/FOOT;
- BIDX before CEND or more than once;
- any section after FOOT;
- bytes after TRAILER;
- missing CORE, CEND, FOOT or TRAILER.

Unknown optional physical sections are permitted only in the AUX phase between CEND and BIDX/FOOT.

## 3. PREAMBLE — fixed 32 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | Magic = ASCII `CSM1` |
| 4 | 2 | FormatMajor = 1 |
| 6 | 2 | PreambleSize = 32 |
| 8 | 8 | RequiredPhysicalFeatures |
| 16 | 8 | OptionalPhysicalFeatures |
| 24 | 8 | Reserved = 0 |

CSM v1 requires PreambleSize = 32 exactly and rejects a different magic/major, non-zero reserved bytes, or unknown required physical bits. A future compatible revision may define a larger preamble only together with explicit format-version rules for interpreting or skipping the added bytes; the current reader does not guess such rules.

## 4. Section header — fixed 16 bytes

Every section after PREAMBLE and before TRAILER starts with:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | Type FourCC |
| 4 | 4 | Flags |
| 8 | 8 | PayloadLength |

Known v1 types: `CORE`, `CBLK`, `CEND`, `AUX0`, `BIDX`, `FOOT`.

Section flag bit 0 means REQUIRED. All other v1 flag bits are reserved and MUST be zero.

Unknown section behavior:

- REQUIRED set -> fail;
- REQUIRED clear -> skip exactly PayloadLength bytes without allocating the payload.

Known optional section behavior: `AUX0` and `BIDX` are optional physical metadata. Writers MUST emit them with REQUIRED clear, and readers MUST reject either one with REQUIRED set, because an optional section cannot demand to be understood. Writers set REQUIRED on `CORE`, `CBLK`, `CEND` and `FOOT`. A known section's type, not its REQUIRED flag, decides where it may appear (section 2.1).

Section length plus header must fit the remaining physical file/range using checked UInt64 arithmetic.

## 5. CORE payload

Fixed prefix: 56 bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | RequiredSemanticFeatures |
| 8 | 8 | OptionalSemanticFeatures |
| 16 | 32 | ProfileFingerprint |
| 48 | 2 | HashSuiteIdLength |
| 50 | 2 | ChunkingProfileIdLength |
| 52 | 4 | ExtensionBytes |

Then, in order:

```text
HashSuiteId UTF-8 bytes
ChunkingProfileId UTF-8 bytes
ExtensionBytes of canonical TLVs
```

Rules:

- both IDs use the ChunkShift ID grammar and are at most 128 bytes;
- v1 hard limit for ExtensionBytes is 65,536;
- CORE PayloadLength MUST equal `56 + HashSuiteIdLength + ChunkingProfileIdLength + ExtensionBytes`;
- CSM v1 defines **no semantic feature bits**: writers MUST emit both `RequiredSemanticFeatures = 0` and `OptionalSemanticFeatures = 0`; readers MUST reject either field when non-zero;
- canonical TLVs are cold semantic metadata only, never per-chunk records.

The TLV registry is empty for CSM v1. Until a concrete semantic extension is accepted and specified, writers MUST emit `ExtensionBytes = 0` and readers MUST reject non-zero ExtensionBytes.

This zero-only rule deliberately closes the current identity ambiguity: no semantic bit or TLV may affect interpretation while remaining outside ManifestId. When a real semantic extension is designed, its identity contribution must be specified before the feature is assigned a bit/TLV.

## 6. CBLK payload

Each block represents 1..4096 logical chunks.

Fixed block prefix: 24 bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ChunkCount |
| 4 | 4 | Reserved = 0 |
| 8 | 8 | FirstChunkIndex |
| 16 | 8 | FirstContentOffset |

Then:

```text
ChunkId[ChunkCount]       // 32 bytes each
Length[ChunkCount]        // UInt32 each
BlockCrc32C               // UInt32
```

Expected PayloadLength:

```text
24 + ChunkCount*32 + ChunkCount*4 + 4
```

`BlockCrc32C` is **CRC-32C / Castagnoli** with these parameters:

```text
width   = 32
poly    = 0x1EDC6F41       # normal form
refin   = true
refout  = true
init    = 0xFFFFFFFF
xorout  = 0xFFFFFFFF
check("123456789") = 0xE3069283
```

The numeric CRC value is stored as UInt32 little-endian; the check value above is therefore serialized as bytes `83 92 06 E3`.

The CRC covers the 16-byte CBLK section header plus all CBLK payload bytes preceding the CRC field. The CRC field itself is excluded.

Rules:

- ChunkCount 0 is invalid;
- ChunkCount > 4096 is invalid in CSM v1;
- FirstChunkIndex MUST equal the global number of chunks preceding this block;
- FirstContentOffset MUST equal the sum of preceding logical chunk lengths;
- every chunk Length MUST be > 0;
- prefix sums use checked UInt64 arithmetic;
- CBLK grouping is physical and does not enter ManifestId.

## 7. CEND payload — fixed 48 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | TotalChunkCount |
| 8 | 8 | TotalContentLength |
| 16 | 32 | ManifestId |

The reader verifies that totals match the streamed CBLK sequence.

## 8. ManifestId canonical calculation

ManifestId is logical and independent of physical grouping/indexes.

Using the manifest-selected HashSuite:

```text
ManifestId = HashSuite.Hash(
    UTF8("chunkshift.manifest-id.v1\0")
    || UInt16LE(HashSuiteIdByteLength)
    || UTF8(HashSuiteId)
    || UInt16LE(ChunkingProfileIdByteLength)
    || UTF8(ChunkingProfileId)
    || ProfileFingerprint[32]
    || repeated {
         ChunkId[32]
         UInt32LE(Length)
       }
    || UInt64LE(TotalChunkCount)
    || UInt64LE(TotalContentLength)
)
```

The following MUST NOT enter ManifestId:

- CBLK boundaries;
- CBLK/section offsets;
- BIDX presence/content;
- AUX sections;
- diagnostics/timestamps;
- physical FileDigest;
- optional ContentId.

Changing any canonical semantic field above changes ManifestId.

The final totals are deliberately encoded **after** the ordered chunk records. They are
not known until source EOF, so placing them before the records would make a true
single-pass, forward-only writer impossible without buffering/spooling the complete
logical entry sequence or rereading the source. The ordering above binds the same
semantic fields while allowing both writer and reader to compute ManifestId
incrementally with bounded memory.

## 9. AUX sections

`AUX0` is an optional physical section family and MUST NOT affect ManifestId.

CSM v1 defines no mandatory AUX payload. Readers skip unknown optional AUX sections by PayloadLength without materialization. A future semantic extension cannot be smuggled into AUX; semantic data belongs in CORE feature bits/TLVs and requires normal compatibility rules.

## 10. BIDX payload

BIDX is optional and physical.

Fixed prefix:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | IndexVersion = 1 |
| 4 | 4 | BlockCount |

Each entry is 16 bytes:

| Size | Field |
| ---: | --- |
| 8 | FirstContentOffset |
| 8 | CblkSectionFileOffset |

Entries are strictly increasing by both content offset and file offset and correspond one-to-one with CBLK sections.

BIDX enables content-position-to-block lookup without storing a UInt64 offset per chunk. Presence/absence does not change ManifestId.

The .NET implementation applies an **operational**, non-persisted cap of 262,144 BIDX entries for writer materialization and forward-reader validation. At 4096 chunks per CBLK this covers more than one billion chunks. This cap is not a CSM v1 format maximum: a forward reader may process a larger non-indexed manifest, while a BIDX beyond the local validation cap is rejected rather than materialized without bound.

## 11. FOOT payload — fixed 48 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | CoreSectionOffset |
| 8 | 8 | CendSectionOffset |
| 16 | 8 | BidxSectionOffset, 0 when absent |
| 24 | 8 | FirstCblkSectionOffset, 0 when no chunks |
| 32 | 8 | CblkCount |
| 40 | 8 | Reserved = 0 |

Offsets identify section headers, not payload starts.

## 12. TRAILER — fixed 64 bytes

TRAILER is not preceded by a section header.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | Magic = ASCII `CSMT` |
| 4 | 2 | FormatMajor = 1 |
| 6 | 2 | TrailerSize = 64 |
| 8 | 8 | FootSectionOffset |
| 16 | 8 | PhysicalLength |
| 24 | 32 | FileDigest |
| 56 | 8 | Reserved = 0 |

`PhysicalLength` is the complete byte length including TRAILER.

`FileDigest` is the manifest-selected HashSuite digest of every physical byte before the TRAILER. The TRAILER is excluded to avoid self-reference.

A tail reader can fetch the fixed 64-byte TRAILER, locate FOOT, then locate CORE/CEND/BIDX.

## 13. Reader resource bounds

A conforming v1 reader enforces at least:

- `RequiredSemanticFeatures == 0` and `OptionalSemanticFeatures == 0`;
- `ExtensionBytes == 0`;
- CORE extension hard ceiling remains 65,536 for future format work but does not authorize v1 extensions;
- identifier byte lengths <= 128 each;
- CBLK ChunkCount <= 4096;
- every CBLK computed payload size matches PayloadLength exactly;
- every offset/count/length multiplication/addition is checked;
- when the remaining physical byte length is known (for example, a seekable file or bounded range), section PayloadLength cannot exceed it;
- on an unknown-length forward-only stream, the reader validates arithmetic and configured limits first, then consumes exactly PayloadLength bytes and treats premature EOF as truncation;
- optional unknown sections are skipped/streamed, not blindly allocated;
- total content length/count must match CEND and observed chunks;
- lengths requiring a .NET `long`/memory operation must additionally fit that implementation boundary: the .NET API exposes chunk lengths as `Int32` and offsets/totals as `Int64`, so a well-formed manifest with a chunk Length above `Int32.MaxValue` or a content length above `Int64.MaxValue` is reported as unsupported (`NotSupportedException`), not as malformed. Every stable profile already satisfies these bounds;
- the .NET implementation tracks at most 262,144 CBLK entries for optional BIDX validation and refuses to generate/validate a larger BIDX rather than grow metadata without bound.

Configurable operational limits may be stricter than the format maxima. Operational limits are not persisted compatibility limits unless the format specification explicitly says otherwise.

## 14. Verification levels

### Structural

Validate magic/version/lengths/order/features/reserved zeros/checked arithmetic.

### Block integrity

Validate every CBLK CRC32C before accepting that block.

### Logical integrity

Recompute ManifestId from CORE semantics plus ordered `(ChunkId, Length)` records and compare with CEND.

### Physical integrity

Recompute FileDigest over all bytes before TRAILER and compare with TRAILER.

### Profile semantics

CORE records `ChunkingProfileId` and `ProfileFingerprint` independently ([PROFILE-FINGERPRINT-V1](PROFILE-FINGERPRINT-V1.md)). The format does not require a reader to know any profile. A reader that registers the declared `ChunkingProfileId` compares its own fingerprint for that identifier with the recorded one and reports a mismatch as a profile-semantics failure; an identifier it does not register is not a failure for manifest-only verification.

Verifying content against a manifest means re-chunking it with the manifest's profile, so it additionally requires the reader to register that profile.

The .NET API maps the levels to outcomes as follows:

| Situation | Manifest-only (`VerifyManifestAsync`, `ManifestReader`) | Content (`VerifyAsync`) |
| --- | --- | --- |
| malformed CSM | `InvalidDataException` | `InvalidDataException` |
| unknown HashSuite | `NotSupportedException` | `NotSupportedException` |
| unknown ProfileId | accepted | `NotSupportedException` |
| known ProfileId, different fingerprint | `ProfileSemantics` | `ProfileSemantics` (content not chunked) |
| content differs | — | `Content` |
| bad CBLK CRC / ManifestId / FileDigest | `BlockCrc` / `ManifestId` / `FileDigest` | `BlockCrc` / `ManifestId` / `FileDigest` |

Hash equality proves integrity against a trusted expected value; it does not by itself provide authenticity/signature semantics.

## 15. Streaming/finalization behavior

Writer:

1. emits PREAMBLE and CORE;
2. consumes source chunks and emits CBLKs;
3. incrementally computes ManifestId inputs and physical FileDigest;
4. emits CEND;
5. optionally emits AUX/BIDX;
6. emits FOOT;
7. finalizes FileDigest over bytes through FOOT;
8. emits TRAILER.

Reader must support forward streaming through CORE/CBLK/CEND without needing BIDX/FOOT materialization. Seek/tail-index use is an optimization, not a semantic requirement.

## 16. Conformance vectors

The committed CSM v1 fixtures ([`tests/ChunkShift.Tests/Fixtures/CsmV1`](../../tests/ChunkShift.Tests/Fixtures/CsmV1/README.md)) include at least:

- empty manifest;
- one chunk;
- multiple CBLKs;
- optional BIDX present/absent with identical ManifestId;
- malformed/truncated section headers;
- impossible/overflowing lengths;
- bad CBLK CRC32C;
- mismatched CEND totals;
- bad ManifestId;
- bad FileDigest;
- non-zero semantic feature rejection;
- duplicate/out-of-order CORE/CBLK/CEND/BIDX/FOOT rejection;
- unknown required section/feature rejection;
- unknown optional AUX-phase section skip;
- CRC-32C known vector `123456789 -> E3069283`;
- equivalent logical manifest encoded with permitted physical differences.

The fixtures are produced by an independent standard-library generator and checked by an independent decoder ([`tools/conformance/csm`](../../tools/conformance/csm/)); neither shares code with the .NET implementation. Changing a fixture byte is a format change, not a test update.
