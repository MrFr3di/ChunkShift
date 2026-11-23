# CSP v1 patch specification

Status: Normative for CSP FormatMajor 1  
Last reviewed: 2026-11-23

CSP (ChunkShift Patch) is the byte format of a declarative, verifiable content update: a target [CSM v1](CSM-V1.md) manifest plus the target chunks a base does not already hold. This document is the byte-level contract for writers, readers and appliers. The layout, identities, apply contract and rejection rules are fixed for FormatMajor 1; a change to any of them requires a format revision and new conformance vectors (section 10). The fixed sizes and format maxima of section 8 are part of the format; its operational defaults are implementation limits, not persisted ones. The CSP format version is independent from the NuGet package version, from the CSM format version and from the chunking-profile version.

## 1. Scope and non-goals

CSP is a declarative content-update artifact:

- it carries a target manifest and the target chunk bytes that are not already present in a base;
- apply is a finite, pre-described sequence of chunk resolutions: a target chunk taken from the base by `ChunkId`, or a payload entry that is a raw copy or a single standard zstd frame of the target chunk bytes, optionally decoded against named base chunks;
- there is no instruction stream, no opcode VM and no executable content of any kind. A VCDIFF-style COPY/INSERT instruction VM is deliberately excluded: it would make the patch executable and its outcome dependent on interpreter state.

Non-goals:

- CSP is not a transport or repository format. Storage, HTTP Range layout and pack placement belong to the distribution layer. A CSP artifact is a byte sequence that can be stored or streamed anywhere.
- CSP does not define signatures or authenticity. A hash is not a signature; authenticity is a detached trust envelope layered outside the patch. No signature, key or trust slot exists inside CSP, including in optional sections, and none may enter a content identity.
- CSP does not define anti-rollback or update-policy metadata.
- CSP is a per-file format. Updating a tree of files (for example a runtime directory) is a set of patches plus a tree manifest, which belongs to the distribution layer, not to CSP v1.
- Compression is not a Core concern. CSP v1 defines zstd (RFC 8878) as its only non-raw payload codec (section 5.2); the codec lives in the Patching package, never in Core, and no codec changes a `ChunkId`, `ManifestId` or profile.

## 2. Byte order and common rules

CSP v1 inherits [CSM v1](CSM-V1.md) §1 unchanged; those rules apply verbatim to every CSP field:

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

Additional conventions:

- four-byte ASCII FourCC section types are encoded exactly as CSM §4 encodes them, and CRC-32C uses the exact CSM §6 contract: Castagnoli parameters, `check("123456789") = 0xE3069283`, the numeric value stored UInt32 little-endian, coverage equal to the 16-byte section header plus every payload byte preceding the CRC field;
- CSP defines no semantic-feature registry of its own. HashSuite, `ChunkingProfileId` and `ProfileFingerprint` semantics come from the embedded target CSM.

## 3. Identities a patch binds

A CSP artifact binds a transformation from a base identity (when it depends on one) to a required target identity. All identities are 256-bit.

### 3.1 Target ManifestId (required)

The patch embeds the complete target CSM byte-for-byte (section 4.5), and the target `ManifestId` is the embedded CSM's `ManifestId` as the CSM reader verifies it ([CSM v1](CSM-V1.md) §14). A patch without a valid target `ManifestId` has no defined target and MUST be rejected. Apply produces exactly the content that manifest describes: the ordered concatenation of its `(ChunkId, Length)` records.

### 3.2 Target FileDigest and ContentLength

The embedded target CSM carries, and the patch therefore binds:

- `FileDigest` (CSM TRAILER): the physical digest of the CSM artifact bytes themselves, verified by the CSM reader; it proves the embedded manifest is intact, not that reconstructed content is correct;
- `TotalContentLength` (CSM CEND): the exact reconstructed payload length, which apply MUST compare against the bytes written.

CSP v1 defines no separate whole-content digest. Reconstruction is bound chunk-by-chunk (section 9). If a later revision records an optional whole-content identity in the target manifest, apply MAY verify it in addition; nothing in v1 depends on it.

### 3.3 Base binding

A patch **depends on a base** when at least one distinct target `ChunkId` has no payload entry (it is taken from the base), or at least one payload entry names dictionary chunks (section 5.2).

- A patch that depends on a base MUST carry the `BASE` section (section 4.4) with the expected base `ManifestId`. Apply requires a base manifest with exactly that `ManifestId` and fails otherwise, without publishing any output (section 6).
- A patch that does not depend on a base (every distinct target `ChunkId` has a payload entry and no entry names dictionary chunks) is **self-contained**. It MAY carry `BASE` as information; apply then still requires the base to match if the caller supplies one, and needs no base otherwise.

CSP v1 makes the expected base optional only for self-contained patches. A base-dependent patch is built for one base (reuse and dictionaries are chosen against it), so the binding makes a wrong base fail fast and gives the update-policy layer an explicit `(base, target)` pair to sign. Serving several bases means one patch per base.

### 3.4 HashSuite and profile compatibility

- The base manifest and the target manifest MUST declare the same `HashSuiteId`. `ChunkId` values are comparable only within one HashSuite, and CSP v1 does not re-hash base chunks under a different suite. A base manifest with a different HashSuite is rejected (section 7, rule 20).
- The base manifest's `ProfileFingerprint` is not an apply requirement, so a base manifest whose only verification failure is profile semantics (CSM §14) is accepted. Reuse is decided by `ChunkId` equality alone, and different chunking profiles can still share identical chunk bytes; dictionary entries (section 5.2) recover most of the remaining similarity. Patch creation SHOULD use a base with the same `ProfileFingerprint`, because a different profile lowers reuse and inflates the payload.
- Target-side profile semantics are unchanged from CSM §14: an unregistered `ChunkingProfileId` does not block manifest-only checks, while the optional re-chunk verification of section 9.5 requires a reader that registers the embedded CSM's profile and fingerprint.

### 3.5 Patch identity

CSP v1 defines no `PatchId` field. The patch is identified by the target `ManifestId` and, when `BASE` is present, the expected base `ManifestId`, that is, by the pair `(base ManifestId, target ManifestId)`; its physical identity is the CSP TRAILER `FileDigest` plus `PhysicalLength`.

A persisted `PatchId` would either restate the physical `FileDigest` or be a deterministic function of that pair under a domain string; neither adds information a consumer of an update cannot derive. A detached signing envelope binds the pair and the physical digests directly. If the update-policy layer later needs a single name, it defines a domain-separated digest over them rather than a stored field.

## 4. Physical order

```text
PREAMBLE
TCSM
[BASE]
PAYL*
[AUX0]*
PIDX
FOOT
TRAILER
```

### 4.1 Section state machine

A conforming v1 physical stream follows this exact state machine:

```text
PREAMBLE
  -> exactly one TCSM
  -> zero or one optional BASE
  -> zero or more PAYL
  -> zero or more optional AUX0*
  -> exactly one PIDX
  -> exactly one FOOT
  -> exactly one fixed TRAILER at physical EOF
```

Sections are contiguous: every section starts where the previous one ends, there is no padding, and the TRAILER starts immediately after the FOOT payload. The reader MUST reject:

- duplicate TCSM, BASE, PIDX or FOOT;
- BASE after the first PAYL, and PAYL before TCSM or after the optional phase;
- an optional section outside the optional phase, which lies after the last PAYL (or after TCSM/BASE when no PAYL exists) and before PIDX;
- any section after FOOT, and any bytes after TRAILER;
- missing TCSM, PIDX, FOOT or TRAILER.

Unknown optional physical sections are permitted only in the optional phase and are skipped by `PayloadLength` without materialization. A writer MUST NOT place semantic data in the optional phase; an unknown optional section cannot demand to be understood.

### 4.2 PREAMBLE — fixed 32 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | Magic = ASCII `CSP1` |
| 4 | 2 | FormatMajor = 1 |
| 6 | 2 | PreambleSize = 32 |
| 8 | 8 | RequiredPhysicalFeatures |
| 16 | 8 | OptionalPhysicalFeatures |
| 24 | 8 | Reserved = 0 |

CSP v1 defines no physical feature bits: writers MUST emit both fields as zero, and a reader MUST reject a different magic/major, a different `PreambleSize`, non-zero reserved bytes and unknown required physical bits. Optional physical bits are reserved for a future revision that also defines how a reader that does not understand them behaves; v1 assigns none.

### 4.3 Section header — fixed 16 bytes

Every section after PREAMBLE and before TRAILER starts with the CSM §4 header:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | Type FourCC |
| 4 | 4 | Flags |
| 8 | 8 | PayloadLength |

Known v1 types: `TCSM`, `BASE`, `PAYL`, `AUX0`, `PIDX`, `FOOT`. Section flag bit 0 means REQUIRED; all other v1 flag bits are reserved and MUST be zero. `TCSM`, `PAYL`, `PIDX` and `FOOT` are required sections and writers MUST set REQUIRED on them. `BASE` and `AUX0` are optional sections: writers MUST clear REQUIRED, and readers MUST reject either one with REQUIRED set, because an optional section cannot demand to be understood. A known section's type, not its REQUIRED flag, decides where it may appear (section 4.1), and a reader accepts a known required section whatever its REQUIRED flag, as the CSM reader does: the flag governs unknown section types, and the optional `BASE` and `AUX0` above. Whether `BASE` must be present is a semantic rule of section 3.3, checked after the payload is known, not a physical-order rule.

Unknown section behavior is the CSM §4 behavior: REQUIRED set -> fail; REQUIRED clear -> skip exactly `PayloadLength` bytes without allocating the payload. Section length plus header MUST fit the remaining physical bytes under checked UInt64 arithmetic.

### 4.4 BASE payload — fixed 32 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 32 | ExpectedBaseManifestId |

Rules:

- at most one `BASE` section; `PayloadLength` MUST equal 32;
- presence means "apply requires a base manifest whose `ManifestId` equals this value"; section 3.3 decides when it is mandatory;
- absence MUST be represented by the absence of the section, never by a reserved digest value (the all-zero 256-bit value is a valid `ManifestId`).

### 4.5 TCSM payload

The `TCSM` payload is one complete CSM v1 artifact, byte-for-byte, exactly as it would be stored on its own. Rules:

- `PayloadLength` MUST equal the embedded CSM's `PhysicalLength`;
- the bytes MUST be accepted unchanged by the existing CSM reader with its own structural, block-integrity, logical and physical checks (CSM §14);
- the embedded CSM's `HashSuiteId`, `ChunkingProfileId` and `ProfileFingerprint` are the patch's target semantics;
- while CSP v1 is current, an embedded CSM of a format major other than 1 is rejected until a CSP revision defines how other majors are embedded.

Embedding the manifest is what makes a patch self-contained: the target identity travels with the payload, and no out-of-band manifest fetch is needed to verify reconstruction. The applier needs the target manifest in any case, so embedding costs no extra bytes end to end.

### 4.6 PAYL payload blocks

A `PAYL` section holds one block of payload entries. Fixed block prefix: 16 bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | EntryCount |
| 4 | 4 | Reserved = 0 |
| 8 | 8 | FirstEntryOrdinal |

Then `EntryCount` entries followed by a trailing `PayloadCrc32C` (UInt32). Each entry:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 32 | ChunkId |
| 32 | 4 | StoredLength |
| 36 | 1 | Encoding |
| 37 | 1 | DictionaryCount |
| 38 | 2 | Reserved = 0 |
| 40 | 32 × DictionaryCount | DictionaryChunkId[DictionaryCount] |
| 40 + 32 × DictionaryCount | StoredLength | Stored bytes |

Expected `PayloadLength`: `16 + sum(40 + 32 × DictionaryCount + StoredLength for each entry) + 4`.

Rules:

- `EntryCount` is 1..4096; a `PAYL` section is never empty;
- `FirstEntryOrdinal` MUST equal the total entry count of all preceding `PAYL` sections; entries carry a global ordinal, and `PIDX` entry `i` describes the payload entry with ordinal `i`;
- every `ChunkId` MUST occur in the target manifest, and at most one payload entry may exist per distinct target `ChunkId`; repeated target occurrences reuse one entry;
- `StoredLength` MUST be > 0 and <= the target chunk `Length` for that `ChunkId`, so the total stored payload cannot exceed the target content length; a writer whose encoded form would be larger stores the chunk raw;
- `DictionaryCount` MUST be 0 when `Encoding` is 0, and 0..4 when `Encoding` is 1 (section 5.2);
- `PayloadCrc32C` is CRC-32C over the section header plus all payload bytes preceding the CRC field, exactly as CSM §6 defines it for `CBLK`; `PAYL` grouping is physical and changes no identity, exactly as CSM `CBLK` grouping does not (CSM §8).

A writer SHOULD emit exactly one entry per distinct target `ChunkId` the base cannot supply. That set, summed by `Length`, is the plan's `UniqueMissingBytes`; the stored bytes are at most that.

### 4.7 PIDX payload

`PIDX` is the payload index that lets a tail reader locate required payload entries without scanning payload sections. Fixed prefix: 8 bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | IndexVersion = 1 |
| 4 | 4 | EntryCount |

Then `EntryCount` fixed 24-byte entries followed by `PidxCrc32C` (UInt32):

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | FirstTargetIndex |
| 8 | 8 | PayloadOffset |
| 16 | 4 | StoredLength |
| 20 | 1 | Encoding |
| 21 | 1 | DictionaryCount |
| 22 | 2 | Reserved = 0 |

Expected `PayloadLength`: `8 + EntryCount × 24 + 4`.

Rules:

- `IndexVersion` is 1; a different value is rejected until a revision defines it;
- `EntryCount` MAY be 0 when the target is fully supplied by the base;
- `FirstTargetIndex` is the index of the first target-manifest record whose `ChunkId` equals the entry's `ChunkId`: that record MUST carry the `PAYL` entry's `ChunkId`, and no earlier record may carry it. Across entries `FirstTargetIndex` MUST strictly increase, so entries are in target first-occurrence order and a forward applier consumes target records, index and payload in lockstep. The `ChunkId` itself is not repeated in the index; it is in the `PAYL` entry and in the embedded target CSM;
- `PayloadOffset` is the absolute patch-file offset of the corresponding `PAYL` entry record (its `ChunkId` field). Section headers and payload starts are located by offsets, consistent with CSM §11;
- PIDX entry `i` corresponds to payload ordinal `i` and MUST agree with that `PAYL` entry on `StoredLength`, `Encoding` and `DictionaryCount`;
- `PidxCrc32C` uses the section coverage rule of section 4.6, and every offset MUST point inside the patch's `PAYL` phase, MUST NOT overlap another entry's stored bytes, and MUST be consistent with that entry's size.

### 4.8 FOOT payload — fixed 56 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | TcsSectionOffset |
| 8 | 8 | BaseSectionOffset, 0 when absent |
| 16 | 8 | PidxSectionOffset |
| 24 | 8 | FirstPaylSectionOffset, 0 when no payload |
| 32 | 8 | PaylCount |
| 40 | 8 | PayloadEntryCount |
| 48 | 8 | Reserved = 0 |

Offsets identify section headers, not payload starts (CSM §11). `PayloadEntryCount` MUST equal both the `PIDX` entry count and the total `PAYL` entry count. `BaseSectionOffset` is zero if and only if no `BASE` section exists. `FirstPaylSectionOffset` is zero if and only if `PaylCount` is zero.

### 4.9 TRAILER — fixed 64 bytes

TRAILER is not preceded by a section header.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | Magic = ASCII `CSPT` |
| 4 | 2 | FormatMajor = 1 |
| 6 | 2 | TrailerSize = 64 |
| 8 | 8 | FootSectionOffset |
| 16 | 8 | PhysicalLength |
| 24 | 32 | FileDigest |
| 56 | 8 | Reserved = 0 |

`PhysicalLength` is the complete byte length including TRAILER. `FileDigest` is the digest of every physical byte before the TRAILER, using the HashSuite declared by the embedded `TCSM`; the TRAILER is excluded to avoid self-reference. Because the HashSuite comes from the embedded CSM, the patch digest cannot be checked before that CSM is readable; a reader that does not know the declared HashSuite rejects the patch as unsupported.

A tail reader can fetch the fixed 64-byte TRAILER, locate `FOOT`, then locate `TCSM`, `BASE`, `PIDX` and the payload sections. A forward reader can stream the same structure from the preamble.

## 5. Payload encoding

Every entry carries an explicit `Encoding` in both `PAYL` and `PIDX`. Whatever the encoding, the invariant is the same and non-negotiable: the bytes an entry produces MUST be exactly the target chunk `Length` long and MUST hash to the entry's `ChunkId` under the embedded manifest's HashSuite, and they are verified before they are written.

### 5.1 Encoding 0: raw

The stored bytes ARE the target chunk bytes: `StoredLength` MUST equal the target chunk `Length` and `DictionaryCount` MUST be 0.

### 5.2 Encoding 1: zstd frame, optionally against base chunks

The stored bytes are exactly one Zstandard frame (RFC 8878) whose decoded content is the target chunk.

- `DictionaryCount` is 0..4. With 0 the frame is decoded without a dictionary. Otherwise the dictionary is the concatenation, in listed order, of the exact bytes of the base chunks named by `DictionaryChunkId[]`; it is used as raw content (not as a trained zstd dictionary), and its total length MUST NOT exceed 1 MiB.
- Every `DictionaryChunkId` MUST be a `ChunkId` of the base manifest; apply reads those chunks from the base and verifies each by `ChunkId` and `Length` before use, exactly as it verifies a reused chunk. The names are digests of the exact dictionary bytes, so a dictionary's identity is a content digest.
- A dictionary whose first four bytes are `37 A4 30 EC` (the zstd dictionary magic) MUST NOT be referenced, because zstd implementations interpret such content as a trained dictionary; readers reject an entry that references one.
- The frame MUST declare `Frame_Content_Size`, equal to the target chunk `Length`; MUST NOT declare a `Dictionary_ID` other than 0; MUST have a window of at most 1 MiB (`Window_Descriptor` or, for a single-segment frame, its content size); and MUST be the only content of the stored bytes (no skippable frame, no second frame, no trailing bytes). A content checksum MAY be present and, when present, MUST validate; the `ChunkId` check remains authoritative.
- A decoder MUST bound its output by the target chunk `Length` before allocating and MUST fail on any frame that would produce more or fewer bytes. Decoder memory per entry is therefore bounded by the window (1 MiB), the dictionary (1 MiB) and the output (the profile's maximum chunk length).

Why this is still declarative: an entry is data plus a codec identifier. The codec is a standardized, widely fuzzed decoder; it can reference only the entry's own output and the named, hash-verified dictionary bytes, never arbitrary base offsets, and its result is accepted only if it reproduces the target `ChunkId`. There is no ChunkShift-defined instruction set and no state shared between entries.


### 5.3 Reserved encodings

`Encoding` values 2..255 are reserved. A reader MUST reject an entry whose encoding it does not implement before using that entry: an undecodable entry makes the target unreachable, so this is an unsupported-encoding failure, never a silent skip. Assigning a value requires a format revision and new vectors (section 10).

## 6. Apply algorithm (normative)

Inputs: the CSP artifact, the base (base manifest plus random-access base content) when the patch depends on one, and a destination path. Apply proceeds in target-manifest order:

1. Read the fixed TRAILER, validate magic/major/`TrailerSize`/`PhysicalLength`, locate `FOOT`, and validate the section state machine of section 4.1, including CRC32C for every `PAYL` and `PIDX` section. The patch `FileDigest` (section 9.2) is recomputed over the same bytes, once the embedded CSM has named the HashSuite; a mismatch fails apply.
2. Read the embedded `TCSM` through a bounded substream and run the existing CSM reader over it. Obtain the target `HashSuiteId`, `ChunkingProfileId`, `ProfileFingerprint`, `ManifestId`, `FileDigest`, `TotalChunkCount`, `TotalContentLength` and the ordered `(ChunkId, Length)` records. An invalid embedded CSM fails apply.
3. Read `PIDX` (bounded by section 8) and validate it against the `PAYL` entries and against the target manifest: every payload `ChunkId` is a target `ChunkId`, `FirstTargetIndex` names its first occurrence, indices agree with payload records, and ordering follows section 4.7.
4. Decide the base binding (section 3.3). If the patch depends on a base and `BASE` is absent, reject it. If `BASE` is present, open the supplied base manifest, require its `HashSuiteId` to equal the target's and its `ManifestId` to equal `ExpectedBaseManifestId`; a missing or different base fails apply. A self-contained patch without `BASE` uses no base.
5. Resolve each target record, in order:
   - if a payload entry exists for the record's `ChunkId`, read its stored bytes; for encoding 1 with dictionary chunks, read each named base chunk and verify it by `ChunkId` and `Length`; decode per section 5 within its bounds; verify `Length` and `ChunkId`; write;
   - otherwise, read the base chunk with that `ChunkId`, verify `Length` and `ChunkId`, and write;
   - otherwise the patch lacks a needed chunk and MUST be rejected (missing payload).
   The reader MUST verify bytes before writing them. When both sources exist, either may be used; both are bound to the same target `ChunkId`, so the choice cannot change the output.
6. After the last record, require the total bytes written to equal `TotalContentLength`.
7. Optional stronger check: if the target profile is registered, re-chunk the written output with it and compare the result against the embedded manifest (section 9.5).
8. Only after all checks pass, publish the output by atomic rename from a temporary file in the destination directory. On any failure, the temporary file is discarded and the destination path is never replaced.

Wrong base or corrupt patch never publishes a target. Publication mechanics (temp naming, disk preflight, Windows locks) are implementation behavior; the format requirement is only that no partial or unverified target becomes visible at the destination path.

**What is observable.** The contract of apply is its outcome, not the order of its reads: the verdict below, the target it publishes, and that nothing is published before every check has passed. The steps above are the reference order. An applier that reads the patch with random access SHOULD complete steps 1–4 before it writes any output, so that a corrupt patch or a wrong base costs no output I/O. An applier MAY instead read the patch once, front to back, writing the reconstruction to its temporary file as it goes; it then decides the verdict only after the end of the patch.

**Verdict order.** An input that breaks more than one rule gets the verdict of the first failing stage, in this order, whatever order the applier reads it in:

1. structure: an artifact shorter than PREAMBLE plus TRAILER (rule 7), the TRAILER (rules 5, 6 and its reserved field), the PREAMBLE (rules 1, 2), then the sections in physical order; inside `PAYL` and `PIDX` the CRC (rule 9) is checked before any field of the section is interpreted, and an unimplemented encoding (rule 16) is reported when its entry is reached;
2. the embedded CSM: malformed (rule 14) or of an unknown HashSuite (rule 16); then its integrity and profile-semantics failures (rule 25, section 9.6) and the patch `FileDigest` (rule 25), which are reported together;
3. payload entries against the target: a `FirstTargetIndex` that is not the first occurrence of its `ChunkId` (rule 12) is malformed, even when rule 17 fails as well; otherwise duplicate entries, entries not in the target (rule 17) and stored lengths (rule 18) are reported together;
4. base binding: a base-dependent patch without `BASE` (rule 13); then a required base that was not supplied, the base HashSuite, the base manifest's integrity and its `ManifestId` (rule 20), in that order;
5. the target records in order, stopping at the first failure (rules 19, 21, 22, 28, 29 and 30);
6. the total length (rule 23), then the optional re-chunk check (rule 24).

A limit of section 8 (rule 26) is reported where it is exceeded. Stages 2 and 3 report every verification failure kind they find together; every other stage reports its first failure. The verdict categories are those of section 7.

Memory bounds, capped by section 8:

- O(1) in target size: the current chunk buffer, the decode window and dictionary of one entry (section 5.2), hash state and per-chunk I/O buffers. The chunk buffer is bounded by the target profile's maximum chunk length.
- The target manifest is streamed in order; a materialized target record table is capped by the configured record limit (section 8).
- `PIDX` is O(payload entry count) if materialized (24 bytes per entry); a lockstep applier may stream it.
- The base locator (`ChunkId` -> base offset) is O(base chunk count), capped by the same configured record limit; the base content is read at random offsets.
- The reconstructed output lives in a temp file, not in memory.

## 7. MUST-reject rules

Each rule is normative and testable. Category: `malformed` = format error, `unsupported` = well-formed but not implementable by this reader, `verification` = integrity failure that MUST NOT publish.

1. (malformed) preamble magic is not `CSP1`, `FormatMajor` is not 1, `PreambleSize` is not 32, or preamble reserved bytes are non-zero.
2. (unsupported) unknown required physical feature bits are set.
3. (malformed) any non-zero reserved field not listed elsewhere: section flag bits above bit 0, `PAYL`/`PIDX` entry reserved bytes, `FOOT` reserved, TRAILER reserved.
4. (malformed) a known optional section has REQUIRED set, or an unknown section with REQUIRED set is encountered; only unknown optional sections may be skipped.
5. (malformed) the state machine of section 4.1 is violated: duplicate, missing or out-of-order required sections (TCSM/PAYL/PIDX/FOOT/TRAILER), a duplicated or misplaced BASE, a section after FOOT, bytes after TRAILER, a gap or padding between sections, or TRAILER not at physical EOF, which includes a TRAILER with the wrong magic, `FormatMajor` or `TrailerSize`.
6. (malformed) `PhysicalLength` does not equal the actual artifact length.
7. (malformed) any section `PayloadLength` cannot fit the remaining bytes under checked arithmetic, a section is truncated, or the artifact is shorter than PREAMBLE plus TRAILER.
8. (malformed) `PAYL` computed payload length differs from `PayloadLength`, `EntryCount` is outside 1..4096, `FirstEntryOrdinal` disagrees with preceding entries, an entry has `StoredLength` 0, or an entry overruns the section.
9. (malformed) `PAYL` or `PIDX` CRC32C mismatch. The CRC is checked before any field of its section is interpreted, so a corrupted field inside a CRC-covered section reports this rule, never a field rule or an unsupported encoding.
10. (malformed) `PIDX` computed payload length differs from `PayloadLength`, or `IndexVersion` is not 1.
11. (malformed) `PIDX` and `PAYL` disagree: entry counts differ, or an entry differs from its payload record in `StoredLength`, `Encoding` or `DictionaryCount`.
12. (malformed) index out of range, overlapping stored ranges, a `PayloadOffset` outside the `PAYL` phase, a `FirstTargetIndex` that is out of range, does not carry the entry's `ChunkId` or is not its first occurrence, or `FirstTargetIndex` values that do not strictly increase.
13. (malformed) `BASE` appears more than once, after the first `PAYL`, or with `PayloadLength` other than 32; or the patch depends on a base (section 3.3) and `BASE` is absent.
14. (malformed) the embedded CSM fails any CSM §14 check, its `PhysicalLength` disagrees with `TCSM.PayloadLength`, or its format major is not 1.
15. (malformed) `FOOT` fields disagree: `BaseSectionOffset`/`FirstPaylSectionOffset`/`PaylCount`/`PayloadEntryCount` do not match the observed sections.
16. (unsupported) the embedded CSM declares an unknown HashSuite, or an entry uses an encoding this reader does not implement.
17. (verification) a payload entry names a `ChunkId` that is not a target-manifest `ChunkId`, or one target `ChunkId` has more than one payload entry. Such an entry necessarily breaks rule 12 as well; it is reported under this rule, and rule 12's first-occurrence check applies to the first entry of each target `ChunkId`.
18. (verification) for raw encoding, `StoredLength` differs from the target chunk `Length`; for any encoding, `StoredLength` exceeds it.
19. (verification) decoded or stored bytes do not hash to the entry's target `ChunkId` under the embedded manifest's HashSuite, or are not exactly the target `Length` long.
20. (verification) the patch depends on a base, `BASE` is present and no base is supplied; the base manifest's HashSuite differs from the target's; the supplied base manifest fails verification for a reason other than profile semantics (section 3.4); or its `ManifestId` differs from `ExpectedBaseManifestId`. A self-contained patch that carries `BASE` applies without a base (section 3.3); a supplied base is still checked.
21. (verification) a reused base chunk's bytes do not hash to the target `ChunkId`, or its base `Length` differs from the target `Length`.
22. (verification) a target chunk is neither supplied by the base nor present in the payload (missing payload).
23. (verification) the total bytes written differ from `TotalContentLength`. The embedded CSM's logical totals already bind the record lengths, so this rule cannot fail on its own; the check stays as a guard.
24. (verification) the optional re-chunk check of section 9.5 was performed and does not reproduce the embedded manifest.
25. (verification) CSP TRAILER `FileDigest` mismatch, or embedded CSM `FileDigest`/`ManifestId` mismatch.
26. (verification) an operational limit of section 8 is exceeded (a limits failure).
27. (malformed) `DictionaryCount` is non-zero for raw encoding or greater than 4 for encoding 1.
28. (verification) a `DictionaryChunkId` is not a chunk of the base manifest, a dictionary chunk's bytes do not hash to its `ChunkId` or have a different length, the dictionary exceeds 1 MiB, or it begins with `37 A4 30 EC`.
29. (malformed) an encoding-1 entry is not exactly one zstd frame: a skippable frame, a second frame or trailing bytes are present, or the frame is truncated or corrupt.
30. (malformed) an encoding-1 frame omits `Frame_Content_Size`, declares one different from the target `Length`, declares a non-zero `Dictionary_ID`, declares a window above 1 MiB, or carries a content checksum that does not validate.

## 8. Resource bounds

A conforming v1 reader/applier enforces at least the following. The fixed sizes, format maxima and derived bounds are **normative**: they are part of CSP v1, and changing one is a format revision. The operational defaults are **not**: they are implementation limits, configurable and never persisted.

Fixed sizes (normative):

- `PreambleSize = 32`, `SectionHeaderSize = 16`, `TrailerSize = 64`;
- `BASE` payload = 32 bytes;
- `PAYL` prefix = 16 bytes, entry header = 40 bytes plus 32 bytes per dictionary reference; `PIDX` prefix = 8 bytes, entry = 24 bytes, `IndexVersion = 1`;
- `FOOT` payload = 56 bytes.

Format maxima (normative):

- `PAYL` `EntryCount` 1..4096;
- per encoding-1 entry: at most 4 dictionary chunks, at most 1 MiB of dictionary, a zstd window of at most 1 MiB, output exactly the target chunk `Length`.

Derived bounds (normative), computed from the embedded CSM before allocating:

- payload entries <= distinct target `ChunkId` count <= `TotalChunkCount`;
- every `StoredLength` <= its target chunk `Length`, therefore total stored payload bytes <= `TotalContentLength`;
- `PIDX` payload length is exactly `8 + EntryCount × 24 + 4` and `EntryCount` equals `FOOT.PayloadEntryCount`;
- every `PayloadOffset` and every section range lies inside the artifact, under checked UInt64 arithmetic;
- the embedded CSM is bounded by the CSM reader's own limits and by the remaining patch bytes.

Operational defaults (not part of the format):

- `MaximumPayloadEntries = 1,048,576`. A fully materialized `PIDX` at this cap is 24 MiB; an applier that streams the index may process more, and a stricter configured cap is allowed.
- `MaximumMaterializedManifestRecords = 4,194,304` for a materialized target record table or base locator. A stricter configured cap is allowed.

Exceeding an operational limit is a limits failure (rule 26), not malformed input, and says nothing about whether another reader with other limits accepts the patch. Configurable operational limits may be stricter than the format maxima, in the CSM §13 sense; a revision may make one persisted only by moving it to the normative lists above. Every offset/count/length multiplication or addition is checked; a reader MUST NOT allocate from an untrusted length before validating them.

## 9. Verification levels

### 9.1 Structural

Validate preamble magic/version/size/features/reserved, the section state machine, section lengths and contiguity, `PAYL`/`PIDX` CRC32C, every fixed-layout reserved field, and checked arithmetic. The embedded `TCSM` must pass CSM structural, block-CRC and logical checks; that includes the embedded CSM's own `ManifestId` and physical `FileDigest`.

### 9.2 Patch physical integrity

Recompute `FileDigest` over all bytes before the TRAILER with the embedded CSM's HashSuite and compare it with the TRAILER, and require `PhysicalLength` to match the consumed representation, exactly as CSM §14 maps its physical level.

### 9.3 Payload integrity

Require `PIDX`/`PAYL` agreement, then verify each payload entry used by apply: `StoredLength`, the zstd frame rules of section 5.2, the dictionary chunks by `ChunkId` and `Length`, the decoded `Length`, and `Hash(bytes) == ChunkId` under the embedded manifest's HashSuite. This is what ties a payload entry to the same identity model as CSM chunk records.

### 9.4 Base binding

Require `BASE` when the patch depends on a base (section 3.3), require the base HashSuite to equal the target HashSuite and the base `ManifestId` to equal `ExpectedBaseManifestId`, and verify every reused base chunk and every dictionary chunk by `ChunkId` and `Length` before it is used.

### 9.5 Full reconstruction

Require the total bytes written to equal `TotalContentLength`. Because every output byte belongs to exactly one chunk that was verified against the target manifest's `ChunkId`, the assembled output is bound by the verified target `ManifestId`. When a reader registers the embedded `ChunkingProfileId`/`ProfileFingerprint`, it SHOULD additionally re-chunk the output with that profile and require the ordered `(ChunkId, Length)` result and the recomputed `ManifestId` to match the embedded CSM, mirroring the CSM content level; an unregistered profile does not block the rest of apply but also cannot provide this check.

### 9.6 Profile semantics

Unchanged from CSM §14: the format does not require a reader to know any profile. A reader that registers the declared `ChunkingProfileId` compares its fingerprint with the embedded CSM's recorded one and reports a mismatch as a profile-semantics failure; an identifier it does not register is not a manifest-only failure.

Hash equality proves integrity against a trusted expected value; it does not provide authenticity. The format contract is the outcome categories of section 7, and no verification failure may publish a target; `ChunkShift.Patching` reports them as `PatchApplyFailure` flags.

## 10. Conformance vectors and compatibility

The committed CSP v1 vectors ([`tests/ChunkShift.Patching.Tests/Fixtures/CspV1`](../../tests/ChunkShift.Patching.Tests/Fixtures/CspV1/)) are produced by an independent standard-library generator and checked by an independent decoder and applier ([`tools/conformance/csp`](../../tools/conformance/csp/)); neither shares code with the .NET implementation. The decoder uses a separate zstd implementation (libzstd through CPython's `compression.zstd`), and the embedded and base manifests are checked by the independent CSM decoder of [`tools/conformance/csm`](../../tools/conformance/csm/), including its specification-derived BLAKE3. `vectors.json` records each vector's expected verdict, failure kinds and, for valid vectors, the SHA-256 and length of the target it reconstructs; vectors pin the exact stored bytes, so encoder differences cannot change them. The vectors cover both v1 HashSuites and at least:

- no payload (target fully supplied by the base), one chunk, and a target with repeated missing chunks (one entry, several uses);
- a self-contained patch without `BASE`, the same with `BASE`, and a base-dependent patch;
- multiple `PAYL` sections and a 4096-entry boundary block;
- `PIDX` order and offset validation, `FirstTargetIndex` pointing at a later occurrence, and a zero-entry index;
- encoding 1 with 0, 1 and 4 dictionary chunks; a dictionary chunk missing from the base; a dictionary beginning with the zstd dictionary magic; a frame without content size, with a wrong content size, with a non-zero dictionary ID, with a window above 1 MiB, followed by a second or skippable frame, and a corrupt frame;
- malformed/truncated section headers at every structural boundary;
- bad `PAYL`/`PIDX` CRC32C;
- `PIDX`/`PAYL` disagreement, duplicate entry, entry whose `ChunkId` is not in the target;
- raw length mismatch, bad encoding value, bad embedded CSM, base `ManifestId` mismatch, base-dependent patch without `BASE`, HashSuite mismatch, missing payload, bad CSP `FileDigest`, bad final length;
- a wrong-base and a corrupt-patch case that must not publish.

Compatibility rules:

- CSP, CSM, package and profile versions are independent; adding or changing an encoding, layout, identity or rule requires a format revision and new vectors. Changing a vector byte is a format change, not a test update;
- unknown major versions and unknown required features are rejected, unknown optional physical sections may be skipped, and reserved fields stay zero. CSP v1 embeds CSM v1 only; a future CSM major inside CSP requires a CSP revision that defines it;
- a change of the zstd implementation or its version is not a format change, but it must reproduce every vector and pass the frame comparison against the independent decoder.
