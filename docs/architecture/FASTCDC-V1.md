# FastCDC Gear ChunkShift v1

Status: Normative; chunk-boundary semantics frozen  
Last reviewed: 2026-09-27  
Algorithm id: `fastcdc.gear.chunkshift.v1`

This specification defines the **scalar reference semantics** for ChunkShift's FastCDC v1 algorithm. Optimized implementations may differ internally but MUST emit the same chunk boundaries for the same input and profile.

Reference material used during design:

- FastCDC 2016/2020 papers;
- fastcdc-rs 5.0.0 implementation and test corpus;
- ChunkShift's own deterministic/vector requirements.

External implementations are references, not runtime dependencies.

## 1. Profile parameters

Every FastCDC v1 profile explicitly contains:

```text
algorithm = "fastcdc.gear.chunkshift.v1"
minimum
target
maximum
normalization = 1
gearTable = "chunkshift.fastcdc.gear.v1"
gearSeed = 0
arithmetic = "uint64-wrap"
eof = "emit-final-remainder"
```

Validation:

- `minimum >= 64`;
- `target >= 256`;
- `maximum >= 1024`;
- `minimum < target < maximum`;
- all three sizes MUST be even;
- `target` MUST be a power of two;
- `maximum <= 16,777,216` for this algorithm version.

Core 0.1 registers exactly one stable profile, which is also the default:

| identity | value |
| --- | --- |
| ProfileId | `fastcdc.gear.chunkshift.v1.64k` |
| minimum | 16 KiB |
| target | 64 KiB |
| maximum | 256 KiB |
| ProfileFingerprint | `054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0` |

The stable profile uses the scalar semantics in this document unchanged. The nominal 64 KiB target is a parameter name, not an expected mean chunk size; on real data the mean chunk is larger than the target. Actual mean chunk size is an observation, not persisted semantics.

Three **non-stable calibration presets** were used to select the stable profile:

| target | minimum | maximum |
| ---: | ---: | ---: |
| 64 KiB | 16 KiB | 256 KiB |
| 128 KiB | 32 KiB | 512 KiB |
| 256 KiB | 64 KiB | 1 MiB |

They use `minimum = target / 4` and `maximum = target * 4`. The independent reference in [`tools/conformance/fastcdc_reference.py`](../../tools/conformance/fastcdc_reference.py) keeps vectors for all three so the scalar semantics stay checked at more than one size; they are not production registrations.

These non-stable presets are identified as `fastcdc.gear.candidate.v1.m<minimum>.t<target>.x<maximum>`, so changing a bound produces a different identifier rather than colliding on target size alone. Core does not register those IDs. The identifier does not embed the `ProfileFingerprint`; CSM records the fingerprint in its own CORE field, and a reader that registers the identifier checks it ([PROFILE-FINGERPRINT-V1](PROFILE-FINGERPRINT-V1.md)).

## 2. GEAR table

The normative 256-entry UInt64 table is [FASTCDC-GEAR-V1.txt](FASTCDC-GEAR-V1.txt).

Normative table digest serialization:

```text
for i = 0..255:
    UInt64LE(GEAR[i])
```

SHA-256:

```text
91a3061015ae351cd3701852712bcd6aa4a1ce26c8a231d3969432b00f028f88
```

No runtime/random table generation is part of v1 semantics. Seeded/XOR-altered GEAR tables are out of scope for the first public profile.

## 3. Mask table

ChunkShift v1 uses the following canonical masks indexed by `log2(target)`:

```text
 5: 0000000001804110
 6: 0000000001803110
 7: 0000000018035100
 8: 0000001800035300
 9: 0000019000353000
10: 0000590003530000
11: 0000d90003530000
12: 0000d90103530000
13: 0000d90303530000
14: 0000d90313530000
15: 0000d90f03530000
16: 0000d90303537000
17: 0000d90703537000
18: 0000d90707537000
19: 0000d91707537000
20: 0000d91747537000
21: 0000d91767537000
22: 0000d93767537000
23: 0000d93777537000
24: 0000d93777577000
25: 0000db3777577000
```

For normalization level 1 and power-of-two target:

```text
bits    = exact integer log2(target)
mask_s  = MASKS[bits + 1]
mask_l  = MASKS[bits - 1]
```

No floating-point logarithm participates in persisted semantics.

For the stable profile and the calibration presets:

| target | strict mask | relaxed mask |
| ---: | ---: | ---: |
| 64 KiB | `0000d90703537000` | `0000d90f03530000` |
| 128 KiB | `0000d90707537000` | `0000d90303537000` |
| 256 KiB | `0000d91707537000` | `0000d90703537000` |

## 4. Scalar boundary algorithm

For one chunk candidate window `source`:

1. `remaining = min(source.Length, maximum)`.
2. If the original remaining source length is `<= minimum`, emit all remaining bytes as the final chunk.
3. `center = min(target, remaining)`.
4. `hash = 0` as UInt64.
5. Start candidate position `index = minimum`.
6. For each `index < center`:
   - `hash = unchecked((hash << 1) + GEAR[source[index]])`;
   - if `(hash & mask_s) == 0`, cut at `index`.
7. For each remaining `index < remaining`:
   - same UInt64 wrapping update;
   - if `(hash & mask_l) == 0`, cut at `index`.
8. If no predicate succeeds, force the cut at `remaining`.

A returned cut position is the chunk length relative to the current chunk start, matching the canonical FastCDC cut-point convention used by the reference implementation.

**Important boundary convention:** the candidate byte at `source[index]` participates in the Gear update/predicate, but when that predicate succeeds the returned chunk length is `index`, not `index + 1`. Therefore that candidate byte is the first byte of the next logical chunk. This is intentionally frozen reference behavior, not an off-by-one to “correct” during implementation.

UInt64 shift/addition wraps modulo `2^64`; checked overflow is NOT part of Gear semantics.

## 5. Stream independence

The algorithm above is defined over a logical contiguous byte sequence, not over `Stream.ReadAsync` calls.

The streaming engine MUST therefore:

- preserve enough bytes to evaluate a candidate window independent of physical read segmentation;
- treat one-byte/random short reads as equivalent to a contiguous source;
- never reset Gear state merely because a Stream read returned short;
- emit the same boundaries for seekable, non-seekable and segmented input.

I/O buffering, ArrayPool usage and async scheduling are implementation details and do not enter ProfileFingerprint.

## 6. EOF and pathological input

- empty input -> zero chunks;
- final remainder `<= minimum` -> one final chunk containing the exact remainder;
- a non-empty final chunk may therefore be smaller than minimum;
- no zero-length chunk is emitted;
- all-zero/repeated data may force cuts at maximum;
- maximum is an absolute chunk-size ceiling;
- exact EOF at a previously selected boundary does not emit an extra empty chunk.

## 7. Reference vs optimized implementation

The scalar algorithm in §4 is the reference. An optimized backend may use:

- two-byte rolling updates;
- bounds-check elimination;
- SIMD-adjacent scheduling;
- specialized branches for known profiles.

The optimized backend is acceptable only if a differential test proves identical `(Offset, Length)` sequences over:

- all normative vectors;
- pathological corpus;
- deterministic random corpus;
- boundary/EOF edge cases;
- randomized segmentation;
- x64 and ARM64.

The two-byte 2020 technique is an optimization, not the specification.

## 8. Hashing separation

Gear hash is boundary-selection state only. It is not ChunkId.

For every emitted chunk:

```text
ChunkId = selected HashSuite.Hash(exact chunk bytes)
```

An implementation may locate a boundary and then hash the contiguous chunk bytes, or hash incrementally in one pass. The choice is an implementation detail and must not change output.

## 9. ProfileFingerprint requirements

A FastCDC profile semantic object MUST bind at least:

- algorithm id/version;
- minimum/target/maximum;
- normalization level;
- GEAR table id and SHA-256 digest;
- strict and relaxed masks or their deterministic table-selection rule;
- UInt64 wrapping arithmetic;
- cut predicate;
- maximum forced-cut rule;
- EOF/final remainder behavior.

Changing any of these requires a different ProfileFingerprint and a new semantic identity decision/ProfileId.

## 10. Required vector coverage

At minimum:

- empty;
- 1 byte;
- minimum-1/minimum/minimum+1;
- target-1/target/target+1;
- maximum-1/maximum/maximum+1;
- all-zero data spanning multiple maximum chunks;
- repeated short pattern;
- deterministic pseudo-random data;
- one-byte perturbations immediately around known cut positions;
- same logical input split into one-byte and randomized Stream reads.

Expected vectors record:

```text
input SHA-256
ProfileFingerprint
ordered [
  Offset Int64,
  Length UInt32
]
ordered chunk-sequence evidence digest
```

At least one vector set should be cross-checked against an independent FastCDC implementation configured to the same table/masks/parameters. Any difference must be explained before ChunkShift's own expected output is accepted.

## 11. External reference notes

fastcdc-rs 5.0.0 documents the v2020 implementation as using Gear hash, sub-minimum skipping, normalized chunking and a two-byte rolling optimization while preserving cut points relative to the scalar algorithm.

ChunkShift intentionally freezes the scalar semantics above and treats such two-byte processing as a replaceable optimization. This avoids binding the persisted profile to implementation-specific loop structure.

The fastcdc-rs 5.0.0 `v2020` two-byte loop does **not** test the last position of an odd-length final window, so it can differ from `v2016` and from §4 at EOF: for `16384 × 0x00 ‖ 02 FF 41` with the 64 KiB preset, §4 and `v2016` give `[(0,16386),(16386,1)]` while `v2020` gives `[(0,16387)]`. `v2016` is therefore the matching external oracle, and a two-byte backend is acceptable under §7 only if it tests that position. This clarifies a reference note; the semantics above are unchanged. The independent reference checks this case (`fastcdc_reference.py --verify`).
