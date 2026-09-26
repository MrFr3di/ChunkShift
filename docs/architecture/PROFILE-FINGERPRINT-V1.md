# Profile Fingerprint V1

Status: Normative semantic-fingerprint contract  
Last reviewed: 2026-09-27

This document defines the semantic fingerprint contract used by ChunkShift Core.

It exists to prevent authoring-file representation from becoming chunking-profile identity.

## Identity rule

A profile artifact is an authoring/input representation. Only its top-level `semantics` object contributes to `ProfileFingerprint`.

Fields such as profile description, documentation, comments stored outside `semantics`, JSON property order and insignificant JSON whitespace do not contribute.

```text
ProfileFingerprint =
  SHA-256(
    UTF8("chunkshift.profile-fingerprint.v1\0")
    || CanonicalSemanticValue(profile.semantics)
  )
```

ProfileFingerprint v1 deliberately uses fixed SHA-256 as its identity function. It is metadata identity, not a content-hashing hot path.

The manifest/repository-selected `HashSuiteId` therefore does **not** change the fingerprint of the same chunking-profile semantics. HashSuite selection remains orthogonal to `ChunkingProfileId` and `ProfileFingerprint`.

Content identities such as ChunkId/ContentId/ManifestId continue to use the selected HashSuite where their specifications say so.

## ProfileId and ProfileFingerprint

A manifest records both, and they have different jobs:

- `ChunkingProfileId` is a **short, stable semantic identifier**: a human-readable label such as a name plus version that tells a reader which profile the producer used.
- `ProfileFingerprint` is the **authoritative digest** of the exact semantics defined above.

Rules:

- A `ChunkingProfileId` MUST NOT embed the full `ProfileFingerprint` (or its hex form). The fingerprint travels in its own field; duplicating it in the label only makes the label long and the two fields able to disagree.
- A stable `ChunkingProfileId` never changes semantics. Different semantics need a different identifier, and the fingerprint is what proves which semantics a manifest actually used.
- An implementation that registers a `ChunkingProfileId` knows its fingerprint. When a manifest pairs a registered identifier with a different fingerprint, verification reports a profile-semantics mismatch; an identifier the implementation does not register can still be verified manifest-only, but content cannot be chunked with it ([CSM-V1 §14](CSM-V1.md#14-verification-levels)).

Core 0.1 registers exactly one stable profile: `fastcdc.gear.chunkshift.v1.64k` ([FASTCDC-V1](FASTCDC-V1.md)). Its frozen fingerprint is `054e6ced561558147f9c35dc66c64142fd4562d21132f0dc51e00544c04200a0`. The calibration identifiers `fastcdc.gear.candidate.v1.m<minimum>.t<target>.x<maximum>` are not production registrations.

## Canonical semantic encoding

The canonicalizer is binary and recursively typed.

Every value starts with one byte:

| Tag | Value |
| --- | --- |
| `00` | null |
| `01` | false |
| `02` | true |
| `03` | integer number |
| `04` | UTF-8 string |
| `05` | array |
| `06` | object |

Lengths/counts are unsigned 32-bit little-endian.

Strings are encoded as:

```text
UInt32 byteLength
UTF8 bytes
```

Objects are encoded with properties sorted by property name using ordinal comparison. Duplicate property names are invalid. Object property order in the authoring JSON therefore cannot alter the fingerprint.

Arrays retain order because array position can be semantic.

Numbers are canonicalized from the original JSON numeric token; floating-point and `decimal` parsing are not part of the identity algorithm.

Numbers must denote exact integers. Equivalent representations such as `1`, `1.0`, `1e0`, `0.001e3` and `1.20e1` (for 12) canonicalize to the same mathematical integer text when they represent the same value. Values with any non-zero fractional remainder are rejected, including fractions smaller than `decimal` precision such as `1.00000000000000000000000000001` and `1e-1000`.

The canonicalizer applies explicit resource bounds:

- raw numeric token: at most 128 characters;
- exponent magnitude: at most 1024;
- canonical integer magnitude: at most 128 decimal digits (excluding sign).

All representations of zero canonicalize to `0`, including negative zero. These limits are part of the fingerprint semantics and prevent authoring input from forcing unbounded canonical expansion.

JSON escapes are decoded before string canonicalization, so equivalent JSON escape spellings represent the same semantic string.

## Logical identity types

The shared 256-bit storage representation does not make these identities interchangeable:

- `ChunkId` — hash of exact uncompressed chunk bytes;
- optional `ContentId` — hash of exact original content bytes;
- `ManifestId` — logical manifest identity defined by the manifest specification;
- `ProfileFingerprint` — canonical profile semantics.

Absence is represented by owner state/nullable values, never by reserving a `Hash256` digest.

The all-zero 256-bit value is valid.

## Compatibility note

This encoding is normative for tests and persisted profile fingerprints. A later change to this encoding or to the semantics bound by an existing stable ProfileId requires an explicit compatibility/version decision rather than silently reinterpreting an existing fingerprint.
