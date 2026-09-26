# CSM v1 candidate golden vectors

These fixtures are compatibility evidence for the pre-freeze CSM v1 candidate.

The checked-in binary files are generated independently from the production
`CsmWriter` / `CsmReader`. The generator is
`tools/csm-fixtures/generate.py` and uses only Python's standard library plus
the byte layout in `docs/architecture/CSM-V1-CANDIDATE.md`.

Checked in during #5:

- `empty-sha256-no-bidx.csm`
- `one-entry-sha256-no-bidx.csm`
- `multiblock-sha256-no-bidx.csm`
- `multiblock-sha256-bidx.csm`

They use:

- HashSuite: `chunkshift.sha256.v1`
- ProfileId: `fixture.csm.synthetic.v1`
- ProfileFingerprint:
  `50e11b907ba2af4c27c4cf196dbc873fa37f50e7c62e829336b7a76649447627`

Expected identities:

| fixture | ManifestId | FileDigest | chunks | content bytes | physical bytes |
| --- | --- | --- | ---: | ---: | ---: |
| empty | `ab0c32c4052ea59a35569b20b23f8d3d0156d3aca59c431a70ba5f365f66a12c` | `7b7fbf21a433c37590b6b9273a6249341a04226174369e685bd6557ecffa32ab` | 0 | 0 | 340 |
| one-entry | `7add187663e900912f9438fcf3a3fc13a826937a188cd377e32aa145ed9b3606` | `2339a525f39e5959d8855fb746e2930cd1dffc8ddc742b0d5626aad691de8cd4` | 1 | 28 | 420 |
| multiblock / no BIDX | `b93a7868fd0714e2ecde57303f9df466e7695677d3d79e88f443d49b55cd82e6` | `abba97ae65253ee7e6b42dd6ca82da3b170d5822e3bdf8feaf682e80f9b2580c` | 4097 | 8390657 | 147920 |
| multiblock / BIDX | `b93a7868fd0714e2ecde57303f9df466e7695677d3d79e88f443d49b55cd82e6` | `9a4ca2a47086c5de0e6556fbe61ad33f1b4127e6079eb9121dae340e9c9b3d25` | 4097 | 8390657 | 147976 |

The 4097-entry pair crosses the normative 4096-entry CBLK boundary. The two
files deliberately have the same ManifestId and different FileDigest/physical
length, proving that BIDX and physical grouping metadata do not enter logical
identity.

## Conformance vectors and the independent decoder

Besides the four golden fixtures, the generator emits one vector per rule it
exercises, all over a small three-entry SHA-256 manifest:

- `valid-*`: permitted physical differences (BIDX, an optional `AUX0`, an
  unknown optional tail section, an unknown optional physical feature bit).
  All share the ManifestId of `valid-small-sha256-no-bidx.csm` and differ in
  FileDigest.
- `integrity-*`: structurally valid representations with exactly one of
  `BlockCrc`, `LogicalTotals`, `ManifestId` or `FileDigest` wrong. The public
  API returns these as result flags.
- `reject-*`: one violated MUST rule each (PREAMBLE, section header, CORE,
  CBLK, section order, BIDX, FOOT, TRAILER, truncation). The public API throws
  `InvalidDataException`.
- `unsupported-*`: a grammatically valid but unknown HashSuite. The public API
  throws `NotSupportedException`.

Every vector is built from the byte layout with all unrelated offsets and
digests kept consistent, so it breaks only the rule in its name.
`vectors.json` records the expected verdict (`expect.outcome`,
`expect.failures`, and the spec rule for rejections). Those expectations come
from the generator's definitions, not from any decoder.

`tools/csm-fixtures/decode.py` is a second, independent implementation of the
reading side of the specification. It uses only the Python standard library
and does not import the generator or any ChunkShift code. Two checks use the
same `vectors.json`:

- `CsmIndependentVectorTests` runs every vector through
  `ChunkManifest.VerifyManifestAsync`;
- CI runs `generate.py --verify`, which regenerates every file byte-for-byte,
  compares `vectors.json`, and runs the independent decoder over every vector.

## Regenerating

Verify the checked-in directory:

```text
python tools/csm-fixtures/generate.py --verify tests/ChunkShift.Tests/Fixtures/CsmV1
```

Regenerate into a temporary directory with:

```text
python tools/csm-fixtures/generate.py --out <directory>
```

Do not silently replace checked-in vectors. Any candidate-format byte change
must update the specification, expected identities, fixtures, and review
evidence together. Adding a vector means adding its definition to
`generate.py`; the C# test and `--verify` both fail for a `.csm` file that
`vectors.json` does not list.
