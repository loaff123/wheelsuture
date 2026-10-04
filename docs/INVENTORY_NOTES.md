# Inventory implementation receipt

Scope: `zipscan.py`, `inventory.py`, `profiles.py`, and original unit fixtures in
`tests/inventory_fixtures.py`. All wheel members are treated as data. No member
is extracted, imported, executed, or passed to an installer by these modules.

## Explicit supported subset

The current candidate accepts ordinary 32-bit, single-disk ZIP archives using
stored or raw-deflate streams. ZIP64 and bit-3 data descriptors are rejected as
unsupported before member decoding. This deliberately narrows the design's
possible archive support; it never treats unvalidated ZIP64/descriptors as
valid. Local records must occupy the payload region contiguously, without
executable stubs, gaps, overlap, concatenated streams, or unexplained trailing
bytes. The exact EOCD comment is permitted. CRC, actual decoded size, and all
local/central sizes/names/methods/flags are checked.

Raw names decode as UTF-8 with flag 11, otherwise CP437. Names retain exact
Unicode spelling. Unicode Cc, Cs, and Cf characters are unsupported, along with
colon, backslash, relative-path ambiguity, overlong components and paths.
Explicit regular directories with zero decoded bytes produce no claim; both
stored and valid deflated empty directories are supported.

Only the expanded tag set `py3-none-any` is currently supported. Tag expansion
is capped at 128 products before invoking packaging's Cartesian tag parser,
including filename parsing. The dist-info spelling must equal the filename's
first two fields plus `.dist-info`; historical unnormalized aliases are not
accepted. Required structural headers must be unique and unfolded. Record
hash encodings are canonical unpadded URL-safe SHA-256, SHA-384, or SHA-512.

Entry points have strict unindented groups and declarations, ASCII non-keyword
Python dotted module/attribute components, no extras, and each target component
is at most 1,024 characters. Basenames and all mapped/generated destinations
receive the same bytecode, startup, legacy-metadata and scaffolding screening.
Structural text caps apply conservatively to every raw member whose basename
is METADATA, WHEEL, entry_points.txt or RECORD, including nonstandard locations.

In addition to the design's explicit scaffold examples, the candidate reserves
the whole `lib64` tree because a target venv may alias it to `lib`, and reserves
`bin/activate`, `bin/activate.csh`, `bin/activate.fish`, `bin/Activate.ps1` and
their descendants. These are fail-closed compatibility restrictions.

The profile catalog stays `design_candidate`; unit success alone does not
qualify installer semantics or authorize release.

## Resource accounting

Global budgets are charged before per-source bookkeeping/allocation. Per-source
aggregate counters and maxima are retained in immutable inventory provenance.
Raw member names (including RECORD and trailing slashes on explicit directories)
are charged once. Each final copied/generated/control destination is charged
once; installed RECORD replaces the wheel RECORD claim and is not double-counted.
All decoded source bytes count, including structural metadata and RECORD.

Raw decompression is independently metered, using an output request no larger
than 64 KiB and no larger than one byte above the lowest remaining member,
aggregate decoded, or structural-text allowance. The claimed uncompressed size
never truncates reads or determines the actual-output budget. Only bounded
structural text is retained; ordinary payloads retain hashes, size, and streamed
shebang-tail summaries.

## Observed test-first evidence

- Initial RED: 22 test methods / 31 failing assertions, explicitly reporting
  that the bounded inventory implementation was absent
- Initial GREEN: 22 methods passed after implementation
- Second RED: lower decompressor output request and five scaffold destinations
  were not enforced; a valid deflated empty directory was rejected
- Second GREEN: 32 methods passed after those changes
- Additional adversarial coverage: 39 methods passed, including truncated,
  trailing, and concatenated deflate; CP437/UTF-8 names; duplicate/malformed
  extras; hash variants; file kinds; source pins and symlinks; per-source budgets
- Fourth RED: four oversized/keyword entry-point targets and large Cartesian
  tag expansion were accepted
- Fourth GREEN: 41 methods passed after bounded target/tag checks
- Full suite at this receipt: 115 methods passed with
  `PYTHONPATH=src:tests python -m unittest discover -s tests`
- Inventory and profile-catalog documents passed the supplied closed JSON
  Schema 2020-12 contracts using jsonschema as a test-only dependency
- All three owned production modules compiled successfully

An earlier whole-suite run while independent verifier implementation was in
progress had nine failing verifier tests reporting its missing reconstruction
API. The fresh 115-test run above supersedes that intermediate result.

## Rulings and limitations

ZIP64/descriptors, historical dist-info spelling, native tags, broad INI
syntax, and additional installer profiles are intentionally unsupported. This
costs compatibility and returns incomplete rather than risking a false preserved
claim. Additional scaffold reservations account for the measured lib64 alias risk.
This historical review did not perform publication or registry actions.


## Later integration qualification

The earlier candidate-only unit receipt above is superseded by the source, real-installer, independent mapping and capacity gates in `QUALIFICATION.md`; the final profile catalog is enabled for that bounded profile. This does not qualify other installers or broader archives.
