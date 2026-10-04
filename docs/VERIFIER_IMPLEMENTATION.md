# Independent verifier implementation

The verifier is independently authored from DESIGN.md, CONTRACTS.md, JSON schemas,
and explicit deterministic construction conventions. It imports no production
archive reader, inventory, scheme mapper, reducer, findings generator, repair
algorithm, or API module. It shares only the frozen data/limit wrappers, generic
budget/canonical hash functions, versioned constants, and packaging normalization.
`tests/test_import_boundary.py` checks this separation in a fresh interpreter.

## Structure

- `verify/_source.py`: no-follow bounded regular-file reads; independent raw central
  and local ZIP record parsing; independently metered stored/deflated streams;
  metadata, RECORD and provider parsing; fixed scheme mapping and restrictions
- `verify/_replay.py`: separate identity/content/tombstone replay; complete canonical
  events and boundary/final findings; independently reconstructed deletion paths
- `verify/__init__.py`: independent strict plan parsing, exact full report and repair
  reconstruction/comparison, final source rehashing, verification verdicts

Reports are original-plan-only. Repairs start from that independently reconstructed
final state, retain original work in their resource counters, and serialize only
repair operations/events/findings. Missing-path deletion advances event provenance
without replacing the effective destructive cause. Unknown resource-limited repair
certificates are compared in full and never become a conflict or positive repair.

## Conservative supported scope

Like the product's candidate profile, this verifier supports ordinary stored and
raw-deflate wheels tagged exactly `py3-none-any`. ZIP64 and bit-3 descriptors are
explicitly unsupported, not silently accepted. Historical unnormalized dist-info
spellings, unknown ZIP extras, special files, editable/bytecode/startup-hook payloads,
unknown generated provider overlap, historical file/ancestor conflicts and scaffold
aliases are refused. No payload is extracted to installation paths, imported, or
executed. Hashes prove consistency against the separately supplied plan, not the
plan's authenticity.

## Test-first evidence

Development regressions covered missing independent
reconstruction; scaffold/casefold/metadata caps; all-component no-follow reads;
prebounded tag expansion and keyword targets; immutable Plan sealing; and exact
resource-limited repair evidence. The fixture archive bytes are original and benign.
The test suite checks complete evidence tampering, hidden deflate output, CRC/header
mismatch, source digest changes, RECORD coverage, causal tombstones, exact desired
identity, repair replay from original state, stricter caller limits, and full
canonical agreement over 24 deterministic mixed-operation histories.

Whole-project reviews and qualification may add further regression evidence. A green
model test is not a substitute for the separately pinned real-installer oracle.

## Closed independent review findings

Independent archive/security review added typed failures for malformed extraction
versions, timestamp fields, file-kind encodings, raw duplicate names under alternate
name encodings, metadata control characters, oversized RECORD integers, reserved
scaffold/metadata aliases and unsupported entry-point syntax. Explicit directory
entries remain visible to namespace validation. Supported EOCD comments may contain
end-record magic, including complete ordinary or ZIP64-looking false markers. The
decoder drains buffered raw-deflate output using bounded empty-input calls; an actual
member cap+1 remains a resource-limit result, not a truncated-data misclassification.

Repair certificates may use stricter effective limits than the original report;
they retain the unchanged original evidence binding. Caller-only stricter limits
that prevent replay return incomplete rather than false/tampered evidence. Declared
repair-stage resource failure yields an exact independently checkable unknown
certificate. Stored-member and deflate output are capped before expanded allocations.

Raw development RED transcripts are not distributed. The regression tests are in `tests/test_verify.py`, `tests/test_verifier_review.py` and `tests/test_archive_review.py`; final source, installed-package, installer-oracle and capacity receipts are indexed in [the public evidence directory](../evidence/README.md).
