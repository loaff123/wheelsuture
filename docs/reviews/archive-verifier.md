# Archive and independent-verifier review

Review date: 2026-10-03. Scope: the implemented bounded profile, not a security
scanner, package-safety assessment, or hostile-filesystem sandbox.

## Outcome

The review found and reproduced three production parsing/profile issues and
several independent-reader acceptance gaps. Production and verifier authors
received original failing regression tests before changing their code. The
reviewer changed only the two review test files and this review document.

All review-owned regression cases pass after the observed fixes. The latest
whole-suite result and its separate qualification-state mismatch are recorded
below. A passing focused review does not replace the required target-installer oracle,
resource calibration, packaging checks, or final qualification decision.

## Findings and remedies

1. **Protected scaffold directory accepted as a payload file.** Both readers
   accepted `.data/data/include/python3.12`, despite its reservation in
   `SUPPORTED_PROFILE.md`. The verifier also omitted the `include`,
   `include/site`, and `include/site/python3.12` ancestors. Such a file cannot
   coexist with the declared scaffold. Both implementations now screen these
   mapped destinations. Production RED tests were observed before the implementation owner
   supplied its fix.

2. **Stored method accepted deflate-only option flags.** The production scanner
   allowed stored members with flag bits 1/2; independent parsing refused them.
   Production now refuses the contradictory method/options combination rather
   than silently broadening the bounded profile.

3. **EOCD marker inside an exact comment caused false rejection.** Both scanners
   initially treated the final `PK\x05\x06` occurrence as the end record, even
   when it was inert comment text. Partial magic, a full inert fake record and
   a fake ZIP64-sentinel record inside the comment are covered. The
   exact-comment support stated in
   `INVENTORY_NOTES.md` therefore failed. The regression uses a short original
   comment; the fix selects a structurally bounded end-record candidate. This
   issue caused false rejection, not a false-preserved result.

4. **Independent ZIP parsing did not enforce every supported restriction.**
   Observed RED cases included high extraction versions in either header,
   central versus local extended-timestamp length rules, duplicate nested NTFS
   attributes, DOS directory attributes on a regular member, and encoded
   nonregular mode bits hidden by a non-Unix creator field. Each is now rejected
   within the declared profile. Unknown/path-reinterpreting and duplicate outer
   extra fields remain unsupported/invalid rather than being interpreted.

5. **Raw duplicate names could evade the independent reader.** Two identical
   raw filename byte strings decoded under CP437 and UTF-8 became distinct
   Unicode names and passed its decoded-name uniqueness test. Production had
   already rejected them. The independent reader now checks raw and decoded
   identity separately.

6. **Independent mapping and directory filtering lost supported restrictions.**
   Review cases covered mapped uppercase `.DIST-INFO` namespaces, copied
   `easy_install` wrapper names, owned metadata paths containing an editable
   marker, and an explicit empty foreign top-level `.dist-info/` directory. A
   structural-only directory cannot silently disappear before the unique
   metadata-directory rule is checked. The independent reader now retains that
   structural evidence and applies the profile restrictions after mapping.

7. **Independent metadata/RECORD parsing admitted malformed evidence or threw
   an untyped exception.** NUL and bare CR in metadata were accepted. A
   5,000-digit RECORD size escaped as Python `ValueError`; comparison without
   integer conversion avoids that failure, while preserving the profile's
   maximum decimal-field length. A follow-on zero-padded size regression checks
   that the fix does not silently broaden that restriction.

8. **Entry-point grammar differed.** Unknown group names containing spaces and
   whitespace around the target colon were independently accepted outside the
   producer's deliberately compact grammar. The verifier now applies its own
   parsing of the same supported grammar. Unequal generated-provider tokens
   remain unknown, never an impossible-byte witness.

The public dataclass-content/provenance replacement issue was assigned to the
implementation owner separately and is not claimed as a finding of these review tests.

## Regression coverage

`tests/test_archive_review.py` contains an original compact raw-ZIP writer and
small inert fixtures. It generates headers, sizes, CRCs, extras and RECORD
locally; it never executes, imports, extracts, installs, or downloads a wheel
payload. No existing user environment is inspected.

`tests/test_verifier_review.py` exercises the independent reader and the complete
evidence comparison. The tests do not add production code or import one runtime
algorithm into the other. The existing fresh-process import-boundary test also
checks that importing the verifier does not load production archive, mapping,
inventory, reducer, repair, or API modules.

Covered cases include:

- Raw local/central names, methods, flags and CRC disagreements; embedded NUL;
  Unicode decode-flag raw duplicates; displaced/overlapping stream offsets
- Unknown Unicode-path extras, duplicate and malformed extras, extraction
  versions and nonregular file-kind encodings
- Independently metered output despite a deliberately false declared size;
  missing end markers, truncated, trailing and concatenated raw-deflate streams
- Prepended stubs, unexplained trailing archive bytes, valid exact ZIP comments
- Metadata/RECORD shape and integer strictness, mapped scaffold and control
  namespaces, structural directory evidence and compact provider declarations
- Equal generated declarations across owners; unequal targets, group-only
  changes and cross-kind overlap remaining unsupported
- Deletion of every analysis/repair top-level field and every field of a
  representative claim, event, operation, identity and final slot
- Boolean/integer substitutions at schema, completion, operation, event, claim,
  wheel and resource-counter layers; canonical JSON comparison distinguishes
  values that Python's ordinary equality would conflate
- Malformed trusted plan structures retaining typed invalid-input outcomes;
  unknown profile and stricter evidence bounds yielding incomplete outcomes
- Real intermediate repair-boundary damage, full action ordering, original
  source digest coverage, event state, resource counters and final-state slots

The initial owned run contained 29 methods and reported 19 failing assertions
plus the expected untyped-RECORD exception. Additional regression cases brought
the owned suite to 38 methods. The failures were sent promptly to the relevant
implementation owner; the reviewer did not change expectations to accept the
buggy behavior.

During integration, a concurrent serialization optimization exposed a public
reconstruction shape regression: immutable coverage tuples remained tuples
instead of JSON arrays. The fresh whole-suite run reported
`test_every_evidence_component_is_compared` as an error and all 24 subcases of
`test_full_production_agreement_on_deterministic_histories` as failures. The
issue was reported immediately rather than hidden behind the review-only green
subset. A subsequent fresh focused run of those methods plus all owned review
tests passed 40 methods. Final whole-suite evidence below supersedes that
intermediate integration result only when it explicitly reports a clean run.

## Final verification

- `PYTHONPATH=src:tests python -m unittest test_archive_review test_verifier_review -q`:
  38 methods passed, exit 0
- The owned review suite plus
  `test_verify.VerifierTests.test_every_evidence_component_is_compared` and
  `test_verify.VerifierTests.test_full_production_agreement_on_deterministic_histories`:
  40 methods passed, exit 0, after all reported verifier fixes
- Latest complete command:
  `PYTHONPATH=src:tests python -m unittest discover -s tests`:
  198 methods, 1 failure, 52.438 seconds, exit 1. The only failure was
  `test_inventory.InventoryTests.test_profile_catalog_schema`: its assertion
  expected `design_candidate`, while the concurrently updated catalog reported
  `enabled`. A fresh targeted invocation confirmed the mismatch. The implementation owner
  was notified to reconcile the expectation with the actual qualification
  decision; the reviewer did not change a qualification assertion to manufacture
  green status.

All archive/verifier findings listed above are closed by the focused regression
run. The whole-suite qualification-state mismatch remains an integration gate,
not an archive-parser finding. This receipt does not claim a clean whole suite
until a later explicitly recorded run supersedes it.

## Boundaries and residual risks

This is a finite regression and code review, not proof that every malformed
archive or possible evidence mutation is rejected. Runtime parsing is bounded
and non-executing; it does not establish package authenticity, application
behavior, import correctness, absence of malicious payloads, or compatibility
with unmodeled installers. ZIP64/descriptors and unsupported provider
compatibility remain explicit non-success cases. The verifier buffers bounded
source/member data differently from the streaming producer, so overall memory
qualification remains the separate calibration task. Shared serialization,
hashing, immutable value types, constants, normalization dependencies and budget
mechanics are not independently reimplemented; source parsing, destination
mapping and state replay are separately authored.


## Integration closure

A subsequent fresh source run passed all 198 test methods (53.472 seconds). The qualification-state expectation was updated to the enabled bounded profile after its installer and mapping gates; earlier failing integration snapshots above remain historical evidence. This does not expand the review scope or imply that every supported Python runtime has been tested. The exact final artifact and oracle receipts are summarized in `../QUALIFICATION.md`.
