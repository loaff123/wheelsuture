# Independent state and repair review

Review date: 2026-10-03 (UTC). Scope: DESIGN.md, CONTRACTS.md, schema contracts, model/canonical/plan/reducer/repair, public API trust boundaries, and tests. No production code was modified by this reviewer. No wheel payload was imported or executed. No publication was attempted.

## Verdict

The reviewed reducer and conservative repair algorithm agree with a separately written direct specification on the finite universes below. Three substantive API issues were demonstrated with failing tests, repaired by the implementation owner, and rechecked successfully. All 25 tests in `tests/test_state_exhaustive.py` passed in the full-suite snapshot and in the final isolated rerun (33.373 seconds).

This is bounded state-model evidence, not a proof of arbitrary wheel/installer behavior or a release qualification. The whole-suite snapshot was **not green**: 179 tests in 34.352 seconds, 17 failing subcases and one error in the concurrent independent verifier archive-review suite. Those findings were passed to the owner and are being addressed in that separate scope. Do not treat this state review as closing those archive-verifier blockers.

## Independently checked cases

The test oracle uses ordinary dictionaries and fresh full scans of all active claims at every boundary. It does not call production reducer/repair helpers to derive expectations, and implements canonical hashing separately with hashlib and json. In contrast, production maintains reverse ownership indexes. Expected operations, event order, before/after signatures, prior-event links, exact causal event IDs, findings, retained flags, identities, slots and final-state digests are compared in full.

### Exhaustive reducer universe: 23,347 cases

Each footprint cell is absent, byte value `0`, or byte value `1`. All legal install/remove/reinstall histories of length zero through three from the empty state are enumerated, with every desired subset:

| Names | Destinations | Footprint layouts | Histories | Desired subsets | Cases |
|---|---:|---:|---:|---:|---:|
| 0 | 2 | 1 | 1 | 1 | 1 |
| 1 | 2 | 9 | 7 | 2 | 126 |
| 2 | 2 | 81 | 27 | 4 | 8,748 |
| 3 | 1 | 27 | 67 | 8 | 14,472 |

This does not claim exhaustive coverage of three names across three destinations.

### Held-out generated histories

64 deterministic seeds, 104729 through 104792, were selected independently of production tuning. Each constructs three canonical names, two versions per name, three destinations, private controls, two payload values, and 20 legal operations including replace. Every full history is checked against the independent oracle, including all intermediate boundaries. Seeds were not discarded or changed to match implementation behavior.

### Exhaustive repair unit universe: 3,061 cases

For each small footprint layout, all installed-subset and desired-subset combinations are checked. Installing all owners then removing nonretained owners deliberately produces broken survivors. Expected conflicts are derived directly from simultaneous desired signatures. Otherwise expected actions are exactly all current removals followed by all desired installs, in canonical-name order.

Every emitted repair event, intermediate finding and final state is independently replayed from the original final state. Only `_independent_check` is mocked in these explicitly labeled synthetic unit tests. Consequently those cases establish algorithmic behavior, **not** successful independent source/certificate verification.

### Unmocked integration

`test_public_repair_from_real_wheels_passes_unmocked_verification` constructs real original wheel ZIPs and exercises public `create_repair` and `verify_report` without mocks. An old alpha owns a destination that the retained desired bravo needs; alpha-new omits it; an extra zulu must be removed. The sequence removes old alpha, bravo and zulu before installing desired alpha-new and bravo. The direct oracle independently checks the original and repair events/findings/state. Public independent verification returns valid and complete, and source bytes remain unchanged.

## Confirmed issue closures

### 1. Validated inventory replacement retained authority (high)

Before correction, `dataclasses.replace(real_inventory, canonical=...)` retained the old private token. Removing every claim and deletion path produced `validated() == True` and a false `preserved` report with zero payload slots. Replacing `usage_canonical` could also erase decoded-byte, archive-byte and entry accounting.

Observed RED tests:

- `test_replaced_real_inventory_cannot_retain_validation_for_forged_claims`
- `test_replaced_real_inventory_cannot_erase_resource_usage`

Correction reviewed: the private seal now binds canonical inventory, profile, source digest, effective limits and resource accounting. Additional source/profile/limit replacement tests pass. This is API provenance validation, not a security sandbox against a Python caller modifying private internals.

### 2. Manual Plan bypassed structural and profile validation (high)

Before correction, constructing exported `Plan` directly allowed an unsupported profile or extra fields to reach a `preserved` output bearing the supported output profile. Plan fields and source/counter provenance could also be replaced without invalidating validation.

Observed RED tests:

- `test_manual_plan_cannot_bypass_supported_profile`
- `test_manual_plan_cannot_bypass_closed_shape`

Correction reviewed: `load_plan` produces a sealed Plan; Replay refuses unvalidated values. The binding includes path, canonical input, effective limits, source-file digest, plan byte count and nesting depth. Additional replacement tests cover these fields. Forged analysis reports are also rejected before repair generation.

### 3. Public simulate omitted final input freshness check (high)

Before correction, loading a real plan and inventory, changing either file, then calling public `simulate` still returned `preserved`.

Observed RED tests:

- `test_public_simulate_rejects_wheel_changed_after_inventory`
- `test_public_simulate_rejects_plan_changed_after_loading`

Correction reviewed: public simulate performs the final source rehash. Synthetic state tests now explicitly use private `_simulate_snapshot`; public provenance/freshness regressions continue to use the public entry point. Both changed-file regressions pass with typed `InputChanged`.

## Specific semantic and resource checks

- Overwrite never rewrites another owner's historical claim
- Initial-phase damage is preserved even after final repair
- Reinstall and replace produce deletion then write evidence, without findings for transient internal subphases
- Retained means the same canonical name exists before and after a whole operation
- Repeated `delete_absent` events link to the latest prior event while the missing-file cause remains the original effective deletion
- A later write clears missing-file causality
- Same-version/different-digest identities remain distinct; stale removal/reinstall and cross-name replace fail
- Global file/ancestor restrictions apply to unused and nonconcurrent historical artifacts
- Equal provider signatures may share; unequal providers and cross-kind overlap remain unsupported, never falsely impossible
- Unicode destinations retain exact codepoint identity
- All active names are removed before any desired installation, including currently intact desired owners and extra identities
- Conflicts include incompatible requirements of currently intact desired owners
- Report bytes are checked at their LF-inclusive fixed point; report and state hashes are independently recomputed
- Owner claim/deletion counts aggregate even when destinations overlap; actual state-slot count is a high-water mark
- Original plus repair operations/events are charged together; near-limit repairs become unknown without a success certificate
- Event/finding limits trigger before corresponding output append; unrelated limit overflows are typed

## Verification commands and limits of this verdict

Commands used:

    PYTHONPATH=src:tests python -m unittest test_state_exhaustive -v
    PYTHONPATH=src:tests python -m unittest discover -s tests -v

Whole-suite snapshot: all 25 state-review tests passed. Remaining failures were confined to `test_verifier_review.VerifierArchiveReviewTests`: protected scaffold ancestors (four subcases), DOS directory flags, duplicate NTFS timestamp attributes, editable metadata, entrypoint group grammar, extraction versions (two), uppercase mapped metadata and easy_install wrapper names (two), metadata NUL/bare CR (two), non-Unix disallowed file mode, timestamp-extra validation (two), and the 5000-digit RECORD-size case raising raw ValueError. These are separate open qualification blockers as of this snapshot.

The finite unit inventories are explicitly synthetic and factory-sealed; they do not establish archive parsing or mapping correctness. The unmocked real-source case adds integration evidence but is not a substitute for real pip differential qualification, capacity calibration, independent archive-parser review, or installed-package checks.


## Integration closure

A subsequent fresh source run passed all 198 test methods (53.472 seconds). The qualification-state expectation was updated to the enabled bounded profile after its installer and mapping gates; earlier failing integration snapshots above remain historical evidence. This does not expand the review scope or imply that every supported Python runtime has been tested. The exact final artifact and oracle receipts are summarized in `../QUALIFICATION.md`.
