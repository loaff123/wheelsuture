# Normative serialization and validation supplement

These details close interface choices that would otherwise make independent implementations disagree. They are part of DESIGN.md, not product code.

## Canonical encoding and identifier tuples

`J(value)` is UTF-8 JSON with lexicographically sorted object keys, no insignificant whitespace, no escaped ASCII slash, Unicode scalars emitted directly except required JSON escaping, and decimal integers without leading zeros. Strings are not Unicode-normalized. No floats, NaN, Infinity or duplicate keys exist. Equivalent Python reference settings are `ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False`, after strict type/string validation. Files add one LF; hashes do not.

`H(domain, value) = lowercase_hex_sha256(ASCII(domain) || 0x00 || J(value))`.

Exact preimages:

- input_sha256: H("wheelsuture/plan/1", parsed_plan)
- case_id: H("wheelsuture/case/1", [profile_id, "wheelsuture-model-v1", input_sha256, [[wheel.id, wheel.sha256] for wheel in manifest order]])
- path_id: H("wheelsuture/path/1", [profile_id, destination])
- claim_id: H("wheelsuture/claim/1", [profile_id, source_wheel_sha256, member_or_null, claim_kind, destination, signature])
- operation_id: H("wheelsuture/operation/1", [case_id, phase, zero_based_index_within_phase, source_operation_object])
- event_id: H("wheelsuture/event/1", [operation_id, zero_based_ordinal_within_operation, destination, action, before_signature_or_null, after_signature_or_null])
- finding_id: H("wheelsuture/finding/1", [case_id, phase, boundary_operation_id_or_null, finding_kind, retained_boolean, sorted_wheel_ids, sorted_claim_ids, destination_or_null, expected_signature_or_null, actual_signature_or_null, cause_event_id_or_null])
- state_sha256: H("wheelsuture/state/1", {"identities": canonical_identities, "slots": canonical_slots})
- analysis evidence_sha256: H("wheelsuture/report/1", report_without_top_level_evidence_sha256)
- repair verification.evidence_sha256: H("wheelsuture/repair/1", repair_without_verification_evidence_sha256)

IDs are recomputed, never accepted as authority. Final-state slots include their last event IDs. Missing slots are absent; tombstones are proved from EFFECTIVE present-to-absent delete events, not serialized as extant files. delete_absent advances event-chain provenance but does not supersede the original effective destructive cause. Writes clear tombstones. All order-sensitive action/event arrays remain in execution order. Other arrays are ordered as follows: wheels in manifest order; tags lexicographic; claims/deletion paths by destination UTF-8, then claim ID; identities by canonical name; slots by destination UTF-8; findings by boundary phase/index, kind, destination (null first), wheel IDs, claim IDs; diagnostics by detection stage then code/wheel/operation/path/message. `desired` preserves manifest order; repair installs/removes sort canonical names. Source SHA lists sort wheel ID. Counts are computed after this canonical construction.

Byte length follows DESIGN.md's fixed-point rule. Report bytes include the LF. Digest placeholders are exactly 64 ASCII zeros, so substituting real digests does not change length. The report-length field is included in the final evidence digest. If independent verification uses a stricter limit that prevents reconstructing an existing report, return incomplete rather than editing its effective_limits or declaring it false.

## Structural versus semantic validation

All six files under [src/wheelsuture/schemas](../src/wheelsuture/schemas/) are closed JSON Schema 2020-12 contracts. They need no remote schema fetches. Schema checks are necessary but not sufficient:

- Exact object/array shapes, primitive types, upper bounds and enums: schemas
- Duplicate JSON keys, UTF-8, surrogates, depth, byte lengths: strict loader before schema
- Unknown well-formed profile IDs: incomplete exit 3 after structural plan validation, not schema-invalid; malformed profile IDs/types are exit 2. Reference resolution, IDs, unique names/paths/digests, aggregate limits, legal active-state preconditions, strict source-path containment: semantic plan validation
- Matching identity/tags/RECORD, archive structure, mapped destinations, transformed signatures, reserved namespaces, global cross-history prefix restrictions: inventory/profile validation
- All object-field cross-consistency, IDs, sorting, complete evidence/findings and exact status: independent verifier

`checked` is true exactly for copied/rewritten_script/entry_point claims, false for control claims. Kind and signature must correspond. Control members are null. Entry-point members identify the wheel's entry_points.txt, with basename/group/target in the signature. A path event's claim/wheel/source must exist in that operation's installation footprint; a removal event may reference the removed wheel's claim even when different bytes were present. `delete_absent` has null before/after; writes have non-null after. Every prior-event reference resolves to the latest earlier event at that path, not an arbitrary older event. Control-write/delete actions apply only to private control slots.

Report phase constraints: analysis report operations and findings include initial/transition/final only; repair verification contains repair operations/events plus all intermediate repair-boundary findings; only final desired findings must be empty for verified status. A repair finding with boundary_operation_id=null is final; a non-null value identifies an intermediate repair action, which may legitimately damage a still-active distribution during the remove-all phase. Retained-boundary findings are computed after each full user operation. A final finding may repeat an earlier underlying damage with its own final-boundary finding ID; it is not a second destructive event. Original-phase findings cannot be removed from a report because a proposed repair would fix them.

Source wheel bytes must be unchanged at final success. All exposed checksums refer to actual files/semantic objects; unknown counters, unverifiable snapshots or incomplete input cannot be replaced by zero to earn a preserved/verified status. For report-level incomplete results, partial inventories/events are permitted only up to the exact stopped boundary, diagnostics explain the first blocking condition, complete=false, and final_state=null. The verifier checks supported partial evidence but returns incomplete, never a complete verified-preserved verdict.

Conflicts must reference at least two valid mandatory claims, or one internally contradictory file/ancestor pair (two claim IDs), from desired artifacts. V1 `different_provider` witnesses are not emitted: the enum is reserved structurally, and semantic validation rejects it without a later versioned profile disjointness proof. Identical provider signatures exclude owning wheel identity; unequal signatures are unknown in v1. `rewritten_script` equality uses the same interpreter/profile token and exact tail digest/size. Different signature kinds are unsupported overlap, not contradiction.

The `replace` operation always expands into explicit old removal followed by new installation, including same-version/different-digest replacements. It is not a bare pip install that might skip an apparently already-installed version. The v1 repair strategy is checked semantically: zero actions for already_satisfied, otherwise exactly all active removals followed by all desired installs, canonical-name order within each phase. The generic operation schema does not authorize a different algorithm under the fixed strategy identifier.

Resource counters: each field named in `effective_limits` has the matching stage counter in resource_usage except bounded error_bytes. `member_bytes`, `record_member_bytes`, `metadata_member_bytes`, json_depth and state_slots are maxima; other quantities are aggregate quantities as specified in DESIGN.md. `central_directory_bytes` sums directories across unique input wheels. `deletion_paths` is the total per-wheel footprint count (shared destinations count for each owner). `mapped_claims` likewise counts per-owner claims. `path_text_bytes` counts UTF-8 bytes of each raw source member and mapped/generated destination occurrence once, not repeated event strings. `user_operations` is initial+transition for analysis and original+repair for repair verification, so a near-limit original plan may legitimately make repair verification unknown unless a separate predeclared verification limit covers it. Limits may be lower but never exceed schema hard maxima. No counter uses elapsed time, current date, or host-dependent paths.

## Error precedence

1. Invalid strict JSON/schema/digest/reference/structural archive: exit 2
2. Well-formed unsupported profile/layout/transform/path semantics or hit hard/effective bound: exit 3
3. I/O read/write failure: exit 4
4. Complete original analysis: preserved exit 0, broken exit 1
5. Report/certificate discrepancies with a valid trusted plan: exit 5
6. Unexpected implementation exception: exit 70, no clean result

If output publication fails, exit 4 supersedes a completed analysis status in the terminal, but already-published valid JSON retains its honest original status. Never output a partial JSON document. Unsupported features and capacity exhaustion do not imply corruption or maliciousness. Digest mismatches are invalid pinned inputs; evidence mismatches are verification failures. Runtime has no installer execution mode.
