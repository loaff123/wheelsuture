"""Independent-reader disagreement and evidence-tampering review regressions."""
import copy
from dataclasses import replace
import hashlib
import json
import struct

from wheelsuture.errors import InvalidInput, LimitExceeded, UnsupportedInput
from wheelsuture.constants import PROFILE_ID
from wheelsuture.model import DEFAULT_LIMITS
from wheelsuture.verify import reconstruct, reconstruct_repair, verify_report

from test_archive_review import ReviewFixture, extra, review_members, review_zip


class VerifierArchiveReviewTests(ReviewFixture):
    def rejected(self, blob, error=InvalidInput):
        _, path = self.write_case(blob)
        with self.assertRaises(error):
            reconstruct(path)

    def test_extraction_version_is_checked_in_both_headers(self):
        for field in ('central_needed', 'local_needed'):
            with self.subTest(field=field):
                self.rejected(review_zip(review_members(), first={field: 63}), UnsupportedInput)

    def test_timestamp_extra_uses_distinct_local_and_central_rules(self):
        for changed in (dict(central_extra=extra(0x5455, b'\x02' + b'\0' * 4)),
                        dict(local_extra=extra(0x5455, b'\x03' + b'\0' * 4))):
            with self.subTest(changed=changed):
                self.rejected(review_zip(review_members(), first=changed))

    def test_duplicate_ntfs_timestamp_attributes_are_rejected(self):
        duplicate = extra(0x000a, b'\0' * 4 + (struct.pack('<HH', 1, 24) + b'\0' * 24) * 2)
        self.rejected(review_zip(review_members(), first={'central_extra': duplicate}), UnsupportedInput)

    def test_dos_directory_bit_cannot_describe_a_regular_file(self):
        self.rejected(review_zip(review_members(), first={'external': 0x10}), UnsupportedInput)

    def test_nonunix_creator_does_not_hide_disallowed_file_kind(self):
        self.rejected(review_zip(review_members(), first={'made': 20, 'external': 0o120777 << 16}), UnsupportedInput)

    def test_duplicate_raw_name_with_two_decodings_is_rejected(self):
        members = review_members({'review/caf├⌐.txt': b'first', 'review/café.txt': b'second'})
        raw = b'review/caf\xc3\xa9.txt'
        self.rejected(review_zip(members, first={'flags': 0, 'central_name': raw, 'local_name': raw}))

    def test_all_protected_scaffold_ancestors_are_reserved(self):
        for destination in ('include', 'include/site', 'include/site/python3.12', 'include/python3.12'):
            with self.subTest(destination=destination):
                self.rejected(review_zip(review_members({'review-1.0.data/data/' + destination: b'inert'})), UnsupportedInput)

    def test_mapped_uppercase_metadata_and_special_wrapper_are_reserved(self):
        for member in ('review-1.0.data/data/lib/python3.12/site-packages/foreign.DIST-INFO/value',
                       'review-1.0.data/scripts/easy_install-3.12',
                       'review-1.0.data/scripts/easy_install-custom'):
            with self.subTest(member=member):
                self.rejected(review_zip(review_members({member: b'inert'})), UnsupportedInput)

    def test_editable_metadata_is_unsupported(self):
        self.rejected(review_zip(review_members({'review-1.0.dist-info/editable.txt': b'inert'})), UnsupportedInput)

    def test_metadata_nul_and_bare_cr_are_invalid(self):
        for suffix in (b'X-Unknown: \0\n\n', b'X-Unknown: value\r\nX-Next: value\r\n\n'.replace(b'value\r\n', b'value\r', 1)):
            metadata = b'Metadata-Version: 2.1\nName: review\nVersion: 1.0\n' + suffix
            with self.subTest(suffix=suffix):
                self.rejected(review_zip(review_members(metadata=metadata)))

    def test_very_long_record_size_returns_typed_invalid_input(self):
        for size in ('9' * 5000, '0' * 30 + str(len(review_members()['review/data.txt']))):
            with self.subTest(size_prefix=size[:30]):
                self.rejected(review_zip(review_members(record_size=size)))

    def test_entrypoint_group_syntax_matches_supported_grammar(self):
        self.rejected(review_zip(review_members(entrypoints=b'[unknown group]\nfield=value\n')))

    def test_entrypoint_target_whitespace_matches_supported_grammar(self):
        self.rejected(review_zip(review_members(entrypoints=b'[console_scripts]\ntool=module : attribute\n')), UnsupportedInput)

    def test_empty_foreign_dist_info_directory_is_not_discarded(self):
        members = review_members()
        members['foreign-1.0.dist-info/'] = b''
        self.rejected(review_zip(members))

    def test_raw_local_central_disagreement_and_deflate_damage(self):
        cases = [dict(local_name=b'review/data.txX'), dict(local_flags=0), dict(local_crc=0),
                 dict(decoded=1), dict(stream=lambda b: b[:-1]), dict(stream=lambda b: b + b),
                 dict(stream=lambda b: b + b'ignored'), dict(offset=1)]
        for index, changed in enumerate(cases):
            with self.subTest(case=index):
                self.rejected(review_zip(review_members(), first=changed))

    def test_actual_decoded_bytes_and_source_bytes_are_bounded(self):
        blob = review_zip(review_members({'review/data.txt': b'x' * 10000}), first={'decoded': 1})
        _, path = self.write_case(blob)
        for limits in (replace(DEFAULT_LIMITS, member_bytes=1024),
                       replace(DEFAULT_LIMITS, archive_bytes=len(blob) - 1)):
            with self.subTest(limits=limits), self.assertRaises(LimitExceeded):
                reconstruct(path, limits=limits)

    def test_exact_zip_comment_may_contain_end_record_magic(self):
        comments = (b'original comment PK\x05\x06 inert suffix',
                    b'original comment ' + struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 0, 0, 0, 0, 0),
                    b'original comment ' + struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 65535, 65535, 0, 0, 0))
        for comment in comments:
            with self.subTest(comment=comment):
                _, path = self.write_case(review_zip(review_members(), comment=comment))
                self.assertEqual(reconstruct(path)['status'], 'preserved')


class VerifierEvidenceReviewTests(ReviewFixture):
    def make_report(self):
        _, path = self.write_case(review_zip(review_members()))
        report = reconstruct(path)
        report_path = self.root / 'report.json'
        report_path.write_text(json.dumps(report))
        return path, report, report_path

    def test_bool_integer_confusions_are_rejected_in_all_evidence_layers(self):
        path, report, report_path = self.make_report()
        # Python considers True == 1 and False == 0. Wire evidence must not.
        mutations = [lambda d: d.update(schema_version=True), lambda d: d.update(complete=1),
                     lambda d: d['operations'][0].update(index=False),
                     lambda d: d['events'][0].update(ordinal=False),
                     lambda d: d['wheels'][0].update(root_is_purelib=1),
                     lambda d: d['wheels'][0]['claims'][0].update(checked=1),
                     lambda d: d['resource_usage'].update(findings=False)]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(report)
            mutate(changed)
            report_path.write_text(json.dumps(changed))
            with self.subTest(case=index):
                self.assertEqual(verify_report(path, report_path).exit_code, 5)

    def test_every_report_top_level_field_is_required(self):
        path, report, report_path = self.make_report()
        for field in report:
            changed = copy.deepcopy(report)
            del changed[field]
            report_path.write_text(json.dumps(changed))
            with self.subTest(field=field):
                self.assertEqual(verify_report(path, report_path).exit_code, 5)

    def test_claim_event_and_state_omissions_are_rejected(self):
        path, report, report_path = self.make_report()
        paths = [('wheels', 0, 'claims', 0), ('events', 0), ('final_state', 'slots', 0),
                 ('operations', 0), ('final_state', 'identities', 0)]
        for location in paths:
            original = report
            for key in location:
                original = original[key]
            for field in original:
                changed = copy.deepcopy(report)
                obj = changed
                for key in location:
                    obj = obj[key]
                del obj[field]
                report_path.write_text(json.dumps(changed))
                with self.subTest(location=location, field=field):
                    self.assertEqual(verify_report(path, report_path).exit_code, 5)

    def test_repair_fields_and_verification_omissions_are_rejected(self):
        path, report, report_path = self.make_report()
        repair = reconstruct_repair(path)
        repair_path = self.root / 'repair.json'
        for location in ((), ('verification',)):
            original = repair if not location else repair['verification']
            for field in original:
                changed = copy.deepcopy(repair)
                target = changed if not location else changed['verification']
                del target[field]
                repair_path.write_text(json.dumps(changed))
                with self.subTest(location=location, field=field):
                    self.assertEqual(verify_report(path, report_path, repair_path=repair_path).exit_code, 5)

    def test_malformed_trusted_plan_stays_invalid_input(self):
        path, report, report_path = self.make_report()
        original = json.loads(path.read_text())
        mutations = [lambda d: d.update(schema_version=True), lambda d: d.update(wheels={}),
                     lambda d: d['initial'][0].update(wheel=True),
                     lambda d: d['initial'][0].update(op=[]), lambda d: d.update(desired=[{}]),
                     lambda d: d['wheels'][0].update(path='../escape.whl')]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(original)
            mutate(changed)
            path.write_text(json.dumps(changed))
            with self.subTest(case=index), self.assertRaises(InvalidInput):
                verify_report(path, report_path)

    def test_unknown_profile_and_stricter_evidence_limit_are_incomplete(self):
        path, report, report_path = self.make_report()
        verdict = verify_report(path, report_path, limits=replace(DEFAULT_LIMITS, report_bytes=100))
        self.assertEqual(verdict.exit_code, 3)
        value = json.loads(path.read_text())
        value['profile'] = 'unknown-well-formed-profile'
        path.write_text(json.dumps(value))
        self.assertEqual(verify_report(path, report_path).exit_code, 3)

    def multi_plan(self, specifications, initial, transition, desired):
        sources = []
        for name, payload, entrypoints in specifications:
            blob = review_zip(review_members(payload, entrypoints=entrypoints, name=name))
            wheel = self.root / (name + '-1.0-py3-none-any.whl')
            wheel.write_bytes(blob)
            sources.append(dict(id=name, path=wheel.name, sha256=hashlib.sha256(blob).hexdigest()))
        value = dict(schema_version=1, profile=PROFILE_ID, wheels=sources,
                     initial=[dict(id='i' + str(i), op='install', wheel=w) for i, w in enumerate(initial)],
                     transition=[dict(id='t' + str(i), op='remove', wheel=w) for i, w in enumerate(transition)],
                     desired=list(desired))
        path = self.root / 'plan.json'
        path.write_text(json.dumps(value))
        return path

    def test_unknown_provider_compatibility_never_becomes_a_conflict_proof(self):
        cases = [(b'[console_scripts]\ntool=shared:main\n', {'other-1.0.data/scripts/tool': b'opaque'}, None),
                 (b'[console_scripts]\ntool=shared:main\n', {}, b'[gui_scripts]\ntool=shared:main\n'),
                 (b'[console_scripts]\ntool=shared:main\n', {}, b'[console_scripts]\ntool=other:main\n')]
        for left, payload, right in cases:
            path = self.multi_plan([('review', {}, left), ('other', payload, right)], [], [], ['review', 'other'])
            with self.subTest(right=right, payload=payload), self.assertRaises(UnsupportedInput):
                reconstruct_repair(path)

    def test_same_provider_declaration_is_equal_across_owners(self):
        entrypoints = b'[console_scripts]\ntool=shared:main\n'
        path = self.multi_plan([('review', {}, entrypoints), ('other', {}, entrypoints)],
                               ['review', 'other'], [], ['review', 'other'])
        self.assertEqual(reconstruct(path)['status'], 'preserved')

    def test_repair_intermediate_damage_and_actions_are_fully_compared(self):
        sources = [(name, {'shared.txt': b'inert shared bytes'}, None) for name in ('review', 'other', 'temporary')]
        path = self.multi_plan(sources, ['review', 'other', 'temporary'], ['temporary'], ['review', 'other'])
        report, repair = reconstruct(path), reconstruct_repair(path)
        self.assertEqual(report['status'], 'broken')
        self.assertEqual(repair['status'], 'verified')
        self.assertTrue(repair['verification']['findings'])
        rp, cp = self.root / 'report.json', self.root / 'repair.json'
        rp.write_text(json.dumps(report))
        cp.write_text(json.dumps(repair))
        self.assertTrue(verify_report(path, rp, repair_path=cp).valid)
        mutations = [lambda d: d['actions'].reverse(),
                     lambda d: d['verification']['findings'].clear(),
                     lambda d: d['verification']['events'][0].update(before=None),
                     lambda d: d['verification']['operations'][0].update(index=False),
                     lambda d: d['verification']['resource_usage'].update(wheels=True),
                     lambda d: d['verification']['final_state']['slots'].pop(),
                     lambda d: d['verification']['source_sha256s'].pop()]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(repair)
            mutate(changed)
            cp.write_text(json.dumps(changed))
            with self.subTest(case=index):
                self.assertEqual(verify_report(path, rp, repair_path=cp).exit_code, 5)
