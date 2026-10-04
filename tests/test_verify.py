"""Original fixtures and independent verifier regression tests.

Runtime verification never imports or executes these wheel members.
"""
import base64
import copy
import csv
import hashlib
import importlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

PROFILE = 'pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1'


def wheel(root, name, files=None, *, version='1.0', entrypoints=None, compression=zipfile.ZIP_DEFLATED):
    stem = name.replace('-', '_') + '-' + version
    di = stem + '.dist-info'
    members = dict(files or {})
    members[di + '/METADATA'] = f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n'.encode()
    members[di + '/WHEEL'] = b'Wheel-Version: 1.0\nGenerator: verifier-original-fixtures\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n'
    if entrypoints is not None:
        members[di + '/entry_points.txt'] = entrypoints
    out = io.StringIO(newline='')
    writer = csv.writer(out, lineterminator='\n')
    for name_, payload in sorted(members.items()):
        value = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b'=').decode()
        writer.writerow((name_, 'sha256=' + value, str(len(payload))))
    writer.writerow((di + '/RECORD', '', ''))
    members[di + '/RECORD'] = out.getvalue().encode()
    path = root / (stem + '-py3-none-any.whl')
    with zipfile.ZipFile(path, 'w', compression=compression) as z:
        for name_, payload in sorted(members.items()):
            info = zipfile.ZipInfo(name_, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = compression
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, payload)
    return {'id': name.replace('-', '_'), 'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def plan_file(root, wheels=(), initial=(), transition=(), desired=()):
    plan = dict(schema_version=1, profile=PROFILE, wheels=list(wheels), initial=list(initial),
                transition=list(transition), desired=list(desired))
    path = root / 'plan.json'
    path.write_text(json.dumps(plan), encoding='utf-8')
    return path


def reseal(document):
    """Give tampered evidence an honest checksum so digest-only checking fails."""
    holder = document.get('verification') if document.get('document_type') == 'repair_proposal' else document
    if holder is None:
        return document
    encode = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    holder['evidence_sha256'] = '0' * 64
    for _ in range(10):
        size = len(encode(document)) + 1
        if holder['resource_usage']['report_bytes'] == size:
            break
        holder['resource_usage']['report_bytes'] = size
    del holder['evidence_sha256']
    domain = b'wheelsuture/repair/1' if document['document_type'] == 'repair_proposal' else b'wheelsuture/report/1'
    holder['evidence_sha256'] = hashlib.sha256(domain + b'\0' + encode(document)).hexdigest()
    return document


def operation(id_, op, whl):
    return {'id': id_, 'op': op, 'wheel': whl}


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.v = importlib.import_module('wheelsuture.verify')

    def reconstruct(self, path):
        self.assertTrue(callable(getattr(self.v, 'reconstruct', None)), 'independent reconstruction API missing')
        return self.v.reconstruct(path)

    def test_empty_case_reconstructs_and_verifies(self):
        path = plan_file(self.root)
        report = self.reconstruct(path)
        self.assertEqual(report['status'], 'preserved')
        self.assertEqual(report['operations'], [])
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['final_state']['slots'], [])
        report_path = self.root / 'report.json'
        report_path.write_text(json.dumps(report))
        self.assertTrue(self.v.verify_report(path, report_path).valid)

    def test_independent_mapping_and_rewritten_tail(self):
        w = wheel(self.root, 'alpha', {'alpha.py': b'x=1\n', 'alpha-1.0.data/scripts/tool': b'#!python\nprint(1)\n',
                                      'alpha-1.0.data/headers/thing.h': b'int x;\n'})
        report = self.reconstruct(plan_file(self.root, [w], [operation('i', 'install', 'alpha')], desired=['alpha']))
        claims = {c['destination']: c for c in report['wheels'][0]['claims']}
        self.assertEqual(claims['bin/tool']['signature']['tail_sha256'], hashlib.sha256(b'print(1)\n').hexdigest())
        self.assertEqual(claims['include/site/python3.12/alpha/thing.h']['kind'], 'copied')
        self.assertEqual(claims['lib/python3.12/site-packages/alpha.py']['kind'], 'copied')
        self.assertEqual(sum(c['kind'] == 'control' for c in claims.values()), 4)
        self.assertEqual(report['status'], 'preserved')

    def test_retained_missing_and_noop_delete_cause(self):
        ws = [wheel(self.root, name, {'shared.py': b'x=1\n'}) for name in ('alpha', 'bravo', 'charlie')]
        path = plan_file(self.root, ws, [operation('i'+w['id'], 'install', w['id']) for w in ws],
                         [operation('r1', 'remove', 'bravo'), operation('r2', 'remove', 'charlie')], ['alpha'])
        report = self.reconstruct(path)
        fs = [f for f in report['findings'] if f['destination'] == 'lib/python3.12/site-packages/shared.py']
        self.assertEqual(report['status'], 'broken')
        self.assertEqual(len(fs), 4)
        self.assertEqual(len({f['cause_event_id'] for f in fs}), 1)
        self.assertEqual([f['retained'] for f in fs], [True, True, True, False])

    def test_every_evidence_component_is_compared(self):
        w = wheel(self.root, 'alpha', {'alpha.py': b'x=1\n'})
        path = plan_file(self.root, [w], [operation('i', 'install', 'alpha')], desired=['alpha'])
        report = self.reconstruct(path)
        mutations = [lambda x: x.update(status='broken'), lambda x: x['operations'].clear(),
                     lambda x: x['events'].pop(), lambda x: x['wheels'][0]['claims'][0].update(destination='bin/fake'),
                     lambda x: x['coverage']['excluded'].pop(), lambda x: x['resource_usage'].update(entries=0),
                     lambda x: x['final_state']['identities'][0].update(wheel_id='fake')]
        for mutate in mutations:
            changed = copy.deepcopy(report)
            mutate(changed)
            reseal(changed)
            report_path = self.root / 'report.json'
            report_path.write_text(json.dumps(changed))
            with self.subTest(mutate=mutate):
                self.assertFalse(self.v.verify_report(path, report_path).valid)

    def test_changed_source_rejected_against_trusted_digest(self):
        w = wheel(self.root, 'alpha', {'alpha.py': b'x=1\n'})
        path = plan_file(self.root, [w])
        report = self.reconstruct(path)
        (self.root / w['path']).write_bytes(b'changed')
        rp = self.root / 'report.json'
        rp.write_text(json.dumps(report))
        from wheelsuture.errors import InvalidInput
        with self.assertRaises(InvalidInput):
            self.v.verify_report(path, rp)

    def test_local_central_name_disagreement_is_rejected(self):
        w = wheel(self.root, 'alpha', {'alpha.py': b'x=1\n'})
        p = self.root / w['path']
        raw = bytearray(p.read_bytes())
        raw[30] ^= 1
        p.write_bytes(raw)
        w['sha256'] = hashlib.sha256(raw).hexdigest()
        from wheelsuture.errors import InvalidInput
        with self.assertRaises(InvalidInput):
            self.reconstruct(plan_file(self.root, [w]))

    def test_declared_size_cannot_hide_deflate_output(self):
        w = wheel(self.root, 'alpha', {'alpha.py': b'A' * 200000})
        p = self.root / w['path']
        raw = bytearray(p.read_bytes())
        local = raw.index(b'PK\x03\x04')
        central = raw.index(b'PK\x01\x02')
        struct.pack_into('<I', raw, local + 22, 1)
        struct.pack_into('<I', raw, central + 24, 1)
        p.write_bytes(raw)
        w['sha256'] = hashlib.sha256(raw).hexdigest()
        from wheelsuture.errors import InvalidInput
        with self.assertRaises(InvalidInput):
            self.reconstruct(plan_file(self.root, [w]))

    def test_source_symlink_is_rejected(self):
        w = wheel(self.root, 'alpha')
        source = self.root / w['path']
        alternate = self.root / ('real-' + source.name)
        source.rename(alternate)
        source.symlink_to(alternate)
        from wheelsuture.errors import InvalidInput
        with self.assertRaises(InvalidInput):
            self.reconstruct(plan_file(self.root, [w]))

    def test_global_unknown_provider_overlap_and_postmap_hooks(self):
        from wheelsuture.errors import UnsupportedInput
        wa = wheel(self.root, 'alpha', entrypoints=b'[console_scripts]\ntool = alpha:main\n')
        wb = wheel(self.root, 'bravo', entrypoints=b'[console_scripts]\ntool = bravo:main\n')
        with self.assertRaises(UnsupportedInput):
            self.reconstruct(plan_file(self.root, [wa, wb]))
        wc = wheel(self.root, 'charlie', {'charlie-1.0.data/data/lib/python3.12/site-packages/sitecustomize.so': b'benign'})
        with self.assertRaises(UnsupportedInput):
            self.reconstruct(plan_file(self.root, [wc]))


    def test_repair_replays_original_state_and_rejects_tampering(self):
        wa = wheel(self.root, 'alpha', {'shared.py': b'same'})
        wb = wheel(self.root, 'bravo', {'shared.py': b'same'})
        path = plan_file(self.root, [wa, wb], [operation('i1', 'install', 'alpha'), operation('i2', 'install', 'bravo')],
                         [operation('r', 'remove', 'bravo')], ['alpha'])
        report = self.reconstruct(path)
        repair = self.v.reconstruct_repair(path)
        self.assertEqual(repair['status'], 'verified')
        self.assertEqual([(x['op'], x['wheel']) for x in repair['actions']], [('remove', 'alpha'), ('install', 'alpha')])
        deletion = next(e for e in repair['verification']['events'] if e['destination'].endswith('/shared.py') and e['action'] == 'delete_absent')
        self.assertIsNotNone(deletion['prior_event_id'])
        rp, cp = self.root / 'report.json', self.root / 'repair.json'
        rp.write_text(json.dumps(report)); cp.write_text(json.dumps(repair))
        self.assertTrue(self.v.verify_report(path, rp, repair_path=cp).valid)
        for mutator in (lambda x: x['actions'].pop(0),
                        lambda x: x['verification']['events'][0].update(prior_event_id=None),
                        lambda x: x['verification']['source_sha256s'][0].update(sha256='0' * 64),
                        lambda x: x.update(analysis_evidence_sha256='0' * 64)):
            changed = copy.deepcopy(repair); mutator(changed); reseal(changed); cp.write_text(json.dumps(changed))
            self.assertFalse(self.v.verify_report(path, rp, repair_path=cp).valid)

    def test_conflict_is_copied_bytes_only_and_already_satisfied_has_no_actions(self):
        wa = wheel(self.root, 'alpha', {'shared.py': b'one'})
        wb = wheel(self.root, 'bravo', {'shared.py': b'two'})
        path = plan_file(self.root, [wa, wb], [], [], ['alpha', 'bravo'])
        repair = self.v.reconstruct_repair(path)
        self.assertEqual(repair['status'], 'conflict')
        self.assertEqual(repair['witnesses'][0]['kind'], 'different_bytes')
        self.assertIsNone(repair['verification'])
        path = plan_file(self.root, [wa], [operation('i', 'install', 'alpha')], [], ['alpha'])
        repair = self.v.reconstruct_repair(path)
        self.assertEqual(repair['status'], 'already_satisfied')
        self.assertEqual(repair['actions'], [])
        self.assertEqual(repair['verification']['events'], [])

    def test_stricter_verification_caps_return_incomplete(self):
        from dataclasses import replace
        from wheelsuture.model import DEFAULT_LIMITS
        w = wheel(self.root, 'alpha')
        path = plan_file(self.root, [w])
        report = self.reconstruct(path)
        rp = self.root / 'report.json'; rp.write_text(json.dumps(report))
        verdict = self.v.verify_report(path, rp, limits=replace(DEFAULT_LIMITS, entries=1))
        self.assertFalse(verdict.complete)
        verdict = self.v.verify_report(path, rp, limits=replace(DEFAULT_LIMITS, entries=100))
        self.assertTrue(verdict.valid)

    def test_malformed_evidence_is_mismatch_not_invalid_trusted_plan(self):
        path = plan_file(self.root)
        self.reconstruct(path)
        rp = self.root / 'report.json'
        rp.write_text('{"a":1,"a":2}')
        self.assertEqual(self.v.verify_report(path, rp).exit_code, 5)

    def test_postmap_extra_scaffold_and_casefold_restrictions(self):
        from wheelsuture.errors import UnsupportedInput
        for member in ('alpha-1.0.data/data/lib64/hook.py', 'alpha-1.0.data/scripts/activate',
                       'alpha-1.0.data/data/bin/activate.fish/child', 'A.PTH', 'A.PYC', 'x\u202e.py'):
            w = wheel(self.root, 'alpha', {member: b'benign'})
            with self.subTest(member=member), self.assertRaises(UnsupportedInput):
                self.reconstruct(plan_file(self.root, [w]))

    def test_text_caps_apply_outside_metadata_directory(self):
        from dataclasses import replace
        from wheelsuture.errors import LimitExceeded
        from wheelsuture.model import DEFAULT_LIMITS
        w = wheel(self.root, 'alpha', {'payload/METADATA': b'x' * 200})
        path = plan_file(self.root, [w])
        with self.assertRaises(LimitExceeded):
            self.v.reconstruct(path, limits=replace(DEFAULT_LIMITS, metadata_member_bytes=150))

    def test_parser_rejects_damaged_record_and_archive_trailing_bytes(self):
        from wheelsuture.errors import InvalidInput
        w = wheel(self.root, 'alpha')
        p = self.root / w['path']
        with zipfile.ZipFile(p) as z:
            entries = {i.filename: z.read(i.filename) for i in z.infolist()}
        record = 'alpha-1.0.dist-info/RECORD'
        entries[record] += b'phantom.py,sha256=bad,0\n'
        with zipfile.ZipFile(p, 'w') as z:
            for name, content in entries.items():
                z.writestr(name, content)
        w['sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
        with self.assertRaises(InvalidInput):
            self.v.reconstruct(plan_file(self.root, [w]))
        w = wheel(self.root, 'alpha')
        p.write_bytes(p.read_bytes() + b'trailer')
        w['sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
        with self.assertRaises(InvalidInput):
            self.v.reconstruct(plan_file(self.root, [w]))


    def test_verifier_rejects_symlink_plan_and_parent(self):
        from wheelsuture.errors import InvalidInput
        path = plan_file(self.root)
        alias = self.root / 'alias.json'; alias.symlink_to(path)
        with self.assertRaises(InvalidInput):
            self.v.reconstruct(alias)
        folder = self.root / 'linked'; folder.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(InvalidInput):
            self.v.reconstruct(folder / 'plan.json')

    def test_nonregular_and_symlink_evidence_fail_verification(self):
        import os
        path = plan_file(self.root)
        report = self.reconstruct(path)
        rp = self.root / 'report.json'; rp.write_text(json.dumps(report))
        link = self.root / 'report-link.json'; link.symlink_to(rp)
        self.assertEqual(self.v.verify_report(path, link).exit_code, 5)
        fifo = self.root / 'report-fifo'; os.mkfifo(fifo)
        self.assertEqual(self.v.verify_report(path, fifo).exit_code, 5)

    def test_entrypoint_keyword_targets_fail_closed(self):
        from wheelsuture.errors import UnsupportedInput
        for target in ('for:main', 'demo:class', 'demo.async:main'):
            w = wheel(self.root, 'alpha', entrypoints=('[console_scripts]\ntool = '+target+'\n').encode())
            with self.subTest(target=target), self.assertRaises(UnsupportedInput):
                self.reconstruct(plan_file(self.root, [w]))

    def test_tag_cartesian_expansion_is_refused_before_packaging(self):
        from unittest.mock import patch
        from wheelsuture.errors import UnsupportedInput
        # A supported-only profile can reject this spelling without expanding
        # hundreds of thousands of packaging.Tag values.
        w = wheel(self.root, 'alpha')
        p = self.root / w['path']
        with zipfile.ZipFile(p) as z:
            files = {i.filename: z.read(i.filename) for i in z.infolist()}
        tag = '.'.join(['py3'] * 100) + '-' + '.'.join(['none'] * 100) + '-' + '.'.join(['any'] * 100)
        files['alpha-1.0.dist-info/WHEEL'] = ('Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: '+tag+'\n').encode()
        # Rebuild valid RECORD for this original malformed-layout fixture.
        out=io.StringIO(newline=''); writer=csv.writer(out,lineterminator='\n')
        for name, data in files.items():
            if name.endswith('/RECORD'): continue
            h=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
            writer.writerow((name,'sha256='+h,str(len(data))))
        writer.writerow(('alpha-1.0.dist-info/RECORD','',''))
        files['alpha-1.0.dist-info/RECORD']=out.getvalue().encode()
        with zipfile.ZipFile(p,'w') as z:
            for name,data in files.items(): z.writestr(name,data)
        w['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
        with patch('wheelsuture.verify._source.parse_tag', side_effect=AssertionError('unsafe tag expansion')):
            with self.assertRaises(UnsupportedInput):
                self.reconstruct(plan_file(self.root,[w]))


    def test_full_production_agreement_on_deterministic_histories(self):
        import random
        from wheelsuture.api import analyze
        rng = random.Random(9684701)
        wheels = [wheel(self.root, name, {'shared.py': bytes([65 + i % 2]), name + '.py': b'benign'})
                  for i, name in enumerate(('alpha', 'bravo', 'charlie'))]
        for case in range(24):
            active = set()
            operations = []
            for i in range(7):
                name = rng.choice(['alpha', 'bravo', 'charlie'])
                op = rng.choice(['remove', 'reinstall']) if name in active else 'install'
                if op == 'remove': active.remove(name)
                elif op == 'install': active.add(name)
                operations.append(operation('step' + str(i), op, name))
            desired = [w['id'] for w in wheels if rng.randrange(2)]
            path = plan_file(self.root, wheels, [], operations, desired)
            with self.subTest(case=case):
                independent = self.reconstruct(path)
                self.assertEqual(independent, analyze(path).to_dict())
                from wheelsuture.canonical import canonical_bytes, digest
                original = copy.deepcopy(independent); expected = original.pop('evidence_sha256')
                self.assertEqual(expected, digest('wheelsuture/report/1', original))
                self.assertEqual(independent['resource_usage']['report_bytes'], len(canonical_bytes(independent)) + 1)

    def test_candidate_rejects_manual_plan_value(self):
        from wheelsuture.canonical import canonical_bytes
        from wheelsuture.model import Plan
        from wheelsuture.errors import InvalidInput
        path = plan_file(self.root)
        report = self.reconstruct(path)
        manual = Plan(path, canonical_bytes(json.loads(path.read_text())))
        with self.assertRaises(InvalidInput):
            self.v.verify_candidate(manual, report)


    def test_repair_stage_resource_exhaustion_has_verifiable_unknown_certificate(self):
        from dataclasses import replace
        from wheelsuture.model import DEFAULT_LIMITS
        wa = wheel(self.root, 'alpha', {'shared.py': b'x'})
        wb = wheel(self.root, 'bravo', {'shared.py': b'x'})
        path = plan_file(self.root, [wa, wb], [operation('ia', 'install', 'alpha'), operation('ib', 'install', 'bravo')],
                         [operation('rb', 'remove', 'bravo')], ['alpha'])
        limits = replace(DEFAULT_LIMITS, expanded_events=30)
        report = self.v.reconstruct(path, limits)
        repair = self.v.reconstruct_repair(path, limits)
        self.assertEqual(repair['status'], 'unknown')
        self.assertEqual(repair['actions'], [])
        self.assertEqual(repair['diagnostics'][0]['code'], 'resource_limit')
        rp, cp = self.root / 'report.json', self.root / 'repair.json'
        rp.write_text(json.dumps(report)); cp.write_text(json.dumps(repair))
        self.assertTrue(self.v.verify_report(path, rp, repair_path=cp).valid)
        repair['diagnostics'][0]['message'] = 'Forged reason'
        cp.write_text(json.dumps(repair))
        self.assertFalse(self.v.verify_report(path, rp, repair_path=cp).valid)


    def test_rehashed_omitted_findings_and_fabricated_cause_are_rejected(self):
        wa = wheel(self.root, 'alpha', {'shared.py': b'x'})
        wb = wheel(self.root, 'bravo', {'shared.py': b'x'})
        path = plan_file(self.root, [wa, wb], [operation('ia', 'install', 'alpha'), operation('ib', 'install', 'bravo')],
                         [operation('rb', 'remove', 'bravo')], ['alpha'])
        report = self.reconstruct(path)
        self.assertEqual(report['status'], 'broken')
        for mutate in (lambda d: d.update(findings=[], status='preserved'),
                       lambda d: d['findings'][0].update(cause_event_id=d['events'][0]['event_id']),
                       lambda d: d['events'][-1].update(prior_event_id=d['events'][0]['event_id'])):
            changed = copy.deepcopy(report); mutate(changed); reseal(changed)
            rp = self.root / 'report.json'; rp.write_text(json.dumps(changed))
            self.assertFalse(self.v.verify_report(path, rp).valid)


    def test_stricter_caller_repair_budget_is_incomplete_not_false_certificate(self):
        from dataclasses import replace
        from wheelsuture.model import DEFAULT_LIMITS
        wa = wheel(self.root, 'alpha', {'shared.py': b'x'})
        wb = wheel(self.root, 'bravo', {'shared.py': b'x'})
        path = plan_file(self.root, [wa, wb], [operation('ia', 'install', 'alpha'), operation('ib', 'install', 'bravo')],
                         [operation('rb', 'remove', 'bravo')], ['alpha'])
        report, repair = self.reconstruct(path), self.v.reconstruct_repair(path)
        self.assertEqual(repair['status'], 'verified')
        rp, cp = self.root / 'report.json', self.root / 'repair.json'
        rp.write_text(json.dumps(report)); cp.write_text(json.dumps(repair))
        verdict = self.v.verify_report(path, rp, repair_path=cp, limits=replace(DEFAULT_LIMITS, expanded_events=30))
        self.assertEqual(verdict.exit_code, 3)


    def test_stricter_repair_certificate_keeps_original_report_binding(self):
        from dataclasses import replace
        from wheelsuture.model import DEFAULT_LIMITS
        wa = wheel(self.root, 'alpha', {'shared.py': b'x'})
        wb = wheel(self.root, 'bravo', {'shared.py': b'x'})
        path = plan_file(self.root, [wa, wb], [operation('ia', 'install', 'alpha'), operation('ib', 'install', 'bravo')],
                         [operation('rb', 'remove', 'bravo')], ['alpha'])
        report = self.reconstruct(path)
        lower = replace(DEFAULT_LIMITS, expanded_events=1000)
        repair = self.v.reconstruct_repair(path, lower)
        repair['analysis_evidence_sha256'] = report['evidence_sha256']
        reseal(repair)
        rp, cp = self.root / 'report.json', self.root / 'repair.json'
        rp.write_text(json.dumps(report)); cp.write_text(json.dumps(repair))
        self.assertTrue(self.v.verify_report(path, rp, repair_path=cp).valid)
        # The independently authored producer must emit the exact lower-stage
        # certificate while preserving the original report's evidence digest.
        from wheelsuture.plan import load_plan
        from wheelsuture.inventory import inventory_wheel
        from wheelsuture.model import Budget, Profile, AnalysisReport
        from wheelsuture.canonical import canonical_bytes
        from wheelsuture.repair import propose_repair
        plan = load_plan(path)
        source_budget = Budget()
        inventories = {source.id: inventory_wheel(source, Profile(PROFILE), source_budget) for source in plan.sources}
        produced = propose_repair(plan, AnalysisReport(canonical_bytes(report)), inventories, budget=Budget(lower)).to_dict()
        self.assertEqual(produced, repair)
        # A larger cap cannot be introduced in a later repair stage.
        report = self.v.reconstruct(path, lower)
        repair = self.v.reconstruct_repair(path)
        repair['analysis_evidence_sha256'] = report['evidence_sha256']; reseal(repair)
        rp.write_text(json.dumps(report)); cp.write_text(json.dumps(repair))
        self.assertEqual(self.v.verify_report(path, rp, repair_path=cp).exit_code, 5)


if __name__ == '__main__':
    unittest.main()
