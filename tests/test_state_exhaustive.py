"""Independent finite-model checks. Synthetic inventories isolate state semantics.

The reference machine below uses no production reducer, repair, or canonical
helpers. It does full fresh scans at boundaries, rather than the implementation's
reverse-index algorithm. Synthetic repair unit tests explicitly bypass only the independent certificate
gate; they do not establish certificate verification. The real-source public
integration test exercises that gate without a mock.
"""
from dataclasses import replace
import hashlib
from itertools import product
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from wheelsuture.constants import PROFILE_ID, MODEL_REVISION
from wheelsuture.errors import InvalidInput, UnsupportedInput, LimitExceeded, VerificationError
from wheelsuture.inventory import inventory_wheel
from wheelsuture.model import Budget, Limits, Plan, Profile, WheelSource, _validated_inventory
from wheelsuture.plan import load_plan
from wheelsuture.reducer import Replay, _simulate_snapshot as simulate, simulate as public_simulate
from wheelsuture.repair import propose_repair
from inventory_fixtures import wheel_bytes, write_wheel


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf8')


def identifier(domain, value):
    return hashlib.sha256(domain.encode('ascii') + b'\0' + wire(value)).hexdigest()


def byte_signature(value):
    return dict(kind='bytes', sha256=hashlib.sha256(value).hexdigest(), size=len(value))


def synthetic(wid, name, paths, *, controls=False, version='1'):
    """Private test factory, deliberately not a claim of archive validation."""
    source = identifier('independent-test-artifact', [wid, name, version, paths])
    claims = []
    descriptions = [(p, p, 'copied' if s['kind'] == 'bytes' else s['kind'], s, True)
                    for p, s in paths.items()]
    if controls:
        p = 'lib/python3.12/site-packages/' + name + '-' + version + '.dist-info/RECORD'
        descriptions.append((p, None, 'control', dict(kind='control', control='RECORD', wheel_sha256=source), False))
    for destination, member, kind, signature, checked in descriptions:
        claims.append(dict(claim_id=identifier('wheelsuture/claim/1', [PROFILE_ID, source, member, kind, destination, signature]),
                           path_id=identifier('wheelsuture/path/1', [PROFILE_ID, destination]),
                           wheel_id=wid, destination=destination, member=member,
                           kind=kind, signature=signature, checked=checked))
    claims.sort(key=lambda c: (c['destination'].encode('utf8'), c['claim_id']))
    doc = dict(wheel_id=wid, source_sha256=source, name=name, canonical_name=name,
               version=version, dist_info=name + '-' + version + '.dist-info',
               root_is_purelib=True, tags=['py3-none-any'], member_count=len(claims),
               decoded_bytes=0, claims=claims, deletion_paths=[c['destination'] for c in claims])
    usage = Budget().usage
    usage.update(wheels=1, mapped_claims=len(claims), deletion_paths=len(claims),
                 member_bytes=max((s.get('size', 0) for s in paths.values()), default=0))
    return _validated_inventory(doc, PROFILE_ID, source, Limits(), usage)


def operation(verb, wid, index=0):
    return dict(id='op' + str(index), op=verb, wheel=wid)


def histories(names, depth):
    """Every legal install/remove/reinstall prefix up to depth from empty."""
    yield []
    def visit(prefix, active):
        if len(prefix) == depth:
            return
        for wid in names:
            verbs = ('remove', 'reinstall') if wid in active else ('install',)
            for verb in verbs:
                action = operation(verb, wid, len(prefix))
                next_active = active | {wid} if verb == 'install' else active - {wid} if verb == 'remove' else active
                result = prefix + [action]
                yield result
                yield from visit(result, next_active)
    yield from visit([], set())


class Reference:
    """Straight-line specification, with independent IDs and full ownership scans."""
    def __init__(self, data, wheels):
        self.data, self.wheels = data, wheels
        self.case = identifier('wheelsuture/case/1', [PROFILE_ID, MODEL_REVISION,
            identifier('wheelsuture/plan/1', data), [[w['id'], w['sha256']] for w in data['wheels']]])
        self.active, self.files, self.previous, self.deleted = {}, {}, {}, {}
        self.events, self.operations, self.findings = [], [], []
        self.peak_slots = 0

    def finding(self, phase, boundary, kind, retained, owners, claims, destination=None,
                expected=None, actual=None, cause=None):
        owners, claims = sorted(owners), sorted(claims)
        return dict(finding_id=identifier('wheelsuture/finding/1', [self.case, phase, boundary, kind,
                        retained, owners, claims, destination, expected, actual, cause]),
                    boundary_operation_id=boundary, phase=phase, kind=kind, retained=retained,
                    wheel_ids=owners, claim_ids=claims,
                    path_id=identifier('wheelsuture/path/1', [PROFILE_ID, destination]) if destination else None,
                    destination=destination, expected=expected, actual=actual, cause_event_id=cause)

    def damage(self, wid, phase, boundary, retained):
        result = []
        for claim in self.wheels[wid]['claims']:
            if not claim['checked']:
                continue
            p = claim['destination']
            existing = self.files.get(p)
            if existing is not None and existing['signature'] == claim['signature']:
                continue
            result.append(self.finding(phase, boundary, 'missing' if existing is None else 'displaced',
                retained, [wid], [claim['claim_id']], p, claim['signature'],
                existing['signature'] if existing else None,
                existing['last_event_id'] if existing else self.deleted.get(p)))
        return result

    @staticmethod
    def sorted_findings(items):
        return sorted(items, key=lambda f: (f['kind'], (f['destination'] or '').encode('utf8'), f['wheel_ids'], f['claim_ids']))

    def apply(self, action, phase, index):
        old_names = set(self.active)
        oid = identifier('wheelsuture/operation/1', [self.case, phase, index, action])
        self.operations.append(dict(operation_id=oid, phase=phase, index=index, source=action))
        verb = action['op']
        steps = [('remove', action['from']), ('install', action['to'])] if verb == 'replace' else (
            [('remove', action['wheel']), ('install', action['wheel'])] if verb == 'reinstall' else [(verb, action['wheel'])])
        ordinal = 0
        for step, wid in steps:
            wheel = self.wheels[wid]
            if step == 'install':
                assert wheel['canonical_name'] not in self.active
                self.active[wheel['canonical_name']] = wid
            else:
                assert self.active[wheel['canonical_name']] == wid
                del self.active[wheel['canonical_name']]
            for claim in wheel['claims']:
                p = claim['destination']
                before = self.files[p]['signature'] if p in self.files else None
                after = claim['signature'] if step == 'install' else None
                event_action = ('control_' if claim['kind'] == 'control' else '') + (
                    'write' if step == 'install' else 'delete' if p in self.files else 'delete_absent')
                eid = identifier('wheelsuture/event/1', [oid, ordinal, p, event_action, before, after])
                self.events.append(dict(event_id=eid, operation_id=oid, ordinal=ordinal, action=event_action,
                    path_id=claim['path_id'], destination=p, wheel_id=wid, claim_id=claim['claim_id'],
                    before=before, after=after, prior_event_id=self.previous.get(p)))
                if step == 'install':
                    self.files[p] = dict(path_id=claim['path_id'], destination=p, signature=after, last_event_id=eid)
                    self.deleted.pop(p, None)
                elif p in self.files:
                    del self.files[p]
                    self.deleted[p] = eid
                self.previous[p] = eid
                self.peak_slots = max(self.peak_slots, len(self.files))
                ordinal += 1
        findings = []
        for name, wid in self.active.items():
            findings.extend(self.damage(wid, phase, oid, name in old_names))
        self.findings.extend(self.sorted_findings(findings))

    def finish(self, phase='final'):
        desired = {self.wheels[w]['canonical_name']: w for w in self.data['desired']}
        findings = []
        for name in set(desired) | set(self.active):
            actual, expected = self.active.get(name), desired.get(name)
            if actual != expected:
                kind = 'identity_missing' if actual is None else 'identity_extra' if expected is None else 'identity_mismatch'
                findings.append(self.finding(phase, None, kind, False,
                    [x for x in (actual, expected) if x is not None], []))
        for wid in self.data['desired']:
            findings.extend(self.damage(wid, phase, None, False))
        self.findings.extend(self.sorted_findings(findings))
        return 'broken' if findings else 'preserved'

    def state(self):
        state = dict(identities=[dict(canonical_name=name, wheel_id=wid,
                   sha256=self.wheels[wid]['source_sha256']) for name, wid in sorted(self.active.items())],
                   slots=[self.files[p] for p in sorted(self.files, key=lambda p: p.encode('utf8'))])
        return dict(state, state_sha256=identifier('wheelsuture/state/1', state))


class StateExhaustiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_plan(self, inventories, initial=(), transition=(), desired=(), limits=Limits()):
        data = dict(schema_version=1, profile=PROFILE_ID,
                    wheels=[dict(id=w, path=w+'.whl', sha256=i.source_sha256) for w, i in inventories.items()],
                    initial=list(initial), transition=list(transition), desired=list(desired))
        p = self.root / 'plan.json'
        p.write_bytes(wire(data))
        return load_plan(p, limits=limits)

    def compare(self, inventories, initial=(), transition=(), desired=()):
        plan = self.make_plan(inventories, initial, transition, desired)
        result = simulate(plan, inventories, budget=Budget()).to_dict()
        reference = Reference(plan.to_dict(), {w: i.to_dict() for w, i in inventories.items()})
        for phase in ('initial', 'transition'):
            for index, action in enumerate(plan.to_dict()[phase]):
                reference.apply(action, phase, index)
        expected_status = reference.finish()
        self.assertEqual(result['status'], expected_status)
        self.assertEqual(result['operations'], reference.operations)
        self.assertEqual(result['events'], reference.events)
        self.assertEqual(result['findings'], reference.findings)
        self.assertEqual(result['final_state'], reference.state())
        for key, expected in [('expanded_events', len(reference.events)), ('findings', len(reference.findings)),
                              ('state_slots', reference.peak_slots), ('user_operations', len(reference.operations))]:
            self.assertEqual(result['resource_usage'][key], expected, key)
        self.assertEqual(result['resource_usage']['report_bytes'], len(wire(result))+1)
        detached = dict(result)
        evidence = detached.pop('evidence_sha256')
        self.assertEqual(evidence, identifier('wheelsuture/report/1', detached))
        return plan, result, reference

    def test_exhaustive_zero_to_three_names_all_legal_short_histories(self):
        count = 0
        for n, destinations in [(0, 2), (1, 2), (2, 2), (3, 1)]:
            names = tuple('abc'[:n])
            all_histories = list(histories(names, 3))
            for cells in product((None, b'0', b'1'), repeat=n*destinations):
                inventories = {}
                for j, name in enumerate(names):
                    paths = {'slot'+str(k): byte_signature(cells[j*destinations+k])
                             for k in range(destinations) if cells[j*destinations+k] is not None}
                    inventories[name] = synthetic(name, name, paths)
                for actions in all_histories:
                    for mask in range(1 << n):
                        desired = [w for j, w in enumerate(names) if mask & (1 << j)]
                        with self.subTest(n=n, cells=cells, actions=actions, desired=desired):
                            self.compare(inventories, transition=actions, desired=desired)
                        count += 1
        self.assertEqual(count, 23347)

    def test_held_out_histories_versions_three_destinations_and_controls(self):
        # Fixed seeds never used to choose or tune production reducer behavior.
        for seed in range(104729, 104793):
            rng = random.Random(seed)
            names = ('alpha', 'beta', 'gamma')
            inventories = {}
            paths = ('lib/python3.12/site-packages/shared', 'bin/cli', 'data/é')
            for name in names:
                for version in ('1', '2'):
                    wid = name + version
                    members = {p: byte_signature(bytes([rng.randrange(2)])) for p in paths if rng.randrange(3)}
                    inventories[wid] = synthetic(wid, name, members, controls=True, version=version)
            active, actions = {}, []
            for index in range(20):
                name = rng.choice(names)
                if name not in active:
                    wid = name + rng.choice(('1', '2'))
                    action = operation('install', wid, index)
                    active[name] = wid
                else:
                    wid = active[name]
                    verb = rng.choice(('remove', 'reinstall', 'replace'))
                    if verb == 'replace':
                        other = name + ('2' if wid.endswith('1') else '1')
                        action = dict(id='op'+str(index), op=verb, **{'from':wid, 'to':other})
                        active[name] = other
                    else:
                        action = operation(verb, wid, index)
                        if verb == 'remove': del active[name]
                actions.append(action)
            desired = [name + rng.choice(('1', '2')) for name in names if rng.randrange(2)]
            with self.subTest(seed=seed):
                self.compare(inventories, transition=actions, desired=desired)

    def test_initial_damage_reinstall_boundary_and_immutable_ownership(self):
        inventories = {'a': synthetic('a', 'alpha', {'x':byte_signature(b'A')}),
                       'b': synthetic('b', 'beta', {'x':byte_signature(b'B')})}
        originals = {w:i.canonical for w,i in inventories.items()}
        plan, result, _ = self.compare(inventories, [operation('install','a',0),operation('install','b',1)],
            [operation('reinstall','a',2),operation('remove','b',3),operation('reinstall','a',4)], ['a'])
        self.assertEqual(result['status'], 'preserved')
        self.assertEqual(result['findings'][0]['phase'], 'initial')
        self.assertEqual(result['findings'][0]['expected'], byte_signature(b'A'))
        self.assertEqual([f['phase'] for f in result['findings']], ['initial','transition','transition'])
        self.assertEqual({w:i.canonical for w,i in inventories.items()}, originals)
        changed = inventories['a'].to_dict(); changed['claims'].clear()
        self.assertTrue(inventories['a'].to_dict()['claims'])
        p = plan.to_dict(); p['desired'].clear()
        self.assertEqual(plan.to_dict()['desired'], ['a'])

    def test_repeated_absent_deletes_keep_original_cause_until_rewrite(self):
        inventories = {w:synthetic(w,w,{'x':byte_signature(b'A')}) for w in 'abcd'}
        initial = [operation('install',w,i) for i,w in enumerate('abcd')]
        actions = [operation('remove','b',4),operation('remove','c',5),operation('remove','d',6)]
        _, report, _ = self.compare(inventories,initial,actions,['a'])
        by_id = {e['event_id']:e for e in report['events']}
        final = [f for f in report['findings'] if f['phase']=='final'][0]
        self.assertEqual(by_id[final['cause_event_id']]['wheel_id'],'b')
        self.assertEqual(by_id[report['events'][-1]['prior_event_id']]['wheel_id'],'c')
        _, repaired, _ = self.compare(inventories,initial,actions+[operation('reinstall','a',7)],['a'])
        self.assertEqual(repaired['status'],'preserved')
        self.assertTrue(all(f['phase']!='final' for f in repaired['findings']))

    def test_unicode_paths_use_exact_codepoint_identity(self):
        inventories = {'a':synthetic('a','alpha',{'é':byte_signature(b'A'),'e\u0301':byte_signature(b'B')})}
        _, report, _ = self.compare(inventories,[operation('install','a')],desired=['a'])
        self.assertEqual(len(report['final_state']['slots']),2)

    def test_same_version_different_digest_requires_exact_identity(self):
        inventories = {'a':synthetic('a','alpha',{'old':byte_signature(b'A')}),
                       'b':synthetic('b','alpha',{'new':byte_signature(b'B')})}
        _, report, _ = self.compare(inventories,[operation('install','a')],desired=['b'])
        self.assertIn('identity_mismatch',[f['kind'] for f in report['findings']])
        _, replaced, _ = self.compare(inventories,[operation('install','a')],
            [dict(id='swap',op='replace',**{'from':'a','to':'b'})],['b'])
        self.assertEqual(replaced['status'],'preserved')
        self.assertEqual([e['action'] for e in replaced['events']],['write','delete','write'])

    def test_global_prefix_in_unused_and_historical_artifacts_is_unsupported(self):
        inventories = {'a':synthetic('a','alpha',{'x':byte_signature(b'A')}),
                       'b':synthetic('b','beta',{'x/y':byte_signature(b'A')})}
        for initial, actions in [((),()),([operation('install','a')],[operation('remove','a',1),operation('install','b',2)])]:
            with self.subTest(initial=initial),self.assertRaises(UnsupportedInput) as error:
                simulate(self.make_plan(inventories,initial,actions),inventories,budget=Budget())
            self.assertEqual(error.exception.code,'historical_prefix')

    def test_equal_providers_share_but_unequal_or_cross_kind_remain_unknown(self):
        provider = dict(kind='entry_point',name='tool',group='console_scripts',module='mod',attribute='main',profile=PROFILE_ID)
        invs = {w:synthetic(w,w,{'bin/tool':provider}) for w in 'ab'}
        self.compare(invs,[operation('install','a'),operation('install','b',1)],desired=['a','b'])
        for other in [dict(provider,module='different'),dict(provider,group='gui_scripts'),byte_signature(b'wrapper')]:
            invs['b'] = synthetic('b','b',{'bin/tool':other})
            with self.subTest(other=other),self.assertRaises(UnsupportedInput) as error:
                simulate(self.make_plan(invs),invs,budget=Budget())
            self.assertEqual(error.exception.code,'unsupported_overlap')

    def test_invalid_active_state_operations_fail_closed(self):
        invs = {'a':synthetic('a','alpha',{}),'a2':synthetic('a2','alpha',{}),'b':synthetic('b','beta',{})}
        cases = [([], [operation('remove','a')]),([], [operation('reinstall','a')]),
                 ([operation('install','a')],[operation('install','a2',1)]),
                 ([operation('install','a')],[operation('remove','a2',1)]),
                 ([operation('install','a')],[operation('reinstall','a2',1)]),
                 ([operation('install','a')],[dict(id='swap',op='replace',**{'from':'a','to':'b'})]),
                 ([operation('install','a')],[dict(id='swap',op='replace',**{'from':'a','to':'a'})])]
        for initial, actions in cases:
            with self.subTest(actions=actions),self.assertRaises(InvalidInput):
                simulate(self.make_plan(invs,initial,actions),invs,budget=Budget())

    def test_resource_counters_aggregate_owner_claims_and_peak_actual_slots(self):
        invs={w:synthetic(w,w,{'x':byte_signature(b'0'),'y':byte_signature(b'12')}) for w in 'ab'}
        p,r,_=self.compare(invs,[operation('install','a'),operation('install','b',1)],
            [operation('remove','b',2)],['a'])
        for key,expected in [('wheels',2),('mapped_claims',4),('deletion_paths',4),('state_slots',2),('member_bytes',2),('expanded_events',6)]:
            self.assertEqual(r['resource_usage'][key],expected,key)
        for key,value in [('mapped_claims',3),('deletion_paths',3),('state_slots',1),('expanded_events',5),('findings',3),('user_operations',2)]:
            with self.subTest(key=key),self.assertRaises(LimitExceeded):
                simulate(p,invs,budget=Budget(Limits(**{key:value})))

    def test_resource_limit_precedes_event_or_finding_append(self):
        invs={'a':synthetic('a','a',{'x':byte_signature(b'A')})}
        p=self.make_plan(invs,transition=[operation('install','a')],desired=['a'])
        replay=Replay(p,invs,Budget(Limits(expanded_events=0)))
        with self.assertRaises(LimitExceeded):replay.apply(operation('install','a'),'transition',0)
        self.assertEqual(replay.events,[])
        self.assertEqual(replay.slots,{})
        self.assertEqual(replay.budget.usage['expanded_events'],0)
        q=self.make_plan(invs,desired=['a'])
        replay=Replay(q,invs,Budget(Limits(findings=0)))
        with self.assertRaises(LimitExceeded):replay.desired_findings()
        self.assertEqual(replay.findings,[])
        self.assertEqual(replay.budget.usage['findings'],0)

    def test_exhaustive_repair_unit_all_compatible_and_conflicting_desired_subsets(self):
        count=0
        # Only the certificate gate is bypassed. Every emitted action/event/state
        # is independently replayed here, from the actual original final state.
        with patch('wheelsuture.repair._independent_check'):
            for n, destinations in [(0,2),(1,2),(2,2),(3,1)]:
                names=tuple('abc'[:n])
                for cells in product((None,b'0',b'1'),repeat=n*destinations):
                    invs={}
                    for j,name in enumerate(names):
                        paths={'slot'+str(k):byte_signature(cells[j*destinations+k])
                               for k in range(destinations) if cells[j*destinations+k] is not None}
                        invs[name]=synthetic(name,name,paths)
                    initial=[operation('install',w,j) for j,w in enumerate(names)]
                    for active_mask in range(1 << n):
                        actions=[operation('remove',w,n+j) for j,w in enumerate(names) if not active_mask & (1 << j)]
                        for desired_mask in range(1 << n):
                            desired=[w for j,w in enumerate(names) if desired_mask & (1 << j)]
                            p=self.make_plan(invs,initial,actions,desired)
                            report=simulate(p,invs,budget=Budget())
                            proposal=propose_repair(p,report,invs,budget=Budget()).to_dict()
                            conflict=any(len({wire(invs[w].to_dict()['claims'][j]['signature'])
                                for w in desired for j in range(len(invs[w].to_dict()['claims']))
                                if invs[w].to_dict()['claims'][j]['destination']==path})>1
                                for path in ('slot'+str(k) for k in range(destinations)))
                            with self.subTest(n=n,cells=cells,active=active_mask,desired=desired_mask):
                                if conflict:
                                    self.assertEqual(proposal['status'],'conflict')
                                    self.assertIsNone(proposal['verification'])
                                    self.assertEqual(proposal['actions'],[])
                                else:
                                    reference=Reference(p.to_dict(),{w:i.to_dict() for w,i in invs.items()})
                                    for phase in ('initial','transition'):
                                        for j,action in enumerate(p.to_dict()[phase]):reference.apply(action,phase,j)
                                    original_status=reference.finish()
                                    expected=[] if original_status=='preserved' else ([('remove',w) for _,w in sorted(reference.active.items())]+[('install',w) for w in desired])
                                    self.assertEqual([(a['op'],a['wheel']) for a in proposal['actions']],expected)
                                    self.assertEqual(proposal['status'],'already_satisfied' if original_status=='preserved' else 'verified')
                                    start_events=len(reference.events);start_findings=len(reference.findings)
                                    for j,action in enumerate(proposal['actions']):reference.apply(action,'repair',j)
                                    self.assertEqual(reference.finish('repair'),'preserved')
                                    verification=proposal['verification']
                                    self.assertEqual(verification['events'],reference.events[start_events:])
                                    self.assertEqual(verification['findings'],reference.findings[start_findings:])
                                    self.assertEqual(verification['final_state'],reference.state())
                            count+=1
        self.assertEqual(count,3061)

    def test_repair_unit_two_phase_from_original_state_and_all_desired_claims(self):
        # alpha-old owns x and y; removing it after installing bravo(y) would break bravo.
        invs={'old':synthetic('old','alpha',{'x':byte_signature(b'old'),'y':byte_signature(b'y')}),
              'new':synthetic('new','alpha',{'x':byte_signature(b'new')}),
              'b':synthetic('b','bravo',{'y':byte_signature(b'y')}),
              'z':synthetic('z','zulu',{'z':byte_signature(b'z')})}
        p=self.make_plan(invs,[operation('install','old'),operation('install','b',1),operation('install','z',2)],desired=['b','new'])
        report=simulate(p,invs,budget=Budget());untouched=report.canonical
        with patch('wheelsuture.repair._independent_check'):
            proposal=propose_repair(p,report,invs,budget=Budget()).to_dict()
        expected=[('remove','old'),('remove','b'),('remove','z'),('install','new'),('install','b')]
        self.assertEqual([(a['op'],a['wheel']) for a in proposal['actions']],expected)
        self.assertEqual(report.canonical,untouched)
        reference=Reference(p.to_dict(),{w:i.to_dict() for w,i in invs.items()})
        for index,action in enumerate(p.to_dict()['initial']):reference.apply(action,'initial',index)
        reference.finish();event_start=len(reference.events);finding_start=len(reference.findings)
        for index,action in enumerate(proposal['actions']):reference.apply(action,'repair',index)
        self.assertEqual(reference.finish('repair'),'preserved')
        verification=proposal['verification']
        self.assertEqual(verification['events'],reference.events[event_start:])
        self.assertEqual(verification['findings'],reference.findings[finding_start:])
        self.assertEqual(verification['final_state'],reference.state())
        self.assertTrue(any(e['before'] is not None for e in verification['events'][:2]))
        self.assertTrue(any(f['boundary_operation_id'] for f in verification['findings']))
        self.assertFalse(any(f['boundary_operation_id'] is None for f in verification['findings']))
        self.assertEqual(verification['resource_usage']['expanded_events'],len(reference.events))
        self.assertEqual(verification['resource_usage']['user_operations'],len(reference.operations))
        self.assertEqual(verification['resource_usage']['report_bytes'],len(wire(proposal))+1)

    def test_repair_unit_conflicts_include_currently_intact_desired_owner(self):
        for kind in ('bytes','rewritten_script'):
            def signature(value):
                return byte_signature(value) if kind=='bytes' else dict(kind=kind,tail_sha256=hashlib.sha256(value).hexdigest(),tail_size=len(value),interpreter_token='profile-interpreter',profile=PROFILE_ID)
            invs={w:synthetic(w,w,{'bin/x':signature(w.encode())}) for w in 'ab'}
            p=self.make_plan(invs,[operation('install','a')],desired=['a','b'])
            report=simulate(p,invs,budget=Budget())
            with patch('wheelsuture.repair._independent_check'):
                proposal=propose_repair(p,report,invs,budget=Budget()).to_dict()
            self.assertEqual(proposal['status'],'conflict')
            self.assertEqual(proposal['actions'],[])
            self.assertEqual(proposal['witnesses'][0]['kind'],'different_bytes' if kind=='bytes' else 'different_rewritten_tail')
            self.assertEqual(set(proposal['witnesses'][0]['claim_ids']),{i.to_dict()['claims'][0]['claim_id'] for i in invs.values()})

    def test_repair_unit_limits_count_original_plus_repair_operations(self):
        invs={'a':synthetic('a','alpha',{'x':byte_signature(b'A')})}
        limits=Limits(user_operations=1)
        p=self.make_plan(invs,[operation('install','a')],desired=[],limits=limits)
        report=simulate(p,invs,budget=Budget(limits))
        with patch('wheelsuture.repair._independent_check'):
            proposal=propose_repair(p,report,invs,budget=Budget(limits)).to_dict()
        self.assertEqual(proposal['status'],'unknown')
        self.assertEqual(proposal['actions'],[])
        self.assertIsNone(proposal['verification'])
        self.assertEqual(proposal['diagnostics'][0]['code'],'resource_limit')

    def test_manual_plan_cannot_bypass_supported_profile(self):
        data=dict(schema_version=1,profile='future-profile',wheels=[],initial=[],transition=[],desired=[])
        with self.assertRaises((InvalidInput,UnsupportedInput)):
            public_simulate(Plan(self.root/'missing.json',wire(data)),{},budget=Budget())

    def test_manual_plan_cannot_bypass_closed_shape(self):
        data=dict(schema_version=1,profile=PROFILE_ID,wheels=[],initial=[],transition=[],desired=[],extra=True)
        with self.assertRaises(InvalidInput):
            public_simulate(Plan(self.root/'missing.json',wire(data)),{},budget=Budget())

    def test_replaced_real_inventory_cannot_retain_validation_for_forged_claims(self):
        path,sha=write_wheel(self.root,wheel_bytes({'shared.py':b'benign fixture'}))
        inv=inventory_wheel(WheelSource('a',path.name,sha,self.root),Profile(PROFILE_ID),Budget())
        changed=inv.to_dict();changed['claims']=[];changed['deletion_paths']=[]
        forged=replace(inv,canonical=wire(changed))
        p=self.make_plan({'a':inv},[operation('install','a')],desired=['a'])
        with self.assertRaises(InvalidInput):
            public_simulate(p,{'a':forged},budget=Budget())

    def test_replaced_real_inventory_cannot_erase_resource_usage(self):
        path,sha=write_wheel(self.root)
        inv=inventory_wheel(WheelSource('a',path.name,sha,self.root),Profile(PROFILE_ID),Budget())
        usage=inv.resource_usage;usage['decoded_bytes']=0;usage['entries']=0;usage['archive_bytes']=0
        forged=replace(inv,usage_canonical=wire(usage))
        p=self.make_plan({'a':inv},[operation('install','a')],desired=['a'])
        with self.assertRaises(InvalidInput):
            public_simulate(p,{'a':forged},budget=Budget())

    def test_plan_replacements_cannot_keep_validation_of_changed_inputs(self):
        trusted=self.make_plan({})
        mutations=[dict(path=self.root/'elsewhere.json'), dict(plan_bytes=0), dict(json_depth=0),
                   dict(source_file_sha256='0'*64), dict(limits=Limits(user_operations=1))]
        for mutation in mutations:
            with self.subTest(mutation=mutation),self.assertRaises(InvalidInput):
                public_simulate(replace(trusted,**mutation),{},budget=Budget())

    def test_inventory_replacements_cannot_rebind_source_profile_or_limits(self):
        path,sha=write_wheel(self.root)
        trusted=inventory_wheel(WheelSource('a',path.name,sha,self.root),Profile(PROFILE_ID),Budget())
        p=self.make_plan({'a':trusted},[operation('install','a')],desired=['a'])
        for mutation in [dict(source_sha256='0'*64),dict(profile_id='future-profile'),dict(limits=Limits(entries=100))]:
            with self.subTest(mutation=mutation),self.assertRaises(InvalidInput):
                public_simulate(p,{'a':replace(trusted,**mutation)},budget=Budget())

    def test_forged_analysis_cannot_authorize_repair(self):
        from wheelsuture.model import AnalysisReport
        invs={'a':synthetic('a','alpha',{'x':byte_signature(b'A')})}
        p=self.make_plan(invs,[operation('install','a')],desired=['a'])
        report=simulate(p,invs,budget=Budget())
        for field,value in [('status','broken'),('events',[]),('findings',[{}]),('desired',[])]:
            changed=report.to_dict();changed[field]=value
            with self.subTest(field=field),self.assertRaises(VerificationError):
                propose_repair(p,AnalysisReport(wire(changed)),invs,budget=Budget())

    def real_plan_and_inventory(self):
        path,sha=write_wheel(self.root)
        data=dict(schema_version=1,profile=PROFILE_ID,wheels=[dict(id='a',path=path.name,sha256=sha)],
                  initial=[operation('install','a')],transition=[],desired=['a'])
        pp=self.root/'real-plan.json';pp.write_bytes(wire(data));plan=load_plan(pp)
        inventory=inventory_wheel(plan.sources[0],Profile(PROFILE_ID),Budget())
        return plan,{'a':inventory},path

    def test_public_simulate_rejects_wheel_changed_after_inventory(self):
        from wheelsuture.errors import InputChanged
        plan,inventories,wheel_path=self.real_plan_and_inventory()
        wheel_path.write_bytes(b'changed after inventory')
        with self.assertRaises(InputChanged):
            public_simulate(plan,inventories,budget=Budget())

    def test_public_simulate_rejects_plan_changed_after_loading(self):
        from wheelsuture.errors import InputChanged
        plan,inventories,_=self.real_plan_and_inventory()
        plan.path.write_bytes(b'{}')
        with self.assertRaises(InputChanged):
            public_simulate(plan,inventories,budget=Budget())

    def test_public_repair_from_real_wheels_passes_unmocked_verification(self):
        from wheelsuture.api import create_repair
        from wheelsuture.verify import verify_report
        cases=[('z','zulu','1.0',{'z.py':b'z'}),
               ('b','bravo','1.0',{'y.py':b'y'}),
               ('old','alpha','1.0',{'x.py':b'old','y.py':b'y'}),
               ('new','alpha','2.0',{'x.py':b'new'})]
        sources=[]
        for wid,name,version,payload in cases:
            directory=self.root/wid;directory.mkdir()
            path,sha=write_wheel(directory,wheel_bytes(payload,name=name,version=version),name+'-'+version+'-py3-none-any.whl')
            sources.append(dict(id=wid,path=wid+'/'+path.name,sha256=sha))
        data=dict(schema_version=1,profile=PROFILE_ID,wheels=sources,
                  initial=[operation('install','old'),operation('install','b',1),operation('install','z',2)],
                  transition=[],desired=['b','new'])
        path=self.root/'public-repair.json';path.write_bytes(wire(data))
        before={s['path']:(self.root/s['path']).read_bytes() for s in sources}
        report,proposal=create_repair(path)
        r,d=report.to_dict(),proposal.to_dict()
        self.assertEqual(d['status'],'verified')
        self.assertEqual([(a['op'],a['wheel']) for a in d['actions']],
                         [('remove','old'),('remove','b'),('remove','z'),('install','new'),('install','b')])
        reference=Reference(data,{w['wheel_id']:w for w in r['wheels']})
        for j,action in enumerate(data['initial']):reference.apply(action,'initial',j)
        self.assertEqual(reference.finish(),'broken')
        self.assertEqual(r['events'],reference.events)
        self.assertEqual(r['findings'],reference.findings)
        begin_events=len(reference.events);begin_findings=len(reference.findings)
        for j,action in enumerate(d['actions']):reference.apply(action,'repair',j)
        self.assertEqual(reference.finish('repair'),'preserved')
        self.assertEqual(d['verification']['events'],reference.events[begin_events:])
        self.assertEqual(d['verification']['findings'],reference.findings[begin_findings:])
        self.assertEqual(d['verification']['final_state'],reference.state())
        report_path=self.root/'report.json';repair_path=self.root/'repair.json'
        report_path.write_bytes(report.canonical+b'\n');repair_path.write_bytes(proposal.canonical+b'\n')
        verdict=verify_report(path,report_path,repair_path=repair_path)
        self.assertTrue(verdict.valid)
        self.assertTrue(verdict.complete)
        self.assertEqual({s['path']:(self.root/s['path']).read_bytes() for s in sources},before)


if __name__=='__main__':
    unittest.main()
