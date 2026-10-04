"""Independent filesystem oracle. No imports from wheelsuture or wheel payloads."""
from __future__ import annotations
import ast, hashlib, json, os, re
from pathlib import Path
PROFILE='pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1'
SITE='lib/python3.12/site-packages'
CONTROLS={'RECORD','INSTALLER','REQUESTED','direct_url.json'}

def sha(data): return hashlib.sha256(data).hexdigest()
def observed_signature(data,template):
    kind=template['kind']
    if kind=='bytes': return {'kind':'bytes','sha256':sha(data),'size':len(data)}
    if kind=='rewritten_script':
        tail=data.partition(b'\n')[2]
        return {'kind':kind,'tail_sha256':sha(tail),'tail_size':len(tail),'interpreter_token':'profile-interpreter','profile':PROFILE}
    raise ValueError(kind)

def provider_present(data,sig):
    """Check syntax/import/call structure without importing or executing script."""
    try: tree=ast.parse(data.decode('utf-8'))
    except (SyntaxError,UnicodeError): return False
    attrs=sig['attribute'].split('.')
    imported=any(isinstance(n,ast.ImportFrom) and n.module==sig['module'] and any(a.name==attrs[0] and a.asname is None for a in n.names) for n in ast.walk(tree))
    def dotted(n):
        if isinstance(n,ast.Name): return n.id
        if isinstance(n,ast.Attribute): return dotted(n.value)+'.'+n.attr
        return ''
    called=any(isinstance(n,ast.Call) and dotted(n.func)==sig['attribute'] for n in ast.walk(tree))
    return imported and called

def snapshot(root,excluded):
    """Observe all ordinary files below one disposable prefix, except scaffold."""
    values={}
    for dirname,dirs,files in os.walk(root,followlinks=False):
        for directory in dirs:
            p=Path(dirname)/directory
            if p.is_symlink() and p.relative_to(root).as_posix() not in excluded:
                raise AssertionError('Unexpected payload directory symlink: '+p.relative_to(root).as_posix())
        dirs[:]=sorted(d for d in dirs if not (Path(dirname)/d).is_symlink())
        for name in sorted(files):
            p=Path(dirname)/name; rel=p.relative_to(root).as_posix()
            if rel in excluded: continue
            if p.is_symlink(): raise AssertionError('Unexpected payload symlink: '+rel)
            data=p.read_bytes()
            values[rel]={'sha256':sha(data),'size':len(data)}
    return values

def identities(root,fixtures):
    by_info={}
    for f in fixtures: by_info.setdefault(f['dist_info'],[]).append(f)
    found=[]
    site=root/SITE
    if not site.exists(): return []
    for p in sorted(site.glob('*.dist-info')):
        if p.name not in by_info: raise AssertionError('Unexpected distribution: '+p.name)
        candidates=by_info[p.name]
        direct=p/'direct_url.json'
        if direct.exists():
            provenance=json.loads(direct.read_text())['archive_info']
            digest=provenance.get('hashes',{}).get('sha256') or provenance.get('hash','').removeprefix('sha256=')
            candidates=[f for f in candidates if f['sha256']==digest]
        assert len(candidates)==1, ('Ambiguous physical artifact',p.name)
        f=candidates[0]
        metadata=(p/'METADATA').read_text()
        assert re.search(r'^Name: '+re.escape(f['name'])+r'$',metadata,re.M)
        assert re.search(r'^Version: '+re.escape(f['version'])+r'$',metadata,re.M)
        found.append({'canonical_name':f['canonical_name'],'wheel_id':f['id'],'sha256':f['sha256']})
    return sorted(found,key=lambda f:f['canonical_name'])

def signature_matches(root,destination,signature):
    p=root/destination
    if not p.is_file(): return False
    data=p.read_bytes()
    if signature['kind']=='entry_point': return provider_present(data,signature)
    if signature['kind']=='rewritten_script' and data.partition(b'\n')[0] != b'#!'+str(root/'bin/python').encode(): return False
    if signature['kind']=='control': return True
    return observed_signature(data,signature)==signature

def check_claim_inventory(report,fixtures):
    """Compare product mappings with fixture-declared destinations and digests."""
    expected={f['id']:f for f in fixtures}
    checks=0
    for wheel in report['wheels']:
        wid=wheel['id'] if 'id' in wheel else wheel['wheel_id']
        f=expected[wid]
        actual={(c['member'],c['destination'],json.dumps(c['signature'],sort_keys=True)) for c in wheel['claims'] if c['checked']}
        want={(c['member'],c['destination'],json.dumps(c['signature'],sort_keys=True)) for c in f['claims']}
        assert actual==want, {'wheel':wid,'missing':sorted(want-actual),'extra':sorted(actual-want)}
        checks+=len(want)
    return checks

def compare_state(root,state,fixtures,scaffold):
    actual=snapshot(root,scaffold)
    slots={s['destination']:s for s in state['slots']}
    assert set(actual)==set(slots), {'missing_physical':sorted(set(slots)-set(actual)), 'unmodeled_physical':sorted(set(actual)-set(slots))}
    for dest,slot in slots.items():
        assert signature_matches(root,dest,slot['signature']), {'destination':dest,'expected':slot['signature'],'observed':actual.get(dest)}
    external=identities(root,fixtures)
    got=sorted((i['canonical_name'],i['wheel_id'],i['sha256']) for i in state['identities'])
    want=sorted((i['canonical_name'],i['wheel_id'],i['sha256']) for i in external)
    assert got==want, {'model_identities':got,'physical_identities':want}
    return {'files':actual,'identities':external,'compared_slots':len(slots)}

def desired_integrity(root,desired,fixtures):
    by_id={f['id']:f for f in fixtures}
    defects=[]
    for wid in desired:
        for claim in by_id[wid]['claims']:
            if not signature_matches(root,claim['destination'],claim['signature']):
                defects.append({'wheel_id':wid,'destination':claim['destination'],'expected':claim['signature']})
    physical={i['wheel_id'] for i in identities(root,fixtures)}
    return {'preserved':not defects and physical==set(desired),'defects':defects,'physical_wheel_ids':sorted(physical),'desired_wheel_ids':sorted(desired)}


def compare_findings(root,report,integrity):
    """Every final missing/displaced claim must match an external observed defect."""
    expected={(d['wheel_id'],d['destination'],json.dumps(d['expected'],sort_keys=True), 'displaced' if (root/d['destination']).is_file() else 'missing') for d in integrity['defects']}
    actual=set()
    for finding in report['findings']:
        if finding['phase']=='final' and finding['kind'] in ('missing','displaced'):
            for wid in finding['wheel_ids']:
                actual.add((wid,finding['destination'],json.dumps(finding['expected'],sort_keys=True),finding['kind']))
    assert expected==actual, {'missing_findings':sorted(expected-actual),'spurious_findings':sorted(actual-expected)}
    return len(expected)
