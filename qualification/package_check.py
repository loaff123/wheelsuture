#!/usr/bin/env python3
"""Reproduce installed-artifact checks without installing or running fixture payloads.

Only this project's candidate and the pinned official packaging wheel enter the
throwaway runtime venvs. The outer controller invokes official pip/build tools;
the runtime audit forbids network, subprocesses, and fixture imports/execution.
All environments and unpacked sources are temporary and are removed on exit.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def members(path):
    if path.suffix == '.whl':
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            assert len(names) == len(set(names)), 'duplicate wheel members'
            return {name: archive.read(name) for name in names if not name.endswith('/')}
    with tarfile.open(path) as archive:
        items = archive.getmembers()
        assert all(item.isfile() or item.isdir() for item in items), 'nonregular sdist members'
        return {'/'.join(item.name.split('/')[1:]): archive.extractfile(item).read()
                for item in items if item.isfile()}


def archive_contract(path, source):
    entries = members(path)
    is_wheel = path.suffix == '.whl'
    prefix = 'wheelsuture/' if is_wheel else 'src/wheelsuture/'
    for name, content in entries.items():
        parts = PurePosixPath(name).parts
        assert not PurePosixPath(name).is_absolute() and '..' not in parts, name
        assert not set(parts) & {'__pycache__', '.venv', '.git', '.aws', '.codex'}, name
        assert not name.endswith(('.pyc', '.pyo', '.pem', '.key')), name
        assert not any(fragment in name for fragment in (
            'docs/superpowers/', 'docs/IMPLEMENTATION_LOG.md',
            'qualification/evidence/', 'qualification/package-tooling/',
            'qualification/tooling/', 'qualification/tools/', 'build/', 'dist/')), name
        assert not any(line.startswith(b'-----BEGIN PRIVATE KEY-----') for line in content.splitlines()), name
        assert not any(line.startswith(b'-----BEGIN OPENSSH PRIVATE KEY-----') for line in content.splitlines()), name
        if name.endswith('.whl'):
            assert name.startswith((prefix + 'examples/wheels/', 'examples/wheels/')), name
    assert len([n for n in entries if n.startswith(prefix + 'schemas/') and n.endswith('.json')]) == 6
    assert len([n for n in entries if n.startswith(prefix + 'examples/') and len(PurePosixPath(n[len(prefix):]).parts) == 2 and n.endswith('.json')]) == 17
    assert len([n for n in entries if n.startswith(prefix + 'examples/wheels/') and n.endswith('.whl')]) == 16
    expected = {str(p.relative_to(source / 'src')).replace(os.sep, '/'): p.read_bytes()
                for p in (source / 'src/wheelsuture').rglob('*')
                if p.is_file() and p.suffix in {'.py', '.json', '.whl'}}
    actual = {(name if is_wheel else name.removeprefix('src/')): data
              for name, data in entries.items() if name.startswith(prefix)}
    assert actual == expected, 'artifact runtime bytes differ from source snapshot'
    notices = ['LICENSE', 'THIRD_PARTY.md', 'licenses/packaging-LICENSE',
               'licenses/packaging-LICENSE.APACHE', 'licenses/packaging-LICENSE.BSD']
    for notice in notices:
        matches = [n for n in entries if n.endswith('.dist-info/licenses/' + notice)] if is_wheel else [notice]
        assert len(matches) == 1 and matches[0] in entries, 'missing notice: ' + notice
        assert entries[matches[0]] == (source / notice).read_bytes(), notice
    if is_wheel:
        metadata = next(data.decode() for name, data in entries.items() if name.endswith('.dist-info/METADATA'))
        assert 'License-Expression: MIT\n' in metadata
        assert 'Requires-Dist: packaging<27,>=26.3\n' in metadata
        assert metadata.count('Requires-Dist: ') == 1
        record = next(data.decode() for name, data in entries.items() if name.endswith('.dist-info/RECORD'))
        rows = list(csv.reader(io.StringIO(record)))
        assert {row[0] for row in rows} == set(entries)
        for name, digest, size in rows:
            if name.endswith('.dist-info/RECORD'):
                assert digest == size == ''
            else:
                value = base64.urlsafe_b64encode(hashlib.sha256(entries[name]).digest()).rstrip(b'=').decode()
                assert digest == 'sha256=' + value and int(size) == len(entries[name]), name
    else:
        for item in (source / 'tests').rglob('*'):
            if item.is_file():
                name = str(item.relative_to(source)).replace(os.sep, '/')
                assert entries.get(name) == item.read_bytes(), 'missing or stale sdist test: ' + name
        for required in ['requirements-test.txt', 'qualification/package_check.py', 'qualification/package-toolchain-sha256.json']:
            assert required in entries, 'missing sdist reproduction file: ' + required
    return {'artifact_sha256': sha(path.read_bytes()), 'files': {
        name: {'bytes': len(data), 'sha256': sha(data)} for name, data in sorted(entries.items())}}


# Executed with an installed runtime interpreter, never from the project cwd.
RUNTIME_AUDIT = r'''
import hashlib, importlib.abc, importlib.metadata, json, locale, os, sys, tempfile, time, zipfile
from importlib.resources import files
from pathlib import Path
import wheelsuture
root = Path(str(files('wheelsuture')))
assert root.is_relative_to(Path(sys.prefix)), (root, sys.prefix)
assert not any('/src' == p[-4:] for p in sys.path)
assert sorted(d.metadata['Name'].lower() for d in importlib.metadata.distributions()) == ['packaging', 'wheelsuture']
assert importlib.metadata.version('packaging') == '26.3'
fixture_roots = set()
for path in (root/'examples/wheels').rglob('*.whl'):
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.endswith('.py') and '.data/' not in name:
                fixture_roots.add(name.split('/')[0].removesuffix('.py'))
class NoPayloadImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in fixture_roots:
            raise AssertionError('fixture payload import attempted: ' + fullname)
sys.meta_path.insert(0, NoPayloadImports())
blocked = []
def audit(event, args):
    bad = event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn', 'os.posix_spawn')) or event in {'os.system','os.fork','os.forkpty'}
    if event == 'exec' and args:
        bad = bad or '.whl/' in getattr(args[0], 'co_filename', '')
    if bad:
        blocked.append(event)
        raise AssertionError('runtime side effect attempted: ' + event)
sys.addaudithook(audit)
from wheelsuture import analyze, create_repair, inspect_wheel, load_plan, verify_report
from wheelsuture.report import json_bytes, render_html
from wheelsuture.model import Profile
output = Path(sys.argv[1]); output.mkdir()
results = []
for plan in sorted((root/'examples').glob('*.json')):
    report, repair = create_repair(plan)
    assert analyze(plan).to_dict() == report.to_dict()
    rpath=output/(plan.stem+'.report.json'); cpath=output/(plan.stem+'.repair.json')
    rpath.write_bytes(json_bytes(report)); cpath.write_bytes(json_bytes(repair))
    (output/(plan.stem+'.html')).write_bytes(render_html(report, json_name='report.json'))
    verified=verify_report(plan,rpath,repair_path=cpath)
    assert verified.valid and verified.complete, (plan.name,verified)
    tampered=report.to_dict(); tampered['status']='broken' if tampered['status']=='preserved' else 'preserved'
    bad=output/'tampered.json'; bad.write_bytes(json_bytes(tampered))
    assert verify_report(plan,bad).exit_code == 5
    bad.unlink()
    results.append({'plan':plan.name,'analysis_status':report.to_dict()['status'],'repair_status':repair.to_dict()['status']})
seen=set()
for plan in sorted((root/'examples').glob('*.json')):
    parsed=load_plan(plan)
    for source in parsed.sources:
        if source.path in seen: continue
        seen.add(source.path)
        result=inspect_wheel(source,Profile(parsed.to_dict()['profile']))
        (output/('inspect-'+source.id+'.json')).write_bytes(json_bytes(result))
assert len(results)==17 and len(seen)==16
assert not blocked
assert not fixture_roots & set(sys.modules)
print(json.dumps({'python':sys.version.split()[0],'runtime_settings':{'hash_seed':os.environ.get('PYTHONHASHSEED'),'locale':locale.setlocale(locale.LC_ALL,None),'timezone':time.tzname,'cwd':os.getcwd()},'package_location':str(root),'sys_path':sys.path,'installed':{'wheelsuture':importlib.metadata.version('wheelsuture'),'packaging':importlib.metadata.version('packaging')},'fixture_imports':[], 'forbidden_runtime_events':blocked,'cases':results,'inventories':len(seen)},sort_keys=True))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--dist', type=Path, default=ROOT / 'dist')
    parser.add_argument('--python313', type=Path, default=Path('/usr/bin/python3.13'))
    args = parser.parse_args()
    assert args.run_id and all(c.isalnum() or c in '-_' for c in args.run_id)
    evidence = ROOT / 'qualification/evidence' / args.run_id
    evidence.mkdir(parents=True, exist_ok=False)
    commands = []
    result = {'status': 'running', 'runtime_isolation': 'temporary venvs without pip; only WheelSuture and pinned packaging installed', 'fixture_execution': 'forbidden'}
    save(evidence / 'result.json', result)
    with tempfile.TemporaryDirectory(prefix='wheelsuture-package-') as temporary:
        work = Path(temporary)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(work / 'home'), 'LC_ALL': 'C.UTF-8',
               'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'PIP_CONFIG_FILE': '/dev/null',
               'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
        (work / 'home').mkdir()
        cwd = work / 'outside'; cwd.mkdir()
        def redact(text):
            return text.replace(str(work), '<TEMP>').replace(str(ROOT), '<PROJECT>').replace(sys.executable, '<CONTROLLER_PYTHON>')
        def run(label, argv, *, expected=(0,), directory=cwd, overrides=None):
            run_env = dict(env); run_env.update(overrides or {})
            completed = subprocess.run(list(map(str, argv)), cwd=directory, env=run_env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            (evidence / (label + '.stdout.txt')).write_text(redact(completed.stdout.decode('utf-8', 'replace')), encoding='utf-8')
            (evidence / (label + '.stderr.txt')).write_text(redact(completed.stderr.decode('utf-8', 'replace')), encoding='utf-8')
            commands.append({'label':label,'argv':[redact(str(a)) for a in argv], 'cwd':redact(str(directory)),
                             'environment':{k:redact(v) for k,v in run_env.items()},'exit_code':completed.returncode})
            save(evidence / 'commands.json', commands)
            assert completed.returncode in expected, (label, completed.returncode, completed.stderr.decode('utf-8','replace')[-4000:])
            return completed
        # Freeze the source/test inputs used to judge the released artifacts.
        snapshot = work / 'source'; snapshot.mkdir()
        for name in ('src', 'tests', 'licenses'):
            shutil.copytree(ROOT/name, snapshot/name, ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.egg-info'))
        for name in ('LICENSE','THIRD_PARTY.md','README.md','pyproject.toml','MANIFEST.in','requirements-test.txt'):
            shutil.copy2(ROOT/name,snapshot/name)
        (snapshot/'qualification').mkdir()
        for name in ('package_check.py','package-toolchain-sha256.json'):
            shutil.copy2(ROOT/'qualification'/name,snapshot/'qualification'/name)
        source_hashes = {str(p.relative_to(snapshot)):sha(p.read_bytes()) for p in snapshot.rglob('*') if p.is_file()}
        save(evidence / 'source-test-sha256.json', source_hashes)
        artifact_dir = evidence / 'artifacts'; artifact_dir.mkdir()
        direct = next(args.dist.glob('wheelsuture-*.whl')); sdist = next(args.dist.glob('wheelsuture-*.tar.gz'))
        for path in (direct, sdist):
            shutil.copy2(path,artifact_dir/path.name)
            save(evidence / (path.name + '.contents.json'),archive_contract(path,snapshot))
        direct, sdist = artifact_dir/direct.name, artifact_dir/sdist.name
        tooling=ROOT/'qualification/package-tooling'
        pins=json.loads((ROOT/'qualification/package-toolchain-sha256.json').read_bytes())
        assert pins and all(sha((tooling/name).read_bytes()) == digest for name,digest in pins.items())
        packaging=tooling/'packaging-26.3-py3-none-any.whl'
        with zipfile.ZipFile(packaging) as archive:
            for name in ('LICENSE','LICENSE.APACHE','LICENSE.BSD'):
                member=next(n for n in archive.namelist() if n.endswith('/licenses/'+name))
                assert archive.read(member)==(ROOT/'licenses'/('packaging-'+name)).read_bytes()
        save(evidence/'toolchain.json',{'official_download_sha256':pins,'controller_python':sys.version,'runtime_dependency':'packaging==26.3','build_isolation':'official pinned disposable build-env, no network'})
        # Extract only checked regular source distribution members.
        unpack=work/'unpack'; unpack.mkdir()
        with tarfile.open(sdist) as archive:
            for member in archive.getmembers():
                assert not member.name.startswith('/') and '..' not in PurePosixPath(member.name).parts
                assert member.isfile() or member.isdir()
            archive.extractall(unpack,filter='data')
        unpacked=next(unpack.iterdir())
        rebuilt=work/'rebuilt'; rebuilt.mkdir()
        build_python=tooling/'build-env/bin/python'
        versions = run('build-tool-versions', [build_python, '-I', '-c', "import json,importlib.metadata as m; print(json.dumps({n:m.version(n) for n in ['build','packaging','pyproject_hooks','setuptools','wheel']},sort_keys=True))"])
        assert json.loads(versions.stdout) == {'build':'1.4.0','packaging':'26.3','pyproject_hooks':'1.2.0','setuptools':'84.0.0','wheel':'0.47.0'}
        run('controller-pip-version', [sys.executable, '-I', '-m', 'pip', '--version'])
        run('rebuild-sdist',[build_python,'-I','-m','build','--wheel','--no-isolation','--outdir',rebuilt,unpacked])
        from_sdist=next(rebuilt.glob('*.whl'))
        save(evidence/'rebuilt-wheel.contents.json',archive_contract(from_sdist,snapshot))
        (artifact_dir/'from-sdist').mkdir(); shutil.copy2(from_sdist,artifact_dir/'from-sdist'/from_sdist.name)
        direct_members=members(direct); rebuilt_members=members(from_sdist)
        assert direct_members==rebuilt_members, 'sdist rebuilt wheel has different logical contents'
        audit=work/'runtime_audit.py'; audit.write_text(RUNTIME_AUDIT,encoding='utf-8')
        phases=[('wheel312',sys.executable,direct),('sdist312',sys.executable,from_sdist)]
        if args.python313.exists(): phases.append(('wheel313',str(args.python313),direct))
        else: result['python313']='unavailable; not tested'
        product_hashes={}; runtimes={}
        for phase, interpreter, artifact in phases:
            runtime=work/phase
            run(phase+'-venv',[interpreter,'-I','-m','venv','--without-pip',runtime])
            python=runtime/'bin/python'
            run(phase+'-install',[sys.executable,'-I','-m','pip','--python',python,'install','--no-index','--no-deps','--no-compile',packaging,artifact])
            run(phase+'-suite',[python,'-I','-m','unittest','discover','-s',snapshot/'tests','-v'])
            variants=[('baseline',{}),('varied',{'PYTHONHASHSEED':'12345','LC_ALL':'C','TZ':'Pacific/Kiritimati'}),('second',{'PYTHONHASHSEED':'99991','LC_ALL':'C.UTF-8','TZ':'America/New_York'})]
            previous=None
            for variant, overrides in variants:
                output=work/(phase+'-'+variant)
                elsewhere=work/(phase+'-cwd-'+variant);elsewhere.mkdir()
                # -P -s (not -I) preserves the selected hash seed; no PYTHONPATH is present.
                audited=run(phase+'-'+variant+'-audit',[python,'-P','-s',audit,output],overrides=overrides,directory=elsewhere)
                data=json.loads(audited.stdout); runtimes[phase]=data
                current={p.name:sha(p.read_bytes()) for p in output.iterdir()}
                if previous is not None: assert current==previous,'nondeterministic runtime documents'
                previous=current
            product_hashes[phase]=previous
            cli=runtime/'bin/wheelsuture'
            run(phase+'-help',[cli,'--help']);run(phase+'-version',[cli,'--version'])
            run(phase+'-module-version',[python,'-I','-m','wheelsuture','--version'])
            run(phase+'-profiles',[cli,'profiles','--json'])
            run(phase+'-invalid-apply',[cli,'apply'],expected=(2,))
            installed=Path(runtimes[phase]['package_location'])
            for plan in sorted((installed/'examples').glob('*.json')):
                label=phase+'-'+plan.stem;report=work/(label+'.json');repair=work/(label+'.repair.json')
                expected_case=next(c for c in runtimes[phase]['cases'] if c['plan']==plan.name)
                status={'preserved':0,'broken':1,'incomplete':3}[expected_case['analysis_status']]
                run(label+'-check',[cli,'check',plan,'--json',report,'--html',work/(label+'.html')],expected=(status,))
                repair_status={'verified':0,'already_satisfied':0,'conflict':1,'unknown':3}[expected_case['repair_status']]
                run(label+'-repair',[cli,'repair-plan',plan,'--output',repair],expected=(repair_status,))
                run(label+'-verify',[cli,'verify',plan,'--report',report,'--repair',repair])
        assert all(value==product_hashes['wheel312'] for value in product_hashes.values()), 'cross-install/runtime output mismatch'
        save(evidence/'document-sha256.json',product_hashes)
        save(evidence/'runtime-audits.json',json.loads(redact(json.dumps(runtimes))))
        result.update(status='passed',phases=list(runtimes),tests='complete unittest suite in each installed phase',
                      example_plans=17,fixture_wheels=16,schemas=6,
                      determinism='all 67 report/repair/HTML/inventory files identical over 3 cwd/hash-seed/locale/timezone variants and all installed phases',
                      logical_wheel_contents_identical=True,
                      artifact_sha256={p.name:sha(p.read_bytes()) for p in (direct,sdist)},
                      rebuilt_wheel_sha256=sha(from_sdist.read_bytes()))
        save(evidence/'result.json',result)
    save(evidence/'evidence-sha256.json',{str(p.relative_to(evidence)):sha(p.read_bytes()) for p in sorted(evidence.rglob('*')) if p.is_file() and p.name!='evidence-sha256.json'})
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if '--run-id' in sys.argv:
            run_id = sys.argv[sys.argv.index('--run-id') + 1]
            if run_id and all(c.isalnum() or c in '-_' for c in run_id):
                result_path = ROOT / 'qualification/evidence' / run_id / 'result.json'
                if result_path.exists():
                    previous = json.loads(result_path.read_bytes())
                    if previous.get('status') == 'running':
                        previous.update(status='failed', failure_type=type(error).__name__)
                        save(result_path, previous)
        raise
