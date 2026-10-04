#!/usr/bin/env python3
"""Qualification-only subprocess harness, explicitly outside product runtime.

Requires the pinned official controller and builds only isolated original fixture
venvs. Receipts replace controlled absolute roots with portable placeholders.
Never imports wheelsuture, arbitrary wheels, entry points, or fixture modules.
"""
from __future__ import annotations
import argparse, hashlib, importlib.metadata, json, os, platform, re, shutil, subprocess, sys, sysconfig, traceback
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from oracle import PROFILE,SITE,sha,snapshot,compare_state,check_claim_inventory,desired_integrity,signature_matches,compare_findings
ROOT=Path(__file__).resolve().parent
FIXTURES=ROOT/'fixtures'
PYTHON=Path(sys.executable).absolute()

class Harness:
    def __init__(self,run_id):
        self.output=ROOT/'evidence'/run_id
        if self.output.exists(): raise ValueError('Refusing to overwrite captured run '+run_id)
        self.output.mkdir(parents=True)
        self.work=self.output/'disposable'; self.work.mkdir()
        self.home=self.work/'empty-home'; self.home.mkdir()
        self.cwd=self.work/'controlled-cwd'; self.cwd.mkdir()
        self.env={'PATH':str(PYTHON.parent),'HOME':str(self.home),'LC_ALL':'C.UTF-8','PIP_CONFIG_FILE':'/dev/null','PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1'}
        self.commands=[]; self.case_results=[]; self.mapping_results=[]; self.scaffolds={}; self.scope='full'
        self.harness_hashes={p.name:sha(p.read_bytes()) for p in sorted(ROOT.glob('*.py'))}
        for source_name in self.harness_hashes:
            target=self.output/'harness-source'/source_name; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/source_name,target)
        self.product_source=self.output/'product-source'
        for source in sorted((ROOT.parent/'src/wheelsuture').rglob('*')):
            if source.is_file() and source.suffix in ('.py','.json'):
                target=self.product_source/'wheelsuture'/source.relative_to(ROOT.parent/'src/wheelsuture')
                target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(source,target)
        self.manifest=json.loads((FIXTURES/'manifest.json').read_text())
        self.fixtures={f['id']:f for f in self.manifest['fixtures']}
        self.contract={'variables':self.redact(self.env),'cwd':'<RUN>/disposable/controlled-cwd','parent_environment_merged':False,'target_creation':'venv --without-pip','execution':'host/controller pip --python TARGET','profile':PROFILE}
        self.save('environment-contract.json',self.contract)
        self.contract_hash=sha(json.dumps(self.contract,sort_keys=True,separators=(',',':')).encode())
    def redact(self,obj):
        if isinstance(obj,str):
            for source,dest in [(str(self.output),'<RUN>'),(str(ROOT),'<QUALIFICATION>'),(str(ROOT.parent),'<PROJECT>'),(str(PYTHON.parent.parent),'<OFFICIAL_PYTHON>')]: obj=obj.replace(source,dest)
            return obj
        if isinstance(obj,list): return [self.redact(x) for x in obj]
        if isinstance(obj,dict): return {k:self.redact(v) for k,v in obj.items()}
        return obj
    def save(self,name,value):
        target=self.output/name; target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(json.dumps(self.redact(value),sort_keys=True,indent=2,ensure_ascii=False)+'\n')
    def run(self,args):
        args=list(args)
        if '-I' in args and '-B' not in args: args.insert(args.index('-I')+1,'-B')
        proc=subprocess.run([str(a) for a in args],cwd=self.cwd,env=self.env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
        receipt={'argv':list(map(str,args)),'cwd':str(self.cwd),'environment_contract_sha256':self.contract_hash,'returncode':proc.returncode,'output':proc.stdout}
        self.commands.append(receipt); self.save('commands.json',self.commands)
        if proc.returncode: raise RuntimeError(self.redact(json.dumps(receipt)))
        return proc.stdout
    def validate_pins(self):
        assert platform.python_version()=='3.12.14',platform.python_version()
        version=self.run([PYTHON,'-I','-m','pip','--isolated','--disable-pip-version-check','--version'])
        assert version.startswith('pip 26.2.1 '),version
        pipd=importlib.metadata.distribution('pip')
        paths=['pip/_internal/operations/install/wheel.py','pip/_internal/req/req_uninstall.py','pip/_internal/locations/__init__.py','pip/_vendor/distlib/scripts.py']
        source=[]
        for rel in paths:
            p=pipd.locate_file(rel); data=p.read_bytes(); out=self.output/'tool-sources'/rel; out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(data)
            source.append({'path':rel,'sha256':sha(data),'size':len(data)})
        licenses=[]
        for f in pipd.files or []:
            if 'LICENSE' in str(f) and 'dist-info' in str(f):
                p=pipd.locate_file(f); data=p.read_bytes(); name='tool-licenses/pip/'+str(f).split('.dist-info/',1)[1]
                out=self.output/name; out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(data); licenses.append({'path':name,'sha256':sha(data)})
        python_license=Path(sysconfig.get_path('stdlib'))/'LICENSE.txt'
        (self.output/'tool-licenses/PYTHON-LICENSE.txt').write_bytes(python_license.read_bytes())
        packaging=importlib.metadata.distribution('packaging')
        packaging_licenses=[]
        for rel in packaging.files or []:
            if 'LICENSE' in str(rel):
                data=packaging.locate_file(rel).read_bytes(); name='tool-licenses/packaging/'+Path(rel).name
                out=self.output/name; out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(data); packaging_licenses.append({'path':name,'sha256':sha(data)})
        wheel=ROOT/'tooling/downloads/installer-0.7.0-py3-none-any.whl'
        assert sha(wheel.read_bytes())=='05d1933f0a5ba7d8d6296bb6d5018e7c94fa473ceb10cf198a92ccea19c27b53'
        self.save('toolchain.json',{'python':platform.python_version(),'python_license':'PSF-2.0 with bundled notices','python_license_sha256':sha(python_license.read_bytes()),'packaging':packaging.version,'packaging_license':'Apache-2.0 OR BSD-2-Clause','packaging_license_files':packaging_licenses,'python_executable_sha256':sha(PYTHON.read_bytes()),'pip':'26.2.1','pip_license':'MIT; bundled vendor notices retained','pip_source_files':source,'pip_license_files':licenses,'installer':'0.7.0','installer_wheel_sha256':sha(wheel.read_bytes()),'installer_license':'MIT','installer_source':'https://pypi.org/project/installer/0.7.0/','arbitrary_downloaded_payloads':False})
    def create_venv(self,name):
        prefix=self.work/name
        self.run([PYTHON,'-I','-m','venv','--without-pip',prefix])
        assert not (prefix/'pip.conf').exists()
        baseline={p.relative_to(prefix).as_posix() for p in prefix.rglob("*") if p.is_file() or p.is_symlink()}
        self.scaffolds[str(prefix)]={rel:({'kind':'symlink','target':os.readlink(prefix/rel)} if (prefix/rel).is_symlink() else {'kind':'regular','sha256':sha((prefix/rel).read_bytes())}) for rel in sorted(baseline)}
        self.save('scaffolding/'+name+'.json',self.scaffolds[str(prefix)])
        # Only official pip inspection runs in the empty target; no wheel installed yet.
        host_site=sysconfig.get_path('purelib')
        code=f"import json,sys;sys.path.insert(0,{host_site!r});from pip._internal.configuration import Configuration;from pip._internal.locations import get_scheme;c=Configuration(isolated=True);c.load();items=dict(c.items());assert not items,sorted(items);s=get_scheme('qual-mixed-name');print(json.dumps({{'config_keys':sorted(items),'scheme':{{k:getattr(s,k) for k in ('purelib','platlib','headers','scripts','data')}},'python':sys.version}}))"
        environment=json.loads(self.run([prefix/'bin/python','-I','-c',code]))
        expected={'purelib':prefix/SITE,'platlib':prefix/SITE,'headers':prefix/'include/site/python3.12/qual-mixed-name','scripts':prefix/'bin','data':prefix}
        assert environment['scheme']=={k:str(v) for k,v in expected.items()},environment
        self.save('environments/'+name+'.json',environment)
        return prefix,baseline
    def assert_scaffold(self,prefix):
        for rel,expected in self.scaffolds[str(prefix)].items():
            p=prefix/rel
            actual={'kind':'symlink','target':os.readlink(p)} if p.is_symlink() else {'kind':'regular','sha256':sha(p.read_bytes())}
            assert actual==expected, ('Scaffold changed',rel)
    def pip(self,prefix,args):
        assert not (prefix/'pip.conf').exists()
        self.assert_scaffold(prefix)
        return self.run([PYTHON,'-I','-m','pip','--python',prefix/'bin/python','--isolated','--disable-pip-version-check',*args])
    def operation(self,prefix,op):
        kind=op['op']
        if kind=='replace':
            self.operation(prefix,{'op':'remove','wheel':op['from']}); self.operation(prefix,{'op':'install','wheel':op['to']}); return
        f=self.fixtures[op['wheel']]
        if kind=='remove': self.pip(prefix,['uninstall','--yes',f['canonical_name']])
        else:
            wheel=FIXTURES/f['path']; assert sha(wheel.read_bytes())==f['sha256']
            self.pip(prefix,['install','--no-deps','--no-index','--no-compile',*(['--force-reinstall'] if kind=='reinstall' else []),wheel])
    def product(self,mode,plan_path,output):
        self.run([PYTHON,'-I',ROOT/'product_driver.py',mode,plan_path,self.output/output,self.product_source])
        return json.loads((self.output/output).read_text())
    def case(self,description,product=True,repair_replay=True):
        name=description['name']; plan_path=FIXTURES/description['plan']; plan=json.loads(plan_path.read_text())
        self.save(name+'/plan.json',plan)
        prefix,baseline=self.create_venv(name)
        fixtures=[self.fixtures[w['id']] for w in plan['wheels']]
        boundaries=[]; active={}; operations=plan['initial']+plan['transition']
        for index,op in enumerate(operations):
            self.operation(prefix,op)
            self.assert_scaffold(prefix)
            if op['op']=='remove': active.pop(self.fixtures[op['wheel']]['canonical_name'])
            elif op['op']=='replace': active[self.fixtures[op['to']]['canonical_name']]=op['to']
            else: active[self.fixtures[op['wheel']]['canonical_name']]=op['wheel']
            if product:
                partial=dict(plan); count_initial=min(index+1,len(plan['initial']))
                partial['initial']=plan['initial'][:count_initial]; partial['transition']=plan['transition'][:max(0,index+1-len(plan['initial']))]; partial['desired']=sorted(active.values())
                self.save(f'{name}/boundary-{index:02d}-plan.json',partial)
                partial_path=FIXTURES/('_boundary_'+name+'.json'); partial_path.write_text(json.dumps(partial)+'\n')
                try: report=self.product('analyze',partial_path,f'{name}/boundary-{index:02d}-report.json')
                finally: partial_path.unlink()
                assert report['complete'] and report['status']!='incomplete',report
                checked=check_claim_inventory(report,fixtures)
                observation=compare_state(prefix,report['final_state'],fixtures,baseline)
                integrity=desired_integrity(prefix,partial['desired'],fixtures)
                assert (report['status']=='preserved')==integrity['preserved'],(report['status'],integrity)
                compare_findings(prefix,report,integrity)
                observation.update({'operation':op,'inventory_claims_compared':checked,'desired_integrity':integrity})
            else: observation={'operation':op,'files':snapshot(prefix,baseline),'desired_integrity':desired_integrity(prefix,sorted(active.values()),fixtures)}
            self.save(f'{name}/boundary-{index:02d}-observation.json',observation)
            boundaries.append({'operation':op['id'],'slots_compared':observation.get('compared_slots',0)})
        integrity=desired_integrity(prefix,plan['desired'],fixtures)
        result={'case':name,'held_out':description['held_out'],'boundaries':boundaries,'external_final':integrity,'product_compared':product}
        if product:
            report=self.product('analyze',plan_path,f'{name}/analysis.json')
            check_claim_inventory(report,fixtures); final=compare_state(prefix,report['final_state'],fixtures,baseline)
            assert (report['status']=='preserved')==integrity['preserved'],(report['status'],integrity)
            compare_findings(prefix,report,integrity)
            self.save(f'{name}/final-observation.json',final)
            if not repair_replay:
                result['repair_status']='not_requested_analysis_only'
                assert not (prefix/'pip.conf').exists()
                result['passed']=True
                self.save(name+'/result.json',result); self.case_results.append(result)
                print('PASS pip original-only '+name,flush=True)
                return
            repair=self.product('repair',plan_path,f'{name}/repair.json')
            result['repair_status']=repair['status']; result['repair_actions']=repair['actions']
            if repair['status'] in ['verified','already_satisfied']:
                replica,replica_baseline=self.create_venv(name+'-replica')
                for op in operations: self.operation(replica,op)
                # Replay exact emitted actions from the original transition's final state.
                model_slots={s['destination']:dict(s) for s in report['final_state']['slots']}
                model_identities={i['canonical_name']:dict(i) for i in report['final_state']['identities']}
                for index,op in enumerate(repair['actions']):
                    self.operation(replica,op)
                    self.assert_scaffold(replica)
                    emitted=repair['verification']['operations'][index]
                    assert emitted['source']==op, (emitted,op)
                    for event in repair['verification']['events']:
                        if event['operation_id']!=emitted['operation_id']: continue
                        dest=event['destination']
                        if event['after'] is None: model_slots.pop(dest,None)
                        else: model_slots[dest]={'destination':dest,'signature':event['after']}
                    f=self.fixtures[op['wheel']]
                    if op['op']=='remove': model_identities.pop(f['canonical_name'])
                    else: model_identities[f['canonical_name']]={'canonical_name':f['canonical_name'],'wheel_id':f['id'],'sha256':f['sha256']}
                    boundary_state={'slots':list(model_slots.values()),'identities':list(model_identities.values())}
                    observed=compare_state(replica,boundary_state,fixtures,replica_baseline)
                    self.save(f'{name}/repair-boundary-{index:02d}.json',{'operation':op,**observed})
                after=desired_integrity(replica,plan['desired'],fixtures)
                assert after['preserved'],after
                if repair.get('verification'): compare_state(replica,repair['verification']['final_state'],fixtures,replica_baseline)
                result['real_repair_replay']=after
                assert not (replica/'pip.conf').exists()
            else: assert repair['status']=='conflict' and name=='incompatible_desired',repair
        assert not (prefix/'pip.conf').exists()
        result['passed']=True
        self.save(name+'/result.json',result); self.case_results.append(result)
        print('PASS pip '+name,flush=True)
    def mapping(self,wid):
        f=self.fixtures[wid]; name='installer-'+wid
        prefix,baseline=self.create_venv(name)
        wheel=FIXTURES/f['path']; assert sha(wheel.read_bytes())==f['sha256']
        info=json.loads(self.run([PYTHON,'-I',ROOT/'installer_driver.py',wheel,prefix,f['canonical_name']]))
        self.assert_scaffold(prefix)
        observed=snapshot(prefix,baseline)
        expected={c['destination'] for c in f['claims']}|{SITE+'/'+f['dist_info']+'/'+c for c in ['RECORD','INSTALLER']}
        assert set(observed)==expected,{'unexpected':sorted(set(observed)-expected),'missing':sorted(expected-set(observed))}
        for claim in f['claims']: assert signature_matches(prefix,claim['destination'],claim['signature']),claim
        result={'wheel_id':wid,'passed':True,'claims_compared':len(f['claims']),'observed':observed,'execution':info,'scope':'mapping only; independent destination and payload verification; no uninstall inference'}
        self.save('mapping/'+wid+'.json',result); self.mapping_results.append(result)
        print('PASS installer mapping '+wid,flush=True)
    def finish(self,status,errors):
        assert not any(self.cwd.iterdir())
        for source_name,expected in self.harness_hashes.items():
            if sha((ROOT/source_name).read_bytes())!=expected:
                errors.append({'scope':'harness','error':'Harness source changed during run: '+source_name}); status='failed'
        input_hashes=dict(self.harness_hashes)
        input_hashes.update({str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(FIXTURES.rglob('*.whl'))})
        result={'status':status,'qualification_scope':self.scope,'profile':PROFILE,'pip_cases':len(self.case_results),'pip_boundaries':sum(len(c['boundaries']) for c in self.case_results),'real_repair_replays':sum('real_repair_replay' in c for c in self.case_results),'installer_mapping_cases':len(self.mapping_results),'installer_mapping_claims':sum(c['claims_compared'] for c in self.mapping_results),'commands':len(self.commands),'failures':errors,'input_hashes':input_hashes,'cases':self.case_results,'payload_imports_or_execution':False,'runtime_installer_calls':False,'original_fixtures_only':True,'captured_venvs':'disposable/; excluded from archival evidence manifest','receipts_portable_paths':True}
        self.save('summary.json',result)
        entries={str(p.relative_to(self.output)):sha(p.read_bytes()) for p in sorted(self.output.rglob('*')) if p.is_file() and not p.is_relative_to(self.work) and '__pycache__' not in p.parts and p.name!='evidence-sha256.json'}
        self.save('evidence-sha256.json',entries)
        print(json.dumps({k:result[k] for k in ['status','pip_cases','pip_boundaries','real_repair_replays','installer_mapping_cases','failures']},indent=2))

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--run-id',required=True); parser.add_argument('--oracle-only',action='store_true'); parser.add_argument('--analysis-only',action='store_true'); parser.add_argument('--mapping-only',action='store_true'); parser.add_argument('--case',action='append'); args=parser.parse_args()
    assert re.fullmatch('[a-zA-Z0-9_-]+',args.run_id)
    harness=Harness(args.run_id); errors=[]
    harness.scope='mapping_only' if args.mapping_only else 'oracle_only' if args.oracle_only else 'analysis_only' if args.analysis_only else 'full'
    try:
        harness.validate_pins()
        if not args.mapping_only:
            for case in harness.manifest['cases']:
                if args.case and case['name'] not in args.case: continue
                try: harness.case(case,product=not args.oracle_only,repair_replay=not args.analysis_only)
                except Exception as exc:
                    errors.append({'scope':'pip','case':case['name'],'error':str(exc),'traceback':traceback.format_exc()}); print('FAIL pip '+case['name']+': '+str(exc),flush=True)
        if not args.case:
            for wid in ['mapping','alias_root','alias_data','alias_plat','ns_a','ns_b','header_name','entry_a','script_a']:
                try: harness.mapping(wid)
                except Exception as exc:
                    errors.append({'scope':'mapping','wheel':wid,'error':str(exc),'traceback':traceback.format_exc()}); print('FAIL mapping '+wid+': '+str(exc),flush=True)
    except Exception as exc: errors.append({'scope':'setup','error':str(exc),'traceback':traceback.format_exc()})
    harness.finish('passed' if not errors else 'failed',errors)
    return bool(errors)
if __name__=='__main__': raise SystemExit(main())
