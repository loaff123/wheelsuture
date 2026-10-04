#!/usr/bin/env python3
"""Original MIT-licensed inert qualification wheels; never execute their payloads."""
from __future__ import annotations
import base64, csv, hashlib, io, json, re, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'fixtures'
PROFILE = 'pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1'
SITE = 'lib/python3.12/site-packages'
SAME = b'# Original inert qualification payload. Never imported.\nVALUE = "same"\n'
OTHER = b'# Original inert qualification payload. Never imported.\nVALUE = "other"\n'

def sha(data): return hashlib.sha256(data).hexdigest()
def save(path,obj): path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(obj,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
def wheel(wid,name,version,payload,*,pure=True):
    canonical=re.sub('[-_.]+','-',name).lower()
    stem=re.sub('[-_.]+','_',name).lower()+'-'+version
    info=stem+'.dist-info'
    files=dict(payload)
    files[info+'/METADATA']=f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: Original inert WheelSuture qualification fixture\n\n'.encode()
    files[info+'/WHEEL']=f'Wheel-Version: 1.0\nGenerator: original-wheelsuture-qualification\nRoot-Is-Purelib: {str(pure).lower()}\nTag: py3-none-any\n'.encode()
    claims=[]
    for member,data in sorted(files.items()):
        parts=member.split('/')
        if parts[0]==stem+'.data':
            category=parts[1]; suffix='/'.join(parts[2:])
            base={'purelib':SITE,'platlib':SITE,'headers':'include/site/python3.12/'+canonical,'scripts':'bin','data':''}[category]
            destination=(base+'/' if base else '')+suffix
        else: category='root'; destination=SITE+'/'+member
        if category=='scripts' and data.startswith(b'#!python'):
            tail=data.partition(b'\n')[2]
            signature={'kind':'rewritten_script','tail_sha256':sha(tail),'tail_size':len(tail),'interpreter_token':'profile-interpreter','profile':PROFILE}
        else: signature={'kind':'bytes','sha256':sha(data),'size':len(data)}
        claims.append({'member':member,'destination':destination,'signature':signature})
    ep=files.get(info+'/entry_points.txt',b'').decode()
    group=None
    for line in ep.splitlines():
        line=line.strip()
        if line.startswith('['): group=line[1:-1]
        elif '=' in line and group in ('console_scripts','gui_scripts'):
            name_,target=[v.strip() for v in line.split('=',1)]; module,attribute=target.split(':')
            claims.append({'member':info+'/entry_points.txt','destination':'bin/'+name_, 'signature':{'kind':'entry_point','group':group,'name':name_,'module':module,'attribute':attribute,'profile':PROFILE}})
    buffer=io.StringIO(newline=''); writer=csv.writer(buffer,lineterminator='\n')
    for member,data in sorted(files.items()): writer.writerow([member,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='),len(data)])
    writer.writerow([info+'/RECORD','','']); files[info+'/RECORD']=buffer.getvalue().encode()
    path=OUT/'wheels'/wid/(stem+'-py3-none-any.whl'); path.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_STORED) as z:
        for member,data in sorted(files.items()):
            zi=zipfile.ZipInfo(member,(2020,1,1,0,0,0)); zi.create_system=3; zi.external_attr=0o100644<<16; z.writestr(zi,data)
    return {'id':wid,'name':name,'canonical_name':canonical,'version':version,'dist_info':info,'path':str(path.relative_to(OUT)),'sha256':sha(path.read_bytes()),'claims':claims}

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    fixtures=[]
    def add(*args,**kwargs): f=wheel(*args,**kwargs); fixtures.append(f); return f
    add('base','qual-base','1.0',{'shared/__init__.py':SAME,'shared/base_only.py':b'# base only\n'})
    add('same','qual-slim','1.0',{'shared/__init__.py':SAME,'shared/slim_only.py':b'# slim only\n'})
    add('different','qual-slim','1.1',{'shared/__init__.py':OTHER,'shared/slim_only.py':b'# slim only\n'})
    add('upgrade','qual-slim','2.0',{'shared/slim_only.py':b'# upgraded slim only\n'})
    add('same_version','qual-slim','1.0',{'shared/slim_only.py':b'# different digest same version\n'})
    add('ns_a','qual-ns-a','1.0',{'deep_namespace/nested/a.py':b'# inert namespace A\n','deep_namespace/caf\u00e9/data.txt':b'Unicode exact path\n'})
    add('ns_b','qual-ns-b','1.0',{'deep_namespace/nested/b.py':b'# inert namespace B\n','deep_namespace/cafe\u0301/data.txt':b'Distinct decomposed Unicode path\n'})
    mapping_stem='qual_mapping-1.0'
    add('mapping','qual-mapping','1.0',{
        'mapping_owner/__init__.py':b'# inert module never imported\ndef main():\n    return 0\n',
        mapping_stem+'.data/purelib/pure_payload.py':b'# purelib\n',
        mapping_stem+'.data/platlib/plat_payload.py':b'# platlib\n',
        mapping_stem+'.data/headers/original.h':b'/* original header */\n',
        mapping_stem+'.data/data/share/qualification/value.txt':b'original data\n',
        mapping_stem+'.data/scripts/qual-raw':b'#!python -E\n# inert raw script\n',
        mapping_stem+'.data/scripts/qual-raw-crlf':b'#!pythonw\r\n# inert CRLF shebang\n',
        mapping_stem+'.data/scripts/qual-raw-no-lf':b'#!python',
        mapping_stem+'.data/scripts/qual-static':b'#!/bin/sh\n# inert script never executed\n',
        mapping_stem+'.dist-info/entry_points.txt':b'[console_scripts]\nqual-console = mapping_owner:main\n\n[gui_scripts]\nqual-gui = mapping_owner:main\n',
    },pure=False)
    add('alias_root','qual-alias-root','1.0',{'alias_namespace/shared.dat':b'alias-common\n','alias_namespace/root.dat':b'root-only\n'})
    add('alias_data','qual-alias-data','1.0',{'qual_alias_data-1.0.data/data/'+SITE+'/alias_namespace/shared.dat':b'alias-common\n','qual_alias_data-1.0.data/data/share/alias/value.dat':b'data-only\n'})
    add('alias_plat','qual-alias-plat','1.0',{'qual_alias_plat-1.0.data/platlib/alias_namespace/shared.dat':b'alias-common\n'})
    for letter in ['a','b']:
        name='qual-entry-'+letter; stem=name.replace('-','_')+'-1.0'
        add('entry_'+letter,name,'1.0',{f'entry_owner_{letter}/__init__.py':b'# inert entry owner\n',stem+'.dist-info/entry_points.txt':b'[console_scripts]\nqual-shared-cli = entry_target:main\n'})
        name='qual-script-'+letter; stem=name.replace('-','_')+'-1.0'
        add('script_'+letter,name,'1.0',{stem+'.data/scripts/qual-shared-raw':(b'#!python -E\n' if letter=='a' else b'#!pythonw\n')+b'# identical rewritten tail\n'})
    add('header_name','Qual.Mixed_Name','1.0',{'qual_mixed_name-1.0.data/headers/nested/original.h':b'/* canonical header name */\n'})
    lookup={f['id']:f for f in fixtures}
    cases=[]
    def case(name,initial,ops,desired,heldout=False):
        setup=[{'id':f'setup_{i}','op':'install','wheel':wid} for i,wid in enumerate(initial)]
        transitions=[]
        for i,op in enumerate(ops):
            if op[0]=='replace': transitions.append({'id':f'change_{i}','op':'replace','from':op[1],'to':op[2]})
            else: transitions.append({'id':f'change_{i}','op':op[0],'wheel':op[1]})
        ids=set(initial+desired)
        for op in ops: ids.update(op[1:])
        manifest=[{k:f[k] for k in ('id','path','sha256')} for f in fixtures if f['id'] in ids]
        plan={'schema_version':1,'profile':PROFILE,'wheels':manifest,'initial':setup,'transition':transitions,'desired':desired}
        save(OUT/(name+'.json'),plan)
        cases.append({'name':name,'plan':name+'.json','held_out':heldout})
    for label in ['same','different']:
        for reverse in [False,True]:
            case(f'{label}_{"reverse" if reverse else "forward"}',['base',label][::(-1 if reverse else 1)],[('remove',label)],['base'])
    case('incompatible_desired',['base','different'],[],['base','different'])
    case('namespace_disjoint',['ns_a','ns_b'],[('remove','ns_b')],['ns_a'],True)
    case('upgrade_omits_shared',['base','same'],[('replace','same','upgrade')],['base','upgrade'])
    case('same_version_replace',['base','same'],[('replace','same','same_version')],['base','same_version'],True)
    case('reinstall_collateral',['base','same'],[('reinstall','base')],['base','same'])
    case('all_scheme_mapping',['mapping'],[],['mapping'],True)
    case('three_aliases',['alias_root','alias_plat','alias_data'],[('remove','alias_plat')],['alias_root','alias_data'],True)
    case('entrypoint_shared',['entry_a','entry_b'],[('remove','entry_b')],['entry_a'],True)
    case('rewritten_shared',['script_a','script_b'],[('remove','script_b')],['script_a'],True)
    case('canonical_header',['header_name'],[],['header_name'],True)
    case('identity_removal',['base'],[],[],True)
    case('identity_addition',[],[],['base'],True)
    case('empty',[],[],[],True)
    save(OUT/'manifest.json',{'original_authorship':True,'license':'MIT','never_import_or_execute_payload':True,'fixtures':fixtures,'cases':cases})
    print(json.dumps({'fixtures':len(fixtures),'cases':len(cases),'held_out_cases':sum(c['held_out'] for c in cases)}))
if __name__=='__main__': main()
