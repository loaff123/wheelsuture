#!/usr/bin/env python3
"""Create a deterministic portable local evidence ZIP, never publish it."""
import argparse, hashlib, json, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser();p.add_argument('run_id');args=p.parse_args()
    run=ROOT/'evidence'/args.run_id
    assert run.is_dir() and run.parent==ROOT/'evidence'
    summary=json.loads((run/'summary.json').read_text())
    assert summary['status']=='passed' and summary.get('qualification_scope')=='full'
    output=ROOT/(args.run_id+'-evidence.zip')
    if output.exists():raise ValueError('Refusing to replace evidence archive')
    files=[]
    for candidate in sorted(run.rglob('*')):
        if candidate.is_file() and not candidate.is_relative_to(run/'disposable') and '__pycache__' not in candidate.parts:files.append((candidate,'qualification/'+candidate.relative_to(ROOT).as_posix()))
    for base in [ROOT/'fixtures',ROOT/'tooling']:
        for candidate in sorted(base.rglob('*')):
            if candidate.is_file() and '__pycache__' not in candidate.parts:files.append((candidate,'qualification/'+candidate.relative_to(ROOT).as_posix()))
    for candidate in sorted(ROOT.iterdir()):
        if candidate.suffix in ('.py','.md'):files.append((candidate,'qualification/'+candidate.name))
    files.append((ROOT.parent/'LICENSE','qualification/LICENSE'))
    manifest={name:hashlib.sha256(path.read_bytes()).hexdigest() for path,name in files}
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for path,name in sorted(files,key=lambda item:item[1]):
            zi=zipfile.ZipInfo(name,(2020,1,1,0,0,0));zi.create_system=3;zi.external_attr=0o100644<<16;zi.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(zi,path.read_bytes())
        zi=zipfile.ZipInfo('qualification/ARCHIVE-SHA256.json',(2020,1,1,0,0,0));zi.create_system=3;zi.external_attr=0o100644<<16;zi.compress_type=zipfile.ZIP_DEFLATED
        z.writestr(zi,json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'archive':output.name,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'size':output.stat().st_size,'files':len(files)+1}))
if __name__=='__main__':main()
