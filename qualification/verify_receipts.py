#!/usr/bin/env python3
"""Read-only archival receipt verifier; imports no product or installer."""
import argparse, hashlib, json
from pathlib import Path

def sha(data):return hashlib.sha256(data).hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('run');args=parser.parse_args();root=Path(args.run)
    manifest=json.loads((root/'evidence-sha256.json').read_text()); checked=0
    for rel,digest in manifest.items():
        p=root/rel
        assert not Path(rel).is_absolute() and '..' not in Path(rel).parts
        assert sha(p.read_bytes())==digest,rel
        checked+=1
    contract=json.loads((root/'environment-contract.json').read_text())
    assert set(contract['variables'])=={'PATH','HOME','LC_ALL','PIP_CONFIG_FILE','PYTHONNOUSERSITE','PYTHONDONTWRITEBYTECODE'}
    assert contract['variables']['PIP_CONFIG_FILE']=='/dev/null'
    assert contract['parent_environment_merged'] is False
    digest=sha(json.dumps(contract,sort_keys=True,separators=(',',':')).encode())
    commands=json.loads((root/'commands.json').read_text())
    for command in commands:
        assert command['environment_contract_sha256']==digest
        assert command['cwd']=='<RUN>/disposable/controlled-cwd'
        assert command['returncode']==0,command
        assert not any(x in json.dumps(command) for x in ['/workspace/','/home/agent/','/root/'])
        argv=command['argv']
        assert argv[0].startswith(('<OFFICIAL_PYTHON>/bin/python','<RUN>/disposable/'))
        assert '-I' in argv
        if 'pip' in argv and 'install' in argv:
            assert all(flag in argv for flag in ['--isolated','--disable-pip-version-check','--no-index','--no-deps','--no-compile'])
            assert argv[-1].startswith('<QUALIFICATION>/fixtures/wheels/') and argv[-1].endswith('.whl')
        if 'uninstall' in argv:assert '--yes' in argv and '--python' in argv
    summary=json.loads((root/'summary.json').read_text())
    assert summary['status']=='passed' and not summary['failures']
    assert summary['commands']==len(commands)
    assert summary['pip_cases']==len(summary['cases'])
    for case in summary['cases']:
        assert case['passed']
        if summary.get('qualification_scope')=='full':
            assert case['product_compared']
            assert case['repair_status'] in ('verified','already_satisfied','conflict')
            if case['repair_status']!='conflict': assert case['real_repair_replay']['preserved']
        if 'real_repair_replay' in case: assert case['real_repair_replay']['preserved']
    print(json.dumps({'verified_files':checked,'verified_commands':len(commands),'pip_cases':summary['pip_cases'],'repair_replays':summary['real_repair_replays'],'installer_mapping_cases':summary['installer_mapping_cases'],'passed':True},sort_keys=True))
if __name__=='__main__':main()
