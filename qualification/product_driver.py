#!/usr/bin/env python3
"""Only adapter importing the product; the external oracle never imports it."""
import json
from pathlib import Path
import sys
def forbid_runtime_effects(event,args):
    if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','socket.connect','socket.bind','socket.getaddrinfo'}:
        raise AssertionError('Product attempted forbidden process/network effect: '+event)
sys.addaudithook(forbid_runtime_effects)
sys.path.insert(0,sys.argv[4] if len(sys.argv)==5 else str(Path(__file__).resolve().parents[1]/'src'))
from wheelsuture import analyze, create_repair

def serialize(value):
    if hasattr(value,'to_dict'): return value.to_dict()
    if isinstance(value,dict): return value
    raise TypeError(type(value).__name__)

def main():
    mode,plan_path,out_path=sys.argv[1:4]
    value=analyze(Path(plan_path)) if mode=='analyze' else create_repair(Path(plan_path))
    # Public create_repair may return the original report with its separate proposal.
    if isinstance(value,tuple): value=value[-1]
    Path(out_path).parent.mkdir(parents=True,exist_ok=True)
    Path(out_path).write_text(json.dumps(serialize(value),sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n')
if __name__=='__main__': main()
