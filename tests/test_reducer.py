import json, tempfile, unittest
from pathlib import Path
from wheelsuture.canonical import digest,canonical_bytes
from wheelsuture.constants import PROFILE_ID
from wheelsuture.model import Plan,Limits,Budget,_validated_inventory,WheelInventory,_validated_plan
from wheelsuture.reducer import _simulate_snapshot as simulate
from wheelsuture.errors import InvalidInput,UnsupportedInput,LimitExceeded

def inventory(wid,name,paths,version='1',sigkind='bytes'):
 sha=digest('test',wid);claims=[]
 for path,value in paths.items():
  sig={'kind':'bytes','sha256':digest('bytes',value),'size':1}
  if sigkind=='entry_point':sig={'kind':'entry_point','name':path,'group':'console_scripts','module':value,'attribute':'main','profile':PROFILE_ID}
  cid=digest('wheelsuture/claim/1',[PROFILE_ID,sha,path,'copied',path,sig])
  claims.append(dict(claim_id=cid,path_id=digest('wheelsuture/path/1',[PROFILE_ID,path]),wheel_id=wid,destination=path,member=path,kind='copied',signature=sig,checked=True))
 claims.sort(key=lambda c:c['destination'].encode())
 w=dict(wheel_id=wid,source_sha256=sha,name=name,canonical_name=name,version=version,dist_info=name+'-'+version+'.dist-info',root_is_purelib=True,tags=['py3-none-any'],member_count=len(claims),decoded_bytes=len(claims),claims=claims,deletion_paths=[c['destination'] for c in claims])
 usage=Budget().usage;usage.update(wheels=1,mapped_claims=len(claims),deletion_paths=len(claims))
 return _validated_inventory(w,PROFILE_ID,sha,Limits(),usage)
def plan(invs,initial,transition,desired):
 d=dict(schema_version=1,profile=PROFILE_ID,wheels=[dict(id=k,path=k+'.whl',sha256=v.source_sha256) for k,v in invs.items()],initial=initial,transition=transition,desired=desired)
 return _validated_plan(Path('/unused/plan.json'),canonical_bytes(d),plan_bytes=100,json_depth=4)
def op(id,verb,w):return dict(id=id,op=verb,wheel=w)
class ReducerTests(unittest.TestCase):
 def run_case(self,invs,initial,trans,desired,limits=Limits()):return simulate(plan(invs,initial,trans,desired),invs,budget=Budget(limits)).to_dict()
 def test_shared_equal_uninstall_loses_survivor(self):
  invs={'a':inventory('a','alpha',{'x':'a'}),'b':inventory('b','beta',{'x':'a'})}
  r=self.run_case(invs,[op('i1','install','a'),op('i2','install','b')],[op('r','remove','b')],['a'])
  self.assertEqual(r['status'],'broken');f=r['findings'][0];self.assertTrue(f['retained']);self.assertEqual(f['kind'],'missing')
  cause=next(e for e in r['events'] if e['event_id']==f['cause_event_id']);self.assertEqual(cause['wheel_id'],'b');self.assertEqual(cause['action'],'delete')
 def test_noop_delete_keeps_effective_cause(self):
  invs={k:inventory(k,k,{'x':'v'}) for k in ['a','b','c']}
  r=self.run_case(invs,[op('i'+k,'install',k) for k in invs],[op('rb','remove','b'),op('rc','remove','c')],['a'])
  final=r['findings'][-1];cause=next(e for e in r['events'] if e['event_id']==final['cause_event_id']);self.assertEqual(cause['wheel_id'],'b')
  self.assertEqual(r['events'][-1]['action'],'delete_absent');self.assertEqual(r['events'][-1]['prior_event_id'],cause['event_id'])
 def test_reinstall_clears_final_but_preserves_history(self):
  invs={k:inventory(k,k,{'x':'v'}) for k in ['a','b']}
  r=self.run_case(invs,[op('ia','install','a'),op('ib','install','b')],[op('rb','remove','b'),op('ra','reinstall','a')],['a'])
  self.assertEqual(r['status'],'preserved');self.assertTrue(r['findings']);self.assertFalse(any(f['phase']=='final' for f in r['findings']))
 def test_displacement_initial_and_identity_exact(self):
  invs={'a':inventory('a','a',{'x':'a'}),'b':inventory('b','b',{'x':'b'})}
  r=self.run_case(invs,[op('ia','install','a'),op('ib','install','b')],[],['a'])
  self.assertEqual(r['findings'][0]['phase'],'initial');self.assertIn('identity_extra',[f['kind'] for f in r['findings']])
 def test_global_prefix_and_provider_unknown(self):
  for invs in [{'a':inventory('a','a',{'x':'a'}),'b':inventory('b','b',{'x/y':'b'})},{'a':inventory('a','a',{'x':'a'},sigkind='entry_point'),'b':inventory('b','b',{'x':'b'},sigkind='entry_point')}]:
   with self.assertRaises(UnsupportedInput):self.run_case(invs,[],[],[])
 def test_preconditions_and_inventory_provenance(self):
  invs={'a':inventory('a','a',{'x':'v'})}
  with self.assertRaises(InvalidInput):self.run_case(invs,[],[op('r','remove','a')],[])
  i=invs['a'];invs['a']=WheelInventory(i.canonical,i.profile_id,i.source_sha256,i.limits,i.usage_canonical)
  with self.assertRaises(InvalidInput):self.run_case(invs,[],[],[])
 def test_event_limit_before_append(self):
  invs={'a':inventory('a','a',{'x':'v'})}
  with self.assertRaises(LimitExceeded):self.run_case(invs,[op('i','install','a')],[],['a'],Limits(expanded_events=0))
if __name__=='__main__':unittest.main()
