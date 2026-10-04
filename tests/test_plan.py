import hashlib, json, os, tempfile, unittest
from pathlib import Path
from wheelsuture.model import Limits, Budget
from wheelsuture.plan import load_plan, strict_json, open_source
from wheelsuture.errors import InvalidInput, UnsupportedInput, LimitExceeded
from wheelsuture.canonical import digest, canonical_bytes
from wheelsuture.constants import PROFILE_ID

class PlanTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def plan(self, **updates):
  d=dict(schema_version=1,profile=PROFILE_ID,wheels=[],initial=[],transition=[],desired=[]);d.update(updates)
  p=self.root/'plan.json';p.write_text(json.dumps(d));return p
 def test_empty_and_immutable(self):
  p=load_plan(self.plan());d=p.to_dict();d['desired'].append('x');self.assertEqual(p.to_dict()['desired'],[])
  self.assertEqual(p.input_sha256,digest('wheelsuture/plan/1',p.to_dict()))
 def test_strict_json(self):
  for raw in [b'{"x":1,"x":2}',b'1.0',b'NaN',b'\xef\xbb\xbf{}',b'"\\ud800"',b'{} {}']:
   with self.subTest(raw=raw),self.assertRaises(InvalidInput): strict_json(raw,Limits())
 def test_depth(self):
  with self.assertRaises(LimitExceeded): strict_json(b'['*40+b']'*40,Limits())
 def test_closed_shapes_and_boolean_integer(self):
  for d in [{'bad':1},{'schema_version':True},{'initial':[{'id':'a','op':'remove','wheel':'x'}]}]:
   with self.subTest(d=d),self.assertRaises(InvalidInput):load_plan(self.plan(**d))
 def test_unknown_profile(self):
  with self.assertRaises(UnsupportedInput):load_plan(self.plan(profile='future-profile'))
 def test_bad_references_and_duplicates(self):
  with self.assertRaises(InvalidInput):load_plan(self.plan(desired=['absent']))
  with self.assertRaises(InvalidInput):load_plan(self.plan(wheels=[{'id':'a','path':'../a.whl','sha256':'0'*64}]))
 def test_symlink_source(self):
  (self.root/'real.whl').write_bytes(b'hello');(self.root/'a.whl').symlink_to('real.whl')
  p=load_plan(self.plan(wheels=[{'id':'a','path':'a.whl','sha256':hashlib.sha256(b'hello').hexdigest()}]))
  with self.assertRaises(InvalidInput):
   with open_source(p.sources[0]):pass
 def test_limits_lower_only_and_precharge(self):
  with self.assertRaises(ValueError):Limits(wheels=33)
  b=Budget(Limits(wheels=1));b.charge('wheels',1)
  with self.assertRaises(LimitExceeded):b.charge('wheels',1)
  self.assertEqual(b.usage['wheels'],1)
 def test_canonical_golden(self):
  self.assertEqual(canonical_bytes({'é':1,'a':[True,None]}),' {"a":[true,null],"é":1}'.strip().encode())
if __name__=='__main__':unittest.main()
