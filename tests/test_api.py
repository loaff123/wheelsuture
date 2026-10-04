import json,tempfile,unittest
from pathlib import Path
from wheelsuture.api import analyze
from wheelsuture.constants import PROFILE_ID
class ApiTests(unittest.TestCase):
 def test_empty_plan(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'empty.json';p.write_text(json.dumps(dict(schema_version=1,profile=PROFILE_ID,wheels=[],initial=[],transition=[],desired=[])))
   r=analyze(p).to_dict();self.assertEqual(r['status'],'preserved');self.assertEqual(r['resource_usage']['report_bytes'],len(json.dumps(r,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode())+1)
if __name__=='__main__':unittest.main()
