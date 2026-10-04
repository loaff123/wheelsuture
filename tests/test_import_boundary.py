import subprocess,sys,unittest
class ImportBoundaryTests(unittest.TestCase):
 def test_verifier_import_does_not_load_production_algorithms(self):
  code="import wheelsuture.verify,sys; banned=['wheelsuture.inventory','wheelsuture.zipscan','wheelsuture.profiles','wheelsuture.reducer','wheelsuture.repair','wheelsuture.api']; assert not any(m in sys.modules for m in banned), [m for m in banned if m in sys.modules]"
  r=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
 def test_coverage_constants_are_immutable(self):
  from wheelsuture.constants import COVERAGE
  original=COVERAGE['assertion']
  try:
   with self.assertRaises(TypeError):COVERAGE['assertion']='forged'
  finally:
   if COVERAGE['assertion']!=original:COVERAGE['assertion']=original
  self.assertIsInstance(COVERAGE['included'],tuple)
