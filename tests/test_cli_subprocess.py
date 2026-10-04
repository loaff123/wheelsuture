import os,subprocess,sys,unittest
class CliSubprocessTests(unittest.TestCase):
 def test_real_closed_stdout_pipe_exit_four(self):
  for args in [['profiles','--json'],['--help'],['--version']]:
   with self.subTest(args=args):
    r,w=os.pipe();os.close(r)
    try:
     proc=subprocess.Popen([sys.executable,'-m','wheelsuture']+args,stdout=w,stderr=subprocess.PIPE)
    finally:os.close(w)
    _,err=proc.communicate(timeout=10)
    self.assertEqual(proc.returncode,4,err.decode())
    self.assertNotIn(b'Exception ignored',err)
