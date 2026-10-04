"""Tests of external-observation helpers, independent of the product."""
import unittest
from pathlib import Path
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).parent))

class OracleContract(unittest.TestCase):
    def test_bytes_signature_observes_exact_bytes(self):
        from oracle import observed_signature
        self.assertEqual(observed_signature(b'abc', {'kind':'bytes'}), {'kind':'bytes','sha256':'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','size':3})
    def test_script_signature_strips_only_first_line(self):
        from oracle import observed_signature, PROFILE
        got=observed_signature(b'#!/specific/disposable/python\nabc', {'kind':'rewritten_script'})
        self.assertEqual(got, {'kind':'rewritten_script','tail_sha256':'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','tail_size':3,'interpreter_token':'profile-interpreter','profile':PROFILE})
    def test_provider_requires_actual_import_and_call(self):
        from oracle import provider_present
        sig={'module':'heldout.cli','attribute':'go'}
        self.assertTrue(provider_present(b'from heldout.cli import go\ngo()\n',sig))
        self.assertFalse(provider_present(b'from wrong.cli import go\ngo()\n',sig))
        self.assertFalse(provider_present(b'from heldout.cli import go\npass\n',sig))
    def test_snapshot_excludes_scaffolding_and_preserves_unknown_file(self):
        from oracle import snapshot
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'bin').mkdir(); (root/'bin/python').write_bytes(b'scaffold')
            before=snapshot(root,set())
            (root/'heldout').write_bytes(b'new')
            after=snapshot(root,set(before))
            self.assertEqual(set(after),{'heldout'})

    def test_comparator_rejects_missing_changed_and_unexpected_payload(self):
        from oracle import compare_state, observed_signature
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            state={'identities':[],'slots':[{'destination':'payload.txt','signature':observed_signature(b'expected',{'kind':'bytes'})}]}
            with self.assertRaises(AssertionError): compare_state(root,state,[],set())
            (root/'payload.txt').write_bytes(b'changed')
            with self.assertRaises(AssertionError): compare_state(root,state,[],set())
            (root/'payload.txt').write_bytes(b'expected')
            compare_state(root,state,[],set())
            (root/'unexpected').write_bytes(b'new')
            with self.assertRaises(AssertionError): compare_state(root,state,[],set())
    def test_unknown_payload_symlink_rejected_but_scaffold_excluded(self):
        from oracle import snapshot
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'python').symlink_to('/does-not-need-to-exist')
            with self.assertRaises(AssertionError): snapshot(root,set())
            self.assertEqual(snapshot(root,{'python'}),{})
    def test_unknown_directory_symlink_is_not_silently_ignored(self):
        from oracle import snapshot
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'real').mkdir(); (root/'alias').symlink_to('real',target_is_directory=True)
            with self.assertRaises(AssertionError): snapshot(root,set())
            self.assertEqual(snapshot(root,{'alias'}),{})
    def test_rewritten_script_requires_exact_profile_interpreter(self):
        from oracle import signature_matches, observed_signature
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); p=root/'script'; template=observed_signature(b'#!x\ntail',{'kind':'rewritten_script'})
            p.write_bytes(b'#!/wrong/python\ntail')
            self.assertFalse(signature_matches(root,'script',template))
            p.write_bytes(b'#!'+str(root/'bin/python').encode()+b'\ntail')
            self.assertTrue(signature_matches(root,'script',template))
    def test_omitted_final_defect_rejected(self):
        from oracle import compare_findings, observed_signature
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            integrity={'defects':[{'wheel_id':'a','destination':'missing','expected':observed_signature(b'expected',{'kind':'bytes'})}]}
            with self.assertRaises(AssertionError): compare_findings(root,{'findings':[]},integrity)

if __name__=='__main__': unittest.main()

