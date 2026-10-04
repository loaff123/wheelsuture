"""Command/report contracts isolated from parser and reducer implementation."""
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from wheelsuture.constants import PROFILE_ID
from wheelsuture.errors import InvalidInput, UnsupportedInput, OutputError, VerificationError
from wheelsuture.model import DEFAULT_LIMITS, AnalysisReport, RepairProposal, Document
from wheelsuture.canonical import canonical_bytes
try:
    from wheelsuture import cli, report
except ImportError:
    cli = report = None


def document(value, cls=Document):
    return cls(canonical_bytes(value))


def analysis(status='preserved'):
    return {'status':status, 'complete':status != 'incomplete', 'profile':PROFILE_ID,
            'case_id':'a'*64, 'wheels':[], 'findings':[], 'operations':[], 'events':[],
            'coverage':{'excluded':['import_correctness','dependencies']},
            'effective_limits':DEFAULT_LIMITS.to_dict(), 'diagnostics':[]}


class HtmlTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(report, 'HTML report renderer is not implemented')

    def test_html_escapes_all_untrusted_content_and_has_no_active_elements(self):
        payload = '\"><script>alert(1)</script><img src=x onerror=alert(2)>&\''
        data = analysis('incomplete')
        data['profile'] = payload
        data['wheels'] = [{'wheel_id':payload,'name':payload,'version':payload}]
        data['operations'] = [{'operation_id':payload,'source':{'op':payload},'phase':payload}]
        data['findings'] = [{'finding_id':payload,'kind':payload,'destination':payload,
                            'wheel_ids':[payload],'cause_event_id':payload}]
        data['events'] = [{'event_id':payload,'destination':payload,'action':payload}]
        data['diagnostics'] = [{'message':payload}]
        value = report.render_html(data, json_name=payload).decode('utf-8')
        self.assertIn('&lt;script&gt;', value)
        self.assertNotIn('<script', value.lower())
        self.assertNotIn('<img', value.lower())
        self.assertNotIn('href="javascript:', value.lower())
        self.assertNotIn('href="file:', value.lower())
        self.assertIn('incomplete', value)
        self.assertIn('Effective limits', value)
        self.assertIn('Excluded claims', value)
        self.assertIn('Causes', value)
        self.assertIn('Repair', value)

    def test_html_is_deterministic_and_event_omission_is_explicit(self):
        data = analysis(); data['events'] = [{'event_id':str(i)} for i in range(3)]
        first = report.render_html(data, max_events=1)
        self.assertEqual(first, report.render_html(data, max_events=1))
        self.assertIn(b'2 additional events omitted', first)
        self.assertIn(b'canonical JSON', first)

    def test_html_size_limit_fails_before_publishing(self):
        data = analysis()
        with self.assertRaises(Exception) as caught:
            report.render_html(data, max_bytes=100)
        self.assertEqual(type(caught.exception).__name__, 'LimitExceeded')

    def test_terminal_text_escapes_newlines_ansi_and_bidi(self):
        result = report.terminal_text('hello\n\x1b[31m\u202eevil')
        self.assertNotIn('\n', result)
        self.assertNotIn('\x1b', result)
        self.assertNotIn('\u202e', result)
        self.assertIn('\\n', result)
        self.assertIn('\\u202e', result)

    def test_serialized_json_is_canonical_with_exactly_one_lf(self):
        self.assertEqual(report.json_bytes({'z':1,'a':'ü'}), b'{"a":"\xc3\xbc","z":1}\n')


class CliTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(cli, 'CLI is not implemented')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.plan_path = self.root/'plan.json'; self.plan_path.write_text('{}')
        self.plan = SimpleNamespace(sources=())
        self.load_patch = patch.object(cli, 'load_plan', return_value=self.plan)
        self.load_patch.start(); self.addCleanup(self.load_patch.stop)
        self.stdout = io.StringIO(); self.stderr = io.StringIO()

    def run_cli(self, *args):
        return cli.main(list(map(str,args)), stdout=self.stdout, stderr=self.stderr)

    def test_check_preserved_and_broken_have_honest_json_and_exit(self):
        for status, expected in [('preserved',0),('broken',1),('incomplete',3)]:
            with self.subTest(status=status):
                dest = self.root/(status+'.json')
                with patch.object(cli, 'analyze', return_value=document(analysis(status), AnalysisReport)):
                    code = self.run_cli('check', self.plan_path, '--json', dest)
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(dest.read_bytes())['status'], status)
                self.assertIn(status, self.stdout.getvalue())

    def test_check_html_and_json_written(self):
        dest = self.root/'report.json'; html = self.root/'report.html'
        with patch.object(cli, 'analyze', return_value=document(analysis(), AnalysisReport)):
            code = self.run_cli('check',self.plan_path,'--json',dest,'--html',html)
        self.assertEqual(code, 0)
        self.assertTrue(html.read_bytes().startswith(b'<!doctype html>'))
        self.assertEqual(json.loads(dest.read_bytes())['status'], 'preserved')

    def test_repair_exit_is_proposal_result_not_original_breakage(self):
        for status, expected in [('verified',0),('already_satisfied',0),('conflict',1),('unknown',3)]:
            with self.subTest(status=status):
                dest = self.root/(status+'.json')
                with patch.object(cli, 'create_repair', return_value=(
                        document(analysis('broken'), AnalysisReport), document({'status':status},RepairProposal))):
                    code = self.run_cli('repair-plan',self.plan_path,'--output',dest)
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(dest.read_bytes())['status'], status)

    def test_verify_honest_broken_evidence_is_consistent(self):
        result = SimpleNamespace(exit_code=0, status='consistent', complete=True, valid=True, diagnostics=())
        with patch.object(cli, 'verify_report', return_value=result):
            code = self.run_cli('verify', self.plan_path, '--report',self.root/'report.json')
        self.assertEqual(code, 0)
        self.assertIn('consistent', self.stdout.getvalue())

    def test_verify_failure_and_incomplete_exit_codes(self):
        for code in (3,5):
            with self.subTest(code=code):
                result = SimpleNamespace(exit_code=code,status='incomplete' if code==3 else 'mismatch',diagnostics=())
                with patch.object(cli,'verify_report',return_value=result):
                    self.assertEqual(self.run_cli('verify',self.plan_path,'--report',self.root/'report.json'),code)

    def test_profiles_is_only_canonical_json(self):
        catalog = {'document_type':'profile_catalog','profiles':[{'id':PROFILE_ID}]}
        with patch.object(cli, 'profile_catalog', return_value=catalog):
            self.assertEqual(self.run_cli('profiles','--json'),0)
        self.assertEqual(self.stdout.getvalue(), canonical_bytes(catalog).decode()+'\n')

    def test_inspect_constructs_standalone_pinned_source(self):
        wheel = self.root/'demo.whl'; wheel.write_bytes(b'fixture')
        dest = self.root/'inventory.json'
        seen = []
        def inspect(source, profile, *, limits=DEFAULT_LIMITS):
            seen.append((source,profile))
            return document({'document_type':'inventory','profile':PROFILE_ID})
        with patch.object(cli,'inspect_wheel', side_effect=inspect):
            code = self.run_cli('inspect',wheel,'--sha256','a'*64,'--profile',PROFILE_ID,'--json',dest)
        self.assertEqual(code,0)
        source, profile = seen[0]
        self.assertEqual((source.id,source.path,source.sha256,source.base),('inspected','demo.whl','a'*64,self.root))
        self.assertEqual(profile.id,PROFILE_ID)

    def test_inspect_rejects_bad_digest_before_inventory(self):
        with patch.object(cli,'inspect_wheel') as inspect:
            code = self.run_cli('inspect', self.root/'a.whl', '--sha256', 'ABC', '--profile', PROFILE_ID,'--json',self.root/'inventory.json')
        self.assertEqual(code,2)
        self.assertFalse(inspect.called)

    def test_typed_failures_produce_bounded_error_json(self):
        failures = [(InvalidInput('bad'),2),(UnsupportedInput('unknown'),3),
                    (VerificationError('tampered'),5),(RuntimeError('secret internals'),70),
                    (KeyboardInterrupt(),130)]
        for error, expected in failures:
            with self.subTest(expected=expected):
                dest = self.root/f'error-{expected}.json'
                with patch.object(cli,'analyze',side_effect=error):
                    code = self.run_cli('check',self.plan_path,'--json',dest)
                self.assertEqual(code,expected)
                data = json.loads(dest.read_bytes())
                self.assertEqual(data['document_type'],'error')
                self.assertEqual(data['exit_code'],expected)
                self.assertLess(len(dest.read_bytes()),DEFAULT_LIMITS.error_bytes)
                if expected == 70:
                    self.assertNotIn('secret internals', dest.read_text())

    def test_output_failure_supersedes_analysis_and_preserves_existing_file(self):
        dest = self.root/'report.json'; dest.write_bytes(b'previous completed report')
        with patch.object(cli,'analyze',return_value=document(analysis('broken'),AnalysisReport)):
            code = self.run_cli('check',self.plan_path,'--json',dest)
        self.assertEqual(code,4)
        self.assertEqual(dest.read_bytes(),b'previous completed report')

    def test_output_cannot_alias_manifest_or_source(self):
        wheel = self.root/'a.whl'; wheel.write_bytes(b'input')
        source = SimpleNamespace(base=self.root,path=wheel.name)
        self.plan.sources = (source,)
        with patch.object(cli,'analyze',return_value=document(analysis(),AnalysisReport)):
            for dest in (self.plan_path,wheel):
                with self.subTest(dest=dest):
                    self.assertEqual(self.run_cli('check',self.plan_path,'--json',dest,'--overwrite'),4)
        self.assertEqual(self.plan_path.read_bytes(),b'{}')
        self.assertEqual(wheel.read_bytes(),b'input')

    def test_summary_broken_pipe_is_output_failure_and_keeps_honest_json(self):
        class BrokenPipe(io.StringIO):
            def write(self, value): raise BrokenPipeError('consumer closed')
        self.stdout = BrokenPipe()
        dest = self.root/'report.json'
        with patch.object(cli,'analyze',return_value=document(analysis(),AnalysisReport)):
            code = self.run_cli('check',self.plan_path,'--json',dest)
        self.assertEqual(code,4)
        self.assertEqual(json.loads(dest.read_bytes())['status'],'preserved')
        self.assertIn('partial',self.stderr.getvalue().lower())

    def test_usage_and_help_and_version_are_offline(self):
        self.assertEqual(self.run_cli('check'),2)
        self.assertEqual(self.run_cli('--help'),0)
        self.assertEqual(self.run_cli('--version'),0)

    def test_unknown_apply_command_is_invalid_usage(self):
        self.assertEqual(self.run_cli('apply', self.plan_path),2)


if __name__ == '__main__':
    unittest.main()
