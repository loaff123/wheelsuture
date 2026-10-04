import unittest
from unittest.mock import patch
from wheelsuture.canonical import finalize_document
from wheelsuture.model import Budget,Limits
from wheelsuture.errors import LimitExceeded
class CanonicalLimitTests(unittest.TestCase):
 def test_oversized_report_rejected_before_unbounded_serialization(self):
  b=Budget(Limits(report_bytes=1024))
  d={'resource_usage':b.usage,'evidence_sha256':'0'*64,'text':'x'*2048}
  with patch('wheelsuture.canonical.canonical_bytes',side_effect=AssertionError('Unbounded encode attempted')):
   with self.assertRaises(LimitExceeded):finalize_document(d,b,'report')
 def test_fixed_point_report_length_is_exact(self):
  from wheelsuture.canonical import canonical_bytes,digest
  b=Budget();d={'resource_usage':b.usage,'evidence_sha256':'0'*64,'value':'é'}
  result=finalize_document(d,b,'report')
  self.assertEqual(result['resource_usage']['report_bytes'],len(canonical_bytes(result))+1)
  h=result.pop('evidence_sha256');self.assertEqual(h,digest('wheelsuture/report/1',result))
 def test_all_published_design_golden_vectors(self):
  import json
  from pathlib import Path
  from wheelsuture.canonical import canonical_bytes,digest
  data=json.loads((Path(__file__).parent/'data/canonical-golden-vectors.json').read_text())
  for vector in data['vectors']:
   with self.subTest(domain=vector['domain']):
    self.assertEqual(canonical_bytes(vector['value']).hex(),vector['canonical_utf8_hex'])
    self.assertEqual(digest(vector['domain'],vector['value']),vector['digest'])
 def test_finalize_returns_plain_json_array_types(self):
  from wheelsuture.constants import COVERAGE
  b=Budget();d={'resource_usage':b.usage,'evidence_sha256':'0'*64,'coverage':COVERAGE}
  result=finalize_document(d,b,'report')
  self.assertIs(type(result['coverage']),dict)
  self.assertIs(type(result['coverage']['excluded']),list)
