import unittest
from unittest.mock import patch
from test_reducer import inventory,plan,op
from wheelsuture.model import Budget
from wheelsuture.reducer import _simulate_snapshot as simulate
from wheelsuture.repair import propose_repair
from wheelsuture.errors import VerificationError
class RepairTests(unittest.TestCase):
 def case(self,conflict=False):
  invs={'a':inventory('a','alpha',{'x':'a'}),'b':inventory('b','beta',{'x':'b' if conflict else 'a'})}
  p=plan(invs,[op('ia','install','a'),op('ib','install','b')],[op('rb','remove','b')],['a','b'] if conflict else ['a'])
  r=simulate(p,invs,budget=Budget());return p,r,invs
 @patch('wheelsuture.repair._independent_check')
 def test_remove_then_install_and_report_unchanged(self,check):
  p,r,invs=self.case();original=r.canonical
  rep=propose_repair(p,r,invs,budget=Budget()).to_dict()
  self.assertEqual(rep['status'],'verified');self.assertEqual([(a['op'],a['wheel']) for a in rep['actions']],[('remove','a'),('install','a')]);self.assertEqual(r.canonical,original);check.assert_called_once()
  self.assertEqual(rep['verification']['findings'],[])
 @patch('wheelsuture.repair._independent_check')
 def test_conflict_requires_different_bytes(self,check):
  p,r,invs=self.case(True);rep=propose_repair(p,r,invs,budget=Budget()).to_dict()
  self.assertEqual(rep['status'],'conflict');self.assertEqual(rep['witnesses'][0]['kind'],'different_bytes');self.assertEqual(rep['actions'],[])
 @patch('wheelsuture.repair._independent_check')
 def test_already_satisfied(self,check):
  invs={'a':inventory('a','alpha',{'x':'a'})};p=plan(invs,[op('i','install','a')],[],['a']);r=simulate(p,invs,budget=Budget())
  rep=propose_repair(p,r,invs,budget=Budget()).to_dict();self.assertEqual(rep['status'],'already_satisfied');self.assertEqual(rep['actions'],[])
 @patch('wheelsuture.repair._independent_check',side_effect=VerificationError('Independent verifier disagrees.'))
 def test_independent_failure_never_verified(self,check):
  p,r,invs=self.case()
  with self.assertRaises(VerificationError):propose_repair(p,r,invs,budget=Budget())
 @patch('wheelsuture.repair._independent_check')
 def test_conflict_uses_first_canonical_pair(self,check):
  from wheelsuture.repair import _conflict
  invs={k:inventory(k,k,{'x':k}) for k in ['a','b','c']}
  wheels={k:v.to_dict() for k,v in invs.items()}
  claims=sorted([w['claims'][0] for w in wheels.values()],key=lambda c:c['claim_id'])
  claims[1]['signature']=claims[0]['signature']
  witness=_conflict(wheels,list(wheels))[0]
  self.assertEqual(witness['claim_ids'],sorted([claims[0]['claim_id'],claims[2]['claim_id']]))
 @patch('wheelsuture.repair._independent_check')
 def test_stricter_repair_budget_preserves_original_evidence(self,check):
  from wheelsuture.model import Limits
  p,r,invs=self.case();before=r.canonical
  proposal=propose_repair(p,r,invs,budget=Budget(Limits(user_operations=10))).to_dict()
  self.assertEqual(proposal['status'],'verified')
  self.assertEqual(proposal['effective_limits']['user_operations'],10)
  self.assertEqual(proposal['analysis_evidence_sha256'],r.to_dict()['evidence_sha256'])
  self.assertEqual(r.canonical,before)
if __name__=='__main__':unittest.main()
