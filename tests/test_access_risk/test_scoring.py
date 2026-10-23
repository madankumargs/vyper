from guardian.access_risk.scoring import score_findings,remediation_plan,DryRunExecutor

def f(sev,id):return {'severity':sev,'identity_id':id,'remediation_tier':'T2','auto_revocation_allowed':False,'finding_id':id,'permission_id':'p','asset_id':None}
def test_band_caps_and_org_grade_formula():
    scores,org,grade=score_findings([f('HIGH','a') for _ in range(5)]+[f('LOW','b')])
    assert scores['a']['HIGH']==40 and scores['b']['total']==5 and org==33 and grade=='B'
def test_total_cap_and_grade_bands():
    scores,org,grade=score_findings([f(s,'a') for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']*10])
    assert scores['a']['total']==100 and org==100 and grade=='F'
def test_tiers_and_no_execute_surface():
    plan=DryRunExecutor().create_plan([f('HIGH','x')]);assert plan[0]['approver_required']
    assert not hasattr(DryRunExecutor(),'execute') and 'dry-run only' in plan[0]['action'] or plan[0]['action']=='request_access_review'
