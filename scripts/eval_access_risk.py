#!/usr/bin/env python3
"""Compare engine tuples against synthetic truth files; no threshold tuning."""
from __future__ import annotations
import json
from collections import defaultdict
from pathlib import Path
from guardian.access_risk.engine import analyze
from guardian.access_risk.loader import load_input

ROOT=Path(__file__).resolve().parents[1]
def tuples(rows):return {(x['rule_id'],x['identity_id'],x.get('permission_id')) for x in rows if not x.get('insufficient_evidence')}
def score(name):
    truth=json.loads((ROOT/'examples'/f'access_risk_{name}.truth.json').read_text())
    data=load_input(ROOT/'examples'/f'access_risk_{name}.json')
    result=analyze(data,contract_reports=[str(ROOT/'examples/access_risk_contract_report.json')])
    expected={(f['rule_id'],f['identity_id'],f.get('permission_id')) for f in truth['expected_findings']}
    actual=tuples(result['findings']); rules=sorted({x[0] for x in expected|actual})
    per={}
    for rule in rules:
        tp=len({x for x in expected&actual if x[0]==rule});fp=len({x for x in actual-expected if x[0]==rule});fn=len({x for x in expected-actual if x[0]==rule})
        prec=tp/(tp+fp) if tp+fp else 1.;rec=tp/(tp+fn) if tp+fn else 1.
        per[rule]={'precision':round(prec,3),'recall':round(rec,3),'f1':round(2*prec*rec/(prec+rec),3) if prec+rec else 0,'tp':tp,'fp':fp,'fn':fn}
    tp=len(expected&actual);fp=len(actual-expected);fn=len(expected-actual);prec=tp/(tp+fp) if tp+fp else 1.;rec=tp/(tp+fn) if tp+fn else 1.
    return {'dataset':name,'synthetic':True,'overall':{'precision':round(prec,3),'recall':round(rec,3),'f1':round(2*prec*rec/(prec+rec),3) if prec+rec else 0,'tp':tp,'fp':fp,'fn':fn},'per_rule':per,'false_positives':[dict(rule_id=r,identity_id=u,permission_id=p) for r,u,p in sorted(actual-expected)],'false_negatives':[dict(rule_id=r,identity_id=u,permission_id=p) for r,u,p in sorted(expected-actual)],'insufficient_evidence_count':sum(f['insufficient_evidence'] for f in result['findings'])}
if __name__=='__main__': print(json.dumps({'results':[score('demo'),score('holdout')]},indent=2,sort_keys=True))
