from pathlib import Path
from dataclasses import replace
import json
from leitir.bts_cli import load_donor_snapshot,python_graph_provider,_default_budget,_default_resolution_policy
from leitir.bts import compute_bts
root=Path('/tmp/leitir-remediation-20260905/final-evidence/concurrent-views/corpus')
s=load_donor_snapshot(root,'pypa','packaging','85442b8032cb7bae72866dfd7782234a98dd2fb7')
g=python_graph_provider(s)(s.source_root)
n=next(n for n in g.nodes if n.id.qualified_name=='noxfile.tests')
results=[]
for units in [2,3,1000000]:
    r=compute_bts(s,n.id,g,replace(_default_budget(),max_work_units=units),_default_resolution_policy())
    results.append({'slug':s.slug,'commit':s.commit_sha,'seed':n.id.qualified_name,'work_budget':units,'status':r.status.value,'unresolved':len(r.report.unresolved),'known_seed_unresolved':sum(x.source==n.id for x in g.unresolved)})
print(json.dumps(results,indent=2))
