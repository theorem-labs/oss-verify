import os, pathlib, subprocess, json, hashlib
R=pathlib.Path(__file__).parent;P='/mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python'
rows=[]
for leg,tree in [('base','/mnt/nvme/sami/clones/ossv538-base'),('head','/mnt/nvme/sami/clones/ossv538')]:
    cmd=[P,'tools/check','--no-shell','--build','plain','--dir',str(R/('public-'+leg)),'projects/cjson']
    with (R/('public-'+leg+'.log')).open('w') as log:
        result=subprocess.run(cmd,cwd=tree,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','OSS_VERIFY_GIT_TOKEN_COMMAND':'/nonexistent/review2-token-command'},stdout=log,stderr=subprocess.STDOUT)
    text=(R/('public-'+leg+'.log')).read_text();row={'leg':leg,'cwd':tree,'command':'OSS_VERIFY_GIT_TOKEN_COMMAND=/nonexistent/review2-token-command PYTHONDONTWRITEBYTECODE=1 '+' '.join(cmd),'exit':result.returncode,'mint_lines':sum('mint a read-only token' in x for x in text.splitlines()),'secret_lines':sum('--secret' in x for x in text.splitlines())}
    rows.append(row);print(json.dumps(row),flush=True)
a=R/'public-base/out';b=R/'public-head/out'
files=lambda d:{str(p.relative_to(d)):hashlib.sha256(p.read_bytes()).hexdigest() for p in d.rglob('*') if p.is_file()}
result={'runs':rows,'base_files':files(a),'head_files':files(b),'byte_identical':files(a)==files(b)}
(R/'public-builds.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
assert all(r['exit']==0 for r in rows) and result['byte_identical']
