import json,os,pathlib,subprocess
R=pathlib.Path(__file__).parent;P=R.parent/'venv/bin/python';B=R.parent.parent/'ossv538-base'
old=json.loads((R/'matrix.json').read_text());(R/'matrix-first-attempt.json').write_text(json.dumps(old,indent=2))
args=[str(P),'-P','-m','pytest','-q','-p','no:cacheprovider','tools/tests']
with (R/'base-base-corrected.log').open('w') as log:
    d=subprocess.run(args,cwd=B,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','TMPDIR':str(R/'tmp')},stdout=log,stderr=subprocess.STDOUT)
text=(R/'base-base-corrected.log').read_text();print('actual base-base exit',d.returncode,text[-2000:],flush=True)
old[0]={'name':'base-base','cwd':str(B),'argv':args,'exit':d.returncode,'tail':text[-2000:]}
(R/'matrix.json').write_text(json.dumps(old,indent=2))
assert d.returncode==0
