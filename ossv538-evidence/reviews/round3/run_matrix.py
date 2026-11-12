import subprocess,os,pathlib,json,time
R=pathlib.Path(__file__).parent
P=R.parent/'venv/bin/python'
W=R.parent.parent
results=[]
for name,tree,tests in [('base-base',W/'ossv538-base',['tools/tests']),('head-head',W/'ossv538',['tools/tests']),('base-head',R/'base-code-head-tests',['tools/tests/test_private_fetch.py','tools/tests/test_check.py','tools/tests/test_print_toolchain.py','tools/tests/test_source_pinning.py'])]:
    args=[str(P),'-P','-m','pytest','-q','-p','no:cacheprovider',*tests]
    with (R/(name+'.log')).open('w') as log:
        p=subprocess.run(args,cwd=tree,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','TMPDIR':str(R/'tmp')},stdout=log,stderr=subprocess.STDOUT)
    text=(R/(name+'.log')).read_text(); print(name,'exit',p.returncode,text[-1800:],flush=True)
    results.append({'name':name,'cwd':str(tree),'argv':args,'exit':p.returncode,'tail':text[-2000:]})
(R/'matrix.json').write_text(json.dumps(results,indent=2))
assert results[0]['exit']==0 and results[1]['exit']==0 and results[2]['exit']!=0
