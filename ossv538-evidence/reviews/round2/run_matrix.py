import os, pathlib, subprocess, json, time
R=pathlib.Path(__file__).parent
P='/mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python'
env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','TMPDIR':str(R/'tmp')}
(R/'tmp').mkdir(exist_ok=True)
legs=[('base-base','/mnt/nvme/sami/clones/ossv538-base',['tools/tests']),('head-head','/mnt/nvme/sami/clones/ossv538',['tools/tests']),('base-head',str(R/'base-code-head-tests'),['tools/tests/test_private_fetch.py','tools/tests/test_check.py','tools/tests/test_print_toolchain.py','tools/tests/test_source_pinning.py'])]
results=[]
for name,cwd,tests in legs:
    cmd=[P,'-P','-m','pytest','-q','-p','no:cacheprovider',*tests]
    start=time.monotonic()
    with (R/(name+'.log')).open('w') as log:
        done=subprocess.run(cmd,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT)
    lines=(R/(name+'.log')).read_text().splitlines()
    entry={'leg':name,'cwd':cwd,'command':'env PYTHONDONTWRITEBYTECODE=1 TMPDIR='+env['TMPDIR']+' '+' '.join(cmd),'exit':done.returncode,'elapsed':time.monotonic()-start,'summary':lines[-1] if lines else ''}
    results.append(entry)
    (R/'matrix.json').write_text(json.dumps(results,indent=2))
    print(json.dumps(entry),flush=True)
assert [x['exit'] for x in results]==[0,0,1], results
