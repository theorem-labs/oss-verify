import base64, gzip, hashlib, io, json, os, pathlib, shutil, subprocess, sys, tarfile
import yaml
R=pathlib.Path(__file__).parent;H=pathlib.Path('/mnt/nvme/sami/clones/ossv538');P='/mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python'
sys.path.insert(0,str(H/'tools'));import check_build as cb
wrapper=R/'build-token-from-env';wrapper.write_text('#!/bin/sh\nprintf %s "$REVIEW2_BUILD_TOKEN"\n');wrapper.chmod(0o700)
rows=[]
def scan(stream,needles):
    total=0;found=False;held=b'';keep=max(map(len,needles))-1
    while chunk:=stream.read(1024*1024):
        total+=len(chunk);data=held+chunk;found=found or any(x in data for x in needles);held=data[-keep:]
    return total,found
for name in ('cjson-ossv267','theorem-cli'):
    project=R/'private-projects'/name;shutil.copytree(R.parent/'projects'/name,project,dirs_exist_ok=True)
    repo='https://github.com/theorem-labs/'+name
    # These are actual default mints; only equality, never their values, is reported.
    token=cb.mint_token(repo);second=cb.mint_token(repo)
    work=R/('private-'+name)
    command=[P,'tools/check','--no-shell','--build','plain','--dir',str(work),str(project)]
    done=subprocess.run(command,cwd=H,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','OSS_VERIFY_GIT_TOKEN_COMMAND':str(wrapper),'REVIEW2_BUILD_TOKEN':token},capture_output=True,text=True,timeout=600)
    text=done.stdout+done.stderr
    needles=[token.encode(),base64.b64encode(('x-access-token:'+token).encode())]
    (R/('private-'+name+'.log')).write_text(cb.redacted(text,token))
    row={'repository':repo,'command':'PYTHONDONTWRITEBYTECODE=1 OSS_VERIFY_GIT_TOKEN_COMMAND='+str(wrapper)+' REVIEW2_BUILD_TOKEN=<inherited, never printed> '+' '.join(command),'cwd':str(H),'exit':done.returncode,'back_to_back_default_mints_differ':token!=second,'raw_log_contains_token':any(x in text.encode() for x in needles)}
    if done.returncode:
        row['error']=cb.redacted(text[-2000:],token);rows.append(row);print(json.dumps(row),flush=True);continue
    manifest=yaml.safe_load((work/'manifest.yaml').read_text());image=manifest['builder']['project_image'];row['commit']=manifest['commit'];row['sources']=manifest['sources'];row['image']=image
    for key,args in [('history',['docker','history','--no-trunc',image]),('inspect',['docker','image','inspect',image])]:
        output=subprocess.check_output(args,cwd=H);row[key]={'bytes':len(output),'contains_token':any(x in output for x in needles)}
    save=subprocess.Popen(['docker','save',image],cwd=H,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    members=[]
    with tarfile.open(fileobj=save.stdout,mode='r|*') as archive:
        for member in archive:
            if not member.isfile():continue
            source=archive.extractfile(member)
            # Docker's save contains layer blobs either as tar bytes or gzip bytes. Scan their decoded contents too.
            buffered=io.BufferedReader(source)
            gz=buffered.peek(2)[:2]==b'\x1f\x8b'
            decoded=gzip.GzipFile(fileobj=buffered) if gz else buffered
            size,hit=scan(decoded,needles)
            members.append({'name':member.name,'bytes':size,'gzip_decoded':gz,'contains_token':hit})
    save.stdout.close();stderr=save.stderr.read();status=save.wait()
    row['docker_save_exit']=status;row['saved_members']=members;row['saved_members_holding_token']=sum(x['contains_token'] for x in members)
    fields=[]
    for path in work.rglob('*'):
        if path.is_file():
            with path.open('rb') as source:size,hit=scan(source,needles)
            if hit:fields.append(str(path.relative_to(work)))
    row['facts_files_holding_token']=fields
    runtime=['docker','run','--rm','--init','--name','ossv538-review2-'+name,'--network=none','--entrypoint','sh',image,'-c','printenv; find /run/secrets -type f 2>/dev/null; for d in /src/*; do if [ -d "$d/.git" ]; then git -C "$d" remote -v; fi; done']
    d=subprocess.run(runtime,cwd=H,capture_output=True);output=d.stdout+d.stderr
    row['runtime']={'exit':d.returncode,'contains_token':any(x in output for x in needles),'token_env_present':b'OSS_VERIFY_GIT_TOKEN=' in output,'secrets_file_present':b'/run/secrets/' in output,'remote_contains_expected_url':repo.encode() in output}
    rows.append(row);(R/'private-builds.json').write_text(json.dumps(rows,indent=2));print(json.dumps(row),flush=True)
(R/'private-builds.json').write_text(json.dumps(rows,indent=2))
assert len(rows)==2 and all(x['exit']==0 and not x['raw_log_contains_token'] and not x['saved_members_holding_token'] and not x['facts_files_holding_token'] for x in rows)
