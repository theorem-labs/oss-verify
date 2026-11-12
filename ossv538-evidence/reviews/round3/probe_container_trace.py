import json, os, pathlib, subprocess, sys, tempfile
R=pathlib.Path(__file__).parent;H=R.parent.parent/'ossv538'
sys.path.insert(0,str(H/'tools/tests'))
import test_private_fetch as pf
import yaml
image=yaml.safe_load((R/'public-head/manifest.yaml').read_text())['builder']['image']
info=json.loads(subprocess.check_output(['docker','image','inspect',image],cwd=H))
image=info[0]['RepoTags'][0]
pf.FetchCommit.setUpClass()
try:
    context=R/'container-trace';context.mkdir(exist_ok=True)
    base=pf.FetchCommit.base
    dockerfile=context/'Dockerfile'
    dockerfile.write_text('''ARG BASE
FROM ${BASE}
RUN mkdir /review-traces && printf '[trace2]\\n eventTarget=/review-traces/event\\n normalTarget=/review-traces/normal\\n perfTarget=/review-traces/perf\\n envVars=OSS_VERIFY_GIT_TOKEN,OSS_VERIFY_TOKEN_FILE,OSS_VERIFY_TOKEN_REPO\\n' > /review-gitconfig
ARG REPO
ARG COMMIT
ARG SERVER
ENV GIT_CONFIG_GLOBAL=/review-gitconfig GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=protocol.http.allow GIT_CONFIG_VALUE_0=always GIT_CONFIG_KEY_1=url.${SERVER}.insteadOf GIT_CONFIG_VALUE_1=https://private.test/ OSS_VERIFY_TOKEN_REPO=${SERVER}/secret.git
RUN --mount=type=secret,id=oss-verify-git-token --network=host fetch-commit /src/review-secret
'''.replace('OSS_VERIFY_TOKEN_REPO=${SERVER}/secret.git','OSS_VERIFY_TOKEN_REPO='+base.partition('//')[2]+'secret.git'))
    tag='ossv538-review3-container-trace'
    cmd=['docker','build','--progress=plain','--network=host','--secret','id=oss-verify-git-token,env=REVIEW3_SYNTHETIC_TOKEN','--build-arg','BASE='+image,'--build-arg','REPO='+pf.HOST+'secret.git','--build-arg','COMMIT='+pf.FetchCommit.commits['secret'],'--build-arg','SERVER='+base,'-t',tag,'-f',str(dockerfile),str(context)]
    done=subprocess.run(cmd,cwd=H,env={**os.environ,'REVIEW3_SYNTHETIC_TOKEN':pf.TOKEN},capture_output=True,text=True,timeout=120)
    text=done.stdout+done.stderr;(R/'container-trace.log').write_text(text)
    row={'command':cmd,'exit':done.returncode,'authenticated_requests':sum(bool(auth) for _,auth in pf.FetchCommit.server.seen),'token_in_log':pf.TOKEN in text}
    if done.returncode==0:
        inspect_cmd=['docker','run','--rm','--init','--name','ossv538-review3-container-trace-inspect','--network=none','--entrypoint','sh',tag,'-c','find /review-traces -type f; test ! -e /run/secrets/oss-verify-git-token; git -C /src/review-secret rev-parse HEAD; git -C /src/review-secret remote -v']
        check=subprocess.run(inspect_cmd,cwd=H,capture_output=True,text=True)
        row.update(inspect_command=inspect_cmd,inspect_exit=check.returncode,inspect_output=check.stdout+check.stderr)
        history=subprocess.check_output(['docker','history','--no-trunc',tag],cwd=H)
        config=subprocess.check_output(['docker','image','inspect',tag],cwd=H)
        row.update(token_in_history=pf.TOKEN.encode() in history,token_in_image_config=pf.TOKEN.encode() in config)
    else:row['error']=text[-2000:]
    print(json.dumps(row),flush=True);(R/'container-trace.json').write_text(json.dumps(row,indent=2))
    assert done.returncode==0 and row['authenticated_requests'] and not row['token_in_log']
finally:pf.FetchCommit.tearDownClass()
