import base64, contextlib, io, json, os, pathlib, subprocess, sys, tempfile
from unittest import mock
R=pathlib.Path(__file__).parent;H=R.parent.parent/'ossv538'
sys.path[:0]=[str(H/'tools'),str(H/'tools/tests')]
import check_build as cb
import test_private_fetch as pf
rows=[]
def note(name,**kw):
    row={'probe':name,**kw};rows.append(row);print(json.dumps(row),flush=True)
mode='normal';original=pf.Handler.serve
def serve(self):
    if mode in ('503-not-found','503-access-denied','200-refusal'):
        if mode=='200-refusal':
            line=b'ERR access denied\n';body=b'%04x'%(len(line)+4)+line
            kind='application/x-git-upload-pack-advertisement';status=200
        else:
            body=(b'repository not found\n' if mode=='503-not-found' else b'upstream connection access denied\n')
            kind='text/plain';status=503
        self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
    return original(self)
with mock.patch.object(pf.Handler,'serve',serve):
    pf.FetchCommit.setUpClass()
    try:
        base=pf.FetchCommit.base;commit=pf.FetchCommit.commits['secret']
        trans={'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'protocol.http.allow','GIT_CONFIG_VALUE_0':'always','GIT_CONFIG_KEY_1':f'url.{base}.insteadOf','GIT_CONFIG_VALUE_1':pf.HOST,'NO_PROXY':'*','no_proxy':'*'}
        with tempfile.TemporaryDirectory(dir=R) as tmp:
            root=pathlib.Path(tmp);secret=root/'token';secret.write_text(pf.TOKEN)
            def shell(extra,label):
                env={**os.environ,**trans,'HOME':tmp,'PATH':str(pf.HELPER.parent)+':/usr/bin:/bin','REPO':pf.HOST+'secret.git','COMMIT':commit,'OSS_VERIFY_TOKEN_FILE':str(secret),'OSS_VERIFY_TOKEN_REPO':base.partition('//')[2]+'secret.git',**extra}
                return subprocess.run(['sh',str(pf.FETCH_COMMIT),str(root/label)],capture_output=True,env=env,cwd=H)
            realenv=cb.git_environment
            def environment(token,repo=None):
                e=realenv(token,repo);e['OSS_VERIFY_TOKEN_REPO']=base.partition('//')[2]+'secret.git';return e
            for route in ('GIT_TRACE_PACKFILE','GIT_TRACE_BARE','GIT_TRACE_WORKING_TREE_ENCODING'):
                trace=root/'trace';done=shell({route:str(trace)},'container-'+route)
                ct=trace.read_bytes() if trace.exists() else b'';trace.unlink(missing_ok=True)
                with mock.patch.dict(os.environ,{**trans,route:str(trace)}),mock.patch.object(cb,'git_environment',environment),contextlib.redirect_stdout(io.StringIO()) as out:
                    try:cb.clone(pf.HOST+'secret.git',commit,root/'host',pf.TOKEN)
                    except cb.Failed as e:hc=1
                    else:hc=0
                ht=trace.read_bytes() if trace.exists() else b'';trace.unlink(missing_ok=True)
                needles=(pf.TOKEN.encode(),base64.b64encode(('x-access-token:'+pf.TOKEN).encode()))
                note('extra-trace',route=route,container_exit=done.returncode,host_exit=hc,container_bytes=len(ct),host_bytes=len(ht),container_token=any(x in ct for x in needles),host_token=any(x in ht for x in needles))
            # In a clean inherited environment, compare the exact generated Git argv with and without the forced 0.
            with mock.patch.dict(os.environ,trans):
                env=environment(pf.TOKEN,pf.HOST+'secret.git')
                for state in ('forced-zero','unset-control'):
                    e=dict(env)
                    if state=='unset-control':e.pop('GIT_CURL_VERBOSE',None)
                    d=subprocess.run(cb.git('ls-remote','--',pf.HOST+'secret.git',token=True),env=e,capture_output=True,cwd=H)
                    note('curl-verbose-presence',state=state,exit=d.returncode,stderr_bytes=len(d.stderr),curl_send_headers=b'=> Send header:' in d.stderr,raw_token=pf.TOKEN.encode() in d.stderr,basic_token=base64.b64encode(('x-access-token:'+pf.TOKEN).encode()) in d.stderr)
            for mode in ('503-not-found','503-access-denied','200-refusal'):
                done=shell({},'container-'+mode);cs=(done.stdout+done.stderr).decode(errors='replace')
                with mock.patch.dict(os.environ,trans),mock.patch.object(cb,'git_environment',environment),contextlib.redirect_stdout(io.StringIO()) as out:
                    try:cb.clone(pf.HOST+'secret.git',commit,root/'host',pf.TOKEN)
                    except cb.Failed as e:hc=1;hm=str(e)
                    else:hc=0;hm='success'
                note('marker-edge',mode=mode,container_exit=done.returncode,container_auth='fetch-commit: not authorised to read' in cs,container_transport='fetch-commit: could not reach' in cs,host_exit=hc,host_auth=hm.startswith('cannot read'),host_transport=hm.startswith('could not reach'),container_git_error=cs.splitlines()[-1],host_git_error=hm.splitlines()[-1])
    finally:pf.FetchCommit.tearDownClass()
# A command echo in output() must be redacted too.
with mock.patch.object(cb.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','failed')):
    try:cb.output('synthetic',pf.TOKEN,'third',token=pf.TOKEN)
    except cb.Failed as e:note('output-command-echo',raw_token=pf.TOKEN in str(e),redaction_marker='<redacted>' in str(e))
(R/'final-edges.json').write_text(json.dumps(rows,indent=2))
