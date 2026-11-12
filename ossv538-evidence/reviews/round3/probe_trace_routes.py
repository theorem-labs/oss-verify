import base64, contextlib, io, json, os, pathlib, subprocess, sys, tempfile
from unittest import mock
R=pathlib.Path(__file__).parent;H=pathlib.Path('/mnt/nvme/sami/clones/ossv538');sys.path[:0]=[str(H/'tools'),str(H/'tools/tests')]
import check_build as cb
import test_private_fetch as pf
routes=('GIT_TRACE_PACK_ACCESS','GIT_TRACE_SETUP','GIT_TRACE_SHALLOW','GIT_TRACE_PERFORMANCE','GIT_TRACE_REFS','GIT_TRACE_FSMONITOR')
rows=[]
pf.FetchCommit.setUpClass()
try:
    with tempfile.TemporaryDirectory(dir=R) as tmp:
        root=pathlib.Path(tmp);secret=root/'token';secret.write_text(pf.TOKEN)
        trans={'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'protocol.http.allow','GIT_CONFIG_VALUE_0':'always','GIT_CONFIG_KEY_1':f'url.{pf.FetchCommit.base}.insteadOf','GIT_CONFIG_VALUE_1':pf.HOST}
        for route in routes:
            trace=root/'trace';extra={route:str(trace)}
            env={**os.environ,**trans,**extra,'PATH':str(pf.HELPER.parent)+':/usr/bin:/bin','HOME':tmp,'OSS_VERIFY_TOKEN_FILE':str(secret),'OSS_VERIFY_TOKEN_REPO':pf.FetchCommit.base.partition('//')[2]+'secret.git','REPO':pf.HOST+'secret.git','COMMIT':pf.FetchCommit.commits['secret']}
            done=subprocess.run(['sh',str(pf.FETCH_COMMIT),str(root/('container-'+route))],env=env,capture_output=True,text=True,cwd=H)
            ct=trace.read_text() if trace.exists() else '';trace.unlink(missing_ok=True)
            original=cb.git_environment
            def environment(token,repo=None):
                e=original(token,repo);e['OSS_VERIFY_TOKEN_REPO']=pf.FetchCommit.base.partition('//')[2]+'secret.git';return e
            with mock.patch.dict(os.environ,{**trans,**extra}),mock.patch.object(cb,'git_environment',environment),contextlib.redirect_stdout(io.StringIO()):
                try:cb.clone(pf.HOST+'secret.git',pf.FetchCommit.commits['secret'],root/'host',pf.TOKEN)
                except cb.Failed:hc=1
                else:hc=0
            ht=trace.read_text() if trace.exists() else '';trace.unlink(missing_ok=True)
            encoded=base64.b64encode(('x-access-token:'+pf.TOKEN).encode()).decode()
            row={'route':route,'container_exit':done.returncode,'container_trace_bytes':len(ct),'container_holds_token':pf.TOKEN in ct or encoded in ct,'host_exit':hc,'host_trace_bytes':len(ht),'host_holds_token':pf.TOKEN in ht or encoded in ht}
            rows.append(row);print(json.dumps(row),flush=True)
finally:pf.FetchCommit.tearDownClass()
(R/'trace-routes.json').write_text(json.dumps(rows,indent=2))
