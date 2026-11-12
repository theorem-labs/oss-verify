import base64, contextlib, io, json, os, pathlib, socket, subprocess, sys, tempfile, threading
from unittest import mock
R=pathlib.Path(__file__).parent;H=pathlib.Path('/mnt/nvme/sami/clones/ossv538')
sys.path[:0]=[str(H/'tools'),str(H/'tools/tests')]
import check_build as cb
import test_private_fetch as pf
rows=[]
def note(name,**kw):
    row={'probe':name,**kw};rows.append(row);print(json.dumps(row),flush=True)
original=pf.Handler.serve
mode='normal';redirect_target='';seen=[]
def serve(self):
    global mode,seen
    auth=self.headers.get('Authorization');seen.append((self.command,self.path,auth is not None))
    parsed=pf.urllib.parse.urlparse(self.path)
    if mode in ('401','403','429','503') or (mode=='deny-upload' and self.command=='POST'):
        self.send_response(int(mode) if mode.isdigit() else 503)
        if mode=='401':self.send_header('WWW-Authenticate','Basic realm="git"')
        self.send_header('Content-Length','0');self.end_headers();return
    if mode.startswith('redirect') and parsed.path.startswith('/secret.git/'):
        # First force git to obtain the scoped credential, then redirect the authenticated request.
        if not auth:
            self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="git"');self.send_header('Content-Length','0');self.end_headers();return
        self.send_response(302);self.send_header('Location',redirect_target+parsed.path.removeprefix('/secret.git')+('?' + parsed.query if parsed.query else ''));self.send_header('Content-Length','0');self.end_headers();return
    return original(self)
with mock.patch.object(pf.Handler,'serve',serve):
    pf.FetchCommit.setUpClass()
    other=pf.GitServer(pf.FetchCommit.served,set(),pf.TOKEN);ot=threading.Thread(target=other.serve_forever,daemon=True);ot.start()
    try:
        pf.git('init','-q','--bare',str(pf.FetchCommit.served/'empty.git'),cwd=H)
        base=pf.FetchCommit.base
        def transport(urlbase):
            return {'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'protocol.http.allow','GIT_CONFIG_VALUE_0':'always','GIT_CONFIG_KEY_1':f'url.{urlbase}.insteadOf','GIT_CONFIG_VALUE_1':pf.HOST,'NO_PROXY':'*','no_proxy':'*','GIT_TERMINAL_PROMPT':'0'}
        def fetch(repo,commit,token=pf.TOKEN,urlbase=base,extra=None,submodules=False):
            global seen
            seen=[]
            with tempfile.TemporaryDirectory(dir=R) as tmp:
                root=pathlib.Path(tmp);secret=root/'token';secret.write_text(token)
                env={**os.environ,**transport(urlbase),'HOME':tmp,'PATH':str(pf.HELPER.parent)+':/usr/bin:/bin','REPO':pf.HOST+repo,'COMMIT':commit,'OSS_VERIFY_TOKEN_FILE':str(secret),'OSS_VERIFY_TOKEN_REPO':urlbase.partition('//')[2]+repo,**(extra or {})}
                done=subprocess.run(['sh',str(pf.FETCH_COMMIT),*(['--submodules'] if submodules else []),str(root/'checkout')],capture_output=True,text=True,env=env,timeout=25)
                return done.returncode,done.stdout+done.stderr,list(seen)
        def host(repo,commit,urlbase=base,token=pf.TOKEN,extra=None):
            global seen
            seen=[]
            with tempfile.TemporaryDirectory(dir=R) as tmp,mock.patch.dict(os.environ,{**transport(urlbase),**(extra or {})}),mock.patch.object(cb,'git_environment',wraps=cb.git_environment):
                # The configured scope is the URL git actually reaches; this is all the fixture rewrite changes.
                realenv=cb.git_environment
                def environment(t,r=None):
                    e=realenv(t,r)
                    if e is not None:e['OSS_VERIFY_TOKEN_REPO']=urlbase.partition('//')[2]+repo
                    return e
                with mock.patch.object(cb,'git_environment',environment),contextlib.redirect_stdout(io.StringIO()) as out:
                    try:cb.clone(pf.HOST+repo,commit,pathlib.Path(tmp)/'checkout',token)
                    except cb.Failed as e:message=str(e);code=1
                    else:message='success';code=0
                return code,message,out.getvalue(),list(seen)
        for name in ('normal','401','403','429','503','empty','deny-upload','missing','wrong-token','dns','connection'):
            mode=name if name in ('401','403','429','503','deny-upload') else 'normal'
            repo='empty.git' if name=='empty' else 'secret.git'
            commit='f'*40 if name in ('missing','empty') else pf.FetchCommit.commits['secret']
            token=pf.OTHER_TOKEN if name=='wrong-token' else pf.TOKEN
            urlbase=base
            if name=='dns':urlbase='http://not-a-real-host.review2.invalid/'
            if name=='connection':urlbase=f'http://127.0.0.1:{pf.closed_port()}/'
            code,said,requests=fetch(repo,commit,token,urlbase)
            hc,hm,raw,hrequests=host(repo,commit,urlbase,token)
            note('failure-'+name,container_exit=code,container_auth='fetch-commit: not authorised to read' in said,container_missing='fetch-commit:' in said and 'has no commit' in said,container_transport='fetch-commit: could not reach' in said,container_end=said.splitlines()[-3:],host_exit=hc,host_message=hm,host_raw_end=raw.splitlines()[-2:],container_requests=len(requests),host_requests=len(hrequests))
        for name,target in [('redirect-same-host',base+'public.git'),('redirect-port',f'http://127.0.0.1:{other.server_address[1]}/public.git')]:
            mode=name;redirect_target=target
            code,said,requests=fetch('secret.git',pf.FetchCommit.commits['public'])
            hc,hm,raw,hrequests=host('secret.git',pf.FetchCommit.commits['public'])
            note(name,container_exit=code,container_message=said.splitlines()[-3:],host_exit=hc,host_message=hm,container_other_path_authorized=any('/public.git/' in p and a for _,p,a in requests),host_other_path_authorized=any('/public.git/' in p and a for _,p,a in hrequests),container_requests=requests,host_requests=hrequests)
        mode='normal'
        # Local config file permissions produce a transport diagnostic containing an auth marker.
        with tempfile.TemporaryDirectory(dir=R) as tmp:
            bad=pathlib.Path(tmp)/'unreadable';bad.mkdir()
            # Git reports "Is a directory" here; a fake diagnostic below covers permission-denied without root assumptions.
        for text in ("fatal: unable to access 'https://x/y': error setting certificate file: /cert/permission denied.pem", "fatal: unable to access 'https://x/y': Could not resolve host: repository not found.invalid"):
            with mock.patch.object(cb,'output',side_effect=cb.Failed(text)):
                message=cb.why_the_fetch_failed('https://x/y','a'*40,pf.TOKEN)
            note('host-marker-collision',input=text,message=message)
        # Actual authenticated request with every named environment route enabled, and with config trace2 routes.
        for source in ('environment','config'):
            with tempfile.TemporaryDirectory(dir=R) as tmp:
                trace=pathlib.Path(tmp)/'trace';extra={k:str(trace) for k in cb.GIT_TRACING};extra['GIT_TRACE_REDACT']='0'
                if source=='config':
                    cfg=pathlib.Path(tmp)/'config';cfg.write_text('[trace2]\n eventTarget = '+str(trace)+'\n envVars = OSS_VERIFY_GIT_TOKEN\n')
                    extra={'GIT_CONFIG_GLOBAL':str(cfg)}
                # config-global override is deliberately applied after the fixture transport.
                code,said,requests=fetch('secret.git',pf.FetchCommit.commits['secret'],extra=extra)
                ct=trace.read_text() if trace.exists() else '';trace.unlink(missing_ok=True)
                hc,hm,raw,hrequests=host('secret.git',pf.FetchCommit.commits['secret'],extra=extra)
                ht=trace.read_text() if trace.exists() else ''
                encoded=base64.b64encode(('x-access-token:'+pf.TOKEN).encode()).decode()
                note('tracing-'+source,container_exit=code,container_trace_bytes=len(ct),container_token_in_trace=pf.TOKEN in ct or encoded in ct,host_exit=hc,host_trace_bytes=len(ht),host_token_in_trace=pf.TOKEN in ht or encoded in ht,host_token_in_output=pf.TOKEN in raw,container_token_in_output=pf.TOKEN in said)
        # A submodule on another path must never get the main repository credential.
        work=pathlib.Path(pf.FetchCommit.temporary.name)/'with-sub';work.mkdir();pf.git('init','-q',str(work),cwd=H)
        (work/'README').write_text('submodule scope\n')
        (work/'.gitmodules').write_text('[submodule "other"]\n path = other\n url = '+base+'public.git\n')
        pf.git('add','README','.gitmodules',cwd=work)
        pf.git('update-index','--add','--cacheinfo','160000',pf.FetchCommit.commits['public'],'other',cwd=work)
        pf.git('commit','-qm','sub',cwd=work);commit=pf.git('rev-parse','HEAD',cwd=work)
        pf.git('clone','-q','--bare',str(work),str(pf.FetchCommit.served/'with-sub.git'),cwd=H)
        pf.FetchCommit.server.private.add('with-sub.git')
        code,said,requests=fetch('with-sub.git',commit,submodules=True)
        note('submodule-other-path',exit=code,other_authorized=any('/public.git/' in p and a for _,p,a in requests),main_authorized=any('/with-sub.git/' in p and a for _,p,a in requests))
    finally:
        other.shutdown();other.server_close();pf.FetchCommit.tearDownClass()
(R/'network.json').write_text(json.dumps(rows,indent=2))
