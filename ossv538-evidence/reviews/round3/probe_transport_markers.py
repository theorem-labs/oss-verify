import contextlib, io, json, os, pathlib, subprocess, sys, tempfile
from unittest import mock
R=pathlib.Path(__file__).parent;H=pathlib.Path('/mnt/nvme/sami/clones/ossv538');sys.path[:0]=[str(H/'tools'),str(H/'tools/tests')]
import check_build as cb
import test_private_fetch as pf
rows=[];mode='plain';original=pf.Handler.serve

def serve(self):
    if mode=='body':
        body=b'upstream connection permission denied\n'
        self.send_response(503);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
    if mode=='redirect' and self.path.startswith('/secret.git/'):
        self.send_response(302);self.send_header('Location',pf.FetchCommit.base+'public.git'+self.path.removeprefix('/secret.git'));self.send_header('Content-Length','0');self.end_headers();return
    return original(self)
with mock.patch.object(pf.Handler,'serve',serve):
    pf.FetchCommit.setUpClass()
    try:
        for mode in ('body','redirect'):
            pf.FetchCommit.server.private.add('public.git')
            f=pf.FetchCommit(methodName='runTest');code,said,head=f.fetch('secret.git',pf.FetchCommit.commits['public'],pf.TOKEN)
            row={'mode':mode,'container_exit':code,'container_auth':'fetch-commit: not authorised to read' in said,'container_transport':'fetch-commit: could not reach' in said,'container_end':said.splitlines()[-4:],'container_other_path_got_token':any(n=='public.git' and auth for n,auth in pf.FetchCommit.server.seen)}
            trans={'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'protocol.http.allow','GIT_CONFIG_VALUE_0':'always','GIT_CONFIG_KEY_1':f'url.{pf.FetchCommit.base}.insteadOf','GIT_CONFIG_VALUE_1':pf.HOST}
            realenv=cb.git_environment
            def env(t,r=None):
                e=realenv(t,r);e['OSS_VERIFY_TOKEN_REPO']=pf.FetchCommit.base.partition('//')[2]+'secret.git';return e
            with tempfile.TemporaryDirectory(dir=R) as work,mock.patch.dict(os.environ,trans),mock.patch.object(cb,'git_environment',env),contextlib.redirect_stdout(io.StringIO()) as out:
                try:cb.clone(pf.HOST+'secret.git',pf.FetchCommit.commits['public'],pathlib.Path(work)/'clone',pf.TOKEN)
                except cb.Failed as e:hm=str(e);hc=1
                else:hm='success';hc=0
            row.update(host_exit=hc,host_message=hm,host_other_path_got_token=any(n=='public.git' and auth for n,auth in pf.FetchCommit.server.seen))
            rows.append(row);print(json.dumps(row),flush=True)
    finally:pf.FetchCommit.tearDownClass()
(R/'transport-markers.json').write_text(json.dumps(rows,indent=2))
