import contextlib
import io
import json
import os
import pathlib
import sys
from unittest import mock

HEAD = pathlib.Path('/mnt/nvme/sami/clones/ossv538')
HERE = pathlib.Path(__file__).resolve().parent
sys.path[:0] = [str(HEAD/'tools'), str(HEAD/'tools/tests')]
import check_build as cb
import test_private_fetch as pf

pf.FetchCommit.setUpClass()
rows = []
try:
    original = pf.Handler.serve
    def serve(self):
        status = getattr(self.server, 'probe_status', None)
        if status:
            self.send_response(status)
            if status == 401:
                self.send_header('WWW-Authenticate', 'Basic realm="git"')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        return original(self)
    transport = {
        'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_CONFIG_SYSTEM':'/dev/null',
        'GIT_CONFIG_COUNT':'2', 'GIT_CONFIG_KEY_0':'protocol.http.allow', 'GIT_CONFIG_VALUE_0':'always',
        'GIT_CONFIG_KEY_1':f'url.{pf.FetchCommit.base}.insteadOf', 'GIT_CONFIG_VALUE_1':pf.HOST,
    }
    with mock.patch.object(pf.Handler, 'serve', serve), mock.patch.dict(os.environ, transport):
        for status in (401, 403, 429, 503, None):
            pf.FetchCommit.server.probe_status = status
            try:
                cb.resolve(pf.HOST+'public.git', 'missing', pf.TOKEN)
            except cb.Failed as failure:
                said = str(failure)
            else:
                said = '<success>'
            row = {'http_status':status, 'host_diagnostic':said, 'authorisation_explained':'cannot read' in said, 'missing_ref':'has no branch or tag' in said}
            rows.append(row)
            print(json.dumps(row), flush=True)
        pf.FetchCommit.server.probe_status = None
        # A credential request is untrusted input. Check whether the helper checks its recipient at all.
        request = 'protocol=https\nhost=unrelated.example\npath=unrelated/repo.git\n\n'
        helper = pf.CredentialHelper(methodName='runTest')
        code, answer = helper.answer(request=request, OSS_VERIFY_GIT_TOKEN=pf.TOKEN)
        row = {'probe':'credential-recipient', 'exit_code':code, 'answers_unrelated_host_with_token':f'password={pf.TOKEN}' in answer}
        rows.append(row)
        print(json.dumps(row), flush=True)
finally:
    pf.FetchCommit.tearDownClass()
(HERE/'host-results.json').write_text(json.dumps(rows, indent=2)+'\n')
