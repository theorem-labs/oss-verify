import base64
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
from unittest import mock

HEAD = pathlib.Path('/mnt/nvme/sami/clones/ossv538')
HERE = pathlib.Path(__file__).resolve().parent
sys.path[:0] = [str(HEAD/'tools'), str(HEAD/'tools/tests')]
import check_build as cb
import test_private_fetch as pf

split = 24
script = ('import os,time; s=os.environ["SYNTHETIC_REVIEW_TOKEN"].encode(); '
          f'os.write(1,b"before-"+s[:{split}]); time.sleep(0.1); '
          f'os.write(1,s[{split}:]+b"-after")')
with contextlib.redirect_stdout(io.StringIO()) as captured:
    code = cb.run(sys.executable, '-c', script, env={**os.environ,'SYNTHETIC_REVIEW_TOKEN':pf.TOKEN}, token=pf.TOKEN)
stream = {'probe':'real-stream-split', 'split':split, 'exit_code':code, 'exact_redaction':captured.getvalue() == 'before-<redacted>-after', 'unredacted_suffix_length':len(pf.TOKEN[split:]) if pf.TOKEN[split:] in captured.getvalue() else 0}
print(json.dumps(stream), flush=True)

pf.FetchCommit.setUpClass()
try:
    with tempfile.TemporaryDirectory(dir=HERE) as tmp:
        trace = pathlib.Path(tmp)/'curl-trace'
        env = {
            'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_CONFIG_SYSTEM':'/dev/null',
            'GIT_CONFIG_COUNT':'2', 'GIT_CONFIG_KEY_0':'protocol.http.allow', 'GIT_CONFIG_VALUE_0':'always',
            'GIT_CONFIG_KEY_1':f'url.{pf.FetchCommit.base}.insteadOf', 'GIT_CONFIG_VALUE_1':pf.HOST,
            'GIT_TRACE_CURL':str(trace), 'GIT_TRACE_REDACT':'0',
        }
        with mock.patch.dict(os.environ, env):
            resolved = cb.resolve(pf.HOST+'secret.git', 'main', pf.TOKEN)
        authorization = base64.b64encode(('x-access-token:'+pf.TOKEN).encode()).decode()
        trace_probe = {'probe':'inherited-git-trace-file', 'resolved_expected_commit':resolved == pf.FetchCommit.commits['secret'], 'trace_created':trace.is_file(), 'recoverable_basic_credential_in_trace':authorization in trace.read_text()}
        print(json.dumps(trace_probe), flush=True)
finally:
    pf.FetchCommit.tearDownClass()
(HERE/'stream-trace-results.json').write_text(json.dumps([stream, trace_probe], indent=2)+'\n')
