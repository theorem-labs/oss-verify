import collections
import contextlib
import datetime
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import types
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
HEAD = pathlib.Path('/mnt/nvme/sami/clones/ossv538')
BASE = pathlib.Path('/mnt/nvme/sami/clones/ossv538-base')
sys.path[:0] = [str(HEAD / 'tools'), str(HEAD / 'tools/tests')]
import check_build as cb
import test_private_fetch as pf
import test_check as tc

results = []
def note(name, **facts):
    record = {'probe': name, **facts}
    results.append(record)
    print(json.dumps(record), flush=True)

def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module

base = load('review_base_check_build', BASE / 'tools/check_build.py')
args = ('ls-remote', '--', 'https://example.invalid/x')
old_shell = re.search(r'^git\(\).*$', (BASE/'infra/base-builder/fetch-commit').read_text(), re.M).group()
new_shell = re.search(r'^git\(\).*$', (HEAD/'infra/base-builder/fetch-commit').read_text(), re.M).group()
note('anonymous-command-identity', host_argv_equal=base.git(*args) == cb.git(*args), shell_function_equal=old_shell == new_shell, head_argv=cb.git(*args))

mount_cases = {
    'comment-private': ('# RUN ' + cb.SECRET_MOUNT + ' fetch-commit /src/x\nRUN fetch-commit /src/x\n', pf.TOKEN),
    'comment-public': ('# Example: ' + cb.SECRET_MOUNT + '\nRUN fetch-commit /src/x\n', None),
    'continued-private': ('RUN --mount=type=secret,\\\nid=oss-verify-git-token fetch-commit /src/x\n', pf.TOKEN),
    'continued-public': ('RUN --mount=type=secret,\\\nid=oss-verify-git-token fetch-commit /src/x\n', None),
    'reordered-public': ('RUN --mount=id=oss-verify-git-token,type=secret fetch-commit /src/x\n', None),
    'wrong-id-private': ('RUN --mount=type=secret,id=oss-verify-git-token-other fetch-commit /src/x\n', pf.TOKEN),
    'unrelated-step-private': ('RUN ' + cb.SECRET_MOUNT + ' true\nRUN fetch-commit /src/x\n', pf.TOKEN),
}
for name, (text, token) in mount_cases.items():
    try:
        cb.check_secret_mount('Dockerfile', text, token, 'https://example.invalid/x')
    except cb.Failed:
        accepted = False
    else:
        accepted = True
    note('mount-' + name, accepted=accepted)

for repository_dockerfile in (False, True):
    with tempfile.TemporaryDirectory(dir=HERE) as tmp:
        root = pathlib.Path(tmp)
        project = root / 'project'
        project.mkdir()
        (project/'Dockerfile').write_text('FROM scratch\n# beside project.yaml\n')
        job = cb.Job(name='x', directory=project, repo='https://example.invalid/x', ref='', dockerfile='packaging/Customfile' if repository_dockerfile else '', builds=['plain'], fuzz_targets=None)
        def clone(repo, commit, checkout, token):
            (checkout/'packaging').mkdir(parents=True)
            (checkout/'packaging/Customfile').write_text('FROM scratch\n# repository Dockerfile\n')
        with mock.patch.object(cb, 'clone', clone), mock.patch.object(cb, 'run', return_value=0), mock.patch.object(cb, 'check_secret_mount') as guard, contextlib.redirect_stdout(io.StringIO()):
            cb.build_project(job, 'a'*40, 'builder', 'tag', root/'work')
        checked, text, token, repo = guard.call_args.args
        note('dockerfile-selection', in_repository=repository_dockerfile, selected=str(checked.relative_to(root)), text=text.strip())

for repo in ('https://github.com/DaveGamble/cJSON', 'https://github.com/theorem-labs/oss-verify'):
    fixture = tc.Project(methodName='runTest')
    fixture.setUp()
    try:
        yaml = fixture.project/'project.yaml'
        yaml.write_text(yaml.read_text().replace('https://example.org/demo', repo))
        def build_all(job, commit, work, *args, **kwargs):
            tc.binaries(work/'out', tc.FIRST)
            return 'builder', 'project', ['demo_fuzzer'], tc.FIRST
        with mock.patch.object(cb, 'mint_token', side_effect=AssertionError('public build asked for a token')) as mint, mock.patch.dict(os.environ, {cb.TOKEN_COMMAND_ENV:'/nonexistent/token-command'}):
            code, said, errors = fixture.main(['--twice'], build_all)
        data = tc.yaml.safe_load((fixture.work/'manifest.yaml').read_text())
        note('public-cli-no-token-command', repo=repo, exit_code=code, mint_calls=mint.call_count, commit=data['commit'], has_secret_fields=any('token' in k or 'secret' in k for k in data))
    finally:
        fixture.doCleanups()

class Pipe:
    def fileno(self):
        return 1234
    def close(self):
        pass

def stream(chunks, token):
    proc = types.SimpleNamespace(stdout=Pipe(), wait=lambda: 0)
    captured = io.StringIO()
    with mock.patch.object(cb.subprocess, 'Popen', return_value=proc), mock.patch.object(cb.os, 'read', side_effect=[*chunks, b'']), contextlib.redirect_stdout(captured):
        code = cb.run('fake-child', token=token)
    return code, captured.getvalue()

bad = []
for split in range(1, len(pf.TOKEN)):
    _, output = stream([('before-' + pf.TOKEN[:split]).encode(), (pf.TOKEN[split:] + '-after').encode()], pf.TOKEN)
    if output != 'before-<redacted>-after':
        bad.append(split)
        if len(bad) == 1:
            note('stream-first-partial-token', split=split, output=output, expected='before-<redacted>-after', complete_token_present=pf.TOKEN in output, leaked_suffix=pf.TOKEN[split:] in output)
note('stream-boundary-enumeration', token_length=len(pf.TOKEN), splits_checked=len(pf.TOKEN)-1, incorrect_splits=bad)
raw = b'ordinary output\n' + pf.TOKEN.encode() + b'\nutf8 \xe2\x82\xac done\n'
_, output = stream([raw[:7], raw[7:-3], raw[-3:]], None)
note('stream-public-byte-preservation', matched=output.encode() == raw)

# The same shell program, with git replaced only to supply otherwise uncontrolled diagnostic bytes.
with tempfile.TemporaryDirectory(dir=HERE) as tmp:
    root = pathlib.Path(tmp)
    git = root/'git'
    git.write_text('''#!/usr/bin/python3
import os, pathlib, sys
args = sys.argv[1:]
if 'fetch' in args:
    token = pathlib.Path(os.environ['OSS_VERIFY_TOKEN_FILE']).read_text().rstrip('\\n')
    print('before-' + token + '-after', file=sys.stdout if os.environ.get('PROBE_STDOUT') else sys.stderr)
    sys.exit(1)
if 'ls-remote' in args:
    sys.exit(1)
sys.exit(0)
''')
    git.chmod(0o755)
    secret = root/'synthetic-secret'
    env = {'PATH':str(root)+':/usr/bin:/bin', 'REPO':'https://example.invalid/x', 'COMMIT':'a'*40, 'OSS_VERIFY_TOKEN_FILE':str(secret)}
    for name, token, stdout in [('metacharacters', 'secret*?[abc]$;`"\\value', False), ('stdout', pf.TOKEN, True), ('replacement-reentry', 'redacted', False)]:
        secret.write_text(token)
        try:
            done = subprocess.run(['/bin/sh', str(pf.FETCH_COMMIT), str(root/'checkout')], env={**env, **({'PROBE_STDOUT':'1'} if stdout else {})}, capture_output=True, text=True, timeout=2)
        except subprocess.TimeoutExpired:
            note('shell-redact-' + name, terminates=False)
        else:
            note('shell-redact-' + name, terminates=True, token_in_stdout=token in done.stdout, token_in_stderr=token in done.stderr, exit_code=done.returncode, marker_present='<redacted>' in done.stderr)

# Real HTTP/git cases. The server remains the head test's git-http-backend server.
pf.FetchCommit.setUpClass()
try:
    instance = pf.FetchCommit(methodName='runTest')
    bare = pf.FetchCommit.served/'empty.git'
    pf.git('init', '-q', '--bare', str(bare), cwd=HEAD)
    code, said, _ = instance.fetch('empty.git', 'f'*40)
    note('container-empty-repository', exit_code=code, missing_commit='has no commit' in said, unauthorised='not authorised to read' in said)
    original = pf.Handler.serve
    def serve(self):
        mode = getattr(self.server, 'probe_mode', 'normal')
        if mode in ('offline', 'limited', 'denied') or (mode == 'deny-upload' and self.command == 'POST'):
            self.send_response({'offline':503, 'limited':429, 'denied':403, 'deny-upload':403}[mode])
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        return original(self)
    with mock.patch.object(pf.Handler, 'serve', serve):
        for mode in ('offline', 'limited', 'denied', 'deny-upload'):
            pf.FetchCommit.server.probe_mode = mode
            code, said, _ = instance.fetch('public.git', pf.FetchCommit.commits['public'])
            note('container-failure-' + mode, exit_code=code, custom_auth='fetch-commit: not authorised to read' in said, custom_missing='has no commit' in said, end=said.splitlines()[-1] if said else '')
        pf.FetchCommit.server.probe_mode = 'normal'
        transport = {
            'HOME':str(HERE), 'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_CONFIG_SYSTEM':'/dev/null',
            'GIT_CONFIG_COUNT':'2', 'GIT_CONFIG_KEY_0':'protocol.http.allow', 'GIT_CONFIG_VALUE_0':'always',
            'GIT_CONFIG_KEY_1':f'url.{pf.FetchCommit.base}.insteadOf', 'GIT_CONFIG_VALUE_1':pf.HOST,
        }
        with mock.patch.dict(os.environ, transport, clear=False):
            for name, commit, token in [('secret.git', pf.FetchCommit.commits['secret'], pf.OTHER_TOKEN), ('secret.git', 'f'*40, pf.TOKEN)]:
                with tempfile.TemporaryDirectory(dir=HERE) as work, contextlib.redirect_stdout(io.StringIO()) as captured:
                    try:
                        cb.clone(pf.HOST+name, commit, pathlib.Path(work)/'clone', token)
                    except cb.Failed as error:
                        message = str(error)
                    else:
                        message = '<success>'
                note('host-clone-' + ('wrong-token' if token == pf.OTHER_TOKEN else 'missing-commit'), exception=message, auth_explained='not authorised' in captured.getvalue() or 'minted for this build' in captured.getvalue(), has_redacted_marker='<redacted>' in captured.getvalue())
finally:
    pf.FetchCommit.tearDownClass()

# Use only synthetic credentials to exercise the real default dependency's cache semantics.
helper = load('review_gh_app_token', pathlib.Path('/home/sami/.dotfiles/shims/gh-app-token'))
with tempfile.TemporaryDirectory(dir=HERE) as tmp:
    cache = pathlib.Path(tmp)
    calls = []
    def broker(secret, owner, scope):
        calls.append((owner, scope))
        return {owner:{'installation_id':1, 'token':pf.TOKEN, 'expires_at':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
    def config(key):
        return None if key.endswith('key-secret') else 'synthetic-config'
    with mock.patch.object(helper, 'CACHE_DIR', cache), mock.patch.object(helper, 'git_config', config), mock.patch.object(helper, 'git_config_optional', config), mock.patch.object(helper, 'request_broker_installations', broker), mock.patch.object(helper, 'remember_covered_owners'), contextlib.redirect_stderr(io.StringIO()):
        scope = helper.scope_of(['theorem-cli'], True)
        first = helper.get_token('agent', 'theorem-labs', 1800, scope)
        second = helper.get_token('agent', 'theorem-labs', 1800, scope)
        files = list(cache.glob('*.json'))
        note('default-helper-build-reuse', same_token=first == second, broker_mint_calls=len(calls), durable_cache_files=len(files), cache_contains_token=any(pf.TOKEN in path.read_text() for path in files), scope=scope)

(HERE/'boundary-results.json').write_text(json.dumps(results, indent=2)+'\n')
