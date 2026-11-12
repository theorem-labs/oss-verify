import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
from unittest import mock

HEAD = pathlib.Path('/mnt/nvme/sami/clones/ossv538')
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HEAD/'tools'))
import check_build as cb

with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
with tempfile.TemporaryDirectory(dir=HERE) as tmp:
    root = pathlib.Path(tmp)
    repo = 'https://network-failure.test/repo.git'
    environment = {
        'PATH':'/usr/bin:/bin', 'HOME':str(root), 'REPO':repo, 'COMMIT':'f'*40,
        'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_CONFIG_SYSTEM':'/dev/null',
        'GIT_CONFIG_COUNT':'2', 'GIT_CONFIG_KEY_0':'protocol.http.allow', 'GIT_CONFIG_VALUE_0':'always',
        'GIT_CONFIG_KEY_1':f'url.http://127.0.0.1:{port}/.insteadOf', 'GIT_CONFIG_VALUE_1':'https://network-failure.test/',
        'OSS_VERIFY_TOKEN_FILE':str(root/'absent-secret'),
    }
    done = subprocess.run(['/bin/sh', str(HEAD/'infra/base-builder/fetch-commit'), str(root/'checkout')], env=environment, capture_output=True, text=True, timeout=10)
    with mock.patch.dict(os.environ, environment):
        try:
            cb.resolve(repo, 'main')
        except cb.Failed as error:
            host = str(error)
        else:
            host = '<success>'
    facts = {'container_exit_code':done.returncode, 'container_calls_network_refusal_unauthorised':'fetch-commit: not authorised to read' in done.stderr, 'container_keeps_raw_connect_failure':'Failed to connect' in done.stderr or 'Could not connect' in done.stderr, 'host_preserves_connect_failure':'Failed to connect' in host or 'Could not connect' in host, 'host_calls_it_auth':'cannot read' in host}
    print(json.dumps(facts))
    (HERE/'connection-results.json').write_text(json.dumps(facts, indent=2)+'\n')
