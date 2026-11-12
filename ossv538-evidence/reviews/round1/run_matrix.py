import json
import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent
HEAD = pathlib.Path('/mnt/nvme/sami/clones/ossv538')
BASE = pathlib.Path('/mnt/nvme/sami/clones/ossv538-base')
PYTHON = '/mnt/nvme/sami/clones/ossv538-scratch/venv/bin/python'
changed_tests = ['test_private_fetch.py', 'test_check.py', 'test_print_toolchain.py', 'test_source_pinning.py']
negative = ROOT / 'base-code-head-tests'
if negative.exists():
    raise SystemExit('negative-control directory already exists')
shutil.copytree(BASE, negative, ignore=shutil.ignore_patterns('.git', '__pycache__', '.pytest_cache'))
for name in changed_tests:
    shutil.copy2(HEAD / 'tools/tests' / name, negative / 'tools/tests' / name)
print('Negative control: copied base tree without .git/caches; overlaid exactly all four added/modified test files.', flush=True)
results = []
for label, tree, selections in [
    ('base-base', BASE, ['tools/tests']),
    ('head-head', HEAD, ['tools/tests']),
    ('base-code-head-tests', negative, ['tools/tests/' + name for name in changed_tests]),
]:
    command = [PYTHON, '-P', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', *selections]
    print(f'RUN {label}: cwd={tree}; PYTHONDONTWRITEBYTECODE=1 ' + ' '.join(command), flush=True)
    with (ROOT / f'{label}.log').open('w') as log:
        completed = subprocess.run(command, cwd=tree, env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'}, stdout=log, stderr=subprocess.STDOUT)
    text = (ROOT / f'{label}.log').read_text()
    result = {'label': label, 'cwd': str(tree), 'command': command, 'environment': {'PYTHONDONTWRITEBYTECODE':'1'}, 'exit_code': completed.returncode, 'log': str(ROOT / f'{label}.log'), 'summary': text.splitlines()[-1] if text else '<empty>'}
    results.append(result)
    (ROOT / 'matrix-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(result), flush=True)
print('MATRIX COMPLETE', flush=True)
