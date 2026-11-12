import json, os, pathlib, subprocess, sys
from unittest import mock
R=pathlib.Path(__file__).parent;sys.path.insert(0,'/mnt/nvme/sami/clones/ossv538/tools');import check_build as cb
rows=[]
token='ghs_'+''.join(str(i%10) for i in range(386))
script='import sys;sys.stderr.write('+repr(token+'x'*1400)+');sys.exit(1)'
child=R/'emit-synthetic-error.py';child.write_text(script)
try:cb.output(sys.executable,str(child),token=token)
except cb.Failed as e:
    text=str(e);rows.append({'probe':'known-token-error-tail','token_length':len(token),'leaked_token_suffix_characters':100 if token[-100:] in text else 0,'complete_token_present':token in text,'redaction_marker_present':'<redacted>' in text})
with mock.patch.dict(os.environ,{cb.TOKEN_COMMAND_ENV:sys.executable+' -c '+__import__('shlex').quote('import sys;sys.stderr.write('+repr(token+'x'*900)+');sys.exit(1)')}):
    try:cb.mint_token('https://github.com/theorem-labs/theorem-cli')
    except cb.Failed as e:
        text=str(e);rows.append({'probe':'token-command-error-tail','leaked_token_suffix_characters':100 if token[-100:] in text else 0,'complete_token_present':token in text,'redaction_marker_present':'<redacted>' in text})
for r in rows:print(json.dumps(r),flush=True)
(R/'error-tail.json').write_text(json.dumps(rows,indent=2))
