import json, os, pathlib, subprocess, sys
R=pathlib.Path(__file__).parent
sys.path.insert(0,'/mnt/nvme/sami/clones/ossv538/tools')
import check_build as cb
context=R/'docker-parser';context.mkdir(exist_ok=True)
script=context/'fetch-commit';script.write_text('#!/bin/sh\nif [ -s /run/secrets/oss-verify-git-token ]; then echo fetch-saw-secret; else echo fetch-has-no-secret; exit 19; fi\n');script.chmod(0o755)
mount=cb.SECRET_MOUNT
prefix='FROM busybox:stable\nCOPY fetch-commit /usr/local/bin/fetch-commit\n'
cases={
'normal':f'RUN {mount} fetch-commit /src/x\n',
'string-only':f'RUN {mount} echo "fetch-commit"\nRUN fetch-commit /src/x\n',
'heredoc-mounted':f'RUN {mount} <<EOF\nfetch-commit /src/x\nEOF\n',
'heredoc-text':f'COPY <<EOF /example\nRUN {mount} fetch-commit /src/x\nEOF\nRUN fetch-commit /src/x\n',
'network-first':f'RUN --network=default {mount} fetch-commit /src/x\n',
'arg-id':f'ARG SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=$SECRET_ID fetch-commit /src/x\n',
'env-id':f'ENV SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=${{SECRET_ID}} fetch-commit /src/x\n',
'quoted-option':f'RUN "{mount}" fetch-commit /src/x\n',
'quoted-command':f'RUN {mount} "fetch-commit" /src/x\n',
'after-command':f'RUN fetch-commit /src/x {mount}\n',
'continued-fields':f'RUN --mount=type=secret,\\\nid=oss-verify-git-token fetch-commit /src/x\n',
'escape-backtick':f'RUN {mount} `\n fetch-commit /src/x\n',
'copy-mount':f'COPY {mount} fetch-commit /tmp/x\n',
'crlf':f'RUN {mount} \\\r\n  fetch-commit /src/x\r\n',
}
rows=[]
for name,tail in cases.items():
    text=('# escape=`\n' if name=='escape-backtick' else '')+prefix+'ENV REVIEW2_CASE='+name+'\n'+tail
    dockerfile=context/('Dockerfile.'+name);dockerfile.write_bytes(text.encode())
    try:cb.check_secret_mount(str(dockerfile),text,'synthetic-secret','https://example.invalid/x');accepted=True
    except cb.Failed:accepted=False
    cmd=['docker','build','--progress=plain','--secret','id=oss-verify-git-token,env=REVIEW2_SYNTHETIC_SECRET','-f',str(dockerfile),str(context)]
    done=subprocess.run(cmd,env={**os.environ,'REVIEW2_SYNTHETIC_SECRET':'synthetic-secret'},capture_output=True,text=True,timeout=60)
    output=done.stdout+done.stderr;(R/('docker-'+name+'.log')).write_text(output)
    row={'case':name,'command':'REVIEW2_SYNTHETIC_SECRET=synthetic-secret '+' '.join(cmd),'private_guard_accepted':accepted,'docker_exit':done.returncode,'saw_secret':'fetch-saw-secret' in output,'no_secret':'fetch-has-no-secret' in output,'end':output.splitlines()[-2:]}
    rows.append(row);print(json.dumps(row),flush=True)
(R/'docker-parser.json').write_text(json.dumps(rows,indent=2))
