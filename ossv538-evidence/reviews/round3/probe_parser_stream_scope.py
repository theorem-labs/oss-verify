import contextlib, datetime, importlib.machinery, importlib.util, io, json, os, pathlib, re, subprocess, sys, tempfile, types
from unittest import mock
R=pathlib.Path(__file__).parent
H=pathlib.Path('/mnt/nvme/sami/clones/ossv538'); B=pathlib.Path('/mnt/nvme/sami/clones/ossv538-base')
sys.path[:0]=[str(H/'tools'),str(H/'tools/tests')]
import check_build as cb
import test_private_fetch as pf
import test_check as tc
rows=[]
def note(name,**kw):
    row={'probe':name,**kw}; rows.append(row); print(json.dumps(row),flush=True)
def load(name,p):
    loader=importlib.machinery.SourceFileLoader(name,str(p)); spec=importlib.util.spec_from_loader(name,loader); m=importlib.util.module_from_spec(spec);sys.modules[name]=m;loader.exec_module(m);return m
old=load('review2_base',B/'tools/check_build.py')
mount=cb.SECRET_MOUNT
cases={
'normal':f'RUN {mount} fetch-commit /src/x\n',
'comment':f'# RUN {mount} fetch-commit /src/x\nRUN fetch-commit /src/x\n',
'after-command':f'RUN fetch-commit /src/x {mount}\n',
'quoted-option':f'RUN "{mount}" fetch-commit /src/x\n',
'quoted-command':f'RUN {mount} "fetch-commit" /src/x\n',
'string-only':f'RUN {mount} echo "fetch-commit"\nRUN fetch-commit /src/x\n',
'inline-comment':f'RUN {mount} true # fetch-commit\nRUN fetch-commit /src/x\n',
'mixed-fetches':f'RUN {mount} fetch-commit /src/x\nRUN fetch-commit /src/y\n',
'arg-id':f'ARG SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=$SECRET_ID fetch-commit /src/x\n',
'env-id':f'ENV SECRET_ID=oss-verify-git-token\nRUN --mount=type=secret,id=${{SECRET_ID}} fetch-commit /src/x\n',
'arg-command':f'ARG FETCH=fetch-commit\nRUN {mount} $FETCH /src/x\n',
'network-option-first':f'RUN --network=default {mount} fetch-commit /src/x\n',
'heredoc-mounted':f'RUN {mount} <<EOF\nfetch-commit /src/x\nEOF\n',
'heredoc-text':f'COPY <<EOF /example\nRUN {mount} fetch-commit /src/x\nEOF\nRUN fetch-commit /src/x\n',
'syntax-directive':f'# syntax=docker/dockerfile:1\nRUN {mount} fetch-commit /src/x\n',
'crlf':f'RUN {mount} \\\r\n  fetch-commit /src/x\r\n',
'escape-backtick':f'# escape=`\nRUN {mount} `\n fetch-commit /src/x\n',
'copy-mount':f'COPY {mount} fetch-commit /src/x\n',
'continued-mount-fields':f'RUN --mount=type=secret,\\\nid=oss-verify-git-token fetch-commit /src/x\n',
'unmatched-shell-quote':'RUN echo "\n',
}
for name,text in cases.items():
    answers={}
    for private in (False,True):
        try: cb.check_secret_mount('Dockerfile',text,pf.TOKEN if private else None,'https://github.com/theorem-labs/theorem-cli')
        except Exception as e: answers['private' if private else 'public']={'accepted':False,'exception':type(e).__name__,'reason':str(e).splitlines()[0]}
        else: answers['private' if private else 'public']={'accepted':True}
    note('parser-'+name,text=text,**answers)
# Exercise the real copy thread, controlling the kernel-read boundaries rather than relying on a sleep.
class Pipe:
    def fileno(self):return 123
    def close(self):pass
def stream(chunks,token):
    proc=types.SimpleNamespace(stdout=Pipe(),wait=lambda:0); out=io.StringIO()
    with mock.patch.object(cb.subprocess,'Popen',return_value=proc), mock.patch.object(cb.os,'read',side_effect=[*chunks,b'']),contextlib.redirect_stdout(out):
        code=cb.run('synthetic-output',token=token)
    return code,out.getvalue()
for token in (pf.TOKEN,'ghs_'+'Z'*386,'redacted','abababa'):
    bad=[]
    for split in range(1,len(token)):
        _,said=stream([('prefix|'+token[:split]).encode(),(token[split:]+'|end').encode()],token)
        if said!='prefix|<redacted>|end':bad.append(split)
    note('stream-every-position',token_length=len(token),positions=len(token)-1,incorrect_positions=bad)
_,said=stream([bytes([b]) for b in ('prefix|'+pf.TOKEN+'|end').encode()],pf.TOKEN)
note('stream-one-byte-reads',exact=said=='prefix|<redacted>|end')
raw=('public '+pf.TOKEN+' euro €\n').encode(); _,said=stream([raw[:3],raw[3:-2],raw[-2:]],None)
note('public-stream-byte-identity',exact=said.encode()==raw)
note('anonymous-git-byte-identity',host=cb.git('ls-remote','--','https://example.invalid/x')==old.git('ls-remote','--','https://example.invalid/x'),container=re.search(r'^git\(\).*$',(B/'infra/base-builder/fetch-commit').read_text(),re.M).group()==re.search(r'^git\(\).*$',(H/'infra/base-builder/fetch-commit').read_text(),re.M).group())
# Real helper protocol, synthetic token only.
for name,host,path,protocol in [('same','github.com','theorem-labs/theorem-cli','https'),('other-path','github.com','theorem-labs/other','https'),('other-host','other.invalid','theorem-labs/theorem-cli','https'),('port','github.com:443','theorem-labs/theorem-cli','https'),('case-host','GITHUB.COM','theorem-labs/theorem-cli','https'),('case-path','github.com','Theorem-Labs/Theorem-CLI','https'),('trailing-slash','github.com','theorem-labs/theorem-cli/','https'),('dotgit-slash','github.com','theorem-labs/theorem-cli.git/','https'),('no-path','github.com',None,'https'),('http-protocol','github.com','theorem-labs/theorem-cli','http')]:
    request=f'protocol={protocol}\nhost={host}\n'+(f'path={path}\n' if path is not None else '')+'\n'
    done=subprocess.run(['sh',str(pf.HELPER),'get'],input=request,text=True,capture_output=True,env={'PATH':os.environ['PATH'],'OSS_VERIFY_GIT_TOKEN':pf.TOKEN,'OSS_VERIFY_TOKEN_REPO':'github.com/theorem-labs/theorem-cli'})
    note('helper-'+name,exit=done.returncode,answered=pf.TOKEN in done.stdout)
# Cache dependency tested with its actual implementation, a synthetic broker and isolated cache.
helper=load('review2_gh_token',pathlib.Path('/home/sami/.dotfiles/shims/gh-app-token'))
for lifetime in (1800,3600):
    with tempfile.TemporaryDirectory(dir=R) as tmp:
        cache=pathlib.Path(tmp);calls=[]
        def broker(secret,owner,scope):
            calls.append(scope);return {owner:{'installation_id':1,'token':pf.TOKEN+str(len(calls)),'expires_at':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
        def config(key):return None if key.endswith('key-secret') else 'synthetic'
        with mock.patch.object(helper,'CACHE_DIR',cache),mock.patch.object(helper,'git_config',config),mock.patch.object(helper,'git_config_optional',config),mock.patch.object(helper,'request_broker_installations',broker),mock.patch.object(helper,'remember_covered_owners'),contextlib.redirect_stderr(io.StringIO()):
            scope=helper.scope_of(['theorem-cli'],True)
            a=helper.get_token('agent','theorem-labs',lifetime,scope);b=helper.get_token('agent','theorem-labs',lifetime,scope)
            c=helper.get_token('different-profile','theorem-labs',lifetime,scope)
            files=list(cache.glob('*.json'))
        note('mint-cache',minimum=lifetime,same_build_equivalent_token=a==b,broker_calls=len(calls),cache_files=len(files),modes=[oct(p.stat().st_mode&0o777) for p in files],scope=scope)
# Public CLI never invokes mint; private --twice invokes it twice. Builds are stubbed, CLI is not.
for repo in ('https://github.com/DaveGamble/cJSON','https://github.com/theorem-labs/oss-verify','https://github.com/theorem-labs/theorem-cli'):
    f=tc.Project(methodName='runTest');f.setUp()
    try:
        p=f.project/'project.yaml';p.write_text(p.read_text().replace('https://example.org/demo',repo))
        tokens=[]
        def build_all(job,commit,work,*args,**kw):
            tokens.append(kw.get('token'));tc.binaries(work/'out',tc.FIRST);return 'builder','project',['demo_fuzzer'],tc.FIRST
        with mock.patch.object(cb,'mint_token',side_effect=[pf.TOKEN,pf.OTHER_TOKEN]) as mint,mock.patch.dict(os.environ,{cb.TOKEN_COMMAND_ENV:'/nonexistent/review2-token-command'}):
            code,said,err=f.main(['--twice'],build_all)
        note('cli-twice',repo=repo,exit=code,mint_calls=mint.call_count,builds=len(tokens),tokens_differ=len(tokens)==2 and tokens[0]!=tokens[1])
    finally:f.doCleanups()
# Overrides are a trust requirement, not enforced freshness.
with tempfile.TemporaryDirectory(dir=R) as tmp:
    cmd=pathlib.Path(tmp)/'fixed-token';cmd.write_text('#!/bin/sh\nprintf %s '+pf.TOKEN+'\n');cmd.chmod(0o700)
    with mock.patch.dict(os.environ,{cb.TOKEN_COMMAND_ENV:str(cmd)}):
        note('custom-command-reuses',same=cb.mint_token('https://github.com/theorem-labs/theorem-cli')==cb.mint_token('https://github.com/theorem-labs/theorem-cli'))
(R/'parser-stream-scope.json').write_text(json.dumps(rows,indent=2))
