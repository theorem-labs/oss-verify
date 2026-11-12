import contextlib, datetime, importlib.machinery, importlib.util, io, json, os, pathlib, subprocess, sys, tempfile
from unittest import mock
R=pathlib.Path(__file__).parent;H=pathlib.Path('/mnt/nvme/sami/clones/ossv538')
sys.path[:0]=[str(H/'tools'),str(H/'tools/tests')]
import check_build as cb
import test_private_fetch as pf
rows=[]
def note(name,**kw):
    row={'probe':name,**kw};rows.append(row);print(json.dumps(row),flush=True)
# Get Git itself to parse the URL and form the helper request.
with tempfile.TemporaryDirectory(dir=R) as tmp:
    root=pathlib.Path(tmp);wrapper=root/'helper';record=root/'request'
    wrapper.write_text('#!/usr/bin/python3\nimport pathlib,os,subprocess,sys\nr=sys.stdin.read();pathlib.Path(os.environ["REQUEST_FILE"]).write_text(r)\np=subprocess.run(["sh",'+repr(str(pf.HELPER))+',*sys.argv[1:]],input=r,text=True);sys.exit(p.returncode)\n');wrapper.chmod(0o700)
    for usepath in (False,True):
        for url in ('https://github.com/theorem-labs/theorem-cli','https://github.com/theorem-labs/theorem-cli/','https://github.com/theorem-labs/theorem-cli.git/','https://GITHUB.COM/theorem-labs/theorem-cli','https://github.com/Theorem-Labs/Theorem-CLI','https://github.com:443/theorem-labs/theorem-cli','https://user@github.com/theorem-labs/theorem-cli','https://github.com/theorem-labs/some-other-repo'):
            want=cb.normalised_repo(url).partition('://')[2] if 'some-other' not in url else 'github.com/theorem-labs/theorem-cli'
            env={'PATH':'/usr/bin:/bin','HOME':tmp,'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','OSS_VERIFY_GIT_TOKEN':pf.TOKEN,'OSS_VERIFY_TOKEN_REPO':want,'REQUEST_FILE':str(record)}
            cmd=['git','-c','credential.helper=','-c','credential.helper=!'+str(wrapper),'-c','credential.useHttpPath='+str(usepath).lower(),'credential','fill']
            done=subprocess.run(cmd,input='url='+url+'\n\n',env=env,capture_output=True,text=True,cwd=H)
            note('git-credential-url',useHttpPath=usepath,url=url,want=want,exit=done.returncode,answered=pf.TOKEN in done.stdout,request=record.read_text(),listed_private=cb.private_reason(url) is not None)
# Real Git errors, not guessed strings: invalid CA filename contains an auth marker.
for repo,extra in [('https://not-found.invalid/x',{}),('https://repository-not-found.invalid/x',{}),('https://github.com/theorem-labs/theorem-cli',{'GIT_SSL_CAINFO':str(R/'permission denied.pem')})]:
    env={'HOME':str(R),'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','NO_PROXY':'*','no_proxy':'*','GIT_TERMINAL_PROMPT':'0',**extra}
    with mock.patch.dict(os.environ,env),contextlib.redirect_stdout(io.StringIO()) as printed:
        try: cb.clone(repo,'a'*40,R/'collision-checkout',pf.TOKEN)
        except cb.Failed as e:message=str(e)
        else:message='success'
    note('real-marker-collision',repo=repo,auth_classified='cannot read' in message,message=message,raw=printed.getvalue())
# Shell redaction of both streams and a replacement-name token, using controlled Git output only.
with tempfile.TemporaryDirectory(dir=R) as tmp:
    root=pathlib.Path(tmp);fake=root/'git';secret=root/'token'
    fake.write_text('#!/usr/bin/python3\nimport os,pathlib,sys\nif "fetch" in sys.argv:\n t=pathlib.Path(os.environ["OSS_VERIFY_TOKEN_FILE"]).read_text();print("out|"+t+"|end");print("err|"+t+"|end",file=sys.stderr);sys.exit(1)\nif "ls-remote" in sys.argv:sys.exit(1)\nsys.exit(0)\n');fake.chmod(0o700)
    for token in (pf.TOKEN,'redacted','secret*?[abc]$;`"\\value'):
        secret.write_text(token)
        done=subprocess.run(['sh',str(pf.FETCH_COMMIT),str(root/'checkout')],env={'PATH':str(root)+':/usr/bin:/bin','REPO':'https://example.invalid/x','COMMIT':'a'*40,'OSS_VERIFY_TOKEN_FILE':str(secret)},capture_output=True,text=True,timeout=4,cwd=H)
        note('shell-both-streams',token_length=len(token),exit=done.returncode,exact_original_output_absent=('out|'+token+'|end') not in done.stdout+done.stderr and ('err|'+token+'|end') not in done.stdout+done.stderr,redacted_stdout='out|<redacted>|end' in done.stderr,redacted_stderr='err|<redacted>|end' in done.stderr)
# Default wrapper's actual lifetime setting, via a synthetic executable at the dependency boundary.
with tempfile.TemporaryDirectory(dir=R) as tmp:
    root=pathlib.Path(tmp);fake=root/'gh-app-token';fake.write_text('#!/bin/sh\nprintf "%s\\n" "$GH_APP_TOKEN_MIN_LIFETIME|$*"\n');fake.chmod(0o700)
    done=subprocess.run([str(H/'infra/github-read-token'),'theorem-labs','theorem-cli'],env={'PATH':str(root)+':/usr/bin:/bin','GH_APP_TOKEN_MIN_LIFETIME':'1'},capture_output=True,text=True,cwd=H)
    note('default-wrapper',exit=done.returncode,dependency_received=done.stdout.strip())
# The cached-expiry comparison uses the client's wall clock, so "cannot ever" is conditional on it.
loader=importlib.machinery.SourceFileLoader('review2_mint_skew','/home/sami/.dotfiles/shims/gh-app-token');spec=importlib.util.spec_from_loader('review2_mint_skew',loader);helper=importlib.util.module_from_spec(spec);loader.exec_module(helper)
with tempfile.TemporaryDirectory(dir=R) as tmp:
    calls=[]
    class Behind(datetime.datetime):
        @classmethod
        def now(cls,tz=None):return datetime.datetime.now(tz)-datetime.timedelta(seconds=60)
    def broker(secret,owner,scope):
        calls.append(scope);return {owner:{'installation_id':1,'token':pf.TOKEN+str(len(calls)),'expires_at':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()}}
    def config(key):return None if key.endswith('key-secret') else 'synthetic'
    with mock.patch.object(helper,'CACHE_DIR',pathlib.Path(tmp)),mock.patch.object(helper,'git_config',config),mock.patch.object(helper,'git_config_optional',config),mock.patch.object(helper,'request_broker_installations',broker),mock.patch.object(helper,'remember_covered_owners'),mock.patch.object(helper,'datetime',Behind),contextlib.redirect_stderr(io.StringIO()):
        scope=helper.scope_of(['theorem-cli'],True);a=helper.get_token('agent','theorem-labs',3600,scope);b=helper.get_token('agent','theorem-labs',3600,scope)
    note('mint-client-clock-behind',clock_behind_seconds=60,mint_calls=len(calls),reused=a==b)
(R/'remaining.json').write_text(json.dumps(rows,indent=2))
