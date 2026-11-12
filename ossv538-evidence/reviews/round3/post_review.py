import collections, datetime, hashlib, json, pathlib, re, subprocess
R=pathlib.Path(__file__).parent;H=R.parent.parent/'ossv538'
PIN='20b96cc6af84a19ced2cdff850a1afee7da0a751'
TRANSCRIPT=pathlib.Path('/home/sami/.omp/agent/sessions/-src-oss-verifier/2026-10-31T03-16-45-511Z_01a18ff5-af47-7740-8244-14ac36832af2/PrivateFetch/PrivateFetch.PrivateFetchReview3.jsonl')

def evidence():
    raw=TRANSCRIPT.read_bytes();records=[json.loads(line) for line in raw.splitlines()]
    turns=[];result_counts=collections.Counter();result_slots=0
    def prefixes(value):
        return collections.Counter(next((p for p in ('call_','fc_','toolu_') if part.startswith(p)),'other') for part in value.split('|'))
    for line,record in enumerate(records,1):
        if record.get('type')!='message':continue
        m=record.get('message',{})
        if m.get('role')=='assistant':
            counts=collections.Counter();slots=0;absent=0
            for part in m.get('content',[]):
                if part.get('type')!='toolCall':continue
                slots+=1
                if 'id' not in part:absent+=1
                else:counts.update(prefixes(part['id']))
            turns.append({'turn':len(turns)+1,'line':line,**{k:m[k] if k in m else '<absent>' for k in ('provider','api','model')},'slots':slots,'parts':dict(counts),'absent_ids':absent})
        elif m.get('role')=='toolResult':
            result_slots+=1
            if 'toolCallId' in m:result_counts.update(prefixes(m['toolCallId']))
            else:result_counts['absent']+=1
    parts=sum((collections.Counter(t['parts']) for t in turns),collections.Counter())
    absent={k:sum(t[k]=='<absent>' for t in turns) for k in ('provider','api','model')}
    meta=collections.Counter((t['provider'],t['api'],t['model']) for t in turns)
    record={'through_jsonl_line':len(records),'sha256':hashlib.sha256(raw).hexdigest(),'turns':turns,'metadata_counts':[{'provider':k[0],'api':k[1],'model':k[2],'count':v} for k,v in meta.items()],'assistant_id_components':dict(parts),'tool_result_slots':result_slots,'tool_result_components':dict(result_counts),'absent_fields':absent,'at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    (R/'posted-transcript-evidence.json').write_text(json.dumps(record,indent=2))
    text=f'''## Transcript evidence

This snapshot ends at JSONL line {len(records)}. Its SHA-256 is `{record['sha256']}`. It includes the posting invocation, but excludes later read-back and final-report turns.

I count only positional fields: `message.provider`, `.api`, and `.model` on assistant messages in `type=message` records. Tool-call IDs come only from those messages' `content` elements with `type=toolCall`. Each ID component is counted after splitting its field on `|`. No prose, arguments, or tool output contribute to the counts.

| Assistant turn | JSONL line | provider | api | model | Tool-call slots | call_ | fc_ | toolu_ |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: |
'''
    for t in turns:
        text+=f"| {t['turn']} | {t['line']} | `{t['provider']}` | `{t['api']}` | `{t['model']}` | {t['slots']} | {t['parts'].get('call_',0)} | {t['parts'].get('fc_',0)} | {t['parts'].get('toolu_',0)} |\n"
    text+='\nMetadata counts:\n'
    for k,v in meta.items():text+=f'- `provider={k[0]}`, `api={k[1]}`, `model={k[2]}`: {v} assistant turns.\n'
    text+=f'''\nAbsent assistant fields: provider {absent['provider']}, api {absent['api']}, model {absent['model']}. Assistant tool-call slots: {sum(t['slots'] for t in turns)}. ID components: `call_` {parts['call_']}, `fc_` {parts['fc_']}, `toolu_` {parts['toolu_']}, other {parts['other']}, absent IDs {sum(t['absent_ids'] for t in turns)}. The observed assistant ID shape is `call_<opaque>|fc_<opaque>`.

Separately, {result_slots} tool-result records use `message.toolCallId`: `call_` {result_counts['call_']}, `fc_` {result_counts['fc_']}, `toolu_` {result_counts['toolu_']}, other {result_counts['other']}, absent {result_counts['absent']}. These response references are not additional assistant calls.
'''
    return text

def body():
    matrix=json.loads((R/'matrix.json').read_text())
    assert len(matrix)==3 and matrix[0]['exit']==0 and matrix[1]['exit']==0 and matrix[2]['exit']!=0,matrix
    assert pathlib.Path(matrix[0]['cwd'])==R.parent.parent/'ossv538-base',matrix[0]
    text='''VERDICT: REQUEST CHANGES at 20b96cc6af84a19ced2cdff850a1afee7da0a751
Reviewed by model: openai/gpt-6.1-sol

This comment supersedes https://github.com/theorem-labs/oss-verify/pull/186#issuecomment-6814323825. I did not edit either earlier verdict. I reviewed the diff against `db31635cc7ceb774951a0495e0eb6c97d19ac981`, including the revision after `1eb1c2a`. I did not write this change.

The configured trace2 token leak, direct host helper scope, and transfer-versus-missing-commit counterexample are fixed. A token suffix still reaches the mint-failure log. The container still misreports the original 503 response as an authorization refusal. The Dockerfile guard still accepts unmounted fetches. These are specific remaining defects, not a requirement for an ideal credential path.

## Runs

`WORK` denotes the supplied checkouts' parent directory. These variables avoid machine-specific account paths:

```sh
H=$WORK/ossv538
B=$WORK/ossv538-base
R=$WORK/ossv538-scratch/review3
P=$WORK/ossv538-scratch/venv/bin/python
```

The supplied trees are pinned to the stated head and base. I ran this matrix driver from `$H`:

```sh
$P $R/run_matrix.py
```

The first driver version mistakenly used `$H` for its first leg too. That extra head/head run exits 0: `1041 passed, 677 skipped, 502 subtests passed in 323.35s (0:05:23)`. I do not count it as base evidence. I corrected the tree selection and ran only the actual baseline with:

```sh
$P $R/run_base.py
```

The three correctly assigned results are below.

'''
    labels=['Base/base','Head/head','Base code + head tests']
    for label,item in zip(labels,matrix):
        cwd={'base-base':'$B','head-head':'$H','base-head':'$R/base-code-head-tests'}[item['name']]
        args=' '.join(item['argv'][1:])
        last=item['tail'].splitlines()[-1]
        text+=f'**{label}**, cwd `{cwd}`:\n\n```sh\nenv PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P {args}\n```\n\nExit {item["exit"]}: `{last}`.\n\n'
    text+='''The negative control copies the base tree without `.git`, bytecode, or pytest caches. It overlays all four changed or added head test files: `test_private_fetch.py`, `test_check.py`, `test_print_toolchain.py`, and `test_source_pinning.py`. No head production file enters it. It **fails as required**, during collection because base lacks `check_build.SECRET_MOUNT`. This confirms an absent API, not execution of a behavioral regression assertion.

**Independent probes**, cwd `$H`:

```sh
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_network.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_parser_stream_scope.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_remaining.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_transport_markers.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_trace_routes.py
env PYTHONDONTWRITEBYTECODE=1 $P -P $R/probe_error_tail.py
env PYTHONDONTWRITEBYTECODE=1 $P -P $R/probe_docker_parser.py
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_final_edges.py
```

All eight scripts exit 0 and record the cases below. They use real Git against a loopback smart-HTTP server with synthetic credentials. The server rewrite changes only the transport and corresponding helper scope. These shell-path checks run the actual `fetch-commit` outside Docker. The additional container check below runs it inside a real BuildKit secret-mounted RUN.

Docker environment commands:

```sh
docker version --format '{{.Client.Version}} {{.Server.Version}}'
docker buildx ls
```

Both exit 0. Client/server: `29.9.3 29.9.3`. Active builder: Docker driver, BuildKit `v0.34.2`.

For each parser case, the script invokes exactly:

```sh
REVIEW2_SYNTHETIC_SECRET=synthetic-secret docker build --progress=plain --secret id=oss-verify-git-token,env=REVIEW2_SYNTHETIC_SECRET -f $R/docker-parser/Dockerfile.<case> $R/docker-parser
```

The 24 cases are `normal`, `string-only`, `heredoc-mounted`, `heredoc-text`, `network-first`, `network-last`, `mixed-fetches`, `heredoc-mixed-fetches`, `heredoc-prefix-id`, `prefix-id`, `continued-word`, `continued-field-value`, `wrapped-fetch`, `exec-fetch`, `comment-heredoc`, `arg-id`, `env-id`, `quoted-option`, `quoted-command`, `after-command`, `continued-fields`, `escape-backtick`, `copy-mount`, and `crlf`. Individual guard and BuildKit results follow below.

**Authenticated BuildKit fetch with configured trace2**, cwd `$H`:

```sh
env PYTHONDONTWRITEBYTECODE=1 TMPDIR=$R/tmp $P -P $R/probe_container_trace.py
```

The first invocation exits 1 before fetching: I used a local `sha256:...` image ID as a FROM reference, which BuildKit resolved as a registry repository. After resolving its existing local tag, the same invocation exits 0. This was a probe error, not a product failure.

The corrected run executes:

```sh
docker build --progress=plain --network=host --secret id=oss-verify-git-token,env=REVIEW3_SYNTHETIC_TOKEN --build-arg BASE=oss-verify-base-builder:580445086990b438-6a6b4816865c --build-arg REPO=https://private.test/secret.git --build-arg COMMIT=dc01a70f44e4bda08677623a38f61a8e641a755d --build-arg SERVER=http://127.0.0.1:34879/ -t ossv538-review3-container-trace -f $R/container-trace/Dockerfile $R/container-trace
docker run --rm --init --name ossv538-review3-container-trace-inspect --network=none --entrypoint sh ossv538-review3-container-trace -c 'find /review-traces -type f; test ! -e /run/secrets/oss-verify-git-token; git -C /src/review-secret rev-parse HEAD; git -C /src/review-secret remote -v'
docker history --no-trunc ossv538-review3-container-trace
docker image inspect ossv538-review3-container-trace
```

All four commands exit 0. The fetch makes three authenticated requests and checks out the requested commit. All three trace2 target files are absent. The build log, image history, and image configuration contain no synthetic token. This is not a scan of every image layer. The disposable loopback address and commit in this command belong to that run.
`REVIEW3_SYNTHETIC_TOKEN` holds the fixture token in the inherited environment, not in argv.

**Public builds**, runner cwd `$H`:

```sh
$P $R/public_builds.py
```

Exit 0. It executes the following once in `$B` and once in `$H`, replacing `<leg>` with `base` and `head` respectively:

```sh
OSS_VERIFY_GIT_TOKEN_COMMAND=/nonexistent/review2-token-command PYTHONDONTWRITEBYTECODE=1 $P tools/check --no-shell --build plain --dir $R/public-<leg> projects/cjson
```

Each build exits 0. There are zero mint lines and zero `--secret` lines in both logs. The published binary bytes match. These passing builds do not establish that all failure diagnostics or Dockerfile forms are correct.

'''
    table='## Complete BuildKit case results\n\nGuard columns say whether `check_secret_mount()` accepts the file. The fetch columns come from the command that actually runs.\n\n| Case | Private guard accepts | Public guard accepts | BuildKit exit | Fetch saw secret | Fetch lacked secret |\n| --- | --- | --- | ---: | --- | --- |\n'
    for row in json.loads((R/'docker-parser.json').read_text()):
        table+=f"| `{row['case']}` | {row['private_guard_accepted']} | {row['public_guard_accepted']} | {row['docker_exit']} | {row['saw_secret']} | {row['no_secret']} |\n"
    return text+table+'\n'+(R/'findings.md').read_text()+evidence()

if __name__=='__main__':
    comment=body();path=R/'review-comment.md';path.write_text(comment)
    assert '/mnt/nvme/' not in comment and '/home/' not in comment
    head=json.loads(subprocess.check_output(['gh','pr','view','186','-R','theorem-labs/oss-verify','--json','headRefOid,state,headRefName'],cwd=H,text=True))
    assert head['state']=='OPEN' and head['headRefOid']==PIN,head
    subprocess.run(['public-text-gate','pr','comment','186','-R','theorem-labs/oss-verify','--body-file',str(path)],cwd=H,check=True)
    result=subprocess.run(['gh','pr','comment','186','-R','theorem-labs/oss-verify','--body-file',str(path)],cwd=H,text=True,capture_output=True,check=True)
    url=result.stdout.strip();(R/'posted-comment-url.txt').write_text(url+'\n')
    print(json.dumps({'url':url,'head':head,'body_bytes':len(comment.encode()),'body_sha256':hashlib.sha256(comment.encode()).hexdigest(),'at':datetime.datetime.now(datetime.timezone.utc).isoformat()}),flush=True)
