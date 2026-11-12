import collections, datetime, hashlib, json, pathlib, subprocess
R=pathlib.Path(__file__).parent;H=pathlib.Path('/mnt/nvme/sami/clones/ossv538')
PIN='1eb1c2adcf61ed60f874a6c84367f5b174af9897'
TRANSCRIPT=pathlib.Path('/home/sami/.omp/agent/sessions/-src-oss-verifier/2026-10-31T03-16-45-511Z_01a18ff5-af47-7740-8244-14ac36832af2/PrivateFetch/PrivateFetch.PrivateFetchReview2.jsonl')

def body():
    # Parse only schema positions. Text, tool arguments and tool output never contribute counts.
    raw=TRANSCRIPT.read_bytes();records=[json.loads(line) for line in raw.splitlines()]
    turns=[];tool_results=collections.Counter();result_slots=0
    for lineno,record in enumerate(records,1):
        message=record.get('message',{})
        if record.get('type')!='message':continue
        if message.get('role')=='assistant':
            counts=collections.Counter();slots=0;missing=0
            for content in message.get('content',[]):
                if content.get('type')!='toolCall':continue
                slots+=1
                if 'id' not in content:missing+=1;continue
                for part in content['id'].split('|'):
                    counts[next((prefix for prefix in ('call_','fc_','toolu_') if part.startswith(prefix)),'other')]+=1
            turns.append({'turn':len(turns)+1,'line':lineno,**{key:message[key] if key in message else '<absent>' for key in ('provider','api','model')},'slots':slots,'parts':dict(counts),'missing_id':missing})
        elif message.get('role')=='toolResult':
            result_slots+=1
            if 'toolCallId' not in message:tool_results['absent']+=1
            else:
                for part in message['toolCallId'].split('|'):
                    tool_results[next((prefix for prefix in ('call_','fc_','toolu_') if part.startswith(prefix)),'other')]+=1
    metadata=collections.Counter((t['provider'],t['api'],t['model']) for t in turns)
    parts=sum((collections.Counter(t['parts']) for t in turns),collections.Counter())
    assert metadata=={('model-gateway-openai','openai-responses','openai/gpt-6.1-sol'):len(turns)},metadata
    absent={key:sum(t[key]=='<absent>' for t in turns) for key in ('provider','api','model')}
    snapshot={'through_jsonl_line':len(records),'sha256':hashlib.sha256(raw).hexdigest(),'turns':turns,'metadata_counts':[{'provider':k[0],'api':k[1],'model':k[2],'count':v} for k,v in metadata.items()],'assistant_id_components':dict(parts),'tool_result_slots':result_slots,'tool_result_id_components':dict(tool_results),'absent_assistant_fields':absent,'snapshot_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    (R/'posted-transcript-evidence.json').write_text(json.dumps(snapshot,indent=2))
    appendix=f'''I read my own JSONL transcript, not the launch label or the prose naming a model. The snapshot includes the posting invocation and stops at JSONL line {len(records)}, before the subsequent comment read-back. Its SHA-256 is `{snapshot['sha256']}`. The table lists every assistant message in that snapshot, in record order. Later read-back/final-report turns are outside this stated cutoff.

Fields come from `record.message.provider`, `.api`, and `.model`, only where `record.type == "message"` and `record.message.role == "assistant"`. Tool IDs come only from that message's `content` elements whose `type == "toolCall"`. I split each ID field on `|` and count component prefixes. I do not search any text, argument or output for those strings.

| Turn | JSONL line | provider | api | model | Tool-call slots | call_ components | fc_ components | toolu_ components |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: |
'''
    for t in turns:
        appendix+=f"| {t['turn']} | {t['line']} | `{t['provider']}` | `{t['api']}` | `{t['model']}` | {t['slots']} | {t['parts'].get('call_',0)} | {t['parts'].get('fc_',0)} | {t['parts'].get('toolu_',0)} |\n"
    appendix+=f'''
Aggregate: **{len(turns)} assistant messages**, all with `provider=model-gateway-openai`, `api=openai-responses`, `model=openai/gpt-6.1-sol`. Absent assistant fields: provider {absent['provider']}, api {absent['api']}, model {absent['model']}. Assistant tool-call ID slots: {sum(t['slots'] for t in turns)}. Their components: `call_` {parts['call_']}, `fc_` {parts['fc_']}, `toolu_` {parts['toolu_']}, other {parts['other']}, absent IDs {sum(t['missing_id'] for t in turns)}. The stored ID shape is `call_<opaque>|fc_<opaque>`, not `toolu_<opaque>`.

Separately, {result_slots} tool-result records have their IDs at `message.toolCallId`: `call_` {tool_results['call_']}, `fc_` {tool_results['fc_']}, `toolu_` {tool_results['toolu_']}, other {tool_results['other']}, absent {tool_results['absent']}. These are response references, not additional assistant calls. The positional fields and ID shapes establish an OpenAI Responses-family review. There is no recorded Claude-family assistant turn in this snapshot.
'''
    return (R/'review-prefix.md').read_text()+appendix

if __name__=='__main__':
    comment=body();path=R/'review-comment.md';path.write_text(comment)
    head=json.loads(subprocess.check_output(['gh','pr','view','186','-R','theorem-labs/oss-verify','--json','headRefOid,state'],cwd=H,text=True))
    assert head['state']=='OPEN' and head['headRefOid']==PIN,head
    gate=['public-text-gate','pr','comment','186','-R','theorem-labs/oss-verify','--body-file',str(path)]
    subprocess.run(gate,cwd=H,check=True)
    result=subprocess.run(['gh','pr','comment','186','-R','theorem-labs/oss-verify','--body-file',str(path)],cwd=H,capture_output=True,text=True,check=True)
    url=result.stdout.strip();print(url,flush=True)
    (R/'posted-comment-url.txt').write_text(url+'\n')
    print(json.dumps({'body_bytes':len(comment.encode()),'body_sha256':hashlib.sha256(comment.encode()).hexdigest(),'posted_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}),flush=True)
