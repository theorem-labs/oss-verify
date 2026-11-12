import json, pathlib, sys, urllib.error, urllib.request
R=pathlib.Path(__file__).parent;sys.path.insert(0,'/mnt/nvme/sami/clones/ossv538/tools');import check_build as cb
rows=[]
for name,other in [('cjson-ossv267','theorem-cli'),('theorem-cli','cjson-ossv267')]:
    token=cb.mint_token('https://github.com/theorem-labs/'+name)
    def get(path):
        req=urllib.request.Request('https://api.github.com/'+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        try:
            with urllib.request.urlopen(req,timeout=20) as response:return response.status,json.load(response)
        except urllib.error.HTTPError as e:return e.code,None
    status,data=get('installation/repositories')
    own_status,own=get('repos/theorem-labs/'+name)
    other_status,_=get('repos/theorem-labs/'+other)
    row={'repository':name,'installation_repositories_status':status,'total_count':data.get('total_count') if data else None,'only_expected_repository':bool(data and [r['full_name'] for r in data.get('repositories',[])]==['theorem-labs/'+name]),'own_repository_status':own_status,'own_permissions':own.get('permissions','<absent>') if own else '<no body>','other_private_repository_status':other_status}
    rows.append(row);print(json.dumps(row),flush=True)
(R/'actual-token-scope.json').write_text(json.dumps(rows,indent=2))
