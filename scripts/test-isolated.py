"""Benign container and Pi protocol checks. No malware or model credentials."""
import hashlib, json, pathlib, struct, subprocess, sys, uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=pathlib.Path(sys.argv[1]);OUT.mkdir(parents=True,exist_ok=True)
IMAGE='gaga-analysis:0.9.0'; passed=[]
def check(name, condition):
    if not condition: raise AssertionError(name)
    passed.append(name)
def base(entry):
    return ['docker','run','--rm','-i','--name','gaga-analysis-test-'+uuid.uuid4().hex,'--label','team.j4.gaga.test=0.9.0','--network','none','--read-only','--user','65534:65534','--cap-drop','ALL','--security-opt','no-new-privileges=true','--pids-limit','64','--memory','768m','--cpus','1','--ipc','none','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=192m,mode=1777','--entrypoint',entry,IMAGE]
script=b'<?php\n// Inert fixture: never execute this source.\nif (false) { eval(base64_decode($_POST["test"])); }\necho "GAGA_BENIGN_FIXTURE";\n'
# Known, inert x86-64 ELF with one file-backed segment, never executed.
elf=bytearray(512);elf[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
struct.pack_into('<HHIQQQIHHHHHH',elf,16,2,62,1,0x400100,64,0,0,64,56,1,0,0,0)
struct.pack_into('<IIQQQQQQ',elf,64,1,5,0,0x400000,0x400000,512,512,0x1000)
elf[256:260]=b'\x48\x31\xc0\xc3';elf[300:319]=b'GAGA_BENIGN_FIXTURE'
(OUT/'inert-source.php').write_bytes(script);(OUT/'inert-x64.elf').write_bytes(elf)
def tool(data,kind,op,params={},ok=True):
    p=subprocess.run(base('gaga-static-worker')+[kind,op,json.dumps(params)],input=data,capture_output=True,timeout=50)
    if not ok:
        check('Denied '+op+' '+str(params),p.returncode!=0);return
    if p.returncode:raise RuntimeError(p.stderr.decode())
    value=json.loads(p.stdout);check('Current worker protocol '+op,value.get('protocol')=='gaga-static/2');check('Hash verified '+op, value['sha256']==hashlib.sha256(data).hexdigest());return value
r=tool(script,'webshell','metadata');check('Static rules preserve source line and context',r['report']['findings'][0]['line']==3 and any(d['label']=='脚本上下文' for d in r['report']['details']))
anti=b'<?php\n// IsDebuggerPresent VMware SleepEx\necho \'benign\';'
r=tool(anti,'webshell','metadata');anti_view=json.loads(next(d['value'] for d in r['report']['details'] if d['label']=='反分析覆盖与线索'));check('Anti-analysis markers in comments remain unverified with exact offsets',anti_view['dynamicEvasion']=='未验证' and anti_view['evidence'][0]['line']==2 and anti_view['evidence'][0]['fileOffset']=='0x9' and not r['report']['findings'])
r=tool(script,'webshell','read_source',{'startLine':3,'count':1});check('Source slicing returns exact original line',r['lines']==[{'line':3,'text':script.decode().splitlines()[2]}])
r=tool(elf,'binary','metadata');check('Known inert ELF header parsed',r['report']['metrics'][0]['value']=='ELF')
r=tool(elf,'binary','disassemble',{'entryOffset':0,'count':2});check('WASM x64 decode preserves address, file offset and instructions',r['instructions'][0]['address']=='0x400100' and r['instructions'][0]['fileOffset']=='0x100' and 'xor' in r['instructions'][0]['text'] and r['instructions'][1]['text']=='ret')
r=tool(elf,'binary','search_strings',{'query':'GAGA_BENIGN'});check('String search returns offset',r['strings'][0]['fileOffset']=='0x12c')
tool(script,'webshell','read_source',{'startLine':0,'count':1},False)
tool(script,'webshell','read_source',{'startLine':1,'count':121},False)
tool(elf,'binary','read_source',{},False)
tool(elf,'binary','disassemble',{'entryOffset':16385,'count':2},False)
tool(elf,'binary','bash',{},False)
# Regression: match the full byte run before clipping its presentation.
long_run=b'\0'*3+b'A'*900+b'Needle.IOC'+b'Z'*400
r=tool(long_run,'binary','search_strings',{'query':'needle.ioc'})
check('Long ASCII tail retains a matching context and exact byte offsets',r['strings'][0]['matchOffset']=='0x387' and r['strings'][0]['fileOffset']=='0x337' and 'Needle.IOC' in r['strings'][0]['text'] and r['strings'][0]['truncated'])
r=tool(b'Needle\0'*101,'binary','search_strings',{'query':'needle'})
check('String coverage exposes omitted matches',len(r['strings'])==100 and r['matchedRuns']==101 and r['omittedMatches']==1)
r=tool(('汉'*1300+'\nlast').encode(),'webshell','read_source',{'startLine':1,'count':2})
check('Clipped source lines expose truncation without losing following lines',r['truncated'] and r['lines'][0]['truncated'] and r['lines'][1]['text']=='last')
tool(script,'webshell','read_source',{'startLine':'1','count':1},False)
tool(script,'webshell','search_strings',{'query':42},False)
tool(script,'webshell','metadata',{'path':'/etc/passwd'},False)
overflow=bytearray(elf);struct.pack_into('<Q',overflow,64+32,2**64-1)
tool(overflow,'binary','disassemble',{'entryOffset':0,'count':2},False)
tool(elf,'binary','disassemble',{'entryOffset':300,'count':2},False)
probe="""import fs from 'node:fs';import net from 'node:net';
let rootWritable=true;try{fs.writeFileSync('/opt/gaga/probe','x')}catch{rootWritable=false}
const network=await new Promise(r=>{const s=net.connect({host:'1.1.1.1',port:443});s.setTimeout(1000);s.on('connect',()=>{s.destroy();r(true)});s.on('error',()=>r(false));s.on('timeout',()=>{s.destroy();r(false)})});
console.log(JSON.stringify({uid:process.getuid(),rootWritable,network,socket:fs.existsSync('/var/run/docker.sock'),sample:fs.existsSync('/tmp/sample'),key:!!(process.env.OPENAI_API_KEY||process.env.DEEPSEEK_API_KEY)}));"""
p=subprocess.run(base('node')+['--input-type=module','-e',probe],capture_output=True,timeout=20)
check('Agent container has no network, key, sample or Docker socket and cannot write root',json.loads(p.stdout)=={'uid':65534,'rootWritable':False,'network':False,'socket':False,'sample':False,'key':False})
# Exercise the actual Pi SDK with controller-provided synthetic SSE tool calls.
p=subprocess.Popen(base('node')+['/opt/gaga/agent.mjs'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def send(v):p.stdin.write(json.dumps(v)+'\n');p.stdin.flush()
send({'endpoint':'https://api.deepseek.com','model':'deepseek-chat','name':'inert-source.php','sha256':hashlib.sha256(script).hexdigest(),'kind':'webshell','question':'synthetic SDK transport check'})
models=0;tools=[];messages=[]
try:
    for line in p.stdout:
        v=json.loads(line);messages.append(v)
        if v['kind']=='ready':check('Pi enables exactly four controlled tools',v.get('protocol')=='gaga-pi/2' and v['tools']==['read_metadata','read_source','search_strings','disassemble'])
        elif v['kind']=='model':
            models+=1;body=v['body'];check('Pi model request has no real credential', 'gaga-stdio' not in json.dumps(body))
            if models<=2:
                name='read_metadata' if models==1 else 'read_source';args={} if models==1 else {'startLine':3,'count':1}
                delta={'role':'assistant','tool_calls':[{'index':0,'id':'call'+str(models),'type':'function','function':{'name':name,'arguments':json.dumps(args)}}]};finish='tool_calls'
            else:delta={'role':'assistant','content':'合成验证完成：第 3 行位于 if(false) 分支；静态工具未执行样本。'};finish='stop'
            chunks=[{'id':'test','object':'chat.completion.chunk','model':'deepseek-chat','choices':[{'index':0,'delta':delta,'finish_reason':None}]},{'id':'test','choices':[{'index':0,'delta':{},'finish_reason':finish}]}]
            sse=''.join('data: '+json.dumps(c)+'\n\n' for c in chunks)+'data: [DONE]\n\n'
            send({'id':v['id'],'result':{'status':200,'contentType':'text/event-stream','body':sse}})
        elif v['kind']=='tool':
            tools.append(v['tool']);value=tool(script,'webshell','metadata' if v['tool']=='read_metadata' else 'read_source',v['params']);send({'id':v['id'],'result':value})
        elif v['kind']=='done':check('Pi completes tool → model loop with grounded text',tools==['read_metadata','read_source'] and '第 3 行' in v['text']);break
        elif v['kind']=='error':raise RuntimeError(v['error'])
    p.stdin.close();p.wait(timeout=15);check('Pi exits cleanly',p.returncode==0)
finally:
    if p.poll() is None:p.kill();p.wait()
    (OUT/'pi-protocol.json').write_text(json.dumps(messages,ensure_ascii=False,indent=2))
(OUT/'container-checks.json').write_text(json.dumps({'passed':passed,'errors':[],'realModelCalled':False,'samplesExecuted':False},ensure_ascii=False,indent=2))
print(json.dumps({'passed':len(passed),'output':str(OUT)},ensure_ascii=False))
