import {isDeepStrictEqual} from 'node:util';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import crypto from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { launchNative } from './native-app.mjs';
const root=await fs.mkdtemp(path.join(os.tmpdir(),'gaga-native-workbench-'));
const binary=process.argv[2];if(!binary)throw Error('Pass an absolute debug app executable path');
await fs.writeFile(path.join(root,'native-harmless.sh'),"#!/bin/sh\nprintf 'native harmless diagnostic\\n'\nprintf 'gaga' > /tmp/native-gaga-marker\n/bin/sh -c 'cat /tmp/native-gaga-marker'\nwget -T 1 -q -O /dev/null http://192.0.2.1/ || true\nsleep 1\n");
await fs.writeFile(path.join(root,'http-valid.txt'),'GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n');
await fs.writeFile(path.join(root,'http-invalid.txt'),Buffer.from([255,254,0,128]));
await fs.writeFile(path.join(root,'http-oversize.txt'),Buffer.alloc(2*1024*1024+1,65));
await fs.writeFile(path.join(root,'ioc-input.txt'),'198.51.100.77 fixture-only.example.test');
await fs.copyFile(new URL('../src-tauri/resources/agents/gaga-agent-windows-amd64.exe',import.meta.url),path.join(root,'fixture-agent.exe'));
await fs.copyFile(new URL('../src-tauri/resources/agents/gaga-agent-linux-arm64',import.meta.url),path.join(root,'fixture-agent.elf'));
await fs.copyFile('/usr/bin/true',path.join(root,'fixture-native.macho'));
let savedScreenshot;
async function handleImageFaults(){
 if(!savedScreenshot){
  try{await fs.access(path.join(root,'ui-corrupt-request.json'));}catch{return;}
  const db=new DatabaseSync(path.join(root,'workspace.sqlite3'));
  const shot=db.prepare('SELECT id FROM screenshots ORDER BY rowid DESC LIMIT 1').get();db.close();
  if(!shot)throw Error('Missing isolated screenshot fixture');
  const file=path.join(root,'screenshots',shot.id),bytes=await fs.readFile(file);savedScreenshot={file,bytes};
  await fs.writeFile(file,Buffer.concat([bytes,Buffer.from('corruption-test')]));
  await fs.writeFile(path.join(root,'ui-corrupt-ready.txt'),'ready');
 }
 if(savedScreenshot&&!savedScreenshot.restored){
  try{await fs.access(path.join(root,'ui-restore-request.json'));}catch{return;}
  await fs.writeFile(savedScreenshot.file,savedScreenshot.bytes);savedScreenshot.restored=true;
  await fs.writeFile(path.join(root,'ui-restore-ready.txt'),'ready');
 }
}
const requests=[];const requestAuthorizations=[];let assetRevision=0;
const service=http.createServer(async(req,res)=>{
  if(req.url.startsWith('/schedule/')){res.end("<title>Scheduled local fixture</title><script src='/schedule-app.js'></script>");return;}
  if(req.url==='/schedule-app.js'){res.end('const GAGA_SCHEDULE_FIXTURE=true;');return;}
  if(req.url==='/asset'){assetRevision++;const page=`<title>Native local fixture</title><script src='/app.js'></script><a hidden href='https://hidden.example.test/${assetRevision}'>fixture</a>`;res.end(page);return;}
  if(req.url==='/app.js'){res.end(`let fixtureRevision=${assetRevision};`);return;}
  let raw='';for await(const chunk of req)raw+=chunk;
  const payload=JSON.parse(raw);requests.push(payload);requestAuthorizations.push(req.headers.authorization||'');
  let content;
  if(requests.length===1){
    const source=payload.messages[1].content.match(/可引用的来源标识[^\n]*\n([^\n]+)/)?.[1];
    content=JSON.stringify({verdict:'credible',category:'敏感路径访问线索 · 本地测试服务',confidence:60,attackSuccess:'confirmed',reasons:[{claim:'设备告警描述了敏感路径访问，但没有原始请求与响应可核对；需补充原始会话。',refs:[source]}],recommendations:['补充原始会话报文，核对请求路径与返回正文。','关联源主机访问日志，核查授权巡检工单。'],evidenceGaps:['原始会话报文','目标地址与采集时间'],mitre:[],notices:['此为本地测试服务的固定响应，用于验证传输与界面，不是外部模型分析。']});
  }else content='本地测试服务：请先补充原始请求与响应，再与主机日志和授权工单交叉核对。当前证据不足，不能确认攻击成功。';
  // Keep the first request open long enough to verify actual running progress.
  setTimeout(()=>{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({choices:[{message:{content},finish_reason:'stop'}]}));},requests.length===1?1800:120);
});
await new Promise(r=>service.listen(0,'127.0.0.1',r));
const db=new DatabaseSync(path.join(root,'workspace.sqlite3'));
db.exec('CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)');
db.prepare("INSERT OR REPLACE INTO settings VALUES('ai_config',?)").run(JSON.stringify({endpoint:`http://127.0.0.1:${service.address().port}/v1/gaga-fixture-${crypto.randomUUID()}`,model:'local-ui-test-service',hasKey:false}));const portProbe=net.createServer();await new Promise(r=>portProbe.listen(0,'127.0.0.1',r));const tlsPort=portProbe.address().port;await new Promise(r=>portProbe.close(r));
db.prepare("INSERT OR REPLACE INTO settings VALUES('collector_receiver',?)").run(JSON.stringify({bind:`127.0.0.1:${tlsPort}`,callbackUrl:`https://localhost:${tlsPort}`,certificate:''}));db.close();
const app=await launchNative(binary,['--ui-smoke',root]);
let output='';for(const source of [app.stdout,app.stderr])source.on('data',s=>{output+=s;fs.appendFile(path.join(root,'native-live.log'),s).catch(()=>{});});
const pause=ms=>new Promise(r=>setTimeout(r,ms));
let result;let callbackSent=false;let callbackStatus=null;let pendingEnvelope=null;
async function sendFixture(){
 const zip=path.join(root,'native-online-task.zip');try{await fs.access(zip)}catch{return;}
 let cfg;try{cfg=JSON.parse(execFileSync('unzip',['-p',zip,'gaga-task.json'],{encoding:'utf8',stdio:['ignore','pipe','ignore']}))}catch{return;}
 const createdAt=new Date().toISOString(),sequence=crypto.randomBytes(16).toString('hex');
 const body={format:'gaga-collection/1',taskId:cfg.taskId,kind:'ebpf',hostname:'fixed-local-fixture',os:'linux',architecture:'amd64',body:{observedPackets:5,kernelDrops:2,unparsedPackets:1,omittedFlowPackets:0,flows:[{sourceIp:'192.0.2.10',destinationIp:'203.0.113.44',sourcePort:34567,destinationPort:443,protocol:'tcp',packets:5,bytes:640}]}};
 const key=crypto.randomBytes(32),nonce=crypto.randomBytes(12);const cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(Buffer.from([cfg.taskId,sequence,createdAt].join('\n')));
 const ciphertext=Buffer.concat([cipher.update(gzipSync(JSON.stringify(body))),cipher.final(),cipher.getAuthTag()]).toString('base64');
 const envelope={format:'gaga-envelope/1',taskId:cfg.taskId,sequence,createdAt,encryptedKey:crypto.publicEncrypt({key:cfg.publicKey,oaepHash:'sha256',oaepLabel:Buffer.from('gaga-envelope/1')},key).toString('base64'),nonce:nonce.toString('base64'),ciphertext};
 envelope.mac=crypto.createHmac('sha256',Buffer.from(cfg.token,'hex')).update([envelope.taskId,sequence,createdAt,envelope.encryptedKey,envelope.nonce,ciphertext].join('\n')).digest('hex');
 const raw=pendingEnvelope||JSON.stringify(envelope);pendingEnvelope=raw;await fs.writeFile(path.join(root,'native-envelope.json'),raw);
 callbackStatus=await new Promise((resolve,reject)=>{const req=https.request(cfg.callbackUrl+'/v1/collect/'+cfg.taskId,{method:'POST',family:4,ca:cfg.certificate,headers:{Authorization:'Bearer '+cfg.token,'Content-Length':Buffer.byteLength(raw)},timeout:10000},res=>{res.resume();res.on('end',()=>resolve(res.statusCode))});req.on('error',reject);req.on('timeout',()=>req.destroy(Error('TLS fixture timeout')));req.end(raw)});
 if(callbackStatus!==202)throw Error('Receiver status '+callbackStatus);callbackSent=true;
}
for(let i=0;i<3000;i++){await handleImageFaults();if(!callbackSent){try{await sendFixture()}catch(error){await fs.appendFile(path.join(root,'callback-errors.log'),String(error)+'\n');}}try{result=JSON.parse(await fs.readFile(path.join(root,'native-ui-verification.json'),'utf8'));break;}catch{}if(app.exitCode!==null)throw Error('Native client exited: '+output.slice(-4000));await pause(100);}
await fs.writeFile(path.join(root,'native-process.log'),output);
await app.stop();
if(!result)throw Error('Native UI verification timed out: '+output.slice(-5000));
const reopened=new DatabaseSync(path.join(root,'workspace.sqlite3'));
const reviews=reopened.prepare('SELECT record FROM ai_reviews ORDER BY rowid').all().map(x=>JSON.parse(x.record));
const turns=reopened.prepare('SELECT record FROM ai_followups ORDER BY rowid').all().map(x=>JSON.parse(x.record));
const feedback=reopened.prepare('SELECT record FROM review_feedback ORDER BY rowid').all().map(x=>JSON.parse(x.record));
const runs=reopened.prepare('SELECT record FROM analysis_runs ORDER BY rowid').all().map(x=>JSON.parse(x.record));
const extra=[];const check=(name,v)=>{if(!v)throw Error(name);extra.push(name);};
if(result.errors.length)throw Error(JSON.stringify(result,null,2));
check('Actual pinned TLS fixture callback accepted',callbackSent&&callbackStatus===202);
check('Analysis followup and connection test reached actual loopback server',requests.length===3);
check('Connection test only sends a fixed short prompt',requests[2].messages.length===1&&requests[2].messages[0].content==='连接验证：请仅回复 GAGA_OK。'&&requests[2].max_tokens===2048);
check('Isolated credential was retrieved from OS keyring for the test',requestAuthorizations[2]==='Bearer gaga-isolated-test-key');
check('SQLite contains no test API key',!reopened.prepare("SELECT value FROM settings WHERE key LIKE 'ai_%'").all().some(r=>r.value.includes('gaga-isolated-test-key')));
check('Review stored exact messages sent over wire',isDeepStrictEqual(requests[0].messages,reviews[0].requestMessages));
check('Followup stored exact messages sent over wire',isDeepStrictEqual(requests[1].messages,turns[0].requestMessages));
check('All persisted native runs completed',runs.length>0&&runs.every(r=>r.state==='completed'));
check('Unexecuted retrieval has no invented duration',runs.every(r=>r.stages.filter(s=>s.status==='skipped').every(s=>s.elapsedMs===null)));
check('Probability and model success assertion were bounded',reviews[0].assessment.confidence===null&&reviews[0].assessment.attackSuccess==='unknown');
check('Feedback and followup survive database reopen',feedback.length===1&&turns.length===1);
reopened.close();
let schedulerVerification;
if(result.passed.includes('Ten scheduled assets are actually registered and enabled')){
 const background=await launchNative(binary,['--workspace',root]);
 let backgroundLog='';for(const stream of [background.stdout,background.stderr])stream.on('data',s=>backgroundLog+=s);
 const reader=new DatabaseSync(path.join(root,'workspace.sqlite3'),{readOnly:true});
 const totals=()=>reader.prepare("SELECT count(*) n FROM monitor_snapshots s JOIN monitor_assets a ON a.id=s.asset_id WHERE json_extract(a.record,'$.url') LIKE '%/schedule/%'").get().n;
 const started=Date.now();let firstAt,secondAt;
 try{
  while(Date.now()-started<85000){
   const n=totals();if(n>=10&&!firstAt)firstAt=Date.now()-started;
   if(n>=20){secondAt=Date.now()-started;break;}
   if(background.exitCode!==null||!background.diagnostics().clientAlive)throw Error('Background client exited: '+JSON.stringify(background.diagnostics())+' '+backgroundLog.slice(-1500));
   await pause(250);
  }
  if(!firstAt||!secondAt)throw Error('Ten actual scheduled assets did not run twice: '+totals());
  const rows=reader.prepare("SELECT s.record FROM monitor_snapshots s JOIN monitor_assets a ON a.id=s.asset_id WHERE json_extract(a.record,'$.url') LIKE '%/schedule/%'").all().map(r=>JSON.parse(r.record));
  if(rows.some(r=>r.status!==200||r.error||!r.scripts.some(s=>s.sha256)))throw Error('Scheduled HTML / JS fetch failed');
  schedulerVerification={actualBackgroundClient:true,assets:10,minimumRounds:2,snapshots:rows.length,firstRoundMs:firstAt,secondRoundMs:secondAt,intervalSeconds:60,allHttp200AndJsHashed:true,externalAiCalled:false};
 }finally{reader.close();await background.stop();await fs.writeFile(path.join(root,'scheduler-native.log'),backgroundLog);}
}
service.close();
const summary={...result,root,schedulerVerification,encryptedCallbackStatus:callbackStatus,ebpfKernelTested:false,persistenceChecks:extra,requestCount:requests.length,externalModelTested:false};
await fs.writeFile(path.join(root,'investigation-verification.json'),JSON.stringify(summary,null,2));
console.log(JSON.stringify(summary,null,2));
