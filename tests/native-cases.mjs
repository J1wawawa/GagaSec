import assert from 'node:assert/strict';
import {launchNative} from './native-app.mjs';
import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs/promises';
import path from 'node:path';
const localOnly=process.env.GAGA_CASE_LOCAL==='1';
const [binary, sourceRoot, output, resumeRoot] = process.argv.slice(2);
if (![binary,sourceRoot,output].every(p=>p&&path.isAbsolute(p))) throw Error('Pass absolute binary, source workspace, output paths');
await fs.mkdir(output,{recursive:true});
const root=resumeRoot||await fs.mkdtemp(path.join(output,'workspace-'));
const source=new DatabaseSync(path.join(sourceRoot,'workspace.sqlite3'),{readOnly:true});
const config=source.prepare("SELECT value FROM settings WHERE key='ai_config'").get().value;
assert.equal(JSON.parse(config).endpoint,'https://api.deepseek.com');assert.equal(JSON.parse(config).hasKey,true);
if(!resumeRoot){
  const db=new DatabaseSync(path.join(root,'workspace.sqlite3'));
  db.exec('CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)');db.prepare("INSERT INTO settings VALUES('ai_config',?)").run(config);db.close();
  await fs.cp(path.resolve('fixtures/cases'),path.join(root,'case-materials'),{recursive:true});
}
let priorRequests=0;
if(resumeRoot){
  try{const old=JSON.parse(await fs.readFile(path.join(root,'first-result.json'),'utf8'));if(old.errors.length){const name='prior-attempt-'+Date.now()+'.json';await fs.writeFile(path.join(root,name),JSON.stringify(old,null,2));}}
  catch{}
  for(const name of await fs.readdir(root))if(name.startsWith('prior-attempt-'))priorRequests+=JSON.parse(await fs.readFile(path.join(root,name),'utf8')).requestsAttempted;
}
async function runPhase(phase){
  await fs.writeFile(path.join(root,'scenario-phase.txt'),phase+'\n');
  const file=path.join(root,'native-ui-verification.json');await fs.rm(file,{force:true});
  const app=await launchNative(binary,['--scenario-ui',root]);let log='';
  const logFile=await fs.open(path.join(root,phase+'-live.log'),'w');
  for(const stream of [app.stdout,app.stderr])stream.on('data',chunk=>{log+=chunk;void logFile.appendFile(chunk);});
  try{
    let result;
    for(let i=0;i<15000;i++){
      try{result=JSON.parse(await fs.readFile(file,'utf8'));break;}catch{}
      if(app.exitCode!==null)throw Error('Native case client exited: '+log.slice(-2000));
      await new Promise(r=>setTimeout(r,100));
    }
    if(!result)throw Error('Native case timeout; inspect '+path.join(root,'ui-checkpoints.log'));
    await fs.writeFile(path.join(root,phase+'-result.json'),JSON.stringify(result,null,2));
    assert.deepEqual(result.errors,[],JSON.stringify({root,phase,errors:result.errors,checks:result.passed.length},null,2));return result;
  }finally{
    await app.stop();
    await logFile.close();await fs.writeFile(path.join(root,phase+'-process.log'),log);
  }
}
console.log(JSON.stringify({stage:'starting',root}));
const first=await runPhase(localOnly?'local':'first');
console.log(JSON.stringify({stage:'first-completed',checks:first.passed.length,officialRequests:first.requestsAttempted,root}));
const reopen=await runPhase(localOnly?'local-reopen':'reopen');
const db=new DatabaseSync(path.join(root,'workspace.sqlite3'));
assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check,'ok');assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
assert.equal(db.prepare('SELECT count(*) n FROM ai_reviews').get().n,localOnly?0:9);
assert.equal(db.prepare('SELECT count(*) n FROM ai_followups').get().n,localOnly?0:1);
assert.equal(db.prepare('SELECT count(*) n FROM node_revisions').get().n>=4,true);
assert.equal(source.prepare("SELECT value FROM settings WHERE key='ai_config'").get().value,config);
for(const c of first.cases)db.prepare('INSERT OR REPLACE INTO settings VALUES(?,?)').run('demo_case:'+c.id,'complete-synthetic-case-suite');
db.exec('PRAGMA wal_checkpoint(TRUNCATE)');db.close();source.close();
const result={format:'gaga-complete-cases/1',version:JSON.parse(await fs.readFile(new URL('../package.json',import.meta.url),'utf8')).version,root,binary,synthetic:true,localOnly,officialRequests:first.requestsAttempted+priorRequests,priorRequests,rawKeyCopied:false,metadataSourceUnchanged:true,first,reopen};
await fs.writeFile(path.join(output,localOnly?'native-cases-local.json':'native-cases.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({stage:'passed',root,firstChecks:first.passed.length,reopenChecks:reopen.passed.length,officialRequests:first.requestsAttempted+priorRequests}));
