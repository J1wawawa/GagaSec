// Reproducible, no malware download or live credentials. Physical 1 GiB log, not a sparse file.
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn, execFileSync} from 'node:child_process';

const [binary, destination] = process.argv.slice(2);
if (!binary || !destination) throw Error('Usage: node tests/field-exercise.mjs /absolute/debug-executable /absolute/new-output-directory');
const base=path.resolve(destination);await fs.mkdir(base,{recursive:false});
const fixtures=path.join(base,'fixtures');await fs.mkdir(fixtures);
const image='gaga-field-fixture:0.7.0';
// Build tests/field-fixture.Dockerfile first. No unrelated project image or web service is used.
execFileSync('docker',['image','inspect',image],{stdio:'ignore'});
execFileSync('docker',['image','inspect','gaga-observer:0.1.0'],{stdio:'ignore'});
await fs.writeFile(path.join(fixtures,'disabled-webshell.php'),`<?php
// J4team inert training fixture: no request execution, all signatures are comments.
echo "GAGA_DISABLED_WEBSHELL_FIXTURE\\n";
exit(0);
/* Static-only signatures; these lines cannot execute:
eval(base64_decode($_POST['fixture']));
system($_REQUEST['fixture']);
*/
`);
await fs.writeFile(path.join(fixtures,'benign.php'),'<?php\necho "GAGA_BENIGN_CONTROL\\n";\n');
await fs.writeFile(path.join(fixtures,'harmless-diagnostic.sh'),`#!/bin/sh
printf 'GAGA harmless container diagnostic\\n'
printf 'gaga-field-marker' > /tmp/gaga-field-marker
/bin/sh -c 'cat /tmp/gaga-field-marker'
wget -T 1 -q -O /dev/null http://192.0.2.1/ || true
sleep 1
`);

async function logFixture(name,minimumBytes,system){
 const handle=await fs.open(path.join(fixtures,name),'wx');const hash=crypto.createHash('sha256');let bytes=0,lines=0,parsed=0,hits=0;
 const push=async(text,lineCount,parsedCount,hitCount)=>{const chunk=Buffer.isBuffer(text)?text:Buffer.from(text);await handle.write(chunk);hash.update(chunk);bytes+=chunk.length;lines+=lineCount;parsed+=parsedCount;hits+=hitCount;};
 const padding='f'.repeat(165);const baseline=system?`Oct 27 10:20:00 lab systemd[1]: GAGA generated heartbeat fixture ${padding}\n`:`192.0.2.10 - - [27/Oct/2026:10:20:00 +0800] "GET /health HTTP/1.1" 200 12 "-" "GAGA generated fixture ${padding}"\n`;
 const malicious=system?'Oct 27 10:21:00 lab sshd[12]: Failed password for invalid user admin from 203.0.113.44 port 40222 ssh2\n':'203.0.113.44 - - [27/Oct/2026:10:21:00 +0800] "GET /uploads/cache.php HTTP/1.1" 200 12 "-" "GAGA fixture"\n';
 const block=baseline.repeat(4095)+malicious;const blockBuffer=Buffer.from(block);
 while(bytes<minimumBytes)await push(blockBuffer,4096,4096,1);
 // Include late, scarce authentication evidence after hundreds of repeated detections.
 const lateSuccessLine=lines+1;
 await push('2026-10-27T10:33:00+08:00 lab sshd[18]: Accepted publickey for analyst from 2001:db8::42 port 40223 ssh2\n',1,1,1);
 await push('Oct 27 10:34:00 lab sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id\n',1,1,1);
 if(system){await push(Buffer.concat([Buffer.alloc(512*1024,0x78),Buffer.from('\n')]),1,0,0);await push(Buffer.from([0xff,0xfe,10]),1,0,0);await push('not-a-structured-record\n',1,0,0);}
 await handle.close();return {name,bytes,lines,parsed,hits,lateSuccessLine,sha256:hash.digest('hex'),synthetic:true,minimumBytes};
}
const logs=[];
logs.push(await logFixture('generated-access-128MiB.log',128*1024*1024,false));
logs.push(await logFixture('generated-auth-1GiB.log',1024*1024*1024,true));
const manifest={format:'gaga-field-fixtures/1',source:'Generated reserved-address training data; not actual customer logs',image,logs};
await fs.writeFile(path.join(fixtures,'manifest.json'),JSON.stringify(manifest,null,2));
console.log(JSON.stringify({generated:logs.map(({name,bytes,lines,hits})=>({name,bytes,lines,hits}))}));
const workspace=path.join(base,'workspace');
const child=spawn(binary,['--verify-field',workspace,fixtures,path.resolve('src-tauri/resources/agents')],{stdio:['ignore','pipe','pipe']});
const log=await fs.open(path.join(base,'run.log'),'wx');let processOutput='';
for(const source of [child.stdout,child.stderr])source.on('data',chunk=>{processOutput+=chunk;process.stdout.write(chunk);log.write(chunk);});
const deadline=setTimeout(()=>{child.kill('SIGTERM');},15*60*1000);
const status=await new Promise(resolve=>child.on('close',(code,signal)=>resolve({code,signal})));clearTimeout(deadline);await log.close();
if(status.code!==0)throw Error('Native field exercise failed: '+JSON.stringify(status)+'\n'+processOutput.slice(-3000));
const result=JSON.parse(await fs.readFile(path.join(workspace,'field-verification.json'),'utf8'));
console.log(JSON.stringify({result:path.join(workspace,'field-verification.json'),logs:result.logs.map(({name,bytes,elapsedMs,throughputMiBPerSecond})=>({name,bytes,elapsedMs,throughputMiBPerSecond})),agent:result.agent,dynamic:result.dynamic},null,2));
