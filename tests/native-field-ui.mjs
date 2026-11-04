import fs from 'node:fs/promises';
import path from 'node:path';
import {spawn} from 'node:child_process';
const [binary,root]=process.argv.slice(2);
const field=JSON.parse(await fs.readFile(path.join(root,'field-verification.json'),'utf8'));
if(field.format!=='gaga-field-verification/1')throw Error('Requires the isolated completed field test workspace');
const file=path.join(root,'native-ui-verification.json');await fs.rm(file,{force:true});
const child=spawn(binary,['--field-ui',root],{stdio:['ignore','pipe','pipe']});let output='';
for(const stream of [child.stdout,child.stderr])stream.on('data',s=>output+=s);
let result;
try{
 for(let i=0;i<600;i++){
  try{result=JSON.parse(await fs.readFile(file,'utf8'));break}catch{}
  if(child.exitCode!==null)throw Error('Native app exited: '+output.slice(-3000));
  await new Promise(r=>setTimeout(r,100));
 }
 if(!result)throw Error('Native field UI timed out: '+output.slice(-3000));
 await fs.writeFile(path.join(root,'native-field-ui.log'),output);
 if(result.errors.length)throw Error(JSON.stringify(result,null,2));
 console.log(JSON.stringify(result,null,2));
}finally{child.kill('SIGTERM');}
