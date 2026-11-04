// Launch bundled macOS apps through Launch Services so system credential UI belongs to the GUI session.
import {spawn, execFileSync} from 'node:child_process';
import path from 'node:path';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function matchingPid(binary,workspace) {
  const rows=execFileSync('ps',['-axo','pid=,command='],{encoding:'utf8'}).split('\n');
  const row=rows.find(row=>{const command=row.replace(/^\s*\d+\s+/,'');return command.startsWith(binary+' ')&&command.endsWith(' '+workspace);});
  return row?Number(row.trim().split(/\s+/,1)[0]):null;
}
export async function launchNative(binary,args) {
  const bundled=process.platform==='darwin'&&binary.includes('.app/Contents/MacOS/');
  const workspace=args.at(-1);
  if(bundled&&matchingPid(binary,workspace))throw Error('Close the existing client for this test workspace before starting another native phase.');
  const app=spawn(bundled?'/usr/bin/open':binary,bundled?['-n','-W','-a',path.resolve(binary,'../../..'),'--args',...args]:args,{stdio:['ignore','pipe','pipe']});
  let pid=app.pid;
  if(bundled){
    pid=null;
    for(let i=0;i<100;i++){
      pid=matchingPid(binary,workspace);if(pid)break;
      if(app.exitCode!==null)throw Error('Launch Services exited before the client started: '+app.exitCode);
      await pause(100);
    }
    if(!pid){app.kill('SIGTERM');throw Error('Launch Services did not start the bundled client');}
  }
  return {
    stdout:app.stdout,stderr:app.stderr,
    get exitCode(){return app.exitCode;},
    get signalCode(){return app.signalCode;},
    pid,
    launchMethod:bundled?'macOS Launch Services':'direct process',
    diagnostics(){
      let clientAlive=false;
      try{process.kill(pid,0);clientAlive=true;}catch(error){if(error.code!=='ESRCH')throw error;}
      return {method:bundled?'macOS Launch Services':'direct process',clientPid:pid,clientAlive,
        launcherPid:app.pid,launcherExitCode:app.exitCode,launcherSignal:app.signalCode};
    },
    async stop(){
      try{process.kill(pid,'SIGTERM');}catch(error){if(error.code!=='ESRCH')throw error;}
      if(app.exitCode===null)await Promise.race([new Promise(resolve=>app.once('exit',resolve)),pause(5000)]);
      if(app.exitCode===null)app.kill('SIGTERM');
    },
  };
}
