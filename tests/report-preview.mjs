// Browser preview or PDF print of an actual HTML export, independent of the native PDF dialog.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const [file,output]=process.argv.slice(2);
const pages=await (await fetch('http://127.0.0.1:9226/json/list')).json();
const ws=new WebSocket(pages.find(p=>p.type==='page').webSocketDebuggerUrl);
await new Promise(r=>ws.addEventListener('open',r,{once:true}));
let next=0;const pending=new Map();
ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}};
const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++next;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
try{
  await call('Page.enable');await call('Runtime.enable');
  await call('Emulation.setDeviceMetricsOverride',{width:1100,height:1000,deviceScaleFactor:1,mobile:false});
  await call('Page.navigate',{url:pathToFileURL(file).href});
  for(let i=0;i<100;i++){
    const r=await call('Runtime.evaluate',{expression:"document.readyState==='complete' && !!document.querySelector('figure img')",returnByValue:true});
    if(r.result.value)break;
    await new Promise(r=>setTimeout(r,50));
  }
  const r=await call('Runtime.evaluate',{expression:"Promise.all([document.fonts.ready,...[...document.images].map(i=>i.decode())]).then(()=>({title:document.title,figures:document.querySelectorAll('figure img').length,viewport:document.body.scrollWidth<=innerWidth}))",awaitPromise:true,returnByValue:true});
  if(r.exceptionDetails||!r.result.value?.figures||!r.result.value?.viewport)throw Error('Exported report cannot render correctly: '+JSON.stringify(r));
  const shot=output.endsWith('.pdf') ? await call('Page.printToPDF',{printBackground:true,paperWidth:8.27,paperHeight:11.69,marginTop:0.5,marginBottom:0.5,marginLeft:0.5,marginRight:0.5,preferCSSPageSize:true}) : await call('Page.captureScreenshot',{format:'png'});
  await fs.writeFile(output,Buffer.from(shot.data,'base64'));
  console.log(JSON.stringify({htmlExportPreview:true,nativeClientScreenshot:false,...r.result.value,output}));
}finally{ws.close();}
