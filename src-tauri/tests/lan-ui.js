// Explicit --lan-ui only: two independent synthetic workspaces use real local TLS.
(async()=>{
 const invoke=(n,a={})=>window.__TAURI_INTERNALS__.invoke(n,a),passed=[],viewportChecks=[];
 const pause=(ms=80)=>new Promise(r=>setTimeout(r,ms));
 const wait=async(fn,label,timeout=35000)=>{const start=Date.now();while(Date.now()-start<timeout){if(await fn())return;await pause();}throw Error('LAN UI timeout: '+label);};
 const check=(name,ok)=>{if(!ok)throw Error(name);passed.push(name);};
 const button=(text,selector='button')=>[...document.querySelectorAll(selector)].find(b=>b.textContent.trim()===text);
 const enter=async(label,value)=>{const el=document.querySelector(`[aria-label="${label}"]`);if(!el)throw Error('Missing '+label);Object.getOwnPropertyDescriptor(el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));await pause();};
 let root;
 try{
  await wait(()=>document.querySelector('.dashboard-footer')?.textContent.includes('更新于'),'ready');document.querySelector('.splash-skip')?.click();
  root=(await invoke('get_workspace')).dataDir;
  document.querySelector('[data-module="lan"]').click();await wait(()=>document.querySelector('.lan-workspace'),'independent page');
  const phase=(await invoke('read_http_text',{path:root+'/phase.txt'})).trim();
  if(phase==='reopen'){
   await wait(()=>document.querySelector('.lan-peer'),'saved contact');
   const s=await invoke('lan_state',{peerId:null,beforeSeq:null});
   check('Restart retains device identity and contacts without opening a listener',!s.enabled&&s.contacts.length===1);
   await wait(()=>document.querySelectorAll('.lan-message').length>=5,'saved history');
   check('Restart restores text, image and file history',document.querySelector('.lan-message-list').textContent.includes('一起复核')&&document.querySelector('.lan-message-list').textContent.includes('演练处置记录.txt'));
   await wait(()=>document.querySelectorAll('.lan-chat-image').length>=2,'stored images');
   check('Encrypted PNG and GIF remain viewable after restart',document.querySelector('img[src^="data:image/png"]')&&document.querySelector('img[src^="data:image/gif"]'));
   await invoke('record_ui_verification',{result:{passed,errors:[],phase,synthetic:true,externalModelCalled:false}});return;
  }
  check('Collaboration defaults off and has a separate desktop page',!((await invoke('lan_state',{peerId:null,beforeSeq:null})).enabled)&&!!button('开启协作'));
  await enter('局域网设备名称','J4team 调查终端');button('开启协作').click();await wait(()=>button('关闭协作'),'enabled');
  const other=await invoke('lan_ui_companion',{action:'prepare'});
  await wait(()=>document.querySelectorAll('.lan-nearby>button').length>0,'real multicast discovery');
  check('Real multicast discovery shows unpaired nearby device',document.querySelector('.lan-nearby').textContent.includes('J4team 协作伙伴')&&document.querySelectorAll('.lan-peer').length===0);
  document.querySelector('.lan-nearby>button').click();await pause();
  await invoke('resize_ui_verification',{width:960,height:660});await pause(120);
  const pairModal=document.querySelector('.lan-pair-modal').getBoundingClientRect();
  check('Pairing dialog fits minimum desktop window and scrolls internally',pairModal.right<=innerWidth&&pairModal.bottom<=innerHeight&&pairModal.top>=0);
  await invoke('resize_ui_verification',{width:1320,height:860});await pause(100);
  await enter('对方设备地址',other.address);await enter('对方配对邀请',other.invite.code);button('确认配对').click();
  await wait(()=>document.querySelector('.lan-chat-header')?.textContent.includes('J4team 协作伙伴'),'pair');
  check('One-time invitation pairs with the pinned peer certificate',document.querySelector('.lan-chat-header').textContent.includes('已认证连接在线'));
  await enter('局域网消息输入','一起复核这次事件 ');document.querySelector('[aria-label="插入表情"]').click();await pause();button('🦆','.lan-emojis button').click();await pause();button('发送','.lan-composer button').click();
  await wait(async()=>{const s=await invoke('lan_ui_companion',{action:'snapshot'});return s.messages.some(m=>m.body.text==='一起复核这次事件 🦆');},'delivered text');
  check('Text and selected emoji are saved on the real peer',true);
  await invoke('lan_ui_companion',{action:'text'});await wait(()=>document.querySelector('.lan-message-list').textContent.includes('收到，我们继续核对证据'),'inbound text');
  check('Inbound reply appears in the active conversation',true);
  const canvas=document.createElement('canvas');canvas.width=64;canvas.height=32;canvas.getContext('2d').fillRect(0,0,64,32);
  const blob=await new Promise(r=>canvas.toBlob(r,'image/png'));const transfer=new DataTransfer();transfer.items.add(new File([blob],'clipboard.png',{type:'image/png'}));
  document.querySelector('[aria-label="局域网消息输入"]').dispatchEvent(new ClipboardEvent('paste',{bubbles:true,clipboardData:transfer}));
  await wait(()=>document.querySelector('[alt="待发送截图预览"]'),'clipboard preview');
  check('Pasted screenshot is previewed before sending',!(await invoke('lan_ui_companion',{action:'snapshot'})).messages.some(m=>m.kind==='image'));
  button('发送','.lan-composer button').click();await wait(async()=> (await invoke('lan_ui_companion',{action:'snapshot'})).messages.some(m=>m.kind==='image'),'screenshot offer');
  await invoke('lan_ui_companion',{action:'receive'});await wait(()=>document.querySelector('.lan-message-list').textContent.includes('对方已接收'),'attachment receipt');
  check('Screenshot transfer is verified and acknowledged only after peer save',true);
  await invoke('lan_ui_companion',{action:'file'});await wait(()=>button('接收文件','.lan-message button'),'pending file');
  check('Incoming file waits for an explicit receive action',document.querySelector('.lan-message-list').textContent.includes('等待接收'));
  button('接收文件','.lan-message button').click();await wait(async()=>{const s=await invoke('lan_state',{peerId:other.id,beforeSeq:null});return s.messages.some(m=>m.kind==='file'&&m.state==='received');},'file received');
  let s=await invoke('lan_state',{peerId:other.id,beforeSeq:null});const file=s.messages.find(m=>m.kind==='file'&&m.state==='received');
  await invoke('lan_action',{action:'save',messageId:file.id,path:root+'/received-file.txt'});
  check('Accepted file exports through native verified storage',(await invoke('read_http_text',{path:root+'/received-file.txt'})).includes('通信验收合成资料'));
  await invoke('lan_ui_companion',{action:'file_long'});await wait(()=>button('接收文件','.lan-message button'),'long filename offer');button('接收文件','.lan-message button').click();
  await wait(async()=> (await invoke('lan_state',{peerId:other.id,beforeSeq:null})).messages.some(m=>m.body.name.startsWith('synthetic-long-name-')&&m.state==='received'),'long filename receive');
  await enter('局域网消息输入','SYNTHETIC_LONG_TOKEN_'.repeat(80));button('发送','.lan-composer button').click();await wait(async()=> (await invoke('lan_ui_companion',{action:'snapshot'})).messages.some(m=>m.body.text.startsWith('SYNTHETIC_LONG_TOKEN_')),'long text');
  await invoke('lan_ui_companion',{action:'gif'});await wait(()=>button('接收图片','.lan-message button'),'GIF offer');button('接收图片','.lan-message button').click();await wait(()=>document.querySelector('.lan-chat-image[src^="data:image/gif"]'),'GIF preview');
  check('GIF sticker receives and renders as an image',true);
  for(const theme of ['light','dark']){
   const select=document.querySelector('[aria-label="主题模式"]');select.value=theme;select.dispatchEvent(new Event('change',{bubbles:true}));
   for(const [width,height] of [[960,660],[1100,720],[1320,860],[1600,1000]]){
    await invoke('resize_ui_verification',{width,height});await pause(150);
    const workspace=document.querySelector('.lan-workspace'),composer=document.querySelector('.lan-composer');
    document.querySelector('[aria-label="插入表情"]').click();await pause();
    const emoji=document.querySelector('.lan-emojis').getBoundingClientRect();
    check(`Chat, long content and emoji fit ${theme} ${width}x${height}`,document.documentElement.scrollWidth<=innerWidth&&workspace.scrollWidth<=workspace.clientWidth&&composer.getBoundingClientRect().bottom<=innerHeight&&emoji.left>=0&&emoji.right<=innerWidth&&[...document.querySelectorAll('.lan-bubble')].every(b=>b.scrollWidth<=b.clientWidth+1));
    viewportChecks.push({theme,requested:{width,height},actual:{width:innerWidth,height:innerHeight}});
    document.querySelector('[aria-label="插入表情"]').click();await pause();
   }
  }
  await invoke('resize_ui_verification',{width:1320,height:860});
  await invoke('lan_ui_companion',{action:'stop'});await wait(()=>document.querySelector('.lan-chat-header').textContent.includes('离线 / 暂不可达'),'authenticated offline timeout',25000);
  check('Online status expires when real peer closes its listener',true);
  button('关闭协作').click();await wait(()=>button('开启协作'),'stop');check('Stopping collaboration closes the listener while retaining the conversation',document.querySelectorAll('.lan-message').length>=5&&!((await invoke('lan_state',{peerId:null,beforeSeq:null})).enabled));
  await invoke('record_ui_verification',{result:{passed,errors:[],phase,viewportChecks,synthetic:true,externalModelCalled:false}});
 }catch(error){let peer=null,self=null;try{peer=await invoke('lan_ui_companion',{action:'snapshot'});self=await invoke('lan_state',{peerId:null,beforeSeq:null});}catch{}await invoke('record_ui_verification',{result:{passed,errors:[String(error),error.stack],peerSnapshot:peer,selfSnapshot:self,uiError:document.querySelector('.lan-banner')?.textContent,synthetic:true,externalModelCalled:false}});}
})();
