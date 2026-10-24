import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const directory = fileURLToPath(new URL('..', import.meta.url));
const vite = fileURLToPath(new URL('../../node_modules/vite/bin/vite.js', import.meta.url));
const port = 1437, url = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, [vite, 'preview', '--host', '127.0.0.1', '--port', String(port), '--strictPort'], {cwd:directory, stdio:['ignore','pipe','pipe']});
let serverLog = '', browser, passed = 0;
server.stdout.on('data', data=>serverLog+=data); server.stderr.on('data', data=>serverLog+=data);
const fixtureEntry = {id:'record-1',hostname:'example.com',title:'Example',username:'test-user',password:'fixture-secret-only',notes:'test note',deleted:false,version:{counter:1,device_id:'device-1',modified_at:Date.now()}};

async function mock(page, options={}) {
 await page.addInitScript(({entry,options})=>{
  const state={initialized:options.initialized!==false,locked:options.locked??false,mobile:options.mobile??false,entries:options.empty?[]:[entry],recovery:options.recovery??[{...entry,password:'previous-fixture-secret'}],restoreError:false,entryCountOverride:null,discovered:options.discovered??[],merges:options.merges??[],discovering:false,discoveryDuration:options.discoveryDuration??20,discoveryRemainingOverride:null,lastDiscovery:null,nextDiscovery:Date.now()/1000+300,discoveryGeneration:0,scanState:options.scanState??'idle',scanChecked:options.scanChecked??0,scanTotal:options.scanTotal??0,scanRanges:options.scanRanges??[],scanLimited:options.scanLimited??false,scanError:options.scanError??null,incompatibleDiscovered:options.incompatibleDiscovered??[],localAddresses:options.localAddresses??['192.168.1.10'],listError:false,calls:[],delays:{},pending:{},copied:[],events:{}};
  state.interfaceLocked=options.interfaceLocked??state.locked;
  state.sessionGeneration=options.sessionGeneration??0;
  state.delaysBefore={};state.pendingBefore={};state.rejected=[];
  window.__fixture=state; window.isTauri=true;
  let next=1; const callbacks=new Map();
  const lockInterface=full=>{state.sessionGeneration++;state.interfaceLocked=true;if(full)state.locked=true;state.merges=[];state.discovered=[];state.incompatibleDiscovered=[];state.discovering=false;state.lastDiscovery=null;state.scanState='cancelled';callbacks.get(state.events['vault-locked'])?.({event:'vault-locked',id:1,payload:null});};
  window.__lock=()=>lockInterface(true);
  window.__softLock=()=>lockInterface(false);
  window.__release=name=>{const pending=state.pending[name]??[];delete state.pending[name];pending.forEach(resolve=>resolve());};
  window.__releaseBefore=name=>{const pending=state.pendingBefore[name]??[];delete state.pendingBefore[name];pending.forEach(resolve=>resolve());};
  window.__TAURI_INTERNALS__={
   transformCallback(fn){const id=next++;callbacks.set(id,fn);return id;},unregisterCallback(id){callbacks.delete(id);},
   async invoke(name,args={}){
    args=structuredClone(args);
    state.calls.push({name,...(args.expectedGeneration===undefined?{}:{expectedGeneration:args.expectedGeneration}),...(name==='save_entry'?{id:args.input.id,hostname:args.input.hostname}:['request_merge','respond_merge','restore_entry'].includes(name)?args:{} )});
    let result;
    if(name==='plugin:event|listen'){state.events[args.event]=args.handler;return next++;}
    if(name==='plugin:event|unlisten')return;
    if(name==='plugin:clipboard-manager|write_text'){state.copied.push(args.text);return;}
    // Suspend before entering the backend, separately from delaying a completed reply.
    if(state.delaysBefore[name])await new Promise(resolve=>(state.pendingBefore[name]??=[]).push(resolve));
    if(!['app_status','lock_vault','fully_lock_vault','user_activity'].includes(name)&&args.expectedGeneration!==state.sessionGeneration){state.rejected.push({name,expectedGeneration:args.expectedGeneration,actualGeneration:state.sessionGeneration});throw '密码库会话已结束，请重新解锁。';}
    if(name==='app_status')result={app_version:options.appVersion??'0.2.5',session_generation:state.sessionGeneration,interface_locked:state.interfaceLocked,browser_available:!state.locked&&!options.serviceError,vault:{initialized:state.initialized,locked:state.locked,device_id:'device-1',device_name:'测试电脑',entry_count:state.entryCountOverride??state.entries.length,peer_count:0},service:options.serviceError?null:{local_endpoint:'http://127.0.0.1:17841',lan_port:17842,running:true,last_error:null,discovery_generation:state.discoveryGeneration,last_discovery_at:state.lastDiscovery,next_discovery_at:state.nextDiscovery,discovering:state.discovering,discovery_duration_secs:state.discoveryDuration,discovery_remaining_secs:state.discovering?(state.discoveryRemainingOverride??Math.max(0,state.discoveryDuration-Math.floor(Date.now()/1000-state.lastDiscovery))):0,scan_state:state.scanState,scan_checked:state.scanChecked,scan_total:state.scanTotal,scan_ranges:state.scanRanges,scan_limited:state.scanLimited,scan_error:state.scanError,scan_port:17842,incompatible_discovered:state.incompatibleDiscovered,discovered:state.discovered,merges:state.merges},service_error:options.serviceError?'端口被其他程序占用':null,local_addresses:state.localAddresses,mobile:state.mobile};
    else if(name==='create_vault'||name==='unlock_vault'){if(args.password==='wrong-password')throw '主密码错误';state.initialized=true;state.locked=false;state.interfaceLocked=false;result=null;}
    else if(name==='lock_vault'){window.__softLock();result=null;}
    else if(name==='fully_lock_vault'){window.__lock();result=null;}
    else if(name==='user_activity')return;
    else if(state.interfaceLocked||state.locked)throw '密码库界面已锁定';
    else if(name==='list_entries'){if(state.listError)throw '密码列表刷新失败';result=state.entries.map(({password,notes,...item})=>({...item,conflict_count:0}));}
    else if(name==='get_entry')result=state.entries.find(item=>item.id===args.id);
    else if(name==='entry_history'||name==='recovery_history')result=state.recovery.filter(item=>item.id===args.id&&!item.deleted);
    else if(name==='list_recovery_entries')result=state.recovery.filter(item=>!item.deleted).map(({password,notes,...item})=>({...item,deleted:!state.entries.some(current=>current.id===item.id),conflict_count:1}));
    else if(name==='restore_entry'){if(state.restoreError)throw '加密备份保存失败，未恢复密码';const historic=state.recovery.find(item=>item.id===args.id&&item.version.counter===args.version.counter);if(!historic)throw '历史版本不存在';const value={...historic,version:{counter:historic.version.counter+1,device_id:'device-1',modified_at:Date.now()}};state.entries=state.entries.filter(item=>item.id!==value.id);state.entries.push(value);result=value;}
    else if(name==='save_entry'){const value={...args.input,id:args.input.id||'new-entry',deleted:false,version:{counter:2,device_id:'device-1',modified_at:Date.now()}};state.entries=state.entries.filter(item=>item.id!==value.id);state.entries.push(value);result=value;}
    else if(name==='delete_entry'){state.entries=state.entries.filter(item=>item.id!==args.id);result=null;}
    else if(name==='detect_devices'){state.discovering=true;state.discoveryGeneration++;state.lastDiscovery=Date.now()/1000;state.discoveryRemainingOverride=null;state.scanTotal=options.scanTotal??253;state.scanState=state.scanTotal?'scanning':'planning';state.scanChecked=0;state.scanRanges=options.scanRanges??['192.168.1.0/24'];state.scanLimited=options.scanLimited??false;state.scanError=null;result=null;}
    else if(name==='request_merge'){
     const peer=state.discovered.find(item=>item.id===args.deviceId);if(!peer)throw '设备已离线';
     result={id:'merge-1',peer_id:peer.id,peer_name:peer.name,endpoint:peer.endpoint,direction:'outgoing',state:'waiting',verification_code:'',created_at:Date.now()/1000,expires_at:Date.now()/1000+120,completed_at:null,error:null};state.merges.push(result);
    }
    else if(name==='respond_merge'){
     const merge=state.merges.find(item=>item.id===args.sessionId);if(!merge)throw '合并请求已结束';
     merge.state=args.accept?'waiting':'rejected';result=null;
    }
    else throw new Error(`Unmocked command ${name}`);
    result=structuredClone(result);
    if(state.delays[name])await new Promise(resolve=>(state.pending[name]??=[]).push(resolve));
    return result;
   }
  };
 }, {entry:fixtureEntry,options});
}
const click = (page,action)=>page.locator(`[data-action="${action}"]`).first().click();
const tick = page=>page.clock.fastForward(5100);
const ready = page=>page.waitForFunction(()=>document.querySelector('#app')?.getAttribute('aria-busy')!=='true');
async function unlock(page){await page.locator('#master-password').fill('correct-fixture-password');await page.locator('#gate-form button').click();await page.locator('.shell').waitFor();await ready(page);}
async function shot(page,name,{fullPage=true}={}){const directory=process.env.OMP_UI_CAPTURE_DIR||process.env.OMP_CAPTURE_DIR;if(directory){await mkdir(directory,{recursive:true});await page.screenshot({path:`${directory}/${name}.png`,fullPage});}}
async function check(name,action,options={}){
 if(process.env.OMP_UI_TEST_FILTER&&!new RegExp(process.env.OMP_UI_TEST_FILTER).test(name))return;
 const context=await browser.newContext({viewport:options.mobile?{width:390,height:844}:{width:1280,height:900}});
 const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
 try{
  await page.clock.install();
  if(!options.preview)await mock(page,options);
  await page.goto(url);await page.locator(options.preview?'.gate':options.interfaceLocked||options.locked||options.initialized===false?'#gate-form':'.shell').waitFor();
  await action(page);assert.deepEqual(errors,[],'No unhandled JavaScript errors');
  console.log(`PASS ${++passed}: ${name}`);
 }catch(error){await shot(page,`failed-${passed+1}`);throw new Error(`${name}: ${error.message}`,{cause:error});}
 finally{await context.close();}
}
try{
 for(let i=0;;i++){
  if(server.exitCode!==null)throw new Error(`Preview stopped: ${serverLog}`);
  try{if((await fetch(url)).ok)break;}catch{}
  if(i>100)throw new Error(`Preview failed: ${serverLog}`);
  await new Promise(resolve=>setTimeout(resolve,100));
 }
 browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH||undefined,args:['--no-sandbox']});
 await check('browser preview cannot store or fetch secrets',async page=>{
  assert.match(await page.locator('main').innerText(),/浏览器预览/);assert.equal(await page.locator('input').count(),0);
 },{preview:true});
 await check('creation requires matching master password and clears inputs',async page=>{
  await page.locator('[name=device_name]').fill('测试手机');await page.locator('#master-password').fill('correct-fixture-password');await page.locator('[name=confirm]').fill('different-password');
  await page.locator('#gate-form button').click();await page.getByText('两次输入的主密码不一致').waitFor();
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='create_vault').length),0);
  await page.locator('[name=confirm]').fill('correct-fixture-password');await page.locator('#gate-form button').click();await page.locator('.shell').waitFor();
  assert.equal(await page.locator('#master-password').count(),0);assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
 },{initialized:false,locked:true});
 await check('wrong password stays locked and can retry',async page=>{
  assert.match(await page.locator('#lock-status').innerText(),/密码库已锁定.*插件暂不可用/);
  await page.locator('#master-password').fill('wrong-password');await page.locator('#gate-form button').click();await page.getByText('主密码错误',{exact:true}).waitFor();
  assert.equal(await page.locator('#master-password').inputValue(),'');assert.equal(await page.locator('.shell').count(),0);assert.equal(await page.evaluate(()=>window.__fixture.locked),true);assert.match(await page.locator('#lock-status').innerText(),/插件暂不可用/);await unlock(page);
 },{locked:true});
 await check('interface lock hides accounts while the browser stays available and full lock disables it',async page=>{
  await page.getByRole('switch',{name:'账号明文显示'}).check();await page.locator('#search').fill(fixtureEntry.username);await page.locator('#lock').click();
  await page.locator('#lock-status').filter({hasText:'插件仍可使用'}).waitFor();await ready(page);
  assert.equal(await page.locator('.shell,dialog,[data-entry],#search').count(),0);assert.equal((await page.content()).includes(fixtureEntry.username),false);assert.equal((await page.content()).includes(fixtureEntry.password),false);
  assert.deepEqual(await page.evaluate(()=>({vault:window.__fixture.locked,interface:window.__fixture.interfaceLocked})),{vault:false,interface:true});
  const listCalls=await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='list_entries').length);await tick(page);assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='list_entries').length),listCalls,'A soft-locked interface must not query or display vault records.');await shot(page,'desktop-interface-locked');
  await page.locator('#master-password').fill('wrong-password');await page.locator('#gate-form button').click();await page.getByText('主密码错误',{exact:true}).waitFor();
  assert.equal(await page.locator('#master-password').inputValue(),'');assert.match(await page.locator('#lock-status').innerText(),/插件仍可使用/);assert.equal(await page.evaluate(()=>window.__fixture.locked),false);
  await page.evaluate(()=>window.__fixture.delays.fully_lock_vault=true);await page.locator('#fully-lock').click();await page.waitForFunction(()=>!!window.__fixture.pending.fully_lock_vault);
  await page.evaluate(()=>window.__lock());assert.equal(await page.locator('#gate-form button').isDisabled(),true,'A second native lock event must not enable unlock while the full-lock command is pending.');assert.equal(await page.locator('#fully-lock').isDisabled(),false);
  await page.evaluate(()=>{window.__fixture.delays.fully_lock_vault=false;window.__release('fully_lock_vault');});await page.locator('#lock-status').filter({hasText:'插件暂不可用'}).waitFor();await ready(page);assert.equal(await page.evaluate(()=>window.__fixture.locked),true);assert.match(await page.locator('.gate').innerText(),/解锁/);await shot(page,'desktop-fully-locked');
  await unlock(page);assert.equal(await page.getByRole('switch',{name:'账号明文显示'}).isChecked(),false);assert.equal(await page.locator('#search').inputValue(),'');
  await page.locator('[data-tab=browser]').click();await page.locator('#fully-lock').click();await page.locator('#lock-status').filter({hasText:'插件暂不可用'}).waitFor();
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='lock_vault').length),1);assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='fully_lock_vault').length),2);
 });
 await check('idle interface-lock event removes revealed secrets before status refresh finishes',async page=>{
  await page.getByRole('switch',{name:'账号明文显示'}).check();await page.locator('[data-entry]').click();await page.locator('#entry-password').waitFor();await click(page,'reveal');
  assert.equal(await page.locator('#entry-password').inputValue(),fixtureEntry.password);
  const afterEvent=await page.evaluate(()=>{window.__fixture.delays.app_status=true;window.__softLock();return {dialog:!!document.querySelector('dialog'),entry:!!document.querySelector('#entry-password'),account:document.body.textContent.includes('test-user')};});
  assert.deepEqual(afterEvent,{dialog:false,entry:false,account:false});await page.waitForFunction(()=>!!window.__fixture.pending.app_status);
  await page.evaluate(()=>{window.__fixture.delays.app_status=false;window.__release('app_status');});await page.locator('#lock-status').filter({hasText:'插件仍可使用'}).waitFor();
  assert.equal(await page.evaluate(()=>window.__fixture.locked),false);assert.equal((await page.content()).includes(fixtureEntry.password),false);await unlock(page);assert.equal(await page.locator('dialog').count(),0);
 });
 await check('late password reply cannot reopen secrets after interface lock',async page=>{
  await page.evaluate(()=>window.__fixture.delays.get_entry=true);await page.locator('[data-entry]').click();await page.waitForFunction(()=>!!window.__fixture.pending.get_entry);
  assert.equal(await page.locator('#lock').isDisabled(),false);await page.locator('#lock').click();await page.locator('#lock-status').filter({hasText:'插件仍可使用'}).waitFor();
  await page.evaluate(()=>window.__release('get_entry'));await ready(page);assert.equal(await page.locator('.shell,dialog,#entry-password').count(),0);assert.equal((await page.content()).includes(fixtureEntry.password),false);assert.equal(await page.evaluate(()=>window.__fixture.locked),false);
  await unlock(page);assert.equal(await page.locator('dialog').count(),0);assert.equal((await page.content()).includes(fixtureEntry.password),false);
 });
 await check('full lock stays available during pending unlock and rejects its late response',async page=>{
  await page.evaluate(()=>window.__fixture.delays.unlock_vault=true);await page.locator('#master-password').fill('correct-fixture-password');await page.locator('#gate-form button').click();await page.waitForFunction(()=>!!window.__fixture.pending.unlock_vault);
  assert.equal(await page.locator('#fully-lock').isDisabled(),false);await page.locator('#fully-lock').click();await page.locator('#lock-status').filter({hasText:'插件暂不可用'}).waitFor();
  await page.evaluate(()=>{window.__fixture.delays.unlock_vault=false;window.__release('unlock_vault');});await ready(page);await tick(page);
  assert.equal(await page.locator('.shell,dialog,[data-entry]').count(),0);assert.equal(await page.locator('#master-password').inputValue(),'');assert.equal((await page.content()).includes(fixtureEntry.username),false);assert.equal((await page.content()).includes(fixtureEntry.password),false);
  assert.deepEqual(await page.evaluate(()=>({vault:window.__fixture.locked,interface:window.__fixture.interfaceLocked})),{vault:true,interface:true});assert.match(await page.locator('#lock-status').innerText(),/插件暂不可用/);await unlock(page);
 },{interfaceLocked:true});
 await check('a queued unlock entering the backend handler after full lock cannot reopen the browser',async page=>{
  await page.evaluate(()=>window.__fixture.delaysBefore.unlock_vault=true);await page.locator('#master-password').fill('correct-fixture-password');await page.locator('#gate-form button').click();await page.waitForFunction(()=>!!window.__fixture.pendingBefore.unlock_vault);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.find(c=>c.name==='unlock_vault').expectedGeneration),0,'Authentication must use the generation shown before the request was queued.');
  await page.locator('#fully-lock').click();await page.locator('#lock-status').filter({hasText:'插件暂不可用'}).waitFor();assert.equal(await page.evaluate(()=>window.__fixture.sessionGeneration),1);
  await page.evaluate(()=>{window.__fixture.delaysBefore.unlock_vault=false;window.__releaseBefore('unlock_vault');});await ready(page);
  assert.deepEqual(await page.evaluate(()=>window.__fixture.rejected),[{name:'unlock_vault',expectedGeneration:0,actualGeneration:1}]);
  const backend=await page.evaluate(()=>window.__TAURI_INTERNALS__.invoke('app_status'));assert.equal(backend.vault.locked,true);assert.equal(backend.interface_locked,true);assert.equal(backend.browser_available,false);assert.equal(await page.locator('.shell,dialog,[data-entry]').count(),0);assert.match(await page.locator('#lock-status').innerText(),/插件暂不可用/);
  await unlock(page);assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='unlock_vault').at(-1).expectedGeneration),1,'A fresh unlock must use the updated generation.');
 },{locked:true});
 await check('a queued save entering the backend handler after full lock cannot change the vault',async page=>{
  await page.locator('[data-entry]').click();await page.locator('#entry-password').fill('must-not-be-saved');await page.evaluate(()=>window.__fixture.delaysBefore.save_entry=true);await page.locator('#entry-form [type=submit]').click();await page.waitForFunction(()=>!!window.__fixture.pendingBefore.save_entry);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.find(c=>c.name==='save_entry').expectedGeneration),0);
  await page.evaluate(()=>window.__lock());await page.locator('#lock-status').filter({hasText:'插件暂不可用'}).waitFor();await page.evaluate(()=>{window.__fixture.delaysBefore.save_entry=false;window.__releaseBefore('save_entry');});await ready(page);
  assert.deepEqual(await page.evaluate(()=>window.__fixture.rejected),[{name:'save_entry',expectedGeneration:0,actualGeneration:1}]);assert.equal(await page.evaluate(()=>window.__fixture.entries[0].password),fixtureEntry.password);assert.equal(await page.evaluate(()=>window.__fixture.locked),true);assert.equal(await page.locator('.shell,dialog,#entry-password').count(),0);assert.equal((await page.content()).includes('must-not-be-saved'),false);
  await unlock(page);await page.locator('[data-entry]').click();assert.equal(await page.locator('#entry-password').inputValue(),fixtureEntry.password);assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='get_entry').at(-1).expectedGeneration),1);
 });
 await check('account visibility is opt-in and preserves search across tabs',async page=>{
  const toggle=page.getByRole('switch',{name:'账号明文显示'});
  assert.equal(await toggle.isChecked(),false);assert.equal((await page.locator('.entries').innerHTML()).includes(fixtureEntry.username),false);
  await page.locator('#search').fill('Example');await toggle.check();assert.match(await page.locator('.entries').innerText(),/test-user/);assert.equal(await page.locator('#search').inputValue(),'Example');
  await page.locator('[data-tab=devices]').click();await page.locator('[data-tab=vault]').click();assert.equal(await toggle.isChecked(),true);assert.equal(await page.locator('#search').inputValue(),'Example');
  await toggle.uncheck();assert.equal((await page.locator('.entries').innerHTML()).includes(fixtureEntry.username),false);assert.match(await page.locator('.entries').innerText(),/账号已隐藏/);
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
 });
 await check('password is fetched on demand, edit persists same record, delete confirms',async page=>{
  assert.equal((await page.content()).includes(fixtureEntry.password),false);assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>c.name==='get_entry')),false);
  await page.locator('[data-entry]').click();await page.locator('#entry-password').waitFor();assert.equal(await page.locator('#entry-password').getAttribute('type'),'password');assert.equal(await page.locator('#entry-form [name=username]').inputValue(),fixtureEntry.username);
  assert.equal(await page.getByRole('button',{name:'显示密码',exact:true}).count(),1);await click(page,'reveal');assert.equal(await page.getByRole('button',{name:'隐藏密码',exact:true}).count(),1);assert.equal(await page.locator('#entry-password').getAttribute('type'),'text');await page.locator('#entry-password').fill('new-fixture-password');await page.locator('#entry-form [type=submit]').click();await page.locator('dialog').waitFor({state:'detached'});await ready(page);
  assert.equal(await page.evaluate(()=>window.__fixture.entries[0].password),'new-fixture-password');assert.equal(await page.evaluate(()=>window.__fixture.entries[0].id),'record-1');
  await page.locator('[data-entry]').click();await click(page,'delete');assert.equal(await page.evaluate(()=>window.__fixture.entries.length),1);await click(page,'confirm');await page.locator('.empty').waitFor();
 });
 await check('global recovery works with an empty vault and restores only after confirmation',async page=>{
  assert.equal(await page.locator('[data-entry]').count(),0);assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>c.name==='recovery_history')),false);
  await click(page,'recovery');await page.locator('[data-recovery-id]').waitFor();assert.match(await page.locator('dialog').innerText(),/已删除，可恢复/);
  assert.equal((await page.locator('dialog').innerHTML()).includes('previous-fixture-secret'),false);assert.equal((await page.locator('dialog').innerHTML()).includes(fixtureEntry.username),false);
  await page.locator('[data-recovery-id]').click();await page.locator('[data-history-restore]').waitFor();assert.equal(await page.locator('input[aria-label="历史密码 1"]').getAttribute('type'),'password');
  await page.locator('[data-history-restore]').click();await page.getByText('恢复这版密码？',{exact:true}).waitFor();assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>c.name==='restore_entry')),false);
  await click(page,'restore-back');await page.locator('[data-history-restore]').click();await click(page,'restore-confirm');await page.locator('dialog').waitFor({state:'detached'});await ready(page);
  assert.match(await page.locator('#notice').innerText(),/已恢复为新的本地修改/);assert.equal(await page.locator('[data-entry]').count(),1);assert.equal(await page.evaluate(()=>window.__fixture.entries[0].password),'previous-fixture-secret');
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='restore_entry').length),1);assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>['request_merge','respond_merge'].includes(c.name))),false);
 },{empty:true});
 await check('missing history is explicit and recovery errors stay visible without success',async page=>{
  await click(page,'recovery');await page.getByText('当前密码库没有可恢复的历史。若密码库文件已被覆盖、重建或卸载，需要从保留的旧密码库或备份找回。',{exact:true}).waitFor();
  assert.equal(await page.locator('[data-history-restore]').count(),0);await click(page,'close');
  await page.evaluate(entry=>{window.__fixture.recovery=[entry];window.__fixture.restoreError=true;},fixtureEntry);await click(page,'recovery');await page.locator('[data-recovery-id]').click();await page.locator('[data-history-restore]').click();await click(page,'restore-confirm');await ready(page);
  assert.match(await page.locator('#dialog-notice').innerText(),/加密备份保存失败/);assert.equal(await page.locator('dialog').count(),1);assert.equal(await page.locator('[data-entry]').count(),0);
 },{empty:true,recovery:[]});
 await check('locking clears recovery history and rejects late recovery replies',async page=>{
  await click(page,'recovery');await page.locator('[data-recovery-id]').click();await page.locator('[data-history-restore]').waitFor();await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();
  assert.equal((await page.content()).includes('previous-fixture-secret'),false);await unlock(page);await click(page,'recovery');await page.evaluate(()=>window.__fixture.delays.recovery_history=true);await page.locator('[data-recovery-id]').click();await page.waitForFunction(()=>!!window.__fixture.pending.recovery_history);
  await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();await page.evaluate(()=>window.__release('recovery_history'));await ready(page);await unlock(page);assert.equal(await page.locator('dialog').count(),0);assert.equal((await page.content()).includes('previous-fixture-secret'),false);
 });
 await check('closing recovery cancels a pending history view without reopening secrets',async page=>{
  await click(page,'recovery');await page.evaluate(()=>window.__fixture.delays.recovery_history=true);await page.locator('[data-recovery-id]').click();await page.waitForFunction(()=>!!window.__fixture.pending.recovery_history);
  await click(page,'close');await page.evaluate(()=>window.__release('recovery_history'));await ready(page);assert.equal(await page.locator('dialog').count(),0);assert.equal((await page.content()).includes('previous-fixture-secret'),false);
 });
 await check('browser connection needs no token or authorization form',async page=>{
  await page.locator('[data-tab=browser]').click();await page.getByText('直接连接本机客户端',{exact:true}).waitFor();
  assert.match(await page.locator('.workspace').innerText(),/无需生成或复制额外令牌/);
  assert.equal(await page.locator('#client-form,.secret-box,input,textarea').count(),0);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>['list_clients','create_client','revoke_client'].includes(c.name))),false);
 });
 await check('mobile background full-lock event clears open password and secret controls',async page=>{
  await page.getByRole('switch',{name:'账号明文显示'}).check();
  await page.locator('[data-entry]').click();await page.locator('#entry-password').waitFor();await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();
  await page.locator('#lock-status').filter({hasText:'插件暂不可用'}).waitFor();assert.equal((await page.content()).includes(fixtureEntry.password),false);assert.equal(await page.locator('dialog').count(),0);assert.equal(await page.evaluate(()=>window.__fixture.locked),true);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await shot(page,'mobile-background-locked',{fullPage:false});await unlock(page);assert.equal(await page.locator('dialog').count(),0);
  assert.equal(await page.getByRole('switch',{name:'账号明文显示'}).isChecked(),false);assert.equal((await page.locator('.entries').innerHTML()).includes(fixtureEntry.username),false);
 },{mobile:true});
 await check('late password reply cannot restore dialog after lock',async page=>{
  await page.evaluate(()=>window.__fixture.delays.get_entry=true);await page.locator('[data-entry]').click();await page.waitForFunction(()=>!!window.__fixture.pending.get_entry);
  await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();await page.evaluate(()=>window.__release('get_entry'));await ready(page);await unlock(page);
  assert.equal(await page.locator('dialog').count(),0);assert.equal((await page.content()).includes(fixtureEntry.password),false);
 });
 await check('remote changes appear without navigation',async page=>{
  await page.evaluate(()=>window.__fixture.entries.push({...window.__fixture.entries[0],id:'remote-entry',title:'来自手机的新密码',hostname:'remote.example.com'}));
  await tick(page);await page.getByText('来自手机的新密码',{exact:true}).waitFor();
 });
 const peer={id:'peer-1',name:'测试手机',endpoint:'http://192.168.1.20:17842',last_seen:Date.now()/1000,app_version:'0.2.4'};
 const incoming={id:'incoming-1',peer_id:peer.id,peer_name:peer.name,endpoint:peer.endpoint,direction:'incoming',state:'awaiting_confirmation',verification_code:'123456',created_at:Date.now()/1000,expires_at:Date.now()/1000+120,completed_at:null,error:null};
 await check('device detection is separate from manual password merging',async page=>{
  await page.locator('[data-tab=devices]').click();assert.match(await page.locator('.workspace').innerText(),/每 5 分钟自动检测/);
  assert.equal(await page.locator('#invite-form,#join-form').count(),0);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>['request_merge','respond_merge','sync_now'].includes(c.name))),false);
  await click(page,'detect');await ready(page);assert.equal(await page.locator('[data-action=detect]').isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='detect_devices').length),1);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>c.name==='request_merge')),false);
  await page.evaluate(peer=>{window.__fixture.discovering=false;window.__fixture.scanState='completed';window.__fixture.scanChecked=window.__fixture.scanTotal;window.__fixture.discovered=[peer];},peer);await tick(page);await page.locator('[data-merge-device]').waitFor();
  assert.equal(await page.locator('[data-action=detect]').isDisabled(),false);
 },{});
 await check('LAN progress follows completed probes and polls status without rereading the vault',async page=>{
  await page.clock.pauseAt(new Date(await page.evaluate(()=>Date.now()+1000)));
  await page.locator('[data-tab=devices]').click();await click(page,'detect');await ready(page);
  const progress=page.locator('#lan-scan-progress');assert.equal(await progress.getAttribute('max'),'100');
  assert.match(await page.locator('#lan-scan-count').innerText(),/已检测 0 \/ 253 个地址/);
  const before=await page.evaluate(()=>({status:window.__fixture.calls.filter(c=>c.name==='app_status').length,list:window.__fixture.calls.filter(c=>c.name==='list_entries').length}));
  await page.clock.runFor(2100);
  assert.match(await page.locator('#lan-scan-count').innerText(),/已检测 0 \/ 253 个地址/);assert.equal(Number(await progress.getAttribute('value')),0,'Time passing cannot invent completed probes.');
  const after=await page.evaluate(()=>({status:window.__fixture.calls.filter(c=>c.name==='app_status').length,list:window.__fixture.calls.filter(c=>c.name==='list_entries').length}));
  assert.ok(after.status>before.status,'Active device discovery refreshes status.');assert.equal(after.list,before.list,'The one-second status poll does not reread password records.');
  await page.evaluate(()=>window.__fixture.scanChecked=64);await page.clock.runFor(1100);await page.locator('#lan-scan-count').filter({hasText:'已检测 64 / 253 个地址'}).waitFor();
  const probePercent=Number(await progress.getAttribute('value'));assert.ok(probePercent>=25&&probePercent<=26);await shot(page,'desktop-discovery-progress');
  await page.evaluate(()=>window.__fixture.discoveryRemainingOverride=0);await page.clock.fastForward(20_000);
  assert.equal(Number(await progress.getAttribute('value')),probePercent,'Ending the mDNS window does not complete the LAN probes.');assert.equal(await page.locator('[data-action=detect]').isDisabled(),true);
  await page.evaluate(()=>{window.__fixture.discovering=false;window.__fixture.scanState='completed';window.__fixture.scanChecked=253;});await tick(page);await page.waitForFunction(()=>!document.querySelector('[data-action=detect]')?.disabled);
  assert.equal(Number(await progress.getAttribute('value')),100);assert.match(await page.locator('#lan-scan-state').innerText(),/完成/);assert.doesNotMatch(await page.locator('#notice').innerText(),/正在检测/);
  await click(page,'detect');await ready(page);assert.match(await page.locator('#lan-scan-count').innerText(),/已检测 0 \/ 253 个地址/);assert.equal(await page.evaluate(()=>window.__fixture.discoveryGeneration),2);
  await page.evaluate(()=>window.__fixture.listError=true);await tick(page);await page.locator('#notice').filter({hasText:'密码列表刷新失败'}).waitFor();
  await page.evaluate(()=>{window.__fixture.listError=false;window.__fixture.discovering=false;window.__fixture.scanState='completed';window.__fixture.scanChecked=253;});await tick(page);assert.match(await page.locator('#notice').innerText(),/密码列表刷新失败/,'Completing a scan must not replace a later error.');
 });
 await check('LAN polling stops offscreen and locked stale replies cannot restore scan details',async page=>{
  await page.clock.pauseAt(new Date(await page.evaluate(()=>Date.now()+1000)));
  await page.locator('[data-tab=devices]').click();await click(page,'detect');await ready(page);
  await page.evaluate(()=>window.__fixture.scanChecked=20);await page.clock.runFor(1100);await page.locator('#lan-scan-count').filter({hasText:'已检测 20 / 253 个地址'}).waitFor();
  await page.locator('[data-tab=vault]').click();await page.locator('#search').fill('Example');
  const statusCalls=await page.evaluate(()=>{window.__heldSearch=document.querySelector('#search');return window.__fixture.calls.filter(c=>c.name==='app_status').length;});await page.clock.runFor(1100);
  assert.equal(await page.locator('#lan-scan-progress').count(),0);assert.equal(await page.locator('#search').inputValue(),'Example');assert.equal(await page.evaluate(()=>window.__heldSearch===document.querySelector('#search')),true);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='app_status').length),statusCalls,'The one-second scan poll stops away from the devices page.');
  await page.locator('[data-tab=devices]').click();assert.match(await page.locator('#lan-scan-count').innerText(),/已检测 20 \/ 253 个地址/);
  await page.evaluate(()=>window.__fixture.delays.app_status=true);await page.clock.runFor(1100);await page.waitForFunction(()=>!!window.__fixture.pending.app_status);
  await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();await page.evaluate(()=>{window.__fixture.delays.app_status=false;window.__release('app_status');});await page.clock.runFor(1100);
  assert.equal(await page.locator('#lan-scan-progress,.local-addresses').count(),0);assert.equal(await page.getByText('正在检测局域网设备…',{exact:true}).count(),0);assert.equal(await page.locator('.app-version').innerText(),'版本 0.2.5');
  await page.evaluate(()=>window.__fixture.localAddresses=['10.0.0.8']);await unlock(page);assert.deepEqual(await page.locator('.local-address').allTextContents(),['10.0.0.8']);
 });
 await check('LAN scan reports actual limited ranges, failures and zero targets without false success',async page=>{
  await page.locator('[data-tab=devices]').click();await click(page,'detect');await ready(page);
  assert.match(await page.locator('#lan-scan-ranges').innerText(),/192\.168\.100\.0\/24/);assert.equal(await page.locator('#lan-scan-limit').isVisible(),true);
  assert.match(await page.locator('#lan-scan-limit').innerText(),/限制扫描范围.*未扫描整个局域网/);
  await page.evaluate(()=>{window.__fixture.discovering=false;window.__fixture.scanState='failed';window.__fixture.scanError='网卡信息读取失败';});await tick(page);
  assert.match(await page.locator('#lan-scan-state').innerText(),/失败/);assert.match(await page.locator('.workspace').innerText(),/网卡信息读取失败/);assert.doesNotMatch(await page.locator('#notice').innerText(),/本轮检测已结束。/);
  await page.evaluate(()=>{window.__fixture.scanState='completed';window.__fixture.scanChecked=0;window.__fixture.scanTotal=0;window.__fixture.scanRanges=[];window.__fixture.scanLimited=false;window.__fixture.scanError='没有可探测的私网 IPv4 地址';});await tick(page);
  assert.match(await page.locator('.workspace').innerText(),/没有可探测的私网 IPv4 地址/);if(await page.locator('#lan-scan-progress').count())assert.notEqual(Number(await page.locator('#lan-scan-progress').getAttribute('value')),100);await shot(page,'desktop-discovery-empty-range');
 },{scanRanges:['192.168.100.0/24'],scanLimited:true});
 await check('peer versions distinguish compatible unknown clients from read-only legacy devices',async page=>{
  await page.locator('[data-tab=devices]').click();assert.deepEqual(await page.locator('[data-merge-device]').evaluateAll(buttons=>buttons.map(button=>button.dataset.mergeDevice).sort()),['peer-1','unknown-version-peer']);
  assert.equal(await page.locator('.app-version').innerText(),'版本 0.2.5');assert.match(await page.locator('#version-compatibility').innerText(),/0\.2\.3.*0\.2\.4.*0\.2\.5/);assert.match(await page.locator('#version-compatibility').innerText(),/0\.2\.2.*不兼容/);
  assert.match(await page.locator('[data-peer-id="peer-1"] .peer-version').innerText(),/版本 0\.2\.4/);
  const unknown=await page.locator('[data-peer-id="unknown-version-peer"] .peer-version').innerText();assert.match(unknown,/版本未提供.*支持单向接收/);assert.doesNotMatch(unknown,/0\.2\.3/,'A compatible older client without version metadata must not be assigned a guessed version.');
  assert.match(await page.locator('#incompatible-devices').innerText(),/旧版测试手机/);assert.match(await page.locator('[data-incompatible-peer-id="legacy-peer"]').innerText(),/具体版本未知.*需更新/);
  assert.equal(await page.locator('#incompatible-devices [data-merge-device]').count(),0);assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>c.name==='request_merge')),false);
 },{discovered:[peer,{id:'unknown-version-peer',name:'兼容客户端',endpoint:'http://192.168.1.22:17842',last_seen:Date.now()/1000,app_version:null}],incompatibleDiscovered:[{id:'legacy-peer',name:'旧版测试手机',endpoint:'http://192.168.1.21:17842',last_seen:Date.now()/1000,protocol:2}]});
 await check('all current LAN addresses render and an empty network has a clear message',async page=>{
  await page.locator('[data-tab=devices]').click();assert.deepEqual(await page.locator('.local-address').allTextContents(),['192.168.100.200','10.10.10.10','172.18.0.4']);
  assert.equal(await page.locator('.local-addresses').getAttribute('aria-label'),'本机局域网 IP');
  await page.evaluate(()=>window.__fixture.localAddresses=[]);await tick(page);assert.equal(await page.locator('.local-address').count(),0);
  assert.match(await page.locator('.local-addresses').innerText(),/未获取到局域网\s*IP/);await shot(page,'desktop-discovery-no-address');
 },{localAddresses:['192.168.100.200','10.10.10.10','172.18.0.4']});
 await check('manual merge waits for confirmation and durable completion before success',async page=>{
  await page.locator('[data-tab=devices]').click();await page.locator('[data-merge-device]').click();await ready(page);
  assert.equal(await page.locator('[data-merge-device]').isDisabled(),true);assert.notEqual(await page.locator('#notice').innerText(),'已合并密码本');
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='request_merge').length),1);
  await page.evaluate(()=>Object.assign(window.__fixture.merges[0],{state:'awaiting_confirmation',verification_code:'123456'}));await tick(page);
  await page.getByText('123456',{exact:true}).waitFor();await shot(page,'desktop-devices');await page.locator('[data-respond-merge][data-accept=true]').click();await ready(page);
  assert.notEqual(await page.locator('#notice').innerText(),'已合并密码本');
  await page.evaluate(()=>window.__fixture.merges[0].state='merging');await tick(page);await page.getByText('正在接收并合并密码…',{exact:true}).waitFor();
  await page.evaluate(()=>{window.__fixture.entries.push({...window.__fixture.entries[0],id:'merged-entry',title:'合并后的新密码'});Object.assign(window.__fixture.merges[0],{state:'completed',completed_at:Date.now()/1000,received_count:1,changed_count:1});});
  await tick(page);await page.locator('#notice').filter({hasText:'已合并密码本'}).waitFor();assert.equal(await page.locator('#notice').innerText(),'已合并密码本');
  await page.locator('[data-tab=vault]').click();await page.getByText('合并后的新密码',{exact:true}).waitFor();
 },{discovered:[peer]});
 await check('incoming merge can be rejected without success feedback',async page=>{
  await page.locator('[data-tab=devices]').click();await page.getByText('123456',{exact:true}).waitFor();
  await page.locator('[data-respond-merge][data-accept=false]').click();await ready(page);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.find(c=>c.name==='respond_merge').accept),false);
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
 },{merges:[incoming]});
 await check('provider stays read-only and reports provision only after records refresh',async page=>{
  await page.locator('[data-tab=devices]').click();await page.locator('[data-respond-merge][data-accept=true]').click();await ready(page);
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
  await page.evaluate(()=>{window.__fixture.listError=true;Object.assign(window.__fixture.merges[0],{state:'completed',completed_at:Date.now()/1000});});await tick(page);
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
  await page.evaluate(()=>{window.__fixture.listError=false;window.__fixture.merges[0].source_count=1;});await tick(page);await page.locator('#notice').filter({hasText:'已向对方提供密码'}).waitFor();
  assert.equal(await page.locator('.merge-state').innerText(),'已向对方提供密码，本机密码未修改');assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);assert.equal(await page.evaluate(()=>window.__fixture.entries.length),1);await shot(page,'mobile-merged',{fullPage:false});
 },{mobile:true,merges:[incoming]});
 await check('empty source is reported honestly and inconsistent empty results never report success',async page=>{
  await page.locator('[data-tab=devices]').click();await page.evaluate(()=>Object.assign(window.__fixture.merges[0],{state:'completed',received_count:0,changed_count:0}));await tick(page);
  assert.match(await page.locator('#notice').innerText(),/对方没有可接收的密码/);assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
  await page.evaluate(()=>{window.__fixture.merges.push({...window.__fixture.merges[0],id:'nonempty-result',received_count:2,changed_count:2});window.__fixture.entries=[];});await tick(page);
  assert.match(await page.locator('#notice').innerText(),/请查看「历史恢复」核对/);assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);await page.locator('[data-tab=vault]').click();assert.equal(await page.locator('[data-entry]').count(),1);
 },{merges:[{...incoming,direction:'outgoing'}]});
 await check('a mismatched empty refresh preserves visible records and reports the problem',async page=>{
  await page.evaluate(()=>{window.__fixture.entryCountOverride=1;window.__fixture.entries=[];});await tick(page);assert.match(await page.locator('#notice').innerText(),/密码列表未能完整读取/);assert.equal(await page.locator('[data-entry]').count(),1);
 });
 await check('failed and expired merges never report success',async page=>{
  await page.locator('[data-tab=devices]').click();
  await page.evaluate(()=>Object.assign(window.__fixture.merges[0],{state:'failed',error:'对方未完成保存，请重试'}));await tick(page);await page.locator('#notice').filter({hasText:'对方未完成保存'}).waitFor();
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
  await page.evaluate(()=>window.__fixture.merges.push({...window.__fixture.merges[0],id:'expired-merge',state:'expired',error:null}));await tick(page);await page.locator('#notice').filter({hasText:'已过期'}).waitFor();
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
 },{merges:[incoming]});
 await check('late merge request cannot restore a verification code after lock',async page=>{
  await page.locator('[data-tab=devices]').click();await page.evaluate(()=>window.__fixture.delays.request_merge=true);await page.locator('[data-merge-device]').click();await page.waitForFunction(()=>!!window.__fixture.pending.request_merge);
  await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();await page.evaluate(()=>window.__release('request_merge'));await ready(page);await unlock(page);
  assert.equal(await page.locator('[data-merge-session]').count(),0);assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
 },{discovered:[peer]});
 await check('late completed merge list cannot show success after locking',async page=>{
  await page.locator('[data-tab=devices]').click();
  await page.evaluate(()=>{window.__fixture.delays.list_entries=true;Object.assign(window.__fixture.merges[0],{state:'completed',completed_at:Date.now()/1000});});await tick(page);await page.waitForFunction(()=>!!window.__fixture.pending.list_entries);
  await page.evaluate(()=>{window.__lock();window.__fixture.delays.list_entries=false;window.__release('list_entries');});await page.locator('#gate-form').waitFor();
  await unlock(page);assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
 },{merges:[incoming]});
 await check('mobile layout remains usable without horizontal overflow',async page=>{
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.getByRole('switch',{name:'账号明文显示'}).check();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.getByRole('switch',{name:'账号明文显示'}).uncheck();assert.equal((await page.locator('.entries').innerHTML()).includes(fixtureEntry.username),false);await shot(page,'mobile-vault',{fullPage:false});await click(page,'recovery');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await shot(page,'mobile-recovery',{fullPage:false});await page.locator('[data-recovery-id]').click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await shot(page,'mobile-recovery-history',{fullPage:false});await click(page,'close');
  await page.locator('[data-tab=devices]').click();await page.getByText('123456',{exact:true}).waitFor();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);assert.deepEqual(await page.locator('.local-address').allTextContents(),['192.168.100.200','10.10.10.10','172.18.0.4']);await shot(page,'mobile-devices',{fullPage:false});await click(page,'detect');await ready(page);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await shot(page,'mobile-discovery-progress',{fullPage:false});
  await page.evaluate(()=>{window.__fixture.discovered[0].name='A'.repeat(64);window.__fixture.merges[0].peer_name='B'.repeat(64);});await tick(page);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 },{mobile:true,discovered:[peer],merges:[incoming],localAddresses:['192.168.100.200','10.10.10.10','172.18.0.4'],scanRanges:['192.168.100.0/24','10.10.10.0/24','172.18.0.0/24'],scanTotal:759});
 await check('local vault remains available when networking failed',async page=>{
  assert.equal(await page.locator('[data-entry]').count(),1);await page.locator('[data-tab=devices]').click();await page.getByText('端口被其他程序占用',{exact:true}).waitFor();assert.equal(await page.locator('[data-action=detect]').isDisabled(),true);assert.equal(await page.locator('#lan-scan-progress').isVisible(),false);assert.deepEqual(await page.locator('.local-address').allTextContents(),['192.168.1.10']);await page.locator('[data-tab=vault]').click();await shot(page,'desktop-vault');
  await page.locator('#lock').click();await page.locator('#lock-status').filter({hasText:'界面已锁定 · 插件暂不可用'}).waitFor();assert.equal(await page.evaluate(()=>window.__fixture.locked),false);assert.match(await page.locator('#gate-hint').innerText(),/服务|失败|不可用/);assert.doesNotMatch(await page.locator('#lock-status').innerText(),/密码库已锁定/);
 },{serviceError:true});
 console.log(`${passed} desktop/mobile UI scenarios passed`);
}finally{await browser?.close();server.kill('SIGTERM');}
