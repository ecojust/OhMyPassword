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
  const state={initialized:options.initialized!==false,locked:options.locked??false,mobile:options.mobile??false,entries:[entry],discovered:options.discovered??[],merges:options.merges??[],discovering:false,lastDiscovery:null,nextDiscovery:Date.now()/1000+300,discoveryGeneration:0,listError:false,calls:[],delays:{},pending:{},copied:[],events:{}};
  window.__fixture=state; window.isTauri=true;
  let next=1; const callbacks=new Map();
  window.__lock=()=>{state.locked=true;state.merges=[];callbacks.get(state.events['vault-locked'])?.({event:'vault-locked',id:1,payload:null});};
  window.__release=name=>state.pending[name]?.();
  window.__TAURI_INTERNALS__={
   transformCallback(fn){const id=next++;callbacks.set(id,fn);return id;},unregisterCallback(id){callbacks.delete(id);},
   async invoke(name,args={}){
    state.calls.push({name,...(name==='save_entry'?{id:args.input.id,hostname:args.input.hostname}:['request_merge','respond_merge'].includes(name)?args:{} )});
    let result;
    if(name==='plugin:event|listen'){state.events[args.event]=args.handler;return next++;}
    if(name==='plugin:event|unlisten')return;
    if(name==='plugin:clipboard-manager|write_text'){state.copied.push(args.text);return;}
    if(name==='app_status')result={vault:{initialized:state.initialized,locked:state.locked,device_id:'device-1',device_name:'测试电脑',entry_count:state.entries.length,peer_count:0},service:options.serviceError?null:{local_endpoint:'http://127.0.0.1:17841',lan_port:17842,running:true,last_error:null,discovery_generation:state.discoveryGeneration,last_discovery_at:state.lastDiscovery,next_discovery_at:state.nextDiscovery,discovering:state.discovering,discovered:state.discovered,merges:state.merges},service_error:options.serviceError?'端口被其他程序占用':null,local_addresses:['192.168.1.10'],mobile:state.mobile};
    else if(name==='create_vault'||name==='unlock_vault'){if(args.password==='wrong-password')throw '主密码错误';state.initialized=true;state.locked=false;result=null;}
    else if(name==='lock_vault'){window.__lock();result=null;}
    else if(name==='user_activity')return;
    else if(state.locked)throw '密码库已锁定';
    else if(name==='list_entries'){if(state.listError)throw '密码列表刷新失败';result=state.entries.map(({password,notes,...item})=>({...item,conflict_count:0}));}
    else if(name==='get_entry')result=state.entries.find(item=>item.id===args.id);
    else if(name==='entry_history')result=[{...entry,password:'previous-fixture-secret'}];
    else if(name==='save_entry'){const value={...args.input,id:args.input.id||'new-entry',deleted:false,version:{counter:2,device_id:'device-1',modified_at:Date.now()}};state.entries=state.entries.filter(item=>item.id!==value.id);state.entries.push(value);result=value;}
    else if(name==='delete_entry'){state.entries=state.entries.filter(item=>item.id!==args.id);result=null;}
    else if(name==='detect_devices'){state.discovering=true;state.discoveryGeneration++;state.lastDiscovery=Date.now()/1000;result=null;}
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
    if(state.delays[name])await new Promise(resolve=>state.pending[name]=resolve);
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
 const context=await browser.newContext({viewport:options.mobile?{width:390,height:844}:{width:1280,height:900}});
 const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
 try{
  await page.clock.install();
  if(!options.preview)await mock(page,options);
  await page.goto(url);await page.locator(options.preview?'.gate':options.locked||options.initialized===false?'#gate-form':'.shell').waitFor();
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
  await page.locator('#master-password').fill('wrong-password');await page.locator('#gate-form button').click();await page.getByText('主密码错误',{exact:true}).waitFor();
  assert.equal(await page.locator('#master-password').inputValue(),'');assert.equal(await page.locator('.shell').count(),0);await unlock(page);
 },{locked:true});
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
 await check('browser connection needs no token or authorization form',async page=>{
  await page.locator('[data-tab=browser]').click();await page.getByText('直接连接本机客户端',{exact:true}).waitFor();
  assert.match(await page.locator('.workspace').innerText(),/无需生成或复制额外令牌/);
  assert.equal(await page.locator('#client-form,.secret-box,input,textarea').count(),0);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>['list_clients','create_client','revoke_client'].includes(c.name))),false);
 });
 await check('locking clears open password and secret controls',async page=>{
  await page.getByRole('switch',{name:'账号明文显示'}).check();
  await page.locator('[data-entry]').click();await page.locator('#entry-password').waitFor();await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();
  assert.equal((await page.content()).includes(fixtureEntry.password),false);assert.equal(await page.locator('dialog').count(),0);await unlock(page);assert.equal(await page.locator('dialog').count(),0);
  assert.equal(await page.getByRole('switch',{name:'账号明文显示'}).isChecked(),false);assert.equal((await page.locator('.entries').innerHTML()).includes(fixtureEntry.username),false);
 });
 await check('late password reply cannot restore dialog after lock',async page=>{
  await page.evaluate(()=>window.__fixture.delays.get_entry=true);await page.locator('[data-entry]').click();await page.waitForFunction(()=>!!window.__fixture.pending.get_entry);
  await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();await page.evaluate(()=>window.__release('get_entry'));await ready(page);await unlock(page);
  assert.equal(await page.locator('dialog').count(),0);assert.equal((await page.content()).includes(fixtureEntry.password),false);
 });
 await check('remote changes appear without navigation',async page=>{
  await page.evaluate(()=>window.__fixture.entries.push({...window.__fixture.entries[0],id:'remote-entry',title:'来自手机的新密码',hostname:'remote.example.com'}));
  await tick(page);await page.getByText('来自手机的新密码',{exact:true}).waitFor();
 });
 const peer={id:'peer-1',name:'测试手机',endpoint:'http://192.168.1.20:17842',last_seen:Date.now()/1000};
 const incoming={id:'incoming-1',peer_id:peer.id,peer_name:peer.name,endpoint:peer.endpoint,direction:'incoming',state:'awaiting_confirmation',verification_code:'123456',created_at:Date.now()/1000,expires_at:Date.now()/1000+120,completed_at:null,error:null};
 await check('device detection is separate from manual password merging',async page=>{
  await page.locator('[data-tab=devices]').click();assert.match(await page.locator('.workspace').innerText(),/每 5 分钟自动检测/);
  assert.equal(await page.locator('#invite-form,#join-form').count(),0);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>['request_merge','respond_merge','sync_now'].includes(c.name))),false);
  await click(page,'detect');await ready(page);assert.equal(await page.locator('[data-action=detect]').isDisabled(),true);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='detect_devices').length),1);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>c.name==='request_merge')),false);
  await page.evaluate(peer=>{window.__fixture.discovering=false;window.__fixture.discovered=[peer];},peer);await tick(page);await page.locator('[data-merge-device]').waitFor();
  assert.equal(await page.locator('[data-action=detect]').isDisabled(),false);
 },{});
 await check('manual merge waits for confirmation and durable completion before success',async page=>{
  await page.locator('[data-tab=devices]').click();await page.locator('[data-merge-device]').click();await ready(page);
  assert.equal(await page.locator('[data-merge-device]').isDisabled(),true);assert.notEqual(await page.locator('#notice').innerText(),'已合并密码本');
  assert.equal(await page.evaluate(()=>window.__fixture.calls.filter(c=>c.name==='request_merge').length),1);
  await page.evaluate(()=>Object.assign(window.__fixture.merges[0],{state:'awaiting_confirmation',verification_code:'123456'}));await tick(page);
  await page.getByText('123456',{exact:true}).waitFor();await shot(page,'desktop-devices');await page.locator('[data-respond-merge][data-accept=true]').click();await ready(page);
  assert.notEqual(await page.locator('#notice').innerText(),'已合并密码本');
  await page.evaluate(()=>window.__fixture.merges[0].state='merging');await tick(page);await page.getByText('正在合并密码本…',{exact:true}).waitFor();
  await page.evaluate(()=>{window.__fixture.entries.push({...window.__fixture.entries[0],id:'merged-entry',title:'合并后的新密码'});Object.assign(window.__fixture.merges[0],{state:'completed',completed_at:Date.now()/1000});});
  await tick(page);await page.locator('#notice').filter({hasText:'已合并密码本'}).waitFor();assert.equal(await page.locator('#notice').innerText(),'已合并密码本');
  await page.locator('[data-tab=vault]').click();await page.getByText('合并后的新密码',{exact:true}).waitFor();
 },{discovered:[peer]});
 await check('incoming merge can be rejected without success feedback',async page=>{
  await page.locator('[data-tab=devices]').click();await page.getByText('123456',{exact:true}).waitFor();
  await page.locator('[data-respond-merge][data-accept=false]').click();await ready(page);
  assert.equal(await page.evaluate(()=>window.__fixture.calls.find(c=>c.name==='respond_merge').accept),false);
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
 },{merges:[incoming]});
 await check('incoming accepted merge reports completion only after records refresh',async page=>{
  await page.locator('[data-tab=devices]').click();await page.locator('[data-respond-merge][data-accept=true]').click();await ready(page);
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
  await page.evaluate(()=>{window.__fixture.listError=true;Object.assign(window.__fixture.merges[0],{state:'completed',completed_at:Date.now()/1000});});await tick(page);
  assert.equal(await page.getByText('已合并密码本',{exact:true}).count(),0);
  await page.evaluate(()=>window.__fixture.listError=false);await tick(page);await page.locator('#notice').filter({hasText:'已合并密码本'}).waitFor();
  assert.equal(await page.locator('.merge-state').innerText(),'已合并密码本');await shot(page,'mobile-merged',{fullPage:false});
 },{mobile:true,merges:[incoming]});
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
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.getByRole('switch',{name:'账号明文显示'}).check();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.getByRole('switch',{name:'账号明文显示'}).uncheck();assert.equal((await page.locator('.entries').innerHTML()).includes(fixtureEntry.username),false);await shot(page,'mobile-vault',{fullPage:false});
  await page.locator('[data-tab=devices]').click();await page.getByText('123456',{exact:true}).waitFor();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await shot(page,'mobile-devices',{fullPage:false});
  await page.evaluate(()=>{window.__fixture.discovered[0].name='A'.repeat(64);window.__fixture.merges[0].peer_name='B'.repeat(64);});await tick(page);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 },{mobile:true,discovered:[peer],merges:[incoming]});
 await check('local vault remains available when networking failed',async page=>{
  assert.equal(await page.locator('[data-entry]').count(),1);await page.locator('[data-tab=devices]').click();await page.getByText('端口被其他程序占用',{exact:true}).waitFor();await page.locator('[data-tab=vault]').click();await shot(page,'desktop-vault');
 },{serviceError:true});
 console.log(`${passed} desktop/mobile UI scenarios passed`);
}finally{await browser?.close();server.kill('SIGTERM');}
