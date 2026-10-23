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
  const state={initialized:options.initialized!==false,locked:options.locked??false,mobile:options.mobile??false,entries:[entry],clients:[],peers:[],calls:[],delays:{},pending:{},copied:[],events:{}};
  window.__fixture=state; window.isTauri=true;
  let next=1; const callbacks=new Map();
  window.__lock=()=>{state.locked=true;callbacks.get(state.events['vault-locked'])?.({event:'vault-locked',id:1,payload:null});};
  window.__release=name=>state.pending[name]?.();
  window.__TAURI_INTERNALS__={
   transformCallback(fn){const id=next++;callbacks.set(id,fn);return id;},unregisterCallback(id){callbacks.delete(id);},
   async invoke(name,args={}){
    state.calls.push({name,...(name==='save_entry'?{id:args.input.id,hostname:args.input.hostname}:{} )});
    let result;
    if(name==='plugin:event|listen'){state.events[args.event]=args.handler;return next++;}
    if(name==='plugin:event|unlisten')return;
    if(name==='plugin:clipboard-manager|write_text'){state.copied.push(args.text);return;}
    if(name==='app_status')result={vault:{initialized:state.initialized,locked:state.locked,device_id:'device-1',device_name:'测试电脑',entry_count:state.entries.length,peer_count:state.peers.length},service:options.serviceError?null:{local_endpoint:'http://127.0.0.1:17841',lan_port:17842,running:true,last_sync:null,last_error:null,discovered:[]},service_error:options.serviceError?'端口被其他程序占用':null,local_addresses:['192.168.1.10'],mobile:state.mobile};
    else if(name==='create_vault'||name==='unlock_vault'){if(args.password==='wrong-password')throw '主密码错误';state.initialized=true;state.locked=false;result=null;}
    else if(name==='lock_vault'){window.__lock();result=null;}
    else if(name==='user_activity')return;
    else if(state.locked)throw '密码库已锁定';
    else if(name==='list_entries')result=state.entries.map(({password,notes,...item})=>({...item,conflict_count:0}));
    else if(name==='list_peers')result=state.peers;
    else if(name==='list_clients')result=state.clients;
    else if(name==='get_entry')result=state.entries.find(item=>item.id===args.id);
    else if(name==='entry_history')result=[{...entry,password:'previous-fixture-secret'}];
    else if(name==='save_entry'){const value={...args.input,id:args.input.id||'new-entry',deleted:false,version:{counter:2,device_id:'device-1',modified_at:Date.now()}};state.entries=state.entries.filter(item=>item.id!==value.id);state.entries.push(value);result=value;}
    else if(name==='delete_entry'){state.entries=state.entries.filter(item=>item.id!==args.id);result=null;}
    else if(name==='create_client'){const client={id:'client-1',name:args.name,origin:args.origin};state.clients.push(client);result={client,token:'fixture-connection-token'};}
    else if(name==='revoke_client'){state.clients=state.clients.filter(item=>item.id!==args.id);result=null;}
    else if(name==='create_invitation')result={code:'omp1.fixture-invitation',expires_at:Date.now()/1000+300,endpoint:'http://192.168.1.10:17842'};
    else if(name==='accept_invitation'){state.peers.push({device_id:'peer-1',name:'测试手机',endpoint:'http://192.168.1.20:17842'});result=null;}
    else if(name==='remove_peer'){state.peers=state.peers.filter(item=>item.device_id!==args.id);result=null;}
    else if(name==='sync_now')result=null;
    else throw new Error(`Unmocked command ${name}`);
    result=structuredClone(result);
    if(state.delays[name])await new Promise(resolve=>state.pending[name]=resolve);
    return result;
   }
  };
 }, {entry:fixtureEntry,options});
}
const click = (page,action)=>page.locator(`[data-action="${action}"]`).first().click();
const ready = page=>page.waitForFunction(()=>document.querySelector('#app')?.getAttribute('aria-busy')!=='true');
async function unlock(page){await page.locator('#master-password').fill('correct-fixture-password');await page.locator('#gate-form button').click();await page.locator('.shell').waitFor();await ready(page);}
async function shot(page,name){if(process.env.OMP_CAPTURE_DIR){await mkdir(process.env.OMP_CAPTURE_DIR,{recursive:true});await page.screenshot({path:`${process.env.OMP_CAPTURE_DIR}/${name}.png`,fullPage:true});}}
async function check(name,action,options={}){
 const context=await browser.newContext({viewport:options.mobile?{width:390,height:844}:{width:1280,height:900}});
 const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
 try{
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
 await check('password is fetched on demand, edit persists same record, delete confirms',async page=>{
  assert.equal((await page.content()).includes(fixtureEntry.password),false);assert.equal(await page.evaluate(()=>window.__fixture.calls.some(c=>c.name==='get_entry')),false);
  await page.locator('[data-entry]').click();await page.locator('#entry-password').waitFor();assert.equal(await page.locator('#entry-password').getAttribute('type'),'password');
  await click(page,'reveal');assert.equal(await page.locator('#entry-password').getAttribute('type'),'text');await page.locator('#entry-password').fill('new-fixture-password');await page.locator('#entry-form [type=submit]').click();await page.locator('dialog').waitFor({state:'detached'});await ready(page);
  assert.equal(await page.evaluate(()=>window.__fixture.entries[0].password),'new-fixture-password');assert.equal(await page.evaluate(()=>window.__fixture.entries[0].id),'record-1');
  await page.locator('[data-entry]').click();await click(page,'delete');assert.equal(await page.evaluate(()=>window.__fixture.entries.length),1);await click(page,'confirm');await page.locator('.empty').waitFor();
 });
 await check('authorization is bound to extension and token can be hidden',async page=>{
  await page.locator('[data-tab=browser]').click();await page.locator('[name=name]').fill('测试 Chrome');await page.locator('[name=origin]').fill('chrome-extension://abcdefghijklmnopabcdefghijklmnop');await page.locator('#client-form [type=submit]').click();await page.locator('.secret-box').waitFor();
  assert.equal(await page.locator('.secret-box textarea').inputValue(),'fixture-connection-token');await click(page,'hide-token');assert.equal(await page.locator('.secret-box').count(),0);
  await page.locator('[data-revoke-client]').click();await click(page,'confirm');await ready(page);assert.equal(await page.evaluate(()=>window.__fixture.clients.length),0);
 });
 await check('locking clears open password and secret controls',async page=>{
  await page.locator('[data-entry]').click();await page.locator('#entry-password').waitFor();await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();
  assert.equal((await page.content()).includes(fixtureEntry.password),false);assert.equal(await page.locator('dialog').count(),0);await unlock(page);assert.equal(await page.locator('dialog').count(),0);
 });
 await check('late password reply cannot restore dialog after lock',async page=>{
  await page.evaluate(()=>window.__fixture.delays.get_entry=true);await page.locator('[data-entry]').click();await page.waitForFunction(()=>!!window.__fixture.pending.get_entry);
  await page.evaluate(()=>window.__lock());await page.locator('#gate-form').waitFor();await page.evaluate(()=>window.__release('get_entry'));await ready(page);await unlock(page);
  assert.equal(await page.locator('dialog').count(),0);assert.equal((await page.content()).includes(fixtureEntry.password),false);
 });
 await check('late authorization token cannot return after lock',async page=>{
  await page.locator('[data-tab=browser]').click();await page.locator('[name=name]').fill('测试 Chrome');await page.locator('[name=origin]').fill('chrome-extension://abcdefghijklmnopabcdefghijklmnop');await page.evaluate(()=>window.__fixture.delays.create_client=true);await page.locator('#client-form [type=submit]').click();await page.waitForFunction(()=>!!window.__fixture.pending.create_client);
  await page.evaluate(()=>window.__lock());await page.evaluate(()=>window.__release('create_client'));await ready(page);await unlock(page);assert.equal(await page.locator('.secret-box').count(),0);
 });
 await check('remote changes appear without navigation',async page=>{
  await page.evaluate(()=>window.__fixture.entries.push({...window.__fixture.entries[0],id:'remote-entry',title:'来自手机的新密码',hostname:'remote.example.com'}));
  await page.getByText('来自手机的新密码',{exact:true}).waitFor({timeout:8000});
 });
 await check('mobile layout remains usable without horizontal overflow',async page=>{
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.locator('[data-tab=devices]').click();await page.locator('#invite-form').waitFor();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await shot(page,'mobile-devices');
 },{mobile:true});
 await check('local vault remains available when networking failed',async page=>{
  assert.equal(await page.locator('[data-entry]').count(),1);await page.locator('[data-tab=devices]').click();await page.getByText('端口被其他程序占用',{exact:true}).waitFor();await page.locator('[data-tab=vault]').click();await shot(page,'desktop-vault');
 },{serviceError:true});
 console.log(`${passed} desktop/mobile UI scenarios passed`);
}finally{await browser?.close();server.kill('SIGTERM');}
