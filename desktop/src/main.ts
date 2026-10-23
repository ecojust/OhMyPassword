import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import type { AppStatus, Entry, EntryInput, EntrySummary, Peer, Client, Grant, Invitation } from './types';
import './styles.css';

const root = document.querySelector<HTMLDivElement>('#app')!;
const esc = (value:unknown) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const icon = (name:string) => ({vault:'▤',devices:'⇄',browser:'▣'}[name] ?? '◇');
let status:AppStatus|null = null;
let entries:EntrySummary[] = [];
let peers:Peer[] = [];
let clients:Client[] = [];
let tab:'vault'|'devices'|'browser' = 'vault';
let query = '';
let busy = false;
let notice = '';
let isError = false;
let selected:Entry|null = null;
let history:Entry[] = [];
let grant:Grant|null = null;
let invitation:Invitation|null = null;
let dialog:'entry'|'history'|'delete'|'revoke-peer'|'revoke-client'|null = null;
let revokeId = '';
let revealed = false;
let epoch = 0;
let lastActivity = 0;

const when = (value?:number|null) => value ? new Date(value < 1e12 ? value*1000 : value).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}) : '尚未同步';
const api = async <T>(command:string,args:Record<string,unknown>={}):Promise<T> => { const generation=epoch; const result=await invoke<T>(command,args); if(generation!==epoch && command!=='lock_vault' && command!=='app_status') throw new Error('密码库会话已结束，请重新解锁。'); return result; };
function clearSecrets() { selected=null; history=[]; grant=null; invitation=null; revealed=false; dialog=null; entries=[]; peers=[]; clients=[]; query=''; epoch++; }
function feedback(message:string,error=false) { notice=message; isError=error; const el=document.querySelector('#notice'); if(el){el.textContent=message;el.className=`notice ${error?'error':''}`;} }
async function run(action:()=>Promise<void>) { if(busy)return;busy=true;setBusy(true);try{await action();}catch(error){feedback(String(error),true);}finally{busy=false;setBusy(false);} }
function setBusy(value:boolean) { document.querySelectorAll<HTMLButtonElement>('button:not([data-action="lock"]):not([data-action="close"])').forEach(el=>el.disabled=value);root.setAttribute('aria-busy',String(value)); }
async function refresh(renderPage=true) {
 const current=epoch;
 const next=await api<AppStatus>('app_status');
 if(current!==epoch)return;
 if(next.vault.locked && status && !status.vault.locked) clearSecrets();
 status=next;
 if(!next.vault.locked){
   const values=await Promise.all([api<EntrySummary[]>('list_entries'),api<Peer[]>('list_peers'),api<Client[]>('list_clients')]);
   if(current!==epoch || status?.vault.locked)return;
   [entries,peers,clients]=values;
 }
 if(renderPage)render();
}
const noticeMarkup = () => `<div id="notice" class="notice ${isError?'error':''}" role="status" aria-live="polite">${esc(notice)}</div>`;
function render() {
 if(!isTauri()) { root.innerHTML=`<main class="gate"><div class="mark">◇</div><h1>OhMyPassword</h1><p>请使用桌面或移动客户端</p><p class="muted">浏览器预览只展示界面，不保存密码，也不会连接本地密码库。</p></main>`; return; }
 if(!status){root.innerHTML='<main class="gate"><div class="mark">◇</div><h1>OhMyPassword</h1><p>正在打开本地密码库…</p>'+noticeMarkup()+'</main>';return;}
 if(status.vault.locked){renderGate();return;}
 root.innerHTML=`<div class="shell"><aside><a class="brand" href="#"><span class="mark small">◇</span><span>OhMyPassword<small>你的本地密码库</small></span></a><nav aria-label="主要页面">${(['vault','devices','browser'] as const).map(t=>`<button data-tab="${t}" class="nav ${tab===t?'active':''}" ${tab===t?'aria-current="page"':''}><span>${icon(t)}</span>${{vault:'密码库',devices:'设备同步',browser:'浏览器'}[t]}</button>`).join('')}</nav><div class="sidebar-foot"><span class="status-dot"></span>本地加密 · 已解锁<br><small>${esc(status.vault.device_name)}</small><button class="quiet" data-action="lock">锁定密码库</button></div></aside><main class="workspace"><header><div><span class="eyebrow">OHMYPASSWORD</span><h1>${{vault:'密码库',devices:'设备同步',browser:'浏览器连接'}[tab]}</h1></div><button class="quiet mobile-lock" data-action="lock">锁定</button>${tab==='vault'?'<button class="primary" data-action="new">＋ 新增密码</button>':''}</header>${noticeMarkup()}${tab==='vault'?vaultView():tab==='devices'?devicesView():browserView()}<footer>15 分钟无应用内操作后自动锁定${status.mobile?' · 切换到后台即锁定':''}</footer></main></div>${dialog?dialogView():''}`;
 bind();
 if(dialog){const el=document.querySelector<HTMLDialogElement>('dialog');el?.showModal();el?.querySelector<HTMLInputElement>('input:not([type=hidden])')?.focus();}
 setBusy(busy);
}
function renderGate() {
 const create=!status!.vault.initialized;
 root.innerHTML=`<main class="gate"><div class="mark">◇</div><span class="eyebrow">OHMYPASSWORD</span><h1>${create?'创建你的密码库':'欢迎回来'}</h1><p>${create?'密码保存在本机，与你信任的设备同步。':'输入主密码，解锁这台设备上的密码库。'}</p><form id="gate-form" class="gate-card">${create?'<label>这台设备的名称<input name="device_name" required maxlength="64" autocomplete="off" placeholder="例如：我的 MacBook"></label>':''}<label>主密码<input id="master-password" name="password" type="password" required ${create?'minlength="10"':''} maxlength="512" autocomplete="${create?'new-password':'current-password'}" autofocus></label>${create?'<label>再次输入主密码<input name="confirm" type="password" required minlength="10" maxlength="512" autocomplete="new-password"></label><p class="hint">至少 10 个字符。主密码不能找回，请妥善保管。每台设备可设置不同主密码。</p>':''}<button class="primary full" type="submit">${create?'创建并加密':'解锁密码库'}</button></form>${noticeMarkup()}<p class="hint">${create?'已有其他设备？先创建本机密码库，再通过配对导入。':'解锁后才会响应浏览器请求并同步已配对设备。'}</p></main>`;
 document.querySelector('#gate-form')?.addEventListener('submit',event=>{event.preventDefault();void run(async()=>{
  const form=event.currentTarget as HTMLFormElement;const data=new FormData(form);let password=String(data.get('password')??'');let confirm=String(data.get('confirm')??'');const name=String(data.get('device_name')??'');
  if(create&&password!==confirm){feedback('两次输入的主密码不一致',true);return;}
  form.reset();try{await api(create?'create_vault':'unlock_vault',{password,deviceName:name});notice='';await refresh();}finally{password='';confirm='';data.delete('password');data.delete('confirm');}
 });});setBusy(busy);
}
function vaultView(){
 const visible=entries.filter(e=>`${e.title} ${e.hostname} ${e.username}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
 return `<div class="toolbar"><label class="search"><span>⌕</span><input id="search" aria-label="搜索密码" placeholder="搜索网站、名称或账号" value="${esc(query)}" autocomplete="off"></label><span class="count">${entries.length} 项</span></div><section class="entries" aria-label="密码列表">${visible.length?visible.map(e=>`<button class="entry" data-entry="${esc(e.id)}"><span class="site-icon">${esc((e.title||e.hostname).slice(0,1).toUpperCase())}</span><span class="entry-copy"><strong>${esc(e.title||e.hostname)}</strong><small>${esc(e.hostname)} · ${esc(e.username||'未填写账号')}</small></span><span class="entry-date">${e.version.modified_at?esc(when(e.version.modified_at)):'••••••••'}</span><span aria-hidden="true">›</span></button>`).join(''):`<div class="empty"><span>◇</span><h2>${query?'没有匹配的密码':'从第一条密码开始'}</h2><p>${query?'试试网站名或账号。':'手动添加，或连接浏览器后保存登录信息。'}</p>${query?'':'<button data-action="new" class="secondary">新增密码</button>'}</div>`}</section><p class="hint">网站账号按完整 hostname 精确匹配。修改后自动同步到在线、已配对且已解锁的设备。</p>`;
}
function devicesView(){
 return `<div class="summary-card"><span class="status-dot ${status!.service?'':'offline'}"></span><div><strong>${status!.service?'同步服务已启动':'同步服务暂不可用'}</strong><p>${status!.service_error?esc(status!.service_error):`<span id="sync-last">上次同步：${esc(when(status!.service?.last_sync))}</span>`}</p>${status!.service?.last_error?`<p class="error-text">${esc(status!.service.last_error)}</p>`:''}</div><button class="secondary" data-action="sync">立即同步</button></div><section class="panel"><h2>已配对设备 <span class="count">${peers.length}</span></h2><p class="muted">同一局域网内自动发现；只有已配对设备可以同步。请保持对方应用打开并解锁。</p>${peers.length?peers.map(p=>`<div class="device-row"><span class="site-icon">⇄</span><div><strong>${esc(p.name)}</strong><small>${esc(p.endpoint)}</small></div><button class="quiet danger" data-revoke-peer="${esc(p.device_id)}">解除配对</button></div>`).join(''):'<p class="empty-line">还没有配对设备</p>'}</section><div class="columns"><section class="panel"><h2>邀请另一台设备</h2><p class="muted">将邀请复制到另一台设备。邀请包含临时配对密钥，请通过你信任的方式传递。</p><form id="invite-form"><label>本机局域网 IP<input name="ip" value="${esc(status!.local_addresses[0]||'')}" placeholder="192.168.1.10" required autocomplete="off" list="local-ips"></label><datalist id="local-ips">${status!.local_addresses.map(ip=>`<option value="${esc(ip)}"></option>`).join('')}</datalist><button class="secondary" type="submit">生成 5 分钟邀请</button></form>${invitation?`<div class="secret-box"><label>一次性配对邀请<textarea readonly rows="4">${esc(invitation.code)}</textarea></label><small>过期时间 ${esc(when(invitation.expires_at))}</small><button class="secondary" data-action="copy-invite">复制邀请</button></div>`:''}</section><section class="panel"><h2>连接已有设备</h2><p class="muted">粘贴另一台设备生成的邀请。配对后自动合并密码；同一条密码采用最新修改。</p><form id="join-form"><label>配对邀请<textarea name="invitation" required rows="4" maxlength="8192" placeholder="omp1.…" autocomplete="off"></textarea></label><button class="primary" type="submit">配对并同步</button></form></section></div><p class="hint">手机进入后台后会锁定并暂停同步；回到前台并解锁后自动恢复。局域网隔离或防火墙可能阻止设备连接。</p>`;
}
function browserView(){
 return `<div class="summary-card"><span class="status-dot ${status!.service?'':'offline'}"></span><div><strong>本地浏览器接口</strong><p>${esc(status!.service?.local_endpoint||'服务未启动')}</p></div><span class="pill">仅本机 · 需授权</span></div><section class="panel"><h2>授权浏览器插件</h2><p class="muted">在 OhMyPassword 插件中复制扩展标识，粘贴到这里。生成连接令牌后，再粘贴回插件。</p><form id="client-form"><label>名称<input name="name" required maxlength="64" placeholder="例如：这台电脑的 Chrome"></label><label>扩展标识<input name="origin" required maxlength="256" placeholder="chrome-extension://… 或 moz-extension://…" spellcheck="false" autocomplete="off"></label><button class="primary" type="submit">生成连接令牌</button></form>${grant?`<div class="secret-box"><label>连接令牌（仅本次显示）<textarea readonly rows="2">${esc(grant.token)}</textarea></label><button class="secondary" data-action="copy-token">复制令牌</button><button class="quiet" data-action="hide-token">已保存，隐藏</button></div>`:''}</section><section class="panel"><h2>已授权浏览器 <span class="count">${clients.length}</span></h2>${clients.length?clients.map(c=>`<div class="device-row"><span class="site-icon">▣</span><div><strong>${esc(c.name)}</strong><small>${esc(c.origin)}</small></div><button class="quiet danger" data-revoke-client="${esc(c.id)}">撤销授权</button></div>`).join(''):'<p class="empty-line">还没有浏览器连接权限</p>'}</section><p class="hint">插件只能在密码库解锁时读取对应网站的账号。普通网页没有读取权限；撤销授权后原令牌立即失效。</p>`;
}
function dialogView(){
 if(dialog==='delete'||dialog==='revoke-peer'||dialog==='revoke-client'){
  const text=dialog==='delete'?'删除这条密码？':dialog==='revoke-peer'?'解除设备配对？':'撤销浏览器授权？';
  const detail=dialog==='delete'?'删除会同步到已配对设备。旧版本仍作为历史保存在加密密码库中。':dialog==='revoke-peer'?'这台设备将不能再与本机同步。对方已保存的密码不会被远程删除。':'这个浏览器需要重新授权才能访问密码。';
  return `<dialog aria-labelledby="dialog-title"><h2 id="dialog-title">${text}</h2><p class="muted">${detail}</p><div class="dialog-actions"><button class="secondary" data-action="close">取消</button><button class="primary danger-fill" data-action="confirm">确认${dialog==='delete'?'删除':'撤销'}</button></div></dialog>`;
 }
 if(dialog==='history')return `<dialog class="wide" aria-labelledby="dialog-title"><div class="dialog-head"><h2 id="dialog-title">历史版本</h2><button class="quiet" data-action="close">关闭</button></div><p class="muted">当前条目已采用最新修改，历史版本供查看。恢复时请复制所需内容，再保存为新的修改。</p>${history.length?history.map((entry,i)=>`<section class="history"><strong>${esc(when(entry.version.modified_at))}</strong><p>${esc(entry.username)} · ${entry.deleted?'已删除':'历史修改'}</p><input aria-label="历史密码 ${i+1}" type="password" value="${esc(entry.password)}" readonly><button class="quiet" data-history-reveal="${i}">显示</button></section>`).join(''):'<p>没有历史版本。</p>'}</dialog>`;
 const e=selected;
 return `<dialog class="wide" aria-labelledby="dialog-title"><form id="entry-form"><div class="dialog-head"><h2 id="dialog-title">${e?'编辑密码':'新增密码'}</h2><button class="quiet" type="button" data-action="close">关闭</button></div><label>网站 hostname<input name="hostname" required maxlength="253" value="${esc(e?.hostname)}" placeholder="例如：github.com" autocomplete="off" spellcheck="false"></label><label>名称<input name="title" maxlength="256" value="${esc(e?.title)}" placeholder="例如：GitHub"></label><label>账号<input name="username" maxlength="1024" value="${esc(e?.username)}" autocomplete="off" autocapitalize="none"></label><label>密码<div class="password-field"><input name="password" id="entry-password" type="${revealed?'text':'password'}" required maxlength="4096" value="${esc(e?.password)}" autocomplete="new-password"><button type="button" class="quiet" data-action="reveal" aria-label="${revealed?'隐藏密码':'显示密码'}">${revealed?'隐藏':'显示'}</button><button type="button" class="quiet" data-action="copy-password" aria-label="复制密码">复制</button></div></label><label>备注<textarea name="notes" rows="3" maxlength="8192">${esc(e?.notes)}</textarea></label><div class="dialog-actions">${e?'<button type="button" class="quiet danger" data-action="delete">删除</button><button type="button" class="quiet" data-action="history">历史版本</button>':'<button type="button" class="quiet" data-action="generate">生成随机密码</button>'}<button type="submit" class="primary">保存密码</button></div></form></dialog>`;
}
function bind(){
 document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(el=>el.addEventListener('click',()=>{grant=null;invitation=null;selected=null;tab=el.dataset.tab as typeof tab;notice='';render();}));
 document.querySelector('#search')?.addEventListener('input',e=>{const el=e.target as HTMLInputElement;query=el.value;const start=el.selectionStart;render();const next=document.querySelector<HTMLInputElement>('#search');next?.focus();if(start!==null)next?.setSelectionRange(start,start);});
 document.querySelectorAll<HTMLButtonElement>('[data-entry]').forEach(el=>el.addEventListener('click',()=>void run(async()=>{selected=await api<Entry>('get_entry',{id:el.dataset.entry});revealed=false;dialog='entry';render();})));
 document.querySelectorAll<HTMLButtonElement>('[data-revoke-peer]').forEach(el=>el.addEventListener('click',()=>{revokeId=el.dataset.revokePeer!;dialog='revoke-peer';render();}));
 document.querySelectorAll<HTMLButtonElement>('[data-revoke-client]').forEach(el=>el.addEventListener('click',()=>{revokeId=el.dataset.revokeClient!;dialog='revoke-client';render();}));
 document.querySelectorAll<HTMLButtonElement>('[data-action]').forEach(el=>el.addEventListener('click',()=>void action(el.dataset.action!)));
 document.querySelector('dialog')?.addEventListener('cancel',e=>{e.preventDefault();close();});
 document.querySelectorAll<HTMLButtonElement>('[data-history-reveal]').forEach(el=>el.addEventListener('click',()=>{const input=el.previousElementSibling as HTMLInputElement;input.type=input.type==='password'?'text':'password';el.textContent=input.type==='password'?'显示':'隐藏';}));
 bindForm('entry-form',async(form,data)=>{
  const input:EntryInput={id:selected?.id??null,hostname:String(data.get('hostname')),title:String(data.get('title')),username:String(data.get('username')),password:String(data.get('password')),notes:String(data.get('notes'))};
  try{await api('save_entry',{input});form.reset();selected=null;dialog=null;notice='密码已加密保存，正在同步在线设备。';isError=false;await refresh();}finally{input.password='';data.delete('password');}
 });
 bindForm('invite-form',async(_form,data)=>{invitation=await api<Invitation>('create_invitation',{ip:String(data.get('ip')).trim()});render();});
 bindForm('join-form',async(form,data)=>{const code=String(data.get('invitation')).trim();form.reset();data.delete('invitation');await api('accept_invitation',{code});notice='设备已配对，正在同步密码。';isError=false;await refresh();});
 bindForm('client-form',async(form,data)=>{grant=await api<Grant>('create_client',{name:String(data.get('name')),origin:String(data.get('origin')).trim()});form.reset();notice='已授权。请把令牌粘贴到对应浏览器插件。';isError=false;await refresh();});
}
function bindForm(id:string,handler:(form:HTMLFormElement,data:FormData)=>Promise<void>){document.getElementById(id)?.addEventListener('submit',e=>{e.preventDefault();const form=e.currentTarget as HTMLFormElement;void run(()=>handler(form,new FormData(form)));});}
function close(){selected=null;history=[];revealed=false;dialog=null;render();}
async function action(name:string){
 if(name==='lock'){clearSecrets();if(status)status.vault.locked=true;render();try{await api('lock_vault');await refresh();}catch(e){feedback(String(e),true);}return;}
 if(name==='close'){close();return;}
 if(name==='new'){selected=null;revealed=false;dialog='entry';render();return;}
 if(name==='reveal'){revealed=!revealed;const input=document.querySelector<HTMLInputElement>('#entry-password')!;input.type=revealed?'text':'password';const button=document.querySelector('[data-action="reveal"]')!;button.textContent=revealed?'隐藏':'显示';button.setAttribute('aria-label',revealed?'隐藏密码':'显示密码');return;}
 if(name==='delete'){dialog='delete';render();return;}
 if(name==='generate'){const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_';const bytes=crypto.getRandomValues(new Uint8Array(48));let value='';for(const n of bytes){if(n<Math.floor(256/alphabet.length)*alphabet.length)value+=alphabet[n%alphabet.length];if(value.length===24)break;}const input=document.querySelector<HTMLInputElement>('#entry-password')!;input.value=value;return;}
 if(name==='hide-token'){grant=null;render();return;}
 await run(async()=>{
  if(name==='copy-password'){await writeText(document.querySelector<HTMLInputElement>('#entry-password')!.value);feedback('密码已复制，请留意剪贴板。');}
  if(name==='copy-token'&&grant){await writeText(grant.token);feedback('连接令牌已复制。');}
  if(name==='copy-invite'&&invitation){await writeText(invitation.code);feedback('配对邀请已复制。');}
  if(name==='sync'){await api('sync_now');feedback('已请求同步，保持对方设备解锁。');await refresh(false);}
  if(name==='history'&&selected){history=await api<Entry[]>('entry_history',{id:selected.id});selected=null;dialog='history';render();}
  if(name==='confirm'){
   if(dialog==='delete'&&selected)await api('delete_entry',{id:selected.id});
   if(dialog==='revoke-peer')await api('remove_peer',{id:revokeId});
   if(dialog==='revoke-client')await api('revoke_client',{id:revokeId});
   selected=null;dialog=null;notice='操作已完成。';isError=false;await refresh();
  }
 });
}
for(const name of ['pointerdown','keydown'])document.addEventListener(name,()=>{if(isTauri()&&Date.now()-lastActivity>30_000){lastActivity=Date.now();void api('user_activity').catch(()=>{});}}, {passive:true});
async function init(){
 render();if(!isTauri())return;
 await listen('vault-locked',()=>{clearSecrets();if(status)status.vault.locked=true;notice='密码库已锁定。';isError=false;render();});
 await refresh();
 setInterval(()=>{if(busy||dialog)return;const before=JSON.stringify(entries);void refresh(false).then(()=>{if(status?.vault.locked&&!document.querySelector('#gate-form')){render();return;}if(tab==='vault'&&before!==JSON.stringify(entries)&&!document.activeElement?.matches('input,textarea,select'))render();const sync=document.querySelector('#sync-last');if(sync)sync.textContent=`上次同步：${when(status?.service?.last_sync)}`;}).catch(()=>{});},5_000);
}
void init().catch(e=>{notice=String(e);isError=true;render();});
