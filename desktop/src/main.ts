import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import type { AppStatus, Entry, EntryInput, EntrySummary, MergeSession } from './types';
import './styles.css';

const root = document.querySelector<HTMLDivElement>('#app')!;
const esc = (value:unknown) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const icon = (name:string) => ({vault:'▤',devices:'⇄',browser:'▣'}[name] ?? '◇');
let status:AppStatus|null = null;
let entries:EntrySummary[] = [];
let tab:'vault'|'devices'|'browser' = 'vault';
let query = '';
let showUsernames = false;
let busy = false;
let notice = '';
let isError = false;
let selected:Entry|null = null;
let history:Entry[] = [];
let recoveryEntries:EntrySummary[] = [];
let restoreCandidate:Entry|null = null;
let historyFromRecovery = false;
let dialogGeneration = 0;
let dialog:'entry'|'history'|'delete'|'recovery'|'restore'|null = null;
const completedVerified = new Set<string>();
const outcomesSeen = new Set<string>();
let refreshing = false;
let refreshSequence = 0;
let renderedSignature = '';
let revealed = false;
let epoch = 0;
let lastActivity = 0;

const when = (value?:number|null) => value ? new Date(value < 1e12 ? value*1000 : value).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}) : '暂无记录';
const api = async <T>(command:string,args:Record<string,unknown>={}):Promise<T> => { const generation=epoch; const result=await invoke<T>(command,args); if(generation!==epoch && command!=='lock_vault' && command!=='app_status') throw new Error('密码库会话已结束，请重新解锁。'); return result; };
function clearSecrets() { dialogGeneration++; selected=null; history=[]; recoveryEntries=[]; restoreCandidate=null; historyFromRecovery=false; revealed=false; dialog=null; entries=[]; query=''; showUsernames=false; completedVerified.clear(); outcomesSeen.clear(); epoch++; }
function feedback(message:string,error=false) { notice=message; isError=error; document.querySelectorAll('#notice,#dialog-notice').forEach(el=>{el.textContent=message;el.className=`notice ${error?'error':''}`;}); }
async function run(action:()=>Promise<void>) { if(busy)return;busy=true;setBusy(true);try{await action();}catch(error){feedback(String(error),true);}finally{busy=false;setBusy(false);} }
function setBusy(value:boolean) { document.querySelectorAll<HTMLButtonElement>('button:not([data-action="lock"]):not([data-action="close"])').forEach(el=>el.disabled=value||el.dataset.unavailable==='true');root.setAttribute('aria-busy',String(value)); }
async function refresh(renderPage=true) {
 const current=epoch;
 const sequence=++refreshSequence;
 const next=await api<AppStatus>('app_status');
 if(current!==epoch||sequence!==refreshSequence)return;
 if(next.vault.locked && status && !status.vault.locked) clearSecrets();
 status=next;
 if(!next.vault.locked){
   const values=await api<EntrySummary[]>('list_entries');
   if(current!==epoch||sequence!==refreshSequence||status?.vault.locked)return;
   if(next.vault.entry_count>0&&values.length===0)throw new Error('密码列表未能完整读取，已保留当前显示。请暂停合并并检查历史恢复。');
   if(values.length===0&&(next.service?.merges??[]).some(merge=>merge.state==='completed'&&merge.direction==='outgoing'&&(merge.received_count??0)>0&&!completedVerified.has(merge.id)))throw new Error('已接收，但本机较新的删除记录可能使密码仍隐藏。请查看「历史恢复」核对，暂不确认合并成功。');
   entries=values;
   // A completed service operation is acknowledged only after the refreshed
   // vault list arrives in the same unlocked UI session.
   for(const merge of next.service?.merges??[]){
    if(merge.state==='completed'){
     completedVerified.add(merge.id);
     if(!outcomesSeen.has(merge.id)){outcomesSeen.add(merge.id);feedback(mergeCompletedMessage(merge));}
    }else if(['rejected','failed','expired'].includes(merge.state)&&!outcomesSeen.has(merge.id)){
     outcomesSeen.add(merge.id);feedback(merge.error||mergeMessage(merge),true);
    }
   }
 }
 if(renderPage)render();
}
const mergeCompletedMessage = (merge:MergeSession) => merge.direction==='incoming' ? '已向对方提供密码，本机密码未修改' : merge.received_count===0 ? '对方没有可接收的密码，本机密码保持不变' : '已合并密码本';
const mergeActive = (merge:MergeSession) => ['waiting','awaiting_confirmation','merging'].includes(merge.state);
function mergeMessage(merge:MergeSession):string {
 if(merge.state==='completed')return completedVerified.has(merge.id)?mergeCompletedMessage(merge):'正在核对本机密码本…';
 return {waiting:merge.verification_code?'等待另一台设备确认':'正在连接另一台设备…',awaiting_confirmation:'请核对两台设备上的编号',merging:merge.direction==='incoming'?'正在向对方提供密码…':'正在接收并合并密码…',rejected:'本次合并已拒绝或取消',failed:'合并失败，请重试',expired:'合并请求已过期，请重新发起'}[merge.state];
}
const noticeMarkup = () => `<div id="notice" class="notice ${isError?'error':''}" role="status" aria-live="polite">${esc(notice)}</div>`;
const viewSignature = () => JSON.stringify({entries,status,completed:[...completedVerified]});
function render() {
 renderedSignature=viewSignature();
 if(!isTauri()) { root.innerHTML=`<main class="gate"><div class="mark">◇</div><h1>OhMyPassword</h1><p>请使用桌面或移动客户端</p><p class="muted">浏览器预览只展示界面，不保存密码，也不会连接本地密码库。</p></main>`; return; }
 if(!status){root.innerHTML='<main class="gate"><div class="mark">◇</div><h1>OhMyPassword</h1><p>正在打开本地密码库…</p>'+noticeMarkup()+'</main>';return;}
 if(status.vault.locked){renderGate();return;}
 root.innerHTML=`<div class="shell"><aside><a class="brand" href="#"><span class="mark small">◇</span><span>OhMyPassword<small>你的本地密码库</small></span></a><nav aria-label="主要页面">${(['vault','devices','browser'] as const).map(t=>`<button data-tab="${t}" class="nav ${tab===t?'active':''}" ${tab===t?'aria-current="page"':''}><span>${icon(t)}</span>${{vault:'密码库',devices:'设备同步',browser:'浏览器'}[t]}</button>`).join('')}</nav><div class="sidebar-foot"><span class="status-dot"></span>本地加密 · 已解锁<br><small>${esc(status.vault.device_name)}</small><button class="quiet" data-action="lock">锁定密码库</button></div></aside><main class="workspace"><header><div><span class="eyebrow">OHMYPASSWORD</span><h1>${{vault:'密码库',devices:'设备同步',browser:'浏览器连接'}[tab]}</h1></div><button class="quiet mobile-lock" data-action="lock">锁定</button>${tab==='vault'?'<button class="primary" data-action="new">＋ 新增密码</button>':''}</header>${noticeMarkup()}${tab==='vault'?vaultView():tab==='devices'?devicesView():browserView()}<footer>15 分钟无应用内操作后自动锁定${status.mobile?' · 切换到后台即锁定':''}</footer></main></div>${dialog?dialogView():''}`;
 bind();
 if(dialog){const el=document.querySelector<HTMLDialogElement>('dialog');el?.insertAdjacentHTML('afterbegin',`<div id="dialog-notice" class="notice ${isError?'error':''}" role="status" aria-live="polite">${esc(isError?notice:'')}</div>`);el?.showModal();el?.querySelector<HTMLInputElement>('input:not([type=hidden])')?.focus();}
 setBusy(busy);
}
function renderGate() {
 const create=!status!.vault.initialized;
 root.innerHTML=`<main class="gate"><div class="mark">◇</div><span class="eyebrow">OHMYPASSWORD</span><h1>${create?'创建你的密码库':'欢迎回来'}</h1><p>${create?'密码保存在本机，与你信任的设备同步。':'输入主密码，解锁这台设备上的密码库。'}</p><form id="gate-form" class="gate-card">${create?'<label>这台设备的名称<input name="device_name" required maxlength="64" autocomplete="off" placeholder="例如：我的 MacBook"></label>':''}<label>主密码<input id="master-password" name="password" type="password" required ${create?'minlength="10"':''} maxlength="512" autocomplete="${create?'new-password':'current-password'}" autofocus></label>${create?'<label>再次输入主密码<input name="confirm" type="password" required minlength="10" maxlength="512" autocomplete="new-password"></label><p class="hint">至少 10 个字符。主密码不能找回，请妥善保管。每台设备可设置不同主密码。</p>':''}<button class="primary full" type="submit">${create?'创建并加密':'解锁密码库'}</button></form>${noticeMarkup()}<p class="hint">${create?'已有其他设备？先创建本机密码库，再检测设备并手动合并。':'解锁后可使用浏览器插件，并检测设备以手动合并密码本。'}</p></main>`;
 document.querySelector('#gate-form')?.addEventListener('submit',event=>{event.preventDefault();void run(async()=>{
  const form=event.currentTarget as HTMLFormElement;const data=new FormData(form);let password=String(data.get('password')??'');let confirm=String(data.get('confirm')??'');const name=String(data.get('device_name')??'');
  if(create&&password!==confirm){feedback('两次输入的主密码不一致',true);return;}
  form.reset();try{await api(create?'create_vault':'unlock_vault',{password,deviceName:name});clearSecrets();notice='';await refresh();}finally{password='';confirm='';data.delete('password');data.delete('confirm');}
 });});setBusy(busy);
}
function vaultView(){
 const visible=entries.filter(e=>`${e.title} ${e.hostname} ${e.username}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
 return `<div class="toolbar"><label class="search"><span>⌕</span><input id="search" aria-label="搜索密码" placeholder="搜索网站、名称或账号" value="${esc(query)}" autocomplete="off"></label><label class="account-toggle"><input id="show-usernames" type="checkbox" role="switch" ${showUsernames?'checked':''}><span>账号明文显示</span></label><span class="count">${entries.length} 项</span><button class="quiet" data-action="recovery">历史恢复</button></div><section class="entries" aria-label="密码列表">${visible.length?visible.map(e=>`<button class="entry" data-entry="${esc(e.id)}"><span class="site-icon">${esc((e.title||e.hostname).slice(0,1).toUpperCase())}</span><span class="entry-copy"><strong>${esc(e.title||e.hostname)}</strong><small>${esc(e.hostname)} · <span class="entry-account">${esc(accountText(e))}</span></small></span><span class="entry-date">${e.version.modified_at?esc(when(e.version.modified_at)):'••••••••'}</span><span aria-hidden="true">›</span></button>`).join(''):`<div class="empty"><span>◇</span><h2>${query?'没有匹配的密码':'从第一条密码开始'}</h2><p>${query?'试试网站名或账号。':'手动添加，或连接浏览器后保存登录信息。'}</p>${query?'':'<button data-action="new" class="secondary">新增密码</button>'}</div>`}</section><p class="hint">网站账号按主域名匹配，同一主域下的登录页面可使用已保存账号。修改仅保存在本机；检测到另一台设备后，可手动合并密码本。</p>`;
}
const accountText = (entry:EntrySummary) => showUsernames ? entry.username||'未填写账号' : '账号已隐藏';
function devicesView(){
 const service=status!.service;
 const available=service?.running===true;
 const merges=service?.merges??[];
 const found=service?.discovered??[];
 const sessions=merges.length?`<section class="panel" aria-label="合并请求"><h2>合并请求</h2>${merges.map(merge=>`<article class="merge-card" data-merge-session="${esc(merge.id)}"><div class="device-row"><span class="site-icon">⇄</span><div><strong>${esc(merge.peer_name||'另一台设备')}</strong><small>${merge.direction==='incoming'?'对方请求接收本机密码 · 本机只读':'从对方接收密码 · 仅更新本机'} · ${esc(merge.endpoint)}</small></div><span class="merge-state ${['failed','rejected','expired'].includes(merge.state)?'error-text':''}">${esc(mergeMessage(merge))}</span></div>${merge.verification_code&&mergeActive(merge)?`<div class="verification"><span>核对编号</span><strong>${esc(merge.verification_code)}</strong><p>${merge.direction==='incoming'?'确认后仅向对方提供密码，本机密码不会被修改或删除。':'确认后仅在本机接收并合并对方的密码，对方密码不会改变。'}请核对两台设备显示的编号一致。</p></div>`:''}${merge.error?`<p class="error-text">${esc(merge.error)}</p>`:''}${merge.state==='completed'&&completedVerified.has(merge.id)?`<p class="hint">${merge.direction==='incoming'?`已提供 ${merge.source_count??0} 条密码；本机未接收或删除任何密码。`:`收到 ${merge.received_count??0} 条密码，写入 ${merge.changed_count??0} 个密码版本；本机原有密码不会因对方缺少记录而删除。`}</p>`:''}${merge.state==='awaiting_confirmation'?`<div class="merge-actions"><button class="secondary" data-respond-merge="${esc(merge.id)}" data-accept="false">拒绝</button><button class="primary" data-respond-merge="${esc(merge.id)}" data-accept="true">${merge.direction==='incoming'?'编号一致，允许提供':'编号一致，接收到本机'}</button></div>`:merge.state==='waiting'?`<div class="merge-actions"><button class="quiet" data-respond-merge="${esc(merge.id)}" data-accept="false">取消请求</button></div>`:''}</article>`).join('')}</section>`:'';
 return `<div class="summary-card"><span class="status-dot ${available?'':'offline'}"></span><div><strong>${available?'设备检测已开启':'设备检测暂不可用'}</strong><p>${status!.service_error?esc(status!.service_error):service?.discovering?'正在检测局域网设备…':`上次检测：${esc(when(service?.last_discovery_at))}`}</p>${service?.next_discovery_at?`<p>下次检测：${esc(when(service.next_discovery_at))}</p>`:''}${service?.last_error?`<p class="error-text">${esc(service.last_error)}</p>`:''}</div><button class="secondary" data-action="detect" ${!available||service?.discovering?'disabled data-unavailable="true"':''}>${service?.discovering?'正在检测…':'手动检测设备'}</button></div><p class="hint">每 5 分钟自动检测一次设备。检测不会交换密码；双方确认后，只有发起方接收数据。提供方不会被修改，删除操作不会传给对方。</p>${sessions}<section class="panel"><h2>发现的设备 <span class="count">${found.length}</span></h2><p class="muted">请让两台设备连接到同一局域网，并保持客户端打开且密码库已解锁。</p>${found.length?found.map(peer=>{const pending=merges.some(merge=>merge.peer_id===peer.id&&mergeActive(merge));return `<div class="device-row"><span class="site-icon">⇄</span><div><strong>${esc(peer.name||'OhMyPassword 设备')}</strong><small>${esc(peer.endpoint)} · ${esc(when(peer.last_seen))}</small></div><button class="secondary" data-merge-device="${esc(peer.id)}" ${!available||pending?'disabled data-unavailable="true"':''}>${pending?'接收处理中':'接收对方密码'}</button></div>`;}).join(''):'<p class="empty-line">尚未发现设备，可以点击“手动检测设备”重试。</p>'}</section><p class="hint">手机进入后台后会锁定并暂停，正在等待的合并会失效。回到前台解锁后，可重新检测并发起合并。</p>`;
}
function browserView(){
 const online=status!.service?.running===true;
 return `<div class="summary-card"><span class="status-dot ${online?'':'offline'}"></span><div><strong>本地浏览器接口</strong><p>${esc(status!.service?.local_endpoint||'服务未启动')}</p></div><span class="pill">仅本机 · 免令牌</span></div><section class="panel"><h2>直接连接本机客户端</h2><p class="muted">打开并解锁 OhMyPassword，官方浏览器插件即可直接连接本地服务，无需生成或复制额外令牌。</p><p>在网站页面打开 OhMyPassword 插件，选择账号即可填充，也可以保存新增或修改的密码。</p>${status!.service_error?`<p class="error-text">${esc(status!.service_error)}</p>`:''}</section><p class="hint">本地密码库锁定或客户端关闭后，浏览器无法读取账号密码。密码修改只保存在本机；需要另一台设备取得这些密码时，请在那台设备上发起接收。</p>`;
}
function dialogView(){
 if(dialog==='delete'){
  return `<dialog aria-labelledby="dialog-title"><h2 id="dialog-title">删除这条密码？</h2><p class="muted">仅删除本机这条密码，不会删除其他设备上的记录。旧版本仍保存在加密密码库中，可从「历史恢复」找回。</p><div class="dialog-actions"><button class="secondary" data-action="close">取消</button><button class="primary danger-fill" data-action="confirm">确认删除</button></div></dialog>`;
 }
 if(dialog==='recovery')return `<dialog class="wide" aria-labelledby="dialog-title"><div class="dialog-head"><h2 id="dialog-title">历史恢复</h2><button class="quiet" data-action="close">关闭</button></div><p class="muted">查看本机保留的历史和已删除记录。恢复会新增一条本地修改，不会修改其他设备。</p>${recoveryEntries.length?`<section class="recovery-list" aria-label="可恢复记录">${recoveryEntries.map(entry=>`<button class="recovery-entry" data-recovery-id="${esc(entry.id)}"><span><strong>${esc(entry.title||entry.hostname)}</strong><small>${esc(entry.hostname)} · ${esc(accountText(entry))}</small><small>${entry.deleted?'已删除，可恢复':'现有记录，可查看历史'} · ${esc(when(entry.version.modified_at))}</small></span><span aria-hidden="true">›</span></button>`).join('')}</section>`:'<p class="empty-line">当前密码库没有可恢复的历史。若密码库文件已被覆盖、重建或卸载，需要从保留的旧密码库或备份找回。</p>'}</dialog>`;
 if(dialog==='restore')return `<dialog aria-labelledby="dialog-title"><div class="dialog-head"><h2 id="dialog-title">恢复这版密码？</h2><button class="quiet" data-action="close">关闭</button></div><p><strong>${esc(restoreCandidate?.title||restoreCandidate?.hostname)}</strong><br>${esc(restoreCandidate?.hostname)} · ${esc(when(restoreCandidate?.version.modified_at))}</p><p class="muted">会先保存本机密码库的加密备份，再将这一版恢复为新的本地修改。原有历史会保留，其他设备不会改变。</p><div class="dialog-actions"><button class="secondary" data-action="restore-back">返回历史</button><button class="primary" data-action="restore-confirm">确认恢复到本机</button></div></dialog>`;
 if(dialog==='history')return `<dialog class="wide" aria-labelledby="dialog-title"><div class="dialog-head"><h2 id="dialog-title">历史版本</h2><button class="quiet" data-action="close">关闭</button></div><p class="muted">选择所需版本恢复为新的本地修改。旧版本会保留，恢复不会修改其他设备。</p>${historyFromRecovery?'<button class="quiet" data-action="recovery-back">← 返回恢复列表</button>':''}${history.length?history.map((entry,i)=>`<section class="history"><strong>${esc(entry.title||entry.hostname)}</strong><p>${esc(entry.hostname)} · ${esc(entry.username)}<br>${esc(when(entry.version.modified_at))}</p><input aria-label="历史密码 ${i+1}" type="password" value="${esc(entry.password)}" readonly><button class="quiet" data-history-reveal="${i}">显示</button><button class="secondary restore-history" data-history-restore="${i}">恢复此版本</button></section>`).join(''):'<p>没有可恢复的历史版本。</p>'}</dialog>`;
 const e=selected;
 return `<dialog class="wide" aria-labelledby="dialog-title"><form id="entry-form"><div class="dialog-head"><h2 id="dialog-title">${e?'编辑密码':'新增密码'}</h2><button class="quiet" type="button" data-action="close">关闭</button></div><label>网站 hostname<input name="hostname" required maxlength="253" value="${esc(e?.hostname)}" placeholder="例如：github.com" autocomplete="off" spellcheck="false"></label><label>名称<input name="title" maxlength="256" value="${esc(e?.title)}" placeholder="例如：GitHub"></label><label>账号<input name="username" maxlength="1024" value="${esc(e?.username)}" autocomplete="off" autocapitalize="none"></label><label>密码<div class="password-field"><input name="password" id="entry-password" type="${revealed?'text':'password'}" required maxlength="4096" value="${esc(e?.password)}" autocomplete="new-password"><button type="button" class="quiet" data-action="reveal" aria-label="${revealed?'隐藏密码':'显示密码'}">${revealed?'隐藏':'显示'}</button><button type="button" class="quiet" data-action="copy-password" aria-label="复制密码">复制</button></div></label><label>备注<textarea name="notes" rows="3" maxlength="8192">${esc(e?.notes)}</textarea></label><div class="dialog-actions">${e?'<button type="button" class="quiet danger" data-action="delete">删除</button><button type="button" class="quiet" data-action="history">历史版本</button>':'<button type="button" class="quiet" data-action="generate">生成随机密码</button>'}<button type="submit" class="primary">保存密码</button></div></form></dialog>`;
}
function bind(){
 document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(el=>el.addEventListener('click',()=>{selected=null;tab=el.dataset.tab as typeof tab;notice='';render();}));
 document.querySelector<HTMLInputElement>('#show-usernames')?.addEventListener('change',e=>{
  showUsernames=(e.currentTarget as HTMLInputElement).checked;
  const byId=new Map(entries.map(entry=>[entry.id,entry]));
  document.querySelectorAll<HTMLElement>('[data-entry]').forEach(el=>{
   const entry=byId.get(el.dataset.entry!);const account=el.querySelector('.entry-account');
   if(entry&&account)account.textContent=accountText(entry);
  });
 });
 document.querySelector('#search')?.addEventListener('input',e=>{const el=e.target as HTMLInputElement;query=el.value;const start=el.selectionStart;render();const next=document.querySelector<HTMLInputElement>('#search');next?.focus();if(start!==null)next?.setSelectionRange(start,start);});
 document.querySelectorAll<HTMLButtonElement>('[data-entry]').forEach(el=>el.addEventListener('click',()=>void run(async()=>{selected=await api<Entry>('get_entry',{id:el.dataset.entry});revealed=false;dialog='entry';render();})));
 document.querySelectorAll<HTMLButtonElement>('[data-merge-device]').forEach(el=>el.addEventListener('click',()=>void run(async()=>{
  await api<MergeSession>('request_merge',{deviceId:el.dataset.mergeDevice});feedback('接收请求已发送。只有本机会合并，对方密码保持不变。');await refresh();
 })));
 document.querySelectorAll<HTMLButtonElement>('[data-respond-merge]').forEach(el=>el.addEventListener('click',()=>void run(async()=>{
  const accept=el.dataset.accept==='true';const merge=status?.service?.merges.find(item=>item.id===el.dataset.respondMerge);await api('respond_merge',{sessionId:el.dataset.respondMerge,accept});feedback(accept?(merge?.direction==='incoming'?'已允许向对方提供密码，本机保持不变。':'已确认，等待接收完成。'):'本次合并已拒绝或取消。');await refresh();
 })));
 document.querySelectorAll<HTMLButtonElement>('[data-action]').forEach(el=>el.addEventListener('click',()=>void action(el.dataset.action!)));
 document.querySelector('dialog')?.addEventListener('cancel',e=>{e.preventDefault();close();});
 document.querySelectorAll<HTMLButtonElement>('[data-recovery-id]').forEach(el=>el.addEventListener('click',()=>void run(()=>openHistory(el.dataset.recoveryId!,true))));
 document.querySelectorAll<HTMLButtonElement>('[data-history-restore]').forEach(el=>el.addEventListener('click',()=>{restoreCandidate=history[Number(el.dataset.historyRestore)]??null;if(restoreCandidate){notice='';isError=false;dialog='restore';render();}}));
 document.querySelectorAll<HTMLButtonElement>('[data-history-reveal]').forEach(el=>el.addEventListener('click',()=>{const input=el.previousElementSibling as HTMLInputElement;input.type=input.type==='password'?'text':'password';el.textContent=input.type==='password'?'显示':'隐藏';}));
 bindForm('entry-form',async(form,data)=>{
  const input:EntryInput={id:selected?.id??null,hostname:String(data.get('hostname')),title:String(data.get('title')),username:String(data.get('username')),password:String(data.get('password')),notes:String(data.get('notes'))};
  try{await api('save_entry',{input});form.reset();selected=null;dialog=null;notice='密码已加密保存。';isError=false;await refresh();}finally{input.password='';data.delete('password');}
 });
}
function bindForm(id:string,handler:(form:HTMLFormElement,data:FormData)=>Promise<void>){document.getElementById(id)?.addEventListener('submit',e=>{e.preventDefault();const form=e.currentTarget as HTMLFormElement;void run(()=>handler(form,new FormData(form)));});}
async function openHistory(id:string,fromRecovery:boolean){const generation=++dialogGeneration;const versions=await api<Entry[]>('recovery_history',{id});if(generation!==dialogGeneration)return;history=versions;historyFromRecovery=fromRecovery;selected=null;dialog='history';render();}
function close(){dialogGeneration++;selected=null;history=[];recoveryEntries=[];restoreCandidate=null;historyFromRecovery=false;revealed=false;dialog=null;render();}
async function action(name:string){
 if(name==='lock'){clearSecrets();if(status)status.vault.locked=true;render();try{await api('lock_vault');await refresh();}catch(e){feedback(String(e),true);}return;}
 if(name==='close'){close();return;}
 if(name==='new'){selected=null;revealed=false;dialog='entry';render();return;}
 if(name==='reveal'){revealed=!revealed;const input=document.querySelector<HTMLInputElement>('#entry-password')!;input.type=revealed?'text':'password';const button=document.querySelector('[data-action="reveal"]')!;button.textContent=revealed?'隐藏':'显示';button.setAttribute('aria-label',revealed?'隐藏密码':'显示密码');return;}
 if(name==='restore-back'){restoreCandidate=null;dialog='history';render();return;}
 if(name==='recovery-back'){history=[];restoreCandidate=null;dialog='recovery';render();return;}
 if(name==='delete'){dialog='delete';render();return;}
 if(name==='generate'){const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_';const bytes=crypto.getRandomValues(new Uint8Array(48));let value='';for(const n of bytes){if(n<Math.floor(256/alphabet.length)*alphabet.length)value+=alphabet[n%alphabet.length];if(value.length===24)break;}const input=document.querySelector<HTMLInputElement>('#entry-password')!;input.value=value;return;}
 await run(async()=>{
  if(name==='detect'){await api('detect_devices');feedback('正在检测局域网设备…');await refresh();}
  if(name==='copy-password'){await writeText(document.querySelector<HTMLInputElement>('#entry-password')!.value);feedback('密码已复制，请留意剪贴板。');}
  if(name==='recovery'){notice='';isError=false;recoveryEntries=await api<EntrySummary[]>('list_recovery_entries');selected=null;history=[];restoreCandidate=null;dialog='recovery';render();}
  if(name==='history'&&selected)await openHistory(selected.id,false);
  if(name==='restore-confirm'&&restoreCandidate){await api<Entry>('restore_entry',{id:restoreCandidate.id,version:restoreCandidate.version});history=[];recoveryEntries=[];restoreCandidate=null;selected=null;dialog=null;query='';render();await refresh();feedback('密码已恢复为新的本地修改，其他设备未改变。');}
  if(name==='confirm'){
   if(dialog==='delete'&&selected)await api('delete_entry',{id:selected.id});
   selected=null;dialog=null;notice='操作已完成。';isError=false;await refresh();
  }
 });
}
for(const name of ['pointerdown','keydown'])document.addEventListener(name,()=>{if(isTauri()&&Date.now()-lastActivity>30_000){lastActivity=Date.now();void api('user_activity').catch(()=>{});}}, {passive:true});
async function init(){
 render();if(!isTauri())return;
 await listen('vault-locked',()=>{clearSecrets();if(status)status.vault.locked=true;notice='密码库已锁定。';isError=false;render();});
 await refresh();
 setInterval(()=>{
  if(refreshing)return;
  refreshing=true;
  void refresh(false).then(()=>{
   if(status?.vault.locked&&!document.querySelector('#gate-form')){render();return;}
   if(dialog||busy||status?.vault.locked)return;
   const changed=renderedSignature!==viewSignature();
   if(changed&&!document.activeElement?.matches('input,textarea,select'))render();
  }).catch(error=>{if(!status?.vault.locked)feedback(String(error),true);}).finally(()=>{refreshing=false;});
 },5_000);
}
void init().catch(e=>{notice=String(e);isError=true;render();});
