import { canFillWebsite, extensionOrigin, sameWebsite, validateEntries, websiteFromUrl } from './lib/model.js';
import { readConnection, request } from './lib/client.js';
import { fillSelectedEntry } from './lib/fill.js';

const api = globalThis.browser ?? globalThis.chrome;
const $ = id => document.getElementById(id);
let target = null;
let entries = [];
let editingId = null;
let controller = null;
let requestId = 0;
let busy = false;

function status(message, type = '') { $('status').textContent = message; $('status').className = `notice ${type}`; }
function clearSecrets() {
  entries = [];
  $('accounts').replaceChildren();
  $('entry-form').reset();
  $('password').type = 'password';
  editingId = null;
  controller?.abort();
  requestId++;
}
function closeForm() {
  $('entry-form').reset();
  $('password').type = 'password';
  $('entry-form').hidden = true;
  $('accounts-section').hidden = false;
  editingId = null;
}
function showForm(entry = null) {
  closeForm();
  editingId = entry?.id ?? null;
  $('form-title').textContent = entry ? '修改账号' : '添加账号';
  $('hostname').value = target.hostname;
  $('title').value = entry?.title ?? '';
  $('username').value = entry?.username ?? '';
  $('password').value = entry?.password ?? '';
  $('notes').value = entry?.notes ?? '';
  $('entry-form').hidden = false;
  $('accounts-section').hidden = true;
  $('username').focus();
}
function renderEntries() {
  $('accounts').replaceChildren();
  if (!entries.length) {
    const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = '还没有这个网站的账号。'; $('accounts').append(empty); return;
  }
  for (const entry of entries) {
    const card = document.createElement('article'); card.className = 'account';
    const title = document.createElement('strong'); title.textContent = entry.title || target.hostname;
    const name = document.createElement('p'); name.className = 'muted'; name.textContent = entry.username || '未填写账号';
    const row = document.createElement('div'); row.className = 'row';
    const fill = document.createElement('button'); fill.className = 'primary quiet'; fill.textContent = '填入此页面';
    fill.addEventListener('click', async () => {
      if (busy) return; busy = true; fill.disabled = true;
      try {
        // Re-fetch immediately: revoked grants, locked vaults and changed passwords must take effect.
        const connection = await readConnection(api);
        const payload = await request(connection, `/v1/credentials?hostname=${encodeURIComponent(target.hostname)}`);
        const latest = validateEntries(payload, target.hostname).find(item => item.id === entry.id);
        if (!latest) throw new Error('这个账号已被删除，请刷新列表。');
        const result = await fillSelectedEntry(api, target, latest);
        status(result.usernameFilled ? '账号与密码已填入，请在网页确认登录。' : '密码已填入，请在网页确认账号并登录。', 'success');
      } catch (error) { clearSecrets(); status(error.message, 'error'); }
      finally { busy = false; fill.disabled = false; }
    });
    const edit = document.createElement('button'); edit.className = 'quiet'; edit.textContent = '修改'; edit.addEventListener('click', () => showForm(entry));
    row.append(fill, edit); card.append(title, name, row); $('accounts').append(card);
  }
}

async function load() {
  if (busy) return;
  clearSecrets(); closeForm();
  const current = ++requestId;
  controller = new AbortController();
  $('add').disabled = true;
  status('正在连接本机密码库…');
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    const site = websiteFromUrl(tab?.url);
    if (!site || typeof tab.id !== 'number') throw new Error('请在普通 HTTP 或 HTTPS 网站打开扩展。');
    target = { id: tab.id, ...site };
    $('site').textContent = site.hostname;
    const connection = await readConnection(api);
    extensionOrigin(api);
    const payload = await request(connection, `/v1/credentials?hostname=${encodeURIComponent(site.hostname)}`, { signal: controller.signal });
    if (current !== requestId) return;
    if (!sameWebsite(target, await api.tabs.get(target.id))) throw new Error('页面已跳转，请重新打开扩展。');
    entries = validateEntries(payload, site.hostname);
    renderEntries(); $('add').disabled = false;
    status(canFillWebsite(target) ? '' : '当前网站使用 HTTP。可管理账号，但需要切换到 HTTPS 后才能填充。');
  } catch (error) { if (current === requestId) status(error.message, 'error'); }
}

$('settings').addEventListener('click', () => api.runtime.openOptionsPage());
$('refresh').addEventListener('click', load);
$('add').addEventListener('click', () => target && showForm());
$('cancel').addEventListener('click', closeForm);
$('show-password').addEventListener('change', event => { $('password').type = event.target.checked ? 'text' : 'password'; });
$('entry-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !target) return;
  busy = true; $('save').disabled = true;
  try {
    if (!sameWebsite(target, await api.tabs.get(target.id))) throw new Error('页面已跳转，账号未保存，请重新打开扩展。');
    const connection = await readConnection(api);
    await request(connection, '/v1/credentials', { method: 'POST', body: {
      id: editingId, hostname: target.hostname, title: $('title').value.trim(),
      username: $('username').value, password: $('password').value, notes: $('notes').value,
    } });
    closeForm(); busy = false; await load(); status('已保存到本机，客户端将同步到已配对的在线设备。', 'success');
  } catch (error) { status(error.message, 'error'); }
  finally { busy = false; $('save').disabled = false; }
});
api.tabs.onActivated.addListener(() => { clearSecrets(); window.close(); });
api.tabs.onUpdated.addListener((id, change) => { if (target?.id === id && change.url) { clearSecrets(); window.close(); } });
window.addEventListener('pagehide', clearSecrets);
document.addEventListener('visibilitychange', () => { if (document.hidden) clearSecrets(); });
load();
