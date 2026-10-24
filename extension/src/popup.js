import { canFillWebsite, credentialForSave, sameWebsite, validateEntries, websiteFromUrl } from './lib/model.js';
import { readConnection, request, searchWebsiteCredentials } from './lib/client.js';
import { fillSelectedEntry, fillSuccessMessage } from './lib/fill.js';
import { OPTIONAL_LOGIN_ORIGINS } from './lib/sites.js';

const api = globalThis.browser ?? globalThis.chrome;
const $ = id => document.getElementById(id);
let target = null;
let entries = [];
let editingEntry = null;
let controller = null;
let requestId = 0;
let busy = false;
let pendingOrigins = [];

function status(message, type = '') { $('status').textContent = message; $('status').className = `notice ${type}`; }
function clearSecrets() {
  entries = [];
  $('accounts').replaceChildren();
  $('entry-form').reset();
  $('password').type = 'password';
  editingEntry = null;
  pendingOrigins = [];
  $('allow-login-frame').hidden = true;
  controller?.abort();
  requestId++;
}
function closeForm() {
  $('entry-form').reset();
  $('password').type = 'password';
  $('entry-form').hidden = true;
  $('accounts-section').hidden = false;
  editingEntry = null;
}
function showForm(entry = null) {
  closeForm();
  editingEntry = entry;
  $('form-title').textContent = entry ? '修改账号' : '添加账号';
  $('hostname').value = entry?.hostname ?? target.hostname;
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
    const title = document.createElement('strong'); title.textContent = entry.title || entry.hostname;
    const name = document.createElement('p'); name.className = 'muted'; name.textContent = entry.username || '未填写账号';
    const source = document.createElement('p'); source.className = 'muted'; source.textContent = `保存网站：${entry.hostname}`;
    const row = document.createElement('div'); row.className = 'row';
    const fill = document.createElement('button'); fill.className = 'primary quiet'; fill.textContent = '填入此页面';
    fill.addEventListener('click', async () => {
      if (busy) return; busy = true; fill.disabled = true;
      try {
        // Re-fetch immediately: locked vaults and changed passwords must take effect.
        const connection = await readConnection(api);
        const payload = await searchWebsiteCredentials(connection, target.hostname, { signal: controller?.signal });
        const latest = validateEntries(payload, target.hostname).find(item => item.id === entry.id);
        if (!latest) throw new Error('这个账号已被删除，请刷新列表。');
        const result = await fillSelectedEntry(api, target, latest, { signal: controller?.signal });
        status(fillSuccessMessage(result), 'success');
      } catch (error) {
        clearSecrets(); status(error.message, 'error');
        if (error.code === 'LOGIN_FRAME_PERMISSION' && error.origins?.length && error.origins.every(origin => OPTIONAL_LOGIN_ORIGINS.includes(origin))) {
          pendingOrigins = [...error.origins];
          $('allow-login-frame').textContent = `允许访问 ${new URL(pendingOrigins[0]).hostname} 登录框`;
          $('allow-login-frame').hidden = false;
        }
      }
      finally { busy = false; fill.disabled = false; }
    });
    const edit = document.createElement('button'); edit.className = 'quiet'; edit.textContent = '修改'; edit.addEventListener('click', () => showForm(entry));
    row.append(fill, edit); card.append(title, name, source, row); $('accounts').append(card);
  }
}

async function load() {
  if (busy) return false;
  clearSecrets(); closeForm();
  const current = ++requestId;
  controller = new AbortController();
  $('add').disabled = true;
  status('正在连接本机密码库…');
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    const site = websiteFromUrl(tab?.url);
    if (!site || typeof tab.id !== 'number') throw new Error('请在普通 HTTP 或 HTTPS 网站打开扩展。');
    target = { id: tab.id, url: tab.url, ...site };
    $('site').textContent = site.hostname;
    const connection = await readConnection(api);
    const payload = await searchWebsiteCredentials(connection, site.hostname, { signal: controller.signal });
    if (current !== requestId) return false;
    if (!sameWebsite(target, await api.tabs.get(target.id))) throw new Error('页面已跳转，请重新打开扩展。');
    entries = validateEntries(payload, site.hostname);
    renderEntries(); $('add').disabled = false;
    status(canFillWebsite(target) ? '' : '当前网站使用 HTTP。可管理账号，但需要切换到 HTTPS 后才能填充。');
    return true;
  } catch (error) { if (current === requestId) status(error.message, 'error'); return false; }
}

$('settings').addEventListener('click', () => api.runtime.openOptionsPage());
$('allow-login-frame').addEventListener('click', async () => {
  if (busy || !pendingOrigins.length) return;
  const origins = [...pendingOrigins];
  if (!origins.every(origin => OPTIONAL_LOGIN_ORIGINS.includes(origin))) return;
  busy = true;
  $('allow-login-frame').disabled = true;
  try {
    // Invoke directly from this click, before any await, to retain user gesture.
    const permission = api.permissions.request({ origins });
    const allowed = await permission;
    busy = false;
    if (allowed) {
      if (await load()) status('已允许访问此登录框，请再次选择账号填充。', 'success');
    } else {
      status('未允许访问登录框。你可以稍后授权，或在客户端复制账号密码。', 'error');
    }
  } catch (error) { status(error.message || '浏览器未完成授权，请重新打开扩展后重试。', 'error'); }
  finally { busy = false; $('allow-login-frame').disabled = false; }
});
$('refresh').addEventListener('click', load);
$('add').addEventListener('click', () => target && showForm());
$('cancel').addEventListener('click', closeForm);
$('show-password').addEventListener('change', event => { $('password').type = event.target.checked ? 'text' : 'password'; });
$('entry-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !target) return;
  busy = true; $('save').disabled = true;
  try {
    const current = requestId;
    const saveTarget = target;
    const body = credentialForSave(saveTarget.hostname, editingEntry, {
      title: $('title').value,
      username: $('username').value, password: $('password').value, notes: $('notes').value,
    });
    if (!sameWebsite(saveTarget, await api.tabs.get(saveTarget.id))) throw new Error('页面已跳转，账号未保存，请重新打开扩展。');
    const connection = await readConnection(api);
    if (current !== requestId) throw new Error('页面已变化，账号未保存，请重新打开扩展。');
    await request(connection, '/v1/credentials', { method: 'POST', body });
    if (current !== requestId) return;
    closeForm(); busy = false; await load(); status('已保存到本机。需要其他设备取得修改时，请在客户端手动合并密码本。', 'success');
  } catch (error) { status(error.message, 'error'); }
  finally { busy = false; $('save').disabled = false; }
});
api.tabs.onActivated.addListener(() => { clearSecrets(); window.close(); });
api.tabs.onUpdated.addListener((id, change) => { if (target?.id === id && change.url) { clearSecrets(); window.close(); } });
window.addEventListener('pagehide', clearSecrets);
document.addEventListener('visibilitychange', () => { if (document.hidden) clearSecrets(); });
load();
