import { checkedPort, extensionOrigin } from './lib/model.js';
import { request, saveConnection } from './lib/client.js';
const api = globalThis.browser ?? globalThis.chrome;
const $ = id => document.getElementById(id);
function status(text, kind = '') { $('status').textContent = text; $('status').className = `notice ${kind}`; }
$('origin').value = extensionOrigin(api);
api.storage.local.get('connection').then(({ connection }) => {
  if (connection) { $('port').value = connection.port; status('此浏览器已保存连接。要更换授权，请填写新的令牌。'); }
});
$('copy-origin').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('origin').value); status('扩展标识已复制。'); }
  catch { $('origin').select(); status('请复制选中的扩展标识。'); }
});
$('connect-form').addEventListener('submit', async event => {
  event.preventDefault(); $('connect').disabled = true;
  try {
    const connection = { token: $('token').value.trim(), port: checkedPort($('port').value) };
    const response = await request(connection, '/v1/browser/connect', { method: 'POST', body: {} });
    if (response.connected !== true || response.protocol !== 1) throw new Error('客户端协议不兼容，请更新客户端和扩展。');
    await saveConnection(api, connection); $('token').value = ''; status('连接成功。打开网站后，点击扩展即可匹配账号。', 'success');
  } catch (error) { status(error.message, 'error'); }
  finally { $('connect').disabled = false; }
});
$('disconnect').addEventListener('click', async () => {
  await api.storage.local.remove('connection'); $('token').value = ''; status('已清除本机连接。如需撤销令牌，请在客户端移除此扩展。');
});
window.addEventListener('pagehide', () => { $('token').value = ''; });
