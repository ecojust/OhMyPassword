import { checkedPort, DEFAULT_PORT } from './lib/model.js';
import { readConnection, request, saveConnection } from './lib/client.js';
const api = globalThis.browser ?? globalThis.chrome;
const $ = id => document.getElementById(id);
function status(text, kind = '') { $('status').textContent = text; $('status').className = `notice ${kind}`; }
readConnection(api).then(connection => { $('port').value = connection.port; }).catch(() => status('无法读取端口设置，请重新打开扩展。', 'error'));
$('connect-form').addEventListener('submit', async event => {
  event.preventDefault(); $('connect').disabled = true;
  try {
    const connection = { port: checkedPort($('port').value) };
    await saveConnection(api, connection);
    const response = await request(connection, '/v1/browser/connect', { method: 'POST', body: {} });
    if (response.connected !== true || response.protocol !== 2) throw new Error('客户端协议不兼容，请更新客户端和扩展。');
    status('连接成功。打开网站后，点击扩展即可匹配账号。', 'success');
  } catch (error) { status(error.message, 'error'); }
  finally { $('connect').disabled = false; }
});
$('reset').addEventListener('click', async () => {
  await saveConnection(api, { port: DEFAULT_PORT }); $('port').value = DEFAULT_PORT; status('已恢复默认端口。打开并解锁客户端后即可使用。');
});
