import { checkedConnection, readableError } from './model.js';

const MAX_RESPONSE_BYTES = 1048576;
async function readBoundedBody(response) {
  const declared = response.headers?.get('Content-Length');
  if (declared && /^\d+$/.test(declared) && Number(declared) > MAX_RESPONSE_BYTES) {
    await response.body?.cancel();
    throw new Error('客户端响应过大，请减少匹配记录。');
  }
  if (!response.body?.getReader) {
    const text = await response.text();
    if (new TextEncoder().encode(text).length > MAX_RESPONSE_BYTES) throw new Error('客户端响应过大，请减少匹配记录。');
    return text;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = '';
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return text + decoder.decode();
      bytes += value.byteLength;
      if (bytes > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('客户端响应过大，请减少匹配记录。');
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally { reader.releaseLock(); }
}

export async function request(connection, path, { method = 'GET', body, signal } = {}, fetcher = fetch) {
  const { port } = checkedConnection(connection);
  if (!/^\/v1\/[a-z/]+(?:\?[^#]*)?$/.test(path)) throw new Error('不支持的客户端接口。');
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 8000);
  const onAbort = () => abort.abort();
  signal?.addEventListener('abort', onAbort, { once: true });
  if (signal?.aborted) abort.abort();
  try {
    const response = await fetcher(`http://127.0.0.1:${port}${path}`, {
      method, mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body), signal: abort.signal,
    });
    const text = await readBoundedBody(response);
    let payload;
    try { payload = JSON.parse(text); } catch { throw new Error('客户端返回了不支持的数据。'); }
    if (!response.ok) throw new Error(readableError(response.status, payload));
    return payload;
  } catch (error) {
    if (error?.name === 'AbortError') throw new Error('连接已取消或超时，请确认本机客户端正在运行。');
    if (error instanceof TypeError) {
      // Browsers hide a rejected CORS preflight behind TypeError. A locked vault
      // may reject that preflight; query only its non-sensitive public status.
      let locked = false;
      try {
        const state = await fetcher(`http://127.0.0.1:${port}/v1/status`, {
          mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error', signal: abort.signal,
        });
        if (state.ok) locked = JSON.parse(await readBoundedBody(state)).locked === true;
      } catch { /* Preserve the original connection failure without disclosing response data. */ }
      if (locked) throw new Error(readableError(423));
      throw new Error('无法连接本机客户端，请打开并解锁 OhMyPassword，检查连接端口。');
    }
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

export async function readConnection(api) {
  const data = await api.storage.local.get('connection');
  let connection;
  try { connection = checkedConnection(data.connection); }
  catch { connection = checkedConnection(); }
  // Rewriting the former {port, token} object removes grants from old versions.
  // Never propagate unknown stored fields into a request or new settings.
  await saveConnection(api, connection);
  return connection;
}

export function searchCredentials(connection, hostname, { signal } = {}, fetcher = fetch) {
  if (typeof hostname !== 'string' || !hostname || hostname.length > 253) throw new Error('网站名称无效。');
  return request(connection, '/v1/credentials/search', { method: 'POST', body: { hostname }, signal }, fetcher);
}

export async function saveConnection(api, connection) {
  const value = checkedConnection(connection);
  await api.storage.local.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });
  await api.storage.local.set({ connection: value });
  await api.storage.local.remove(['token', 'origin', 'clientId', 'client_id', 'grant']);
}
