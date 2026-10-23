export const DEFAULT_PORT = 17841;

export function websiteFromUrl(value) {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) return null;
    return { hostname: url.hostname.toLowerCase().replace(/\.$/, ''), origin: url.origin };
  } catch { return null; }
}

export function checkedPort(value = DEFAULT_PORT) {
  if (!/^\d{1,5}$/.test(String(value))) throw new Error('端口需要是 1024–65535 之间的整数。');
  const port = Number(value);
  if (port < 1024 || port > 65535) throw new Error('端口需要是 1024–65535 之间的整数。');
  return port;
}

export function checkedConnection(value) {
  if (!value || typeof value.token !== 'string' || !value.token.trim() || value.token.length > 1024 || /[\r\n]/.test(value.token)) {
    throw new Error('请先在连接设置中填写客户端提供的连接令牌。');
  }
  return { token: value.token.trim(), port: checkedPort(value.port) };
}

export function extensionOrigin(api) {
  const url = new URL(api.runtime.getURL(''));
  if (!['chrome-extension:', 'moz-extension:'].includes(url.protocol)) throw new Error('只能在浏览器扩展中连接。');
  return `${url.protocol}//${url.host}`;
}

export function sameWebsite(target, current) {
  const site = websiteFromUrl(current?.url);
  return !!site && current.id === target.id && site.hostname === target.hostname && site.origin === target.origin;
}

export function canFillWebsite(site) {
  return site?.origin?.startsWith('https://') || (site?.origin?.startsWith('http://') && ['127.0.0.1', 'localhost', '[::1]'].includes(site.hostname));
}

export function readableError(status, payload) {
  if (status === 401) return '连接令牌无效或已撤销，请重新授权此扩展。';
  if (status === 423) return '密码库已锁定，请先在 OhMyPassword 客户端解锁。';
  if (status === 403) return '客户端尚未授权此扩展标识，请检查连接设置。';
  if (status === 429) return '请求过于频繁，请稍后重试。';
  if (status === 413) return '提交内容过大，请缩短备注后重试。';
  // The local client's error text is displayed only as text, never markup.
  if (typeof payload?.message === 'string' && payload.message.length <= 300) return payload.message;
  return `客户端请求失败（${status}）。`;
}

export function validateEntries(payload, hostname) {
  if (!payload || !Array.isArray(payload.entries) || payload.entries.length > 2000) throw new Error('客户端返回了不支持的数据。');
  return payload.entries.filter(entry => {
    if (!entry || entry.deleted || typeof entry.id !== 'string' || typeof entry.hostname !== 'string') return false;
    if (entry.hostname.toLowerCase().replace(/\.$/, '') !== hostname) return false;
    return ['title', 'username', 'password'].every(key => typeof entry[key] === 'string' && entry[key].length <= 65536);
  });
}
