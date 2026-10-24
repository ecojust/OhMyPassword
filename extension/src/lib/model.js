import { sameCredentialSite } from './domains.js';

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
  return { port: checkedPort(value?.port) };
}

export function sameWebsite(target, current) {
  const site = websiteFromUrl(current?.url);
  return !!site && current.id === target.id && site.hostname === target.hostname && site.origin === target.origin;
}

export function canFillWebsite(site) {
  return site?.origin?.startsWith('https://') || (site?.origin?.startsWith('http://') && ['127.0.0.1', 'localhost', '[::1]'].includes(site.hostname));
}

export function readableError(status, payload) {
  if (status === 401) return '客户端仍使用旧连接协议，请更新客户端和扩展。';
  if (status === 423) return '密码库已锁定，请先在 OhMyPassword 客户端解锁。';
  if (status === 403) return '客户端拒绝了此浏览器请求，请确认客户端与扩展均为最新版。';
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
    if (!sameCredentialSite(entry.hostname, hostname)) return false;
    return ['title', 'username', 'password'].every(key => typeof entry[key] === 'string' && entry[key].length <= 65536);
  });
}

export function credentialForSave(hostname, entry, fields) {
  if (!sameCredentialSite(hostname, hostname)) throw new Error('当前网站地址无效。');
  if (entry && (typeof entry.id !== 'string' || !entry.id || !sameCredentialSite(entry.hostname, hostname))) {
    throw new Error('此账号不属于当前网站，未保存修改。');
  }
  return {
    id: entry?.id ?? null,
    hostname: entry?.hostname ?? hostname,
    title: fields.title.trim(),
    username: fields.username,
    password: fields.password,
    notes: fields.notes,
  };
}
