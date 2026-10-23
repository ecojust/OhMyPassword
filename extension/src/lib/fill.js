import { canFillWebsite, sameWebsite } from './model.js';

// Serialized into the isolated world in the main frame. Keep dependencies inside.
export function fillInPage(expectedOrigin, expectedHostname, username, password) {
  const hostname = location.hostname.toLowerCase().replace(/\.$/, '');
  if (location.origin !== expectedOrigin || hostname !== expectedHostname || !['http:', 'https:'].includes(location.protocol)) {
    return { ok: false, reason: '页面已跳转，请重新打开扩展后选择账号。' };
  }
  if (location.protocol !== 'https:' && !['127.0.0.1', 'localhost', '[::1]'].includes(hostname)) {
    return { ok: false, reason: '此页面使用未加密的 HTTP，请切换到 HTTPS 后填充。' };
  }
  const usable = input => input instanceof HTMLInputElement && !input.disabled && !input.readOnly &&
    input.getClientRects().length > 0 && getComputedStyle(input).visibility !== 'hidden';
  const passwords = [...document.querySelectorAll('input[type="password"]')].filter(input =>
    usable(input) && !['new-password', 'one-time-code'].includes(input.autocomplete));
  const current = passwords.filter(input => input.autocomplete === 'current-password');
  const candidates = current.length ? current : passwords;
  if (candidates.length !== 1) return { ok: false, reason: candidates.length ? '页面有多个密码框，请只保留需要填写的登录表单后重试。' : '当前页面没有可填写的登录密码框。' };
  const secret = candidates[0];
  const scope = secret.form ?? document;
  const names = [...scope.querySelectorAll('input')].filter(input => usable(input) &&
    ['text', 'email', 'tel'].includes(input.type) && input.compareDocumentPosition(secret) & Node.DOCUMENT_POSITION_FOLLOWING);
  const explicit = names.filter(input => input.autocomplete === 'username');
  const recognizable = names.filter(input => input.type === 'email' || /user|email|login|account/i.test(`${input.name} ${input.id}`));
  const name = explicit.at(-1) ?? recognizable.at(-1) ?? (secret.form ? names.at(-1) : undefined);
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const set = (input, value) => {
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (name) set(name, username);
  set(secret, password);
  return { ok: true, usernameFilled: !!name };
}

export async function fillSelectedEntry(api, target, entry) {
  if (!canFillWebsite(target)) throw new Error('此页面使用未加密的 HTTP，请切换到 HTTPS 后填充。');
  if (entry.hostname.toLowerCase().replace(/\.$/, '') !== target.hostname) throw new Error('此账号不属于当前网站。');
  const tab = await api.tabs.get(target.id);
  if (!sameWebsite(target, tab)) throw new Error('页面已跳转，请重新打开扩展后选择账号。');
  const results = await api.scripting.executeScript({
    target: { tabId: target.id, frameIds: [0] },
    func: fillInPage,
    args: [target.origin, target.hostname, entry.username, entry.password],
    world: 'ISOLATED',
  });
  const result = results?.find(item => item.frameId === 0)?.result;
  if (!result?.ok) throw new Error(result?.reason ?? '此页面不允许填充，请使用客户端复制密码。');
  return result;
}
