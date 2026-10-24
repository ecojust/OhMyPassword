import { canFillWebsite, sameWebsite } from './model.js';
import { allowedLoginFrame, credentialMatchesPage, getLoginRules } from './sites.js';
import { loginPageOperation } from './login-page.js';

// All-frame enumeration never inspects fields or receives account credentials.
export function describeFrame() {
  return { url: location.href, origin: location.origin, hostname: location.hostname.toLowerCase().replace(/\.$/, '') };
}

function liveDocument(result, label) {
  if (!result || typeof result.documentId !== 'string' || !result.documentId || !Number.isInteger(result.frameId)) {
    throw new Error(`${label}已变化或浏览器不支持此填充方式，请刷新后重试。`);
  }
  return result;
}

function framePermission(origin) {
  return `${origin}/*`;
}

export function fillSuccessMessage(result) {
  if (result.usernameFilled && !result.passwordFilled) return '账号已填入。请在网页点击“下一步”；如出现密码步骤，再次选择此账号填充。';
  if (result.usernameFilled && result.passwordFilled) return '账号与密码已填入，请在网页确认登录。';
  if (result.passwordFilled) return '密码已填入，请在网页确认账号并登录。';
  return '当前步骤没有需要填写的登录字段。';
}

export async function fillSelectedEntry(api, target, entry, { signal } = {}) {
  if (!canFillWebsite(target)) throw new Error('此页面使用未加密的 HTTP，请切换到 HTTPS 后填充。');
  if (!credentialMatchesPage(entry?.hostname, target.hostname)) throw new Error('此账号不属于当前网站。');
  const active = () => {
    if (signal?.aborted) throw new Error('页面已变化，请重新打开扩展后选择账号。');
  };
  active();
  const tab = await api.tabs.get(target.id);
  if (!sameWebsite(target, tab) || (target.url && tab.url !== target.url)) throw new Error('页面已跳转，请重新打开扩展后选择账号。');
  const topUrl = tab.url;
  const recheckTop = async () => {
    active();
    const current = await api.tabs.get(target.id);
    if (!sameWebsite(target, current) || current.url !== topUrl) throw new Error('页面已跳转，请重新打开扩展后选择账号。');
    active();
  };
  const execute = async (injectionTarget, func, request) => {
    active();
    const results = await api.scripting.executeScript({ target: injectionTarget, func, args: request === undefined ? [] : [request], world: 'ISOLATED' });
    active();
    return results;
  };
  const nonce = crypto.randomUUID();
  const topRequest = {
    mode: 'probe', nonce, expectedOrigin: target.origin, expectedHostname: target.hostname, expectedUrl: topUrl,
    rules: getLoginRules(target.hostname, { url: topUrl, topHostname: target.hostname }),
  };
  const topResults = await execute({ tabId: target.id, frameIds: [0] }, loginPageOperation, topRequest);
  const top = liveDocument(topResults?.find(item => item.frameId === 0), '页面');
  const topInfo = top.result;
  if (!topInfo || topInfo.url !== topUrl || topInfo.origin !== target.origin || topInfo.hostname !== target.hostname) {
    throw new Error('页面已变化，请重新打开扩展后选择账号。');
  }
  let selected = top;
  let probe = topInfo;
  let request = topRequest;
  let frameUrl = null;

  if (!topInfo.ok) {
    // Only a direct, visible and uniquely identifiable login frame can be used.
    const frames = Array.isArray(topInfo.iframeSources) ? topInfo.iframeSources : [];
    const candidates = frames.filter(frame => {
      if (!frame?.visible || typeof frame.src !== 'string') return false;
      try {
        const url = new URL(frame.src);
        if (url.username || url.password || !['https:', 'http:'].includes(url.protocol)) return false;
        return url.origin === target.origin || allowedLoginFrame(target.hostname, url.origin);
      } catch { return false; }
    });
    if (candidates.length !== 1) throw new Error(candidates.length ? '页面有多个登录框，请只保留需要填写的登录表单后重试。' : topInfo.reason || '当前页面没有可填写的登录字段，请先打开密码登录方式。');
    const frame = candidates[0];
    const url = new URL(frame.src);
    // An inaccessible hidden frame with the same URL/origin must not be guessed.
    const sameOrigin = frames.filter(item => {
      try { return new URL(item.src).origin === url.origin; } catch { return false; }
    });
    if (sameOrigin.length !== 1) throw new Error('登录框无法唯一确认，请刷新页面或使用客户端手动复制。');
    if (url.origin !== target.origin) {
      const origins = [framePermission(url.origin)];
      const permitted = await api.permissions.contains({ origins });
      await recheckTop();
      if (!permitted) {
        const error = new Error('此网站使用嵌入式登录框。请先允许访问这个登录框，再点击填充。');
        error.code = 'LOGIN_FRAME_PERMISSION'; error.origins = origins;
        throw error;
      }
    }
    await recheckTop();
    let described;
    try { described = await execute({ tabId: target.id, allFrames: true }, describeFrame); }
    catch (error) {
      active();
      throw new Error('浏览器暂时无法访问登录框，请确认已允许此网站的登录框权限并刷新后重试。');
    }
    const matching = described.filter(item => item.frameId !== 0 && item.result?.url === url.href && item.result?.origin === url.origin);
    if (matching.length !== 1) throw new Error('登录框正在加载或地址已变化，请等待加载完成后重新选择账号。');
    selected = liveDocument(matching[0], '登录框');
    frameUrl = url.href;
    request = {
      mode: 'probe', nonce: crypto.randomUUID(), expectedOrigin: url.origin,
      expectedHostname: url.hostname.toLowerCase().replace(/\.$/, ''), expectedUrl: frameUrl,
      rules: getLoginRules(url.hostname, { url: frameUrl, topHostname: target.hostname }),
    };
    const results = await execute({ tabId: target.id, documentIds: [selected.documentId] }, loginPageOperation, request);
    selected = liveDocument(results?.find(item => item.documentId === selected.documentId), '登录框');
    probe = selected.result;
    if (!probe || probe.url !== request.expectedUrl || probe.origin !== request.expectedOrigin || probe.hostname !== request.expectedHostname) {
      throw new Error('登录框已变化，请重新选择账号。');
    }
  }

  if (!probe?.ok || !['username', 'password', 'both'].includes(probe.stage)) throw new Error(probe?.reason || '当前步骤没有可填写的登录字段，请先切换到账号密码登录。');
  await recheckTop();
  if (frameUrl) {
    const checks = await execute({ tabId: target.id, documentIds: [top.documentId] }, loginPageOperation, { ...topRequest, mode: 'frame-check', frameUrl });
    if (!checks?.some(item => item.documentId === top.documentId && item.result?.ok)) throw new Error('登录框已隐藏或变化，请重新选择账号。');
    await recheckTop();
  }
  // Send only the values needed at this stage, to one immutable document ID.
  const fill = { ...request, mode: 'fill' };
  if (probe.stage === 'username' || probe.stage === 'both') fill.username = entry.username;
  if (probe.stage === 'password' || probe.stage === 'both') fill.password = entry.password;
  const results = await execute({ tabId: target.id, documentIds: [selected.documentId] }, loginPageOperation, fill);
  await recheckTop();
  const result = results?.find(item => item.documentId === selected.documentId)?.result;
  if (!result?.ok || (!result.usernameFilled && !result.passwordFilled)) throw new Error(result?.reason || '此页面不允许填充，请使用客户端复制密码。');
  return result;
}
