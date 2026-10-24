// Serialized into an isolated frame by chrome.scripting. Keep every dependency
// inside this function; the probe cache contains DOM references, never secrets.
export function loginPageOperation(request) {
  const cacheKey = '__ohMyPasswordLoginProbeV1';
  const previous = globalThis[cacheKey];
  delete globalThis[cacheKey];
  const page = {
    url: location.href,
    origin: location.origin,
    hostname: location.hostname.toLowerCase().replace(/\.$/, ''),
    nonce: typeof request?.nonce === 'string' ? request.nonce : '',
    iframeSources: [],
  };
  const fail = reason => ({ ...page, ok: false, usernameFilled: false, passwordFilled: false, reason });
  const unchanged = () => location.href === page.url && location.origin === page.origin &&
    location.hostname.toLowerCase().replace(/\.$/, '') === page.hostname;
  if (!request || !['probe', 'fill', 'frame-check'].includes(request.mode) || !page.nonce || page.nonce.length > 200) {
    return fail('填充请求已失效，请重新选择账号。');
  }
  if (request.expectedOrigin !== page.origin || request.expectedHostname !== page.hostname ||
      (request.expectedUrl !== undefined && request.expectedUrl !== page.url)) {
    return fail('页面已跳转，请重新打开扩展后选择账号。');
  }
  if (location.protocol !== 'https:' && !(location.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(page.hostname))) {
    return fail('此页面使用未加密的 HTTP，请切换到 HTTPS 后填充。');
  }
  if (request.mode !== 'probe' && (!previous || previous.nonce !== page.nonce || previous.url !== page.url ||
      previous.origin !== page.origin || previous.hostname !== page.hostname || performance.now() >= previous.expiresAt)) {
    return fail('登录表单确认已过期，请重新选择账号。');
  }
  const rawRules = request.mode !== 'probe' ? previous.rules : request.rules;
  const selectors = value => Array.isArray(value) ? value.filter(item => typeof item === 'string' && item.length <= 300).slice(0, 24) : [];
  const rules = {
    usernameSelectors: selectors(rawRules?.usernameSelectors),
    passwordSelectors: selectors(rawRules?.passwordSelectors),
    loginPasswordSelectors: selectors(rawRules?.loginPasswordSelectors),
    allowUsernameOnly: rawRules?.allowUsernameOnly === true,
  };
  const parent = element => element.assignedSlot ?? element.parentElement ?? element.getRootNode()?.host ?? null;
  const visible = element => {
    if (!element.isConnected || ![...element.getClientRects()].some(rect => rect.width > 0 && rect.height > 0)) return false;
    let depth = 0;
    for (let node = element; node; node = parent(node)) {
      if (++depth > 128 || node.hidden || node.inert || node.getAttribute('aria-hidden')?.toLowerCase() === 'true') return false;
      const style = getComputedStyle(node);
      if (style.display === 'none' || ['hidden', 'collapse'].includes(style.visibility) || style.opacity === '0' || style.contentVisibility === 'hidden') return false;
    }
    return true;
  };
  const usable = input => input instanceof HTMLInputElement && !input.disabled && !input.readOnly &&
    !input.matches(':disabled') && input.type !== 'hidden' && visible(input);
  const tokens = input => (input.getAttribute('autocomplete') ?? '').toLowerCase().split(/\s+/).filter(Boolean);
  const description = input => [input.id, input.name, input.getAttribute('aria-label'), input.getAttribute('placeholder'),
    ...Array.from(input.labels ?? [], label => label.textContent?.slice(0, 200) ?? '')].filter(Boolean).join(' ').toLowerCase();
  const matches = (input, list) => list.some(selector => {
    try { return input.matches(selector); } catch { return false; }
  });
  const loginException = input => {
    if (input.type !== 'password' || !matches(input, rules.loginPasswordSelectors) ||
        input.getAttribute('data-loginname') !== 'loginPassword' || input.form?.id !== 'login-form' || !visible(input.form)) return false;
    // This exception is supplied only for the verified NetEase login frame.
    // Its registration mode must never inherit the misleading new-password hint.
    const actions = [...input.form.querySelectorAll('a#dologin[data-action="dologin"]')].filter(visible);
    return actions.length === 1 && actions[0].textContent?.replace(/\s+/g, '') === '登录';
  };
  const passwordInput = input => input.type === 'password' || (input.type === 'text' &&
    (tokens(input).includes('current-password') || (matches(input, rules.passwordSelectors) && /pass|pwd|密码/i.test(description(input)))));
  const forbidden = (input, allowLoginPassword = false) => tokens(input).some(token =>
    token === 'one-time-code' || (token === 'new-password' && !allowLoginPassword)) ||
    /(?:confirm|confirmation|repeat|retype|re[-_\s]?password|new[-_\s]?pass|password[-_\s]?new|hidden[-_\s]?pass|captcha|one[-_\s]?time|(?:^|[\s_-])(?:otp|totp|mfa|code)(?:$|[\s_-])|(?:otp|totp|mfa)(?:code|input|field)|(?:verification|security|sms)[-_\s]?code|确认|再次|重复|新密码|验证码|校验码|动态码)/i.test(description(input));
  const usernameInput = input => ['text', 'email', 'tel'].includes(input.type) && !forbidden(input) &&
    !tokens(input).some(token => token === 'current-password' || token.startsWith('cc-')) &&
    !/(?:pass|pwd|search|captcha|(?:^|[\s_-])query(?:$|[\s_-])|搜索)/i.test(description(input));
  const activeForm = () => {
    let active = document.activeElement;
    for (let depth = 0; active?.shadowRoot?.activeElement && depth < 32; depth++) active = active.shadowRoot.activeElement;
    if (active?.form) return active.form;
    for (let node = active, depth = 0; node && depth < 128; node = parent(node), depth++) {
      if (node instanceof HTMLFormElement) return node;
    }
    return null;
  };
  const scan = () => {
    const inputs = [], frames = [], headings = [], actions = [], roots = [document];
    let count = 0;
    for (let index = 0; index < roots.length; index++) {
      const walker = document.createTreeWalker(roots[index], NodeFilter.SHOW_ELEMENT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        if (++count > 12000 || inputs.length > 256 || roots.length > 64) return { error: '页面表单过于复杂，请在客户端复制账号密码。' };
        if (node instanceof HTMLInputElement) inputs.push(node);
        else if (/^H[1-3]$/.test(node.tagName) || node.getAttribute('role') === 'heading') headings.push(node);
        else if (node instanceof HTMLButtonElement && node.type === 'submit') actions.push(node);
        else if (node instanceof HTMLIFrameElement) {
          if (frames.length >= 32) return { error: '页面内嵌表单过多，请打开独立登录页面后重试。' };
          const source = node.getAttribute('src');
          let url = null;
          try { url = new URL(node.hasAttribute('srcdoc') ? 'about:srcdoc' : source ? node.src : 'about:blank'); } catch { /* Report invalid addresses without granting them an origin. */ }
          frames.push({ node, src: url?.href ?? '', origin: url && !url.username && !url.password ? url.origin : 'null',
            hostname: url?.hostname.toLowerCase().replace(/\.$/, '') ?? '', visible: visible(node) });
        }
        if (node.shadowRoot) roots.push(node.shadowRoot);
      }
    }
    return { inputs: inputs.filter(usable), frames, headings, actions };
  };
  const unrelatedFlow = (input, collected) => {
    const blockedPath = /(?:^|\/)(?:sign[-_]?up|register|registration|recover(?:y)?|forgot(?:[-_]password)?|reset(?:[-_]password)?|password[-_]reset|change[-_]password|new[-_]password|newsletter|subscribe|(?:otp|totp|sms)[-_]?verification)(?:\/|$)/i;
    if (blockedPath.test(location.pathname)) return true;
    if (input?.form) {
      const form = input.form;
      const otherForm = /^(?:sign[-_]?up|register|registration|forgot[-_]?password|password[-_]?reset|reset[-_]?password|newsletter|subscribe)(?:[-_]?form)?$/i;
      if ([form.id, form.getAttribute('name'), ...form.classList].some(value => value && otherForm.test(value))) return true;
      if (form.getAttribute('action')) {
        try { if (blockedPath.test(new URL(form.action).pathname)) return true; } catch { /* The DOM may contain an invalid form action. */ }
      }
    }
    const forbiddenFlow = /(?:\b(?:sign[ -]?up|register|registration|create (?:(?:an?|your) )?account|reset (?:your )?password|(?:recover|restore) (?:your )?account|password recovery|forgot (?:your )?password|change (?:your )?password|new password|verify (?:your )?(?:email|code)|enter (?:(?:the|your) )?(?:verification|security|one[- ]time) code|two[- ](?:step|factor) (?:verification|authentication)|authenticator code|newsletter|subscribe|subscription)\b|注册|创建(?:新)?(?:账号|账户)|重置密码|修改密码|更改密码|找回(?:密码|账号|账户)|忘记密码|设置新密码|验证码|安全码|订阅)/i;
    let scope = input?.form ?? null;
    if (!scope) {
      for (let node = input, depth = 0; node && depth < 128; node = parent(node), depth++) {
        if (node.matches('main,section,dialog,[role="main"],[role="dialog"]')) { scope = node; break; }
      }
    }
    const within = node => {
      for (let current = node, depth = 0; current && depth < 128; current = parent(current), depth++) if (current === scope) return true;
      return false;
    };
    let headings = collected.headings.filter(node => (!scope || within(node)) && visible(node));
    if (!headings.length) headings = collected.headings.filter(node => node.tagName === 'H1' && visible(node));
    const actions = collected.actions.filter(node => (input?.form ? node.form === input.form : scope && within(node)) && visible(node));
    const text = node => (node.textContent?.slice(0, 500) ?? '').replace(/\s+/g, ' ').trim();
    // Known login routes can present a shared identifier step under this exact
    // mixed heading. Pure registration headings and submit actions stay blocked.
    return headings.some(node => {
      const heading = text(node);
      return !(rules.allowUsernameOnly && /^(?:log|sign) in or sign up[.!]?$/i.test(heading)) && forbiddenFlow.test(heading);
    }) || actions.some(node => forbiddenFlow.test(text(node)));
  };
  const detect = collected => {
    collected ??= scan();
    if (collected.error) return collected;
    page.iframeSources = collected.frames.map(({ node, ...source }) => source);
    const { inputs } = collected;
    const form = activeForm();
    let passwords = inputs.filter(input => passwordInput(input) && !forbidden(input, loginException(input)));
    if (passwords.some(input => loginException(input) && tokens(input).includes('new-password')) &&
        inputs.some(input => passwordInput(input) && !passwords.includes(input) && forbidden(input))) {
      return { error: '页面包含新密码或确认密码框，请进入登录步骤后重试。' };
    }
    if (passwords.length > 1 && form) {
      const focused = passwords.filter(input => input.form === form);
      if (focused.length) passwords = focused;
    }
    if (passwords.length > 1) return { error: '页面有多个密码框，请先点击需要填写的登录表单后重试。' };
    const password = passwords[0] ?? null;
    // Site selectors never override hidden/OTP/new-password exclusions or a
    // multiple-password ambiguity. A generic unique login form still works.
    let usernames = inputs.filter(usernameInput);
    if (password?.form) usernames = usernames.filter(input => input.form === password.form);
    else if (password) usernames = usernames.filter(input => input.getRootNode() === password.getRootNode());
    else if (form) {
      const focused = usernames.filter(input => input.form === form);
      if (focused.length) usernames = focused;
    }
    if (!password && (!rules.allowUsernameOnly || inputs.some(input => passwordInput(input) || forbidden(input)))) {
      return { error: '当前页面没有可填写的登录密码框，请进入账号或密码步骤后重试。' };
    }
    const explicit = usernames.filter(input => matches(input, rules.usernameSelectors));
    const autocomplete = usernames.filter(input => tokens(input).includes('username'));
    const recognizable = usernames.filter(input => input.type === 'email' || tokens(input).includes('email') ||
      /(?:user|email|login|account|identifier|用户名|账号|账户|邮箱|手机号)/i.test(description(input)));
    let candidates = explicit.length ? explicit : autocomplete.length ? autocomplete : password ? recognizable : [];
    if (!candidates.length && password?.form) {
      candidates = usernames.filter(input => input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING);
    }
    if (candidates.length > 1) return { error: '页面有多个账号输入框，请先点击需要填写的登录表单后重试。' };
    const username = candidates[0] ?? null;
    if (!password && !username) return { error: '当前页面没有可确认的登录账号框，请进入登录步骤后重试。' };
    if (unrelatedFlow(username ?? password, collected)) return { error: '当前页面是注册、找回密码或验证步骤，请返回登录页面后填充。' };
    return { username, password, stage: username && password ? 'both' : username ? 'username' : 'password' };
  };
  try {
    const collected = scan();
    if (collected.error) return fail(collected.error);
    page.iframeSources = collected.frames.map(({ node, ...source }) => source);
    if (request.mode === 'frame-check') {
      const cached = previous.frames.filter(frame => frame.src === request.frameUrl);
      const current = collected.frames.filter(frame => frame.src === request.frameUrl);
      if (!unchanged() || typeof request.frameUrl !== 'string' || cached.length !== 1 || current.length !== 1 ||
          cached[0].node !== current[0].node || !cached[0].visible || !current[0].visible || !current[0].node.isConnected ||
          !['http:', 'https:'].includes(new URL(current[0].src).protocol) || current[0].origin === 'null') {
        return fail('内嵌登录页面已变化或无法唯一确认，请重新选择账号。');
      }
      return { ...page, ok: true };
    }
    const selection = detect(collected);
    if (!unchanged()) return fail('页面已跳转，请重新打开扩展后选择账号。');
    if (request.mode === 'probe') {
      globalThis[cacheKey] = {
        nonce: page.nonce, url: page.url, origin: page.origin, hostname: page.hostname,
        expiresAt: performance.now() + 10000, rules,
        username: selection.username, password: selection.password, stage: selection.stage,
        frames: collected.frames,
      };
      if (selection.error) return fail(selection.error);
      return { ...page, ok: true, stage: selection.stage };
    }
    if (selection.error) return fail(selection.error);
    if (selection.username !== previous.username || selection.password !== previous.password || selection.stage !== previous.stage) {
      return fail('登录表单已变化，请重新选择账号。');
    }
    if ((selection.username && typeof request.username !== 'string') || (selection.password && typeof request.password !== 'string')) {
      return fail('账号数据不完整，请重新选择账号。');
    }
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (!setter) return fail('此页面不支持填充，请使用客户端复制密码。');
    let usernameFilled = false, passwordFilled = false;
    const sameSelection = current => !current.error && current.username === selection.username && current.password === selection.password && current.stage === selection.stage;
    const set = (input, value) => {
      HTMLElement.prototype.focus.call(input, { preventScroll: true });
      if (!unchanged() || performance.now() >= previous.expiresAt || !sameSelection(detect())) return false;
      setter.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
      input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
      HTMLElement.prototype.blur.call(input);
      return true;
    };
    if (selection.username) {
      if (!set(selection.username, request.username)) return fail('登录表单已变化，请重新选择账号。');
      usernameFilled = true;
    }
    if (selection.password) {
      // Focusing the same cached password also restores the user's chosen form
      // after our username blur; set() re-detects every candidate before writing.
      if (!set(selection.password, request.password)) return { ...fail('登录表单已变化，请重新选择账号。'), usernameFilled };
      passwordFilled = true;
    }
    if (!unchanged()) return { ...fail('页面已跳转，请重新打开扩展后确认登录状态。'), usernameFilled, passwordFilled };
    return { ok: true, stage: selection.stage, usernameFilled, passwordFilled };
  } catch {
    delete globalThis[cacheKey];
    return fail('无法确认当前登录表单，请重新选择账号或在客户端复制。');
  }
}
