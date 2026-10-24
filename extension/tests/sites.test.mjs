import assert from 'node:assert/strict';
import test from 'node:test';
import {
  getLoginRules, credentialLookupHosts, credentialMatchesPage,
  allowedLoginFrame, OPTIONAL_LOGIN_ORIGINS,
} from '../src/lib/sites.js';

test('known login selectors retain evidence-based hints without assuming a login path', () => {
  for (const [host, id, selector] of [
    ['account.apple.com', 'apple', 'input#account_name_text_field'],
    ['idmsa.apple.com', 'apple', 'input#account_name_text_field'],
    ['chatgpt.com', 'chatgpt', 'input[name="username"][type="email"]'],
    ['accounts.google.com', 'google', 'input#identifierId'],
    ['login.live.com', 'microsoft', 'input#usernameEntry'],
    ['github.com', 'github', 'input#login_field'],
    ['gitee.com', 'gitee', 'input#user_login[name="user[login]"]'],
    ['mail.163.com', 'netease163', 'input[name="email"]'],
    ['passport.126.com', 'netease126', 'input[name="email"]'],
    ['passport.bilibili.com', 'bilibili', 'input[type="text"][placeholder="请输入账号"]'],
    ['passport.baidu.com', 'baidu', 'input[name="userName"]'],
  ]) {
    const rules = getLoginRules(host);
    assert.equal(rules.id, id, host);
    assert.ok(rules.usernameSelectors.includes(selector), host);
    assert.deepEqual(rules.loginPasswordSelectors, [], host);
    assert.equal(rules.allowUsernameOnly, false, host);
  }
  assert.ok(getLoginRules('github.com').passwordSelectors.includes('input#password[type="password"]'));
  assert.deepEqual(getLoginRules('accounts.google.com').passwordSelectors, []);
  assert.ok(!JSON.stringify(getLoginRules('dl.reg.163.com')).includes('pwdtext'));
  for (const host of ['example.com', 'accounts.google.com.evil.com', 'sub.accounts.google.com', 'qq.com', '', null]) {
    assert.deepEqual(getLoginRules(host), {
      id: 'generic', usernameSelectors: [], passwordSelectors: [],
      allowUsernameOnly: false, loginPasswordSelectors: [],
    });
  }
  const modified = getLoginRules('github.com');
  modified.usernameSelectors.push('input');
  assert.deepEqual(getLoginRules('github.com').usernameSelectors, ['input#login_field']);
});

test('username-only filling is enabled only on explicit first-party login routes', () => {
  for (const url of [
    'https://chatgpt.com/auth/login', 'https://chat.openai.com/auth/login/',
    'https://auth.openai.com/log-in', 'https://auth.openai.com/login',
    'https://auth0.openai.com/u/login', 'https://auth.openai.com/u/login/identifier',
    'https://auth.openai.com/u/login/password', 'https://auth0.openai.com/u/login/identifier-and-password',
    'https://accounts.google.com/v3/signin/identifier?flowName=GlifWebSignIn',
    'https://accounts.google.com/signin/v2/identifier',
    'https://accounts.google.com/v3/signin/challenge/pwd',
    'https://accounts.google.com/signin/login',
    'https://account.apple.com/sign-in', 'https://appleid.apple.com/signin',
    'https://idmsa.apple.com/appleauth/auth/authorize/signin',
    'https://icloud.com', 'https://www.icloud.com/mail/', 'https://www.icloud.com/iclouddrive',
    'https://login.live.com/', 'https://login.live.com/login.srf',
  ]) assert.equal(getLoginRules(new URL(url).hostname, { url }).allowUsernameOnly, true, url);

  // These are unrelated return destinations and opaque OAuth values, not the
  // current form's mode. Do not disable the observed Apple authorize frame.
  for (const url of [
    'https://idmsa.apple.com/appleauth/auth/authorize/signin?redirect_uri=https%3A%2F%2Fexample.com%2Fsignup&state=recovery_token',
    'https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fexample.com%2Freset&flowName=GlifWebSignIn',
    'https://chatgpt.com/auth/login?redirect=%2Fregister&state=forgot-password&flow=login',
  ]) assert.equal(getLoginRules(new URL(url).hostname, { url }).allowUsernameOnly, true, url);
});

test('username-only filling rejects registration, recovery, ordinary email pages and untrusted URL context', () => {
  for (const url of [
    'https://chatgpt.com/', 'https://chatgpt.com/newsletter', 'https://chatgpt.com/auth/signup',
    'https://chatgpt.com/auth/login/newsletter', 'https://chatgpt.com/auth/login#signup',
    'https://auth.openai.com/', 'https://auth.openai.com/authorize', 'https://auth.openai.com/u/signup',
    'https://auth0.openai.com/u/login/recovery', 'https://auth.openai.com/u/login/reset-password',
    'https://accounts.google.com/', 'https://accounts.google.com/signup',
    'https://accounts.google.com/signin/recovery', 'https://accounts.google.com/v3/signin/challenge/recovery',
    'https://accounts.google.com/v3/signin/challenge/resetPassword',
    'https://accounts.google.com/signin/identifier/forgot-password',
    'https://mail.google.com/', 'https://account.apple.com/', 'https://appleid.apple.com/account',
    'https://idmsa.apple.com/appleauth/auth/authorize',
    'https://www.icloud.com/newsletter', 'https://www.icloud.com/recovery',
    'https://login.live.com/recover', 'https://login.live.com/password/reset',
    'https://login.live.com/register', 'https://login.live.com/change-password',
    'https://login.live.com/forgot', 'https://login.live.com/reset',
    'https://login.live.com/newsletter',
  ]) assert.equal(getLoginRules(new URL(url).hostname, { url }).allowUsernameOnly, false, url);

  for (const query of [
    'screen_hint=signup', 'flow=register', 'flow_name=GlifWebSignUp', 'mode=registration',
    'action=recover', 'flowType=accountRecovery', 'intent=reset-password', 'view=forgotPassword',
    'authType=sign_up', 'type=change-password', 'screen=password_change', 'flow=createAccount',
    'flow=login&flow=recovery', 'SCREEN_HINT=sign-up',
  ]) {
    for (const base of ['https://chatgpt.com/auth/login', 'https://accounts.google.com/v3/signin/identifier',
      'https://idmsa.apple.com/appleauth/auth/authorize/signin', 'https://login.live.com/']) {
      const url = `${base}?${query}`;
      assert.equal(getLoginRules(new URL(url).hostname, { url }).allowUsernameOnly, false, url);
    }
  }
  for (const url of [undefined, null, '', 'not a URL', 'http://chatgpt.com/auth/login',
    'https://chatgpt.com:8443/auth/login', 'https://user:password@chatgpt.com/auth/login',
    'https://auth.openai.com/login', 'https://chatgpt.com.evil.com/auth/login']) {
    assert.equal(getLoginRules('chatgpt.com', { url }).allowUsernameOnly, false, String(url));
  }
});

test('NetEase new-password exception needs the exact owning site, frame, path and product', () => {
  for (const [topHostname, hostname, product] of [
    ['mail.163.com', 'dl.reg.163.com', 'mail163'],
    ['mail.126.com', 'passport.126.com', 'mail126'],
  ]) {
    const origin = `https://${hostname}`;
    const pathname = '/webzj/v1.0.1/pub/index_dl2_new.html';
    const url = `${origin}${pathname}?product=${product}`;
    assert.deepEqual(getLoginRules(hostname, { topHostname, url }).loginPasswordSelectors,
      ['input[type="password"][name="password"]']);
    const attempts = [
      { topHostname, url: url.replace('https:', 'http:') },
      { topHostname, url: url.replace(origin, `${origin}:8443`) },
      { topHostname, url: url.replace(origin, `https://user:pass@${hostname}`) },
      { topHostname, url: `${origin}/register?product=${product}` },
      { topHostname, url: `${origin}${pathname}` },
      { topHostname, url: `${origin}${pathname}?product=other` },
      { topHostname, url: `${url}&product=${product}` },
      { topHostname, url: `${url}#register` },
      { topHostname: 'evil.com', url },
      { topHostname: topHostname === 'mail.163.com' ? 'mail.126.com' : 'mail.163.com', url },
      { topHostname: `sub.${topHostname}`, url },
      { url },
      { topHostname },
    ];
    for (const attempt of attempts) assert.deepEqual(getLoginRules(hostname, attempt).loginPasswordSelectors, [], JSON.stringify(attempt));
    assert.deepEqual(getLoginRules('evil.com', { topHostname, url }).loginPasswordSelectors, []);
    assert.deepEqual(getLoginRules(hostname, { topHostname, url: url.replace(hostname, `${hostname}.evil.com`) }).loginPasswordSelectors, []);
  }
});

test('lookup aliases are bounded, normalized and enabled only on exact official login hosts', () => {
  const cases = [
    ['ACCOUNTS.GOOGLE.COM.', ['accounts.google.com', 'gmail.com', 'google.com']],
    ['mail.google.com', ['mail.google.com', 'gmail.com', 'google.com']],
    ['auth.openai.com', ['auth.openai.com', 'chatgpt.com', 'openai.com']],
    ['auth0.openai.com', ['auth0.openai.com', 'chatgpt.com', 'openai.com']],
    ['chatgpt.com', ['chatgpt.com', 'openai.com']],
    ['chat.openai.com', ['chat.openai.com', 'chatgpt.com', 'openai.com']],
    ['account.apple.com', ['account.apple.com', 'apple.com', 'icloud.com']],
    ['appleid.apple.com', ['appleid.apple.com', 'apple.com', 'icloud.com']],
    ['idmsa.apple.com', ['idmsa.apple.com', 'apple.com', 'icloud.com']],
    ['icloud.com', ['icloud.com', 'apple.com']],
    ['www.icloud.com', ['www.icloud.com', 'apple.com', 'icloud.com']],
    ['mail.163.com', ['mail.163.com']],
    ['mail.126.com', ['mail.126.com']],
    ['www.google.com', ['www.google.com']],
    ['gmail.com', ['gmail.com']],
    ['openai.com', ['openai.com']],
    ['apple.com', ['apple.com']],
    ['apps.apple.com', ['apps.apple.com']],
    ['sub.accounts.google.com', ['sub.accounts.google.com']],
    ['accounts.google.com.evil.com', ['accounts.google.com.evil.com']],
    ['BÜCHER.de', ['xn--bcher-kva.de']],
    ['[::1]', ['[::1]']],
  ];
  for (const [host, expected] of cases) {
    const actual = credentialLookupHosts(host);
    assert.deepEqual(actual, expected, host);
    assert.ok(actual.length <= 3, host);
    assert.equal(new Set(actual).size, actual.length, host);
  }
  for (const bad of ['', null, undefined, 42, 'https://accounts.google.com', 'accounts.google.com:443', 'user@accounts.google.com', 'accounts.google.com/path']) {
    assert.deepEqual(credentialLookupHosts(bad), [], String(bad));
  }
});

test('credential aliases are directional and never cross OAuth providers or mail products', () => {
  for (const [entry, page] of [
    ['gmail.com', 'accounts.google.com'], ['www.gmail.com', 'mail.google.com'],
    ['chatgpt.com', 'auth.openai.com'], ['openai.com', 'chatgpt.com'],
    ['icloud.com', 'account.apple.com'], ['apple.com', 'www.icloud.com'],
    ['accounts.example.co.uk', 'login.example.co.uk'],
    ['login.alice.github.io', 'alice.github.io'], ['[::1]', '[::1]'],
    ['localhost', 'localhost'], ['mail.163.com', 'dl.reg.163.com'],
  ]) assert.equal(credentialMatchesPage(entry, page), true, `${entry} -> ${page}`);

  for (const [entry, page] of [
    ['accounts.google.com', 'gmail.com'], ['chatgpt.com', 'openai.com'],
    ['icloud.com', 'apple.com'], ['icloud.com', 'apps.apple.com'],
    ['gmail.com', 'sub.accounts.google.com'], ['gmail.com', 'www.google.com'],
    ['gmail.com', 'accounts.google.com.evil.com'], ['gmail.com.evil.com', 'accounts.google.com'],
    ['chatgpt.com', 'accounts.google.com'], ['openai.com', 'accounts.google.com'],
    ['gmail.com', 'chatgpt.com'], ['google.com', 'auth.openai.com'],
    ['apple.com', 'chatgpt.com'], ['chatgpt.com', 'idmsa.apple.com'],
    ['github.com', 'accounts.google.com'], ['github.com', 'idmsa.apple.com'],
    ['163.com', 'mail.126.com'], ['126.com', 'mail.163.com'],
    ['mail.163.com', 'passport.126.com'], ['mail.126.com', 'dl.reg.163.com'],
    ['alice.github.io', 'bob.github.io'], ['alice.appspot.com', 'bob.appspot.com'],
    ['127.0.0.1', '127.0.0.2'], ['localhost', 'app.localhost'],
    ['vault.invalid', 'sub.vault.invalid'], ['co.uk', 'example.co.uk'],
  ]) assert.equal(credentialMatchesPage(entry, page), false, `${entry} -> ${page}`);
  for (const invalid of [null, undefined, '', 3, 'google.com/path', 'https://gmail.com', 'gmail.com:443']) {
    assert.equal(credentialMatchesPage(invalid, 'accounts.google.com'), false);
    assert.equal(credentialMatchesPage('gmail.com', invalid), false);
  }
});

test('frame permissions allow only verified HTTPS top/frame pairs and default ports', () => {
  for (const [top, frame] of [
    ['mail.163.com', 'dl.reg.163.com'], ['mail.126.com', 'passport.126.com'],
    ['account.apple.com', 'idmsa.apple.com'], ['appleid.apple.com', 'idmsa.apple.com'],
    ['icloud.com', 'idmsa.apple.com'], ['www.icloud.com', 'idmsa.apple.com'],
  ]) {
    assert.equal(allowedLoginFrame(top, `https://${frame}`), true);
    assert.equal(allowedLoginFrame(top, `https://${frame}:443`), true);
    for (const origin of [
      `http://${frame}`, `https://${frame}:8443`, `https://${frame}.evil.com`,
      `https://sub.${frame}`, `https://${frame}.`, `https://${frame}/login`,
      `https://${frame}?redirect=1`, `https://${frame}#login`, `https://user:pass@${frame}`,
      ` https://${frame}`, `https://${frame}\n`, `https://${frame}\\`,
      `https://${top}`, 'null', '', null, 42,
    ]) assert.equal(allowedLoginFrame(top, origin), false, `${top} -> ${origin}`);
    assert.equal(allowedLoginFrame(`sub.${top}`, `https://${frame}`), false);
    assert.equal(allowedLoginFrame(`${top}.evil.com`, `https://${frame}`), false);
  }
  for (const [top, origin] of [
    ['mail.163.com', 'https://passport.126.com'], ['mail.126.com', 'https://dl.reg.163.com'],
    ['apple.com', 'https://idmsa.apple.com'], ['account.apple.com', 'https://apps.apple.com'],
    ['chatgpt.com', 'https://accounts.google.com'], ['chatgpt.com', 'https://sentinel.openai.com'],
    ['accounts.google.com', 'https://accounts.google.com'], ['example.com', 'https://idmsa.apple.com'],
  ]) assert.equal(allowedLoginFrame(top, origin), false, `${top} -> ${origin}`);
  assert.deepEqual(OPTIONAL_LOGIN_ORIGINS, [
    'https://dl.reg.163.com/*', 'https://passport.126.com/*', 'https://idmsa.apple.com/*',
  ]);
  assert.ok(Object.isFrozen(OPTIONAL_LOGIN_ORIGINS));
});
