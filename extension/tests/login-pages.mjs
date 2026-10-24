// Synthetic login-page DOM regressions in a real Chromium renderer. Every URL
// is intercepted locally. This does not log in to, or certify, any live site.
// Frame.evaluate validates frame DOM behavior, not extension iframe permissions.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chromium } from 'playwright';
import { loginPageOperation } from '../src/lib/login-page.js';

const USERNAME = 'test-only@example.invalid';
const PASSWORD = 'fixture-only-password-42';
const executablePath = process.env.CHROMIUM_PATH || (existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined);
const browser = await chromium.launch({ executablePath, headless: true, args: ['--no-sandbox'] });
let passed = 0;

function documentHtml(content, script = '') {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    body { padding: 24px; font: 16px sans-serif; } input,button { margin: 6px; padding: 8px; }
    form { margin: 12px; } iframe { width: 600px; height: 300px; border: 0; }
  </style></head><body>${content}<script>
    window.fixtureSubmits = 0; window.fixtureClicks = 0;
    document.addEventListener('submit', event => { event.preventDefault(); window.fixtureSubmits++; });
    document.addEventListener('click', event => { if (event.target.closest('button,a')) window.fixtureClicks++; });
    ${script}
  </script></body></html>`;
}

const pair = (prefix = 'login') => `<form id="${prefix}-form"><label>Account
  <input id="${prefix}-user" autocomplete="username"></label><label>Password
  <input id="${prefix}-password" type="password" autocomplete="current-password"></label>
  <button type="submit">Sign in</button></form>`;

async function scenario(name, url, html, exercise, extraPages = {}) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: 'block' });
  const fixtures = new Map([[url, html], ...Object.entries(extraPages)]);
  await context.route('**/*', route => {
    const body = fixtures.get(route.request().url());
    return body === undefined ? route.abort() : route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body });
  });
  const page = await context.newPage();
  try {
    await page.goto(url);
    await exercise(page);
    assert.equal(await page.evaluate(() => window.fixtureSubmits), 0, `${name}: the engine must not submit a form`);
    passed++;
    console.log(`PASS: ${name}`);
  } catch (error) {
    error.message = `${name}: ${error.message}`;
    throw error;
  } finally {
    await context.close();
  }
}

async function probe(frame, rules = {}) {
  const url = new URL(frame.url());
  const request = {
    mode: 'probe', nonce: randomUUID(), expectedUrl: url.href,
    expectedOrigin: url.origin, expectedHostname: url.hostname.toLowerCase(), rules,
  };
  const result = await frame.evaluate(loginPageOperation, request);
  assert.equal(result.nonce, request.nonce);
  assert.ok(!JSON.stringify(result).includes(PASSWORD), 'Probe results must not expose a password');
  return { request, result };
}

async function fill(frame, candidate, changes = {}) {
  return frame.evaluate(loginPageOperation, {
    ...candidate.request, mode: 'fill', username: USERNAME, password: PASSWORD, ...changes,
  });
}

async function fillPair(page, usernameSelector, passwordSelector, rules = {}) {
  const candidate = await probe(page, rules);
  assert.equal(candidate.result.ok, true, candidate.result.reason);
  assert.equal(candidate.result.stage, 'both');
  const result = await fill(page, candidate);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.usernameFilled, true);
  assert.equal(result.passwordFilled, true);
  assert.equal(await page.locator(usernameSelector).inputValue(), USERNAME);
  assert.equal(await page.locator(passwordSelector).inputValue(), PASSWORD);
  assert.equal(await page.evaluate(() => window.fixtureClicks), 0, 'Filling must not click a login or next button');
}

try {
  for (const fixture of [
    {
      name: 'GitHub-shaped username and current-password fields',
      url: 'https://github.com/login',
      html: '<form><input id="login_field" name="login" autocomplete="username"><input id="password" name="password" type="password" autocomplete="current-password"><button>Sign in</button></form>',
      username: '#login_field', password: '#password',
    },
    {
      name: 'Apple-shaped account and password fields',
      url: 'https://account.apple.com/sign-in',
      html: '<form><input id="account_name_text_field" type="email" aria-label="Apple Account"><input id="password_text_field" type="password" autocomplete="current-password"><button>Continue</button></form>',
      username: '#account_name_text_field', password: '#password_text_field',
      rules: { usernameSelectors: ['#account_name_text_field'], passwordSelectors: ['#password_text_field'] },
    },
    {
      name: 'Bilibili-shaped Chinese placeholder fields',
      url: 'https://passport.bilibili.com/login',
      html: '<form><input placeholder="请输入账号"><input type="password" placeholder="请输入密码"><button>登录</button></form>',
      username: 'input[placeholder="请输入账号"]', password: 'input[type=password]',
    },
  ]) {
    await scenario(fixture.name, fixture.url, documentHtml(fixture.html), page =>
      fillPair(page, fixture.username, fixture.password, fixture.rules));
  }

  await scenario('Google-shaped username step ignores hidden password fields', 'https://accounts.google.com/v3/signin/identifier', documentHtml(`
    <form><input id="identifierId" type="email" autocomplete="username">
      <input name="hiddenPassword" type="password" tabindex="-1" hidden>
      <button type="button" id="next">Next</button></form>`), async page => {
    const candidate = await probe(page, { allowUsernameOnly: true, usernameSelectors: ['#identifierId'] });
    assert.equal(candidate.result.ok, true, candidate.result.reason);
    assert.equal(candidate.result.stage, 'username');
    const result = await fill(page, candidate);
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.passwordFilled, false);
    assert.equal(await page.locator('#identifierId').inputValue(), USERNAME);
    assert.equal(await page.locator('[name=hiddenPassword]').inputValue(), '');
    assert.equal(await page.evaluate(() => window.fixtureClicks), 0);
  });

  await scenario('Microsoft-shaped username webauthn autocomplete tokens', 'https://login.live.com/login.srf', documentHtml(`
    <form><input id="usernameEntry" name="loginfmt" type="email" autocomplete="username webauthn">
    <button type="button">Next</button></form>`), async page => {
    const candidate = await probe(page, { allowUsernameOnly: true });
    assert.equal(candidate.result.ok, true, candidate.result.reason);
    assert.equal(candidate.result.stage, 'username');
    const result = await fill(page, candidate);
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.passwordFilled, false);
    assert.equal(await page.locator('#usernameEntry').inputValue(), USERNAME);
    assert.equal(await page.evaluate(() => window.fixtureClicks), 0);
  });

  await scenario('Gitee-shaped duplicate IDs do not select the hidden SMS form', 'https://gitee.com/login', documentHtml(`
    <form id="sms" style="display:none"><input id="user_login" autocomplete="username">
      <input id="user_password" type="password" autocomplete="one-time-code"></form>
    <form id="account"><input id="user_login" autocomplete="username">
      <input id="user_password" type="password" autocomplete="current-password"><button>登录</button></form>`), async page => {
    await fillPair(page, '#account #user_login', '#account #user_password', {
      usernameSelectors: ['#user_login'], passwordSelectors: ['#user_password'],
    });
    assert.equal(await page.locator('#sms #user_login').inputValue(), '');
    assert.equal(await page.locator('#sms #user_password').inputValue(), '');
  });

  const mailUrl = 'https://mail.163.com/';
  const frameUrl = 'https://dl.reg.163.com/webzj/login';
  await scenario('NetEase-shaped login iframe reports its URL and fills only its own DOM', mailUrl,
    documentHtml(`<h1>Mail</h1><iframe src="${frameUrl}"></iframe>`), async page => {
      const main = await probe(page);
      const source = main.result.iframeSources.find(item => item.src === frameUrl);
      assert.ok(source, 'The visible login iframe must be reported even without main-frame fields');
      assert.equal(source.origin, 'https://dl.reg.163.com');
      assert.equal(source.hostname, 'dl.reg.163.com');
      assert.equal(source.visible, true);
      const allowed = await page.evaluate(loginPageOperation, { ...main.request, mode: 'frame-check', frameUrl });
      assert.equal(allowed.ok, true, allowed.reason);
      assert.equal((await page.evaluate(loginPageOperation, { ...main.request, mode: 'frame-check', frameUrl })).ok, false, 'A frame check is single-use');
      const frame = page.frames().find(item => item.url() === frameUrl);
      assert.ok(frame);
      await fillPair(frame, '[name=email]', '[name=password]');
      assert.equal(await page.locator('input').count(), 0);
      assert.equal(await frame.evaluate(() => window.fixtureSubmits), 0);
    }, {
      [frameUrl]: documentHtml('<form><input name="email" type="email" placeholder="邮箱帐号"><input name="password" type="password" autocomplete="current-password"><button>登录</button></form>'),
    });

  await scenario('A narrow NetEase-shaped login rule waits for manual readonly release', frameUrl, documentHtml(`
    <form id="login-form"><input name="email" type="email" placeholder="邮箱帐号">
      <input name="password" type="password" data-loginname="loginPassword" autocomplete="new-password" tabindex="-1" readonly>
      <a id="dologin" data-action="dologin" class="btndisabled" href="#">登录</a></form>`, `
    document.querySelector('[name=password]').addEventListener('focus', event => { event.target.readOnly = false; });`), async page => {
    const rules = { usernameSelectors: ['input[name="email"]'], loginPasswordSelectors: ['input[type="password"][name="password"]'] };
    assert.equal((await probe(page, rules)).result.ok, false);
    assert.equal(await page.locator('[name=password]').evaluate(input => input.readOnly), true);
    assert.equal(await page.locator('[name=password]').inputValue(), '');
    await page.locator('[name=password]').click();
    assert.equal(await page.locator('[name=password]').evaluate(input => input.readOnly), false);
    await fillPair(page, '[name=email]', '[name=password]', rules);
  });

  await scenario('A login new-password exception does not override a visible confirmation field', 'https://dl.reg.163.com/webzj/register', documentHtml(`
    <form id="login-form"><input name="email" type="email"><input name="password" type="password" data-loginname="loginPassword" autocomplete="new-password">
      <input name="password_confirmation" type="password" autocomplete="new-password"><a id="dologin" data-action="dologin" href="#">登录</a></form>`), async page => {
    const candidate = await probe(page, { loginPasswordSelectors: ['input[type="password"][name="password"]'] });
    assert.equal(candidate.result.ok, false);
    assert.equal((await fill(page, candidate)).ok, false);
    assert.deepEqual(await page.locator('input[type=password]').evaluateAll(inputs => inputs.map(input => input.value)), ['', '']);
  });

  for (const kind of ['missing-login-markers', 'registration-at-same-url']) {
    const registration = kind === 'registration-at-same-url';
    await scenario(`NetEase-shaped ${kind} cannot reuse the new-password exception`, frameUrl, documentHtml(`
      ${registration ? '<h1>注册账号</h1>' : ''}<form id="${registration ? 'register-form' : 'login-form'}">
        <input name="email" type="email"><input name="password" type="password" autocomplete="new-password">
        <button type="submit">${registration ? '注册' : '登录'}</button></form>`), async page => {
      const candidate = await probe(page, { loginPasswordSelectors: ['input[type="password"][name="password"]'] });
      assert.equal(candidate.result.ok, false);
      assert.equal((await fill(page, candidate)).ok, false);
      assert.equal(await page.locator('[name=password]').inputValue(), '');
    });
  }

  await scenario('A password-display text field requires an explicit password selector', 'https://mail.126.com/login-fixture', documentHtml(`
    <form><input name="email" type="email"><input id="pwdtext" type="text" aria-label="密码"><button>登录</button></form>`), async page => {
    assert.equal((await probe(page)).result.ok, false);
    await fillPair(page, '[name=email]', '#pwdtext', { passwordSelectors: ['#pwdtext'] });
  });

  for (const mutation of ['hide', 'remove', 'replace', 'change-src', 'duplicate']) {
    await scenario(`Iframe ${mutation} after probing invalidates its frame check`, mailUrl,
      documentHtml(`<iframe src="${frameUrl}"></iframe>`), async page => {
        const candidate = await probe(page);
        assert.equal(candidate.result.iframeSources.length, 1);
        await page.evaluate(({ mutation, next }) => {
          const frame = document.querySelector('iframe');
          if (mutation === 'hide') frame.hidden = true;
          if (mutation === 'remove') frame.remove();
          if (mutation === 'replace') frame.replaceWith(frame.cloneNode(true));
          if (mutation === 'change-src') frame.src = next;
          if (mutation === 'duplicate') {
            const clone = frame.cloneNode(true); clone.hidden = true; document.body.append(clone);
          }
        }, { mutation, next: `${frameUrl}?changed=1` });
        const result = await page.evaluate(loginPageOperation, { ...candidate.request, mode: 'frame-check', frameUrl });
        assert.equal(result.ok, false);
      }, {
        [frameUrl]: documentHtml(pair('frame')),
        [`${frameUrl}?changed=1`]: documentHtml(pair('other-frame')),
      });
  }

  await scenario('An existing hidden duplicate iframe also prevents a unique frame selection', mailUrl,
    documentHtml(`<iframe src="${frameUrl}"></iframe><iframe src="${frameUrl}" hidden></iframe>`), async page => {
      const candidate = await probe(page);
      assert.equal(candidate.result.iframeSources.length, 2);
      assert.deepEqual(candidate.result.iframeSources.map(frame => frame.visible), [true, false]);
      assert.equal((await page.evaluate(loginPageOperation, { ...candidate.request, mode: 'frame-check', frameUrl })).ok, false);
    }, { [frameUrl]: documentHtml(pair('frame')) });

  await scenario('ChatGPT-shaped email then password requires a deliberate next click and a fresh probe', 'https://auth.openai.com/log-in', documentHtml(`
    <h1>Log in or sign up</h1><form id="step"><input id="email-input" type="email" autocomplete="username">
      <button id="continue" type="button">Continue</button></form>`, `
    document.getElementById('continue').addEventListener('click', () => {
      document.getElementById('step').innerHTML = '<input id="step-password" type="password" autocomplete="current-password"><button type="submit">Log in</button>';
    });`), async page => {
    const chatRules = { allowUsernameOnly: true };
    const first = await probe(page, chatRules);
    assert.equal(first.result.ok, true, first.result.reason);
    assert.equal(first.result.stage, 'username');
    const username = await fill(page, first);
    assert.equal(username.ok, true, username.reason);
    assert.equal(username.passwordFilled, false);
    assert.equal(await page.locator('#email-input').inputValue(), USERNAME);
    assert.equal(await page.locator('#step-password').count(), 0);
    assert.equal(await page.evaluate(() => window.fixtureClicks), 0);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    const second = await probe(page, chatRules);
    assert.equal(second.result.ok, true, second.result.reason);
    assert.equal(second.result.stage, 'password');
    const password = await fill(page, second);
    assert.equal(password.ok, true, password.reason);
    assert.equal(password.usernameFilled, false);
    assert.equal(await page.locator('#step-password').inputValue(), PASSWORD);
    assert.equal(await page.evaluate(() => window.fixtureClicks), 1);
  });

  await scenario('OTP, new-password and confirmation fields remain untouched beside a login form', 'https://fixture.example.com/login', documentHtml(`
    ${pair()}<form><input id="otp" type="password" autocomplete="one-time-code">
    <input id="new-password" type="password" autocomplete="new-password">
    <input id="confirm-password" type="password" aria-label="确认密码"></form>`), async page => {
    await fillPair(page, '#login-user', '#login-password');
    for (const selector of ['#otp', '#new-password', '#confirm-password']) assert.equal(await page.locator(selector).inputValue(), '');
  });

  await scenario('An OTP or registration-only form cannot become a login candidate', 'https://fixture.example.com/register', documentHtml(`
    <form><input type="email" autocomplete="username"><input id="new" type="password" autocomplete="new-password">
      <input id="confirm" type="password" placeholder="Repeat password"><input id="otp" autocomplete="one-time-code"></form>`), async page => {
    const candidate = await probe(page, { allowUsernameOnly: true, passwordSelectors: ['#new', '#confirm'] });
    assert.equal(candidate.result.ok, false);
    assert.equal((await fill(page, candidate)).ok, false);
    assert.deepEqual(await page.locator('input').evaluateAll(inputs => inputs.map(input => input.value)), ['', '', '', '']);
  });

  for (const step of [
    { path: 'signup', heading: 'Create your account', button: 'Sign up' },
    { path: 'password/reset', heading: 'Reset your password', button: 'Reset password' },
    { path: 'challenge/verify', heading: 'Enter your verification code', button: 'Verify' },
  ]) {
    await scenario(`Known username-only rules refuse the ${step.path} stage`, `https://accounts.google.com/${step.path}`, documentHtml(`
      <h1>${step.heading}</h1><form><input id="identifierId" autocomplete="username"><button type="button">${step.button}</button></form>`), async page => {
      const candidate = await probe(page, { allowUsernameOnly: true, usernameSelectors: ['#identifierId'] });
      assert.equal(candidate.result.ok, false);
      assert.equal((await fill(page, candidate)).ok, false);
      assert.equal(await page.locator('#identifierId').inputValue(), '');
      assert.equal(await page.evaluate(() => window.fixtureClicks), 0);
    });
  }

  await scenario('Normal sign-in links to reset or registration do not block its username step', 'https://accounts.google.com/signin', documentHtml(`
    <h1>Sign in</h1><form><input id="identifierId" type="email" autocomplete="username"><button type="button">Next</button><button type="button">Create account</button></form>
    <a href="/password/reset">Forgot password?</a><a href="/signup">Create account</a>`), async page => {
    const candidate = await probe(page, { allowUsernameOnly: true });
    assert.equal(candidate.result.ok, true, candidate.result.reason);
    const result = await fill(page, candidate);
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.passwordFilled, false);
    assert.equal(await page.locator('#identifierId').inputValue(), USERNAME);
    assert.equal(await page.evaluate(() => window.fixtureClicks), 0);
  });

  await scenario('Multiple visible login forms need a focus choice', 'https://fixture.example.com/accounts', documentHtml(pair('first') + pair('second')), async page => {
    assert.equal((await probe(page)).result.ok, false);
    await page.locator('#second-user').focus();
    await fillPair(page, '#second-user', '#second-password');
    assert.equal(await page.locator('#first-user').inputValue(), '');
    assert.equal(await page.locator('#first-password').inputValue(), '');
  });

  await scenario('Focus does not resolve two current-password fields inside one form', 'https://fixture.example.com/ambiguous', documentHtml(`
    <form><input autocomplete="username"><input id="primary" type="password" autocomplete="current-password">
      <input id="secondary" type="password" autocomplete="current-password"></form>`), async page => {
    await page.locator('#primary').focus();
    assert.equal((await probe(page)).result.ok, false);
    assert.deepEqual(await page.locator('input[type=password]').evaluateAll(inputs => inputs.map(input => input.value)), ['', '']);
  });

  await scenario('A fresh caller retry finds a delayed SPA form', 'https://fixture.example.com/spa', documentHtml('<main id="app">Loading…</main>'), async page => {
    const first = await probe(page);
    assert.equal(first.result.ok, false);
    await page.evaluate(html => { setTimeout(() => { document.getElementById('app').innerHTML = html; }, 50); }, pair('spa'));
    await page.locator('#spa-password').waitFor();
    await fillPair(page, '#spa-user', '#spa-password');
  });

  await scenario('Native setters bypass React-like instance setters and emit input/change events', 'https://fixture.example.com/react', documentHtml(pair(), `
    window.instanceWrites = 0; window.state = {}; window.events = [];
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    for (const input of document.querySelectorAll('input')) {
      Object.defineProperty(input, 'value', {
        configurable: true, get() { return descriptor.get.call(this); },
        set(value) { window.instanceWrites++; descriptor.set.call(this, value); }
      });
      for (const type of ['input', 'change']) input.addEventListener(type, event => {
        window.state[input.id] = event.target.value; window.events.push(type + ':' + input.id);
      });
    }`), async page => {
    await fillPair(page, '#login-user', '#login-password');
    assert.deepEqual(await page.evaluate(() => ({ writes: window.instanceWrites, state: window.state, events: window.events })), {
      writes: 0, state: { 'login-user': USERNAME, 'login-password': PASSWORD },
      events: ['input:login-user', 'change:login-user', 'input:login-password', 'change:login-password'],
    });
  });

  await scenario('Native focus and blur surround field updates without invoking overridden methods', 'https://fixture.example.com/focus-events', documentHtml(pair(), `
    window.focusEvents = []; window.overriddenFocusCalls = 0;
    for (const input of document.querySelectorAll('input')) {
      input.focus = () => window.overriddenFocusCalls++;
      input.blur = () => window.overriddenFocusCalls++;
      for (const type of ['focus', 'input', 'change', 'blur']) input.addEventListener(type, () => window.focusEvents.push(type + ':' + input.id));
    }`), async page => {
    await fillPair(page, '#login-user', '#login-password');
    assert.equal(await page.evaluate(() => window.overriddenFocusCalls), 0);
    assert.deepEqual(await page.evaluate(() => window.focusEvents), [
      'focus:login-user', 'input:login-user', 'change:login-user', 'blur:login-user',
      'focus:login-password', 'input:login-password', 'change:login-password', 'blur:login-password',
    ]);
  });

  await scenario('A revealed text field marked current-password remains a password candidate', 'https://fixture.example.com/revealed', documentHtml(`
    <form><input id="account" autocomplete="username"><input id="revealed" type="text" autocomplete="current-password"><button>Sign in</button></form>`), async page => {
    await fillPair(page, '#account', '#revealed');
  });

  await scenario('An open shadow-root login form is detected and filled', 'https://fixture.example.com/shadow', documentHtml('<div id="host"></div>', `
    document.getElementById('host').attachShadow({mode:'open'}).innerHTML = ${JSON.stringify(pair('shadow'))};`), async page => {
    await fillPair(page, '#shadow-user', '#shadow-password');
  });

  await scenario('Hidden, inert, aria-hidden, disabled and readonly decoys are excluded', 'https://fixture.example.com/hidden', documentHtml(`
    <div hidden>${pair('hidden')}</div><div inert>${pair('inert')}</div>
    <div aria-hidden="true">${pair('aria')}</div><div style="opacity:0">${pair('transparent')}</div>
    <fieldset disabled>${pair('disabled')}</fieldset><input id="readonly-password" type="password" readonly>
    ${pair('visible')}`), async page => {
    await fillPair(page, '#visible-user', '#visible-password');
    assert.ok((await page.locator('input:not(#visible-user):not(#visible-password)').evaluateAll(inputs => inputs.map(input => input.value))).every(value => value === ''));
  });

  await scenario('A same-origin route change invalidates the probed page', 'https://fixture.example.com/before', documentHtml(pair()), async page => {
    const candidate = await probe(page);
    assert.equal(candidate.result.ok, true);
    await page.evaluate(() => history.pushState({}, '', '/after'));
    assert.equal((await fill(page, candidate)).ok, false);
    assert.equal(await page.locator('#login-password').inputValue(), '');
  });

  await scenario('Replacing a candidate with an identical-looking input invalidates it', 'https://fixture.example.com/replaced', documentHtml(pair()), async page => {
    const candidate = await probe(page);
    assert.equal(candidate.result.ok, true);
    await page.evaluate(() => {
      const original = document.getElementById('login-password');
      window.detachedPassword = original;
      original.replaceWith(original.cloneNode(true));
    });
    assert.equal((await fill(page, candidate)).ok, false);
    assert.equal(await page.locator('#login-password').inputValue(), '');
    assert.equal(await page.evaluate(() => window.detachedPassword.value), '');
  });

  await scenario('A candidate becoming inert after probing cannot receive a password', 'https://fixture.example.com/becomes-inert', documentHtml(pair()), async page => {
    const candidate = await probe(page);
    await page.locator('#login-form').evaluate(form => { form.inert = true; });
    assert.equal((await fill(page, candidate)).ok, false);
    assert.equal(await page.locator('#login-password').inputValue(), '');
  });

  await scenario('Wrong and replayed nonces cannot be used to fill', 'https://fixture.example.com/nonces', documentHtml(pair()), async page => {
    const candidate = await probe(page);
    assert.equal((await fill(page, candidate, { nonce: randomUUID() })).ok, false);
    assert.equal((await fill(page, candidate)).ok, false, 'A failed fill must also consume the old probe');
    const fresh = await probe(page);
    assert.equal((await fill(page, fresh)).ok, true);
    await page.locator('input').evaluateAll(inputs => inputs.forEach(input => { input.value = ''; }));
    assert.equal((await fill(page, fresh)).ok, false);
    assert.equal(await page.locator('#login-password').inputValue(), '');
  });

  await scenario('An expired probe cannot be filled', 'https://fixture.example.com/expired', documentHtml(pair()), async page => {
    await page.clock.install();
    const candidate = await probe(page);
    assert.equal(candidate.result.ok, true);
    await page.clock.fastForward(10001);
    assert.equal((await fill(page, candidate)).ok, false);
    assert.equal(await page.locator('#login-password').inputValue(), '');
  });

  await scenario('Synchronous username handlers cannot redirect the password into a replacement field', 'https://fixture.example.com/react-rerender', documentHtml(pair(), `
    document.getElementById('login-user').addEventListener('input', () => {
      const original = document.getElementById('login-password');
      window.detachedPassword = original; original.replaceWith(original.cloneNode(true));
    });`), async page => {
    const candidate = await probe(page);
    const result = await fill(page, candidate);
    assert.equal(result.ok, false);
    assert.equal(result.usernameFilled, true);
    assert.equal(await page.locator('#login-password').inputValue(), '');
    assert.equal(await page.evaluate(() => window.detachedPassword.value), '');
  });

  await scenario('A focus handler replacing the selected password stops before entering credentials', 'https://fixture.example.com/focus-replacement', documentHtml(pair(), `
    document.getElementById('login-user').addEventListener('focus', () => {
      const original = document.getElementById('login-password');
      window.detachedPassword = original; original.replaceWith(original.cloneNode(true));
    });`), async page => {
    const candidate = await probe(page);
    assert.equal((await fill(page, candidate)).ok, false);
    assert.equal(await page.locator('#login-user').inputValue(), '');
    assert.equal(await page.locator('#login-password').inputValue(), '');
    assert.equal(await page.evaluate(() => window.detachedPassword.value), '');
  });

  await scenario('A focus-triggered route change stops filling', 'https://fixture.example.com/focus-navigation', documentHtml(pair(), `
    document.getElementById('login-user').addEventListener('focus', () => history.pushState({}, '', '/changed-during-focus'));`), async page => {
    const candidate = await probe(page);
    assert.equal((await fill(page, candidate)).ok, false);
    assert.equal(await page.locator('#login-user').inputValue(), '');
    assert.equal(await page.locator('#login-password').inputValue(), '');
  });

  for (const event of ['input', 'blur']) {
    await scenario(`A password ${event} handler changing the route cannot report success`, `https://fixture.example.com/${event}-navigation`, documentHtml(pair(), `
      document.getElementById('login-password').addEventListener('${event}', () => history.pushState({}, '', '/changed-after-password'));`), async page => {
      const candidate = await probe(page);
      assert.equal((await fill(page, candidate)).ok, false);
      assert.equal(new URL(page.url()).pathname, '/changed-after-password');
    });
  }

  console.log(`${passed} synthetic login-page DOM scenarios passed in real Chromium; no live website login or extension iframe permission is claimed.`);
} finally {
  await browser.close();
}
