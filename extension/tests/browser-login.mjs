import assert from 'node:assert/strict';

// Real Chromium extension checks. Every fixture is intercepted locally; no
// permission is added and no credential is sent to a live login website.
export async function runLoginExtensionChecks({ context, page, extensionOrigin, port }) {
  assert.ok(page.url().startsWith(`${extensionOrigin}/`));
  const base = `http://127.0.0.1:${port}`;
  const foreign = `http://localhost:${port}`;
  const frameUrl = `${base}/omp-frame-login`;
  const username = 'login-fixture-alice';
  const password = 'login-fixture-secret';
  const form = '<form id="login"><label>Username<input id="user" autocomplete="username"></label><label>Password<input id="secret" type="password" autocomplete="current-password"></label><button type="submit">Sign in</button></form>';
  const passwordForm = '<form id="login"><label>Password<input id="secret" type="password" autocomplete="current-password"></label><button type="submit">Sign in</button></form>';
  const watch = '<script>window.submitted=0;window.inputEvents=0;window.changeEvents=0;document.addEventListener("submit",e=>{e.preventDefault();window.submitted++});document.addEventListener("input",()=>window.inputEvents++);document.addEventListener("change",()=>window.changeEvents++);</script>';
  const markup = body => `<!doctype html><html><head><meta charset="utf-8"></head><body>${body}${watch}</body></html>`;
  const iframe = (src = frameUrl, attributes = '') => `<iframe id="login-frame" src="${src}" width="500" height="240" ${attributes}></iframe>`;
  const fixtures = new Map([
    ['/omp-both', `<h1>Sign in</h1>${form}`],
    ['/omp-password', `<h1>Sign in</h1>${passwordForm}`],
    ['/omp-otp', '<h1>Enter verification code</h1><form><input id="otp" autocomplete="one-time-code"><button type="submit">Verify</button></form>'],
    ['/omp-new-password', '<h1>Create account</h1><form id="register"><input id="user" autocomplete="username"><input id="secret" type="password" autocomplete="new-password"><input id="confirm" type="password" autocomplete="new-password"><button type="submit">Create account</button></form>'],
    ['/omp-iframe', `<h1>Sign in</h1>${iframe()}`],
    ['/omp-hidden-frame', `<h1>Sign in</h1><section hidden>${iframe()}</section>`],
    ['/omp-duplicate-frame', `<h1>Sign in</h1>${iframe()}${iframe()}`],
    ['/omp-hidden-duplicate', `<h1>Sign in</h1>${iframe()}<section hidden>${iframe()}</section>`],
    ['/omp-cross-origin', `<h1>Sign in</h1>${iframe(`${foreign}/omp-frame-login`)}`],
    ['/omp-frame-login', form],
    ['/omp-frame-alternate', form],
  ]);
  const matchesFixture = url => [base, foreign].includes(url.origin) && url.pathname.startsWith('/omp-');
  const serveFixture = route => {
    const url = new URL(route.request().url());
    const body = fixtures.get(url.pathname);
    return route.fulfill({ status: body === undefined ? 404 : 200, contentType: 'text/html; charset=utf-8', body: markup(body ?? 'Missing fixture') });
  };
  await context.route(matchesFixture, serveFixture);
  const site = await context.newPage();

  async function open(path) {
    await site.goto(`${base}${path}`);
    await site.waitForLoadState('load');
    return site.url();
  }

  async function fill() {
    return page.evaluate(async ({ url, username, password }) => {
      const { fillSelectedEntry } = await import('./lib/fill.js');
      const tabs = await chrome.tabs.query({});
      const tab = tabs.find(item => item.url === url);
      if (!tab) throw new Error('Fixture tab was not found');
      const parsed = new URL(url);
      const target = { id: tab.id, url, origin: parsed.origin, hostname: parsed.hostname };
      const calls = [];
      // Record destinations and presence of fields, never the credential values.
      // The actual browser scripting API still performs every injection.
      const api = {
        tabs: { get: id => chrome.tabs.get(id) },
        permissions: { contains: query => chrome.permissions.contains(query) },
        scripting: { executeScript: async options => {
          const request = options.args?.[0];
          const call = {
            target: options.target,
            mode: request?.mode ?? 'describe',
            usernameSent: Object.hasOwn(request ?? {}, 'username'),
            passwordSent: Object.hasOwn(request ?? {}, 'password'),
          };
          calls.push(call);
          const results = await chrome.scripting.executeScript(options);
          call.documents = results.map(item => ({ frameId: item.frameId, documentId: item.documentId }));
          return results;
        } },
      };
      try {
        const result = await fillSelectedEntry(api, target, { hostname: target.hostname, username, password });
        return { ok: true, result, calls };
      } catch (error) { return { ok: false, error: error.message, calls }; }
    }, { url: site.url(), username, password });
  }

  function assertSecretTarget(result, stage, child = false) {
    assert.equal(result.ok, true, result.error);
    const writes = result.calls.filter(call => call.usernameSent || call.passwordSent);
    assert.equal(writes.length, 1, 'Exactly one immutable document may receive credentials.');
    const write = writes[0];
    assert.equal(write.mode, 'fill');
    assert.equal(write.target.allFrames, undefined);
    assert.equal(write.target.frameIds, undefined);
    assert.equal(write.target.documentIds?.length, 1);
    assert.equal(typeof write.target.documentIds[0], 'string');
    assert.equal(write.usernameSent, stage === 'both');
    assert.equal(write.passwordSent, true);
    const probe = result.calls.find(call => call.mode === 'probe' && call.documents?.some(item => item.documentId === write.target.documentIds[0]));
    assert.ok(probe, 'The secret destination must be a previously probed document.');
    const destination = write.documents.find(item => item.documentId === write.target.documentIds[0]);
    assert.ok(destination);
    assert.equal(destination.frameId === 0, !child);
    assert.equal(result.result.usernameFilled, stage === 'both');
    assert.equal(result.result.passwordFilled, true);
  }

  async function probeTop() {
    return page.evaluate(async url => {
      const { loginPageOperation } = await import('./lib/login-page.js');
      const { getLoginRules } = await import('./lib/sites.js');
      const tab = (await chrome.tabs.query({})).find(item => item.url === url);
      const parsed = new URL(url);
      const request = { mode: 'probe', nonce: crypto.randomUUID(), expectedUrl: url, expectedOrigin: parsed.origin,
        expectedHostname: parsed.hostname, rules: getLoginRules(parsed.hostname, { url, topHostname: parsed.hostname }) };
      const results = await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: loginPageOperation, args: [request], world: 'ISOLATED' });
      const result = results.find(item => item.frameId === 0);
      return { tabId: tab.id, documentId: result.documentId, request, result: result.result };
    }, site.url());
  }

  async function checkFrame(probe) {
    return page.evaluate(async ({ probe, frameUrl }) => {
      const { loginPageOperation } = await import('./lib/login-page.js');
      const results = await chrome.scripting.executeScript({ target: { tabId: probe.tabId, documentIds: [probe.documentId] },
        func: loginPageOperation, args: [{ ...probe.request, mode: 'frame-check', frameUrl }], world: 'ISOLATED' });
      return results[0].result;
    }, { probe, frameUrl });
  }

  try {
    for (const [path, stage] of [['/omp-both', 'both'], ['/omp-password', 'password']]) {
      await open(path);
      const result = await fill();
      assertSecretTarget(result, stage);
      assert.equal(await site.locator('#secret').inputValue(), password);
      if (stage === 'both') assert.equal(await site.locator('#user').inputValue(), username);
      assert.deepEqual(await site.evaluate(() => [window.submitted, window.inputEvents, window.changeEvents]), [0, stage === 'both' ? 2 : 1, stage === 'both' ? 2 : 1]);
    }
    console.log('PASS: real extension fills combined and password-only steps into one documentId, emits events and never submits.');

    for (const path of ['/omp-otp', '/omp-new-password']) {
      await open(path);
      const result = await fill();
      assert.equal(result.ok, false, path);
      assert.equal(result.calls.some(call => call.usernameSent || call.passwordSent), false);
      assert.deepEqual(await site.locator('input').evaluateAll(inputs => inputs.map(input => input.value)), path === '/omp-otp' ? [''] : ['', '', '']);
      assert.equal(await site.evaluate(() => window.submitted), 0);
    }
    console.log('PASS: real OTP and registration pages receive no credential-bearing scripting request.');

    await open('/omp-iframe');
    const framed = await fill();
    assertSecretTarget(framed, 'both', true);
    assert.equal(framed.calls.filter(call => call.target.allFrames).length, 1);
    assert.equal(framed.calls.find(call => call.target.allFrames).usernameSent, false);
    assert.equal(framed.calls.find(call => call.target.allFrames).passwordSent, false);
    assert.equal(await site.frameLocator('iframe').locator('#user').inputValue(), username);
    assert.equal(await site.frameLocator('iframe').locator('#secret').inputValue(), password);
    assert.equal(await site.frames().find(frame => frame.url() === frameUrl).evaluate(() => window.submitted), 0);
    console.log('PASS: one visible same-origin login iframe is filled by its probed immutable documentId.');

    for (const path of ['/omp-hidden-frame', '/omp-duplicate-frame', '/omp-hidden-duplicate', '/omp-cross-origin']) {
      await open(path);
      const result = await fill();
      assert.equal(result.ok, false, path);
      assert.equal(result.calls.some(call => call.usernameSent || call.passwordSent), false, path);
      assert.equal(result.calls.some(call => call.target.allFrames), false, path);
      const frames = site.frames().filter(frame => frame !== site.mainFrame());
      assert.ok(frames.length);
      for (const frame of frames) {
        assert.equal(await frame.locator('#user').inputValue(), '', path);
        assert.equal(await frame.locator('#secret').inputValue(), '', path);
      }
    }
    assert.equal(await page.evaluate(() => chrome.permissions.contains({ origins: ['http://localhost/*'] })), false);
    console.log('PASS: hidden, duplicate and untrusted cross-origin iframes stay empty without broad permissions.');

    for (const mutation of ['src', 'replacement', 'hidden']) {
      await open('/omp-iframe');
      const probe = await probeTop();
      await site.evaluate(({ mutation, alternate }) => {
        const frame = document.querySelector('iframe');
        if (mutation === 'src') frame.src = alternate;
        else if (mutation === 'replacement') frame.replaceWith(frame.cloneNode(true));
        else frame.parentElement.style.visibility = 'hidden';
      }, { mutation, alternate: `${base}/omp-frame-alternate` });
      const result = await checkFrame(probe);
      assert.equal(result.ok, false, mutation);
    }
    console.log('PASS: real cached iframe checks reject changed src, replaced elements and hidden ancestors.');

    await open('/omp-both');
    const staleNodes = await probeTop();
    await site.locator('#secret').evaluate(input => input.replaceWith(input.cloneNode(true)));
    const staleResult = await page.evaluate(async ({ probe, username, password }) => {
      const { loginPageOperation } = await import('./lib/login-page.js');
      const result = await chrome.scripting.executeScript({ target: { tabId: probe.tabId, documentIds: [probe.documentId] }, func: loginPageOperation,
        args: [{ ...probe.request, mode: 'fill', username, password }], world: 'ISOLATED' });
      return result[0].result;
    }, { probe: staleNodes, username, password });
    assert.equal(staleResult.ok, false);
    assert.equal(await site.locator('#user').inputValue(), '');
    assert.equal(await site.locator('#secret').inputValue(), '');

    await open('/omp-iframe');
    const oldDocument = await page.evaluate(async ({ url, frameUrl }) => {
      const { describeFrame } = await import('./lib/fill.js');
      const { loginPageOperation } = await import('./lib/login-page.js');
      const { getLoginRules } = await import('./lib/sites.js');
      const tab = (await chrome.tabs.query({})).find(item => item.url === url);
      const described = await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func: describeFrame, args: [], world: 'ISOLATED' });
      const frame = described.find(item => item.frameId !== 0 && item.result.url === frameUrl);
      const parsed = new URL(frameUrl);
      const request = { mode: 'probe', nonce: crypto.randomUUID(), expectedOrigin: parsed.origin, expectedHostname: parsed.hostname,
        expectedUrl: frameUrl, rules: getLoginRules(parsed.hostname, { url: frameUrl, topHostname: parsed.hostname }) };
      const results = await chrome.scripting.executeScript({ target: { tabId: tab.id, documentIds: [frame.documentId] }, func: loginPageOperation, args: [request], world: 'ISOLATED' });
      if (!results[0].result.ok) throw new Error('Expected frame probe to succeed');
      return { tabId: tab.id, documentId: frame.documentId, request };
    }, { url: site.url(), frameUrl });
    const replacementUrl = `${frameUrl}?new-document=1`;
    await site.frames().find(frame => frame.url() === frameUrl).goto(replacementUrl);
    const removed = await page.evaluate(async ({ probe, username, password }) => {
      const { loginPageOperation } = await import('./lib/login-page.js');
      try {
        const result = await chrome.scripting.executeScript({ target: { tabId: probe.tabId, documentIds: [probe.documentId] }, func: loginPageOperation,
          args: [{ ...probe.request, mode: 'fill', username, password }], world: 'ISOLATED' });
        return { rejected: !result.some(item => item.result?.ok) };
      } catch { return { rejected: true }; }
    }, { probe: oldDocument, username, password });
    assert.equal(removed.rejected, true, 'A replaced frame document must not receive an injection addressed to its old documentId.');
    const replacement = site.frames().find(frame => frame.url() === replacementUrl);
    assert.equal(await replacement.locator('#user').inputValue(), '');
    assert.equal(await replacement.locator('#secret').inputValue(), '');
    console.log('PASS: real DOM replacement and expired frame documentIds cannot redirect a cached fill into new fields.');
  } finally {
    await site.close();
    await context.unroute(matchesFixture, serveFixture);
  }
}
