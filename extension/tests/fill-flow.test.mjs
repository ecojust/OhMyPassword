import assert from 'node:assert/strict';
import test from 'node:test';
import { describeFrame, fillSelectedEntry, fillSuccessMessage } from '../src/lib/fill.js';
import { loginPageOperation } from '../src/lib/login-page.js';

const USERNAME = 'test-only-alice';
const PASSWORD = 'test-only-password';
const TOP_DOCUMENT = 'top-document';
const FRAME_DOCUMENT = 'login-frame-document';

function metadata(url) {
  const parsed = new URL(url);
  return { url: parsed.href, origin: parsed.origin, hostname: parsed.hostname };
}

// Model actual scripting responses, including immutable document IDs. The
// mock never invokes a DOM engine: these tests exercise only dispatch policy.
function fixture(options = {}) {
  const url = options.url ?? 'https://example.com/login';
  const target = { id: 42, ...metadata(url) };
  const frameUrl = options.frameUrl ?? `${target.origin}/embedded-login`;
  const frames = options.frames ?? [{ src: frameUrl, visible: true }];
  const stage = options.stage ?? 'both';
  const frame = options.frame === true;
  const state = { tab: { id: 42, url }, calls: [], injections: [], permissionChecks: [], permissionRequests: [] };
  const entry = { hostname: options.entryHostname ?? target.hostname, username: USERNAME, password: PASSWORD };
  async function finish(kind, value, detail = {}) {
    const event = { kind, ...detail };
    state.calls.push(event);
    await Promise.resolve();
    return options.after?.(event, value, state) ?? value;
  }
  const api = {
    tabs: { get: async id => {
      assert.equal(id, target.id);
      await finish('tab');
      return { ...state.tab };
    } },
    permissions: {
      contains: async query => {
        state.permissionChecks.push(query);
        return finish('permission', options.permission !== false, { query });
      },
      request: async query => { state.permissionRequests.push(query); throw new Error('dispatch must not request permissions'); },
    },
    scripting: { executeScript: async injection => {
      state.injections.push(injection);
      assert.equal(injection.world, 'ISOLATED');
      assert.equal(injection.target.tabId, target.id);
      if (injection.target.allFrames) {
        assert.equal(injection.func, describeFrame);
        assert.deepEqual(injection.args, []);
        return finish('describe', [
          { frameId: 0, documentId: TOP_DOCUMENT, result: metadata(url) },
          { frameId: 7, documentId: FRAME_DOCUMENT, result: metadata(frameUrl) },
        ], { injection });
      }
      assert.equal(injection.func, loginPageOperation);
      const request = injection.args[0];
      const isTop = injection.target.frameIds?.[0] === 0 || injection.target.documentIds?.[0] === TOP_DOCUMENT;
      const documentId = isTop ? TOP_DOCUMENT : FRAME_DOCUMENT;
      let result;
      if (request.mode === 'probe') {
        assert.equal(Object.hasOwn(request, 'username'), false);
        assert.equal(Object.hasOwn(request, 'password'), false);
        result = { ...metadata(isTop ? url : frameUrl), ok: !isTop || !frame, stage, iframeSources: isTop ? frames : [] };
      } else if (request.mode === 'frame-check') {
        assert.equal(Object.hasOwn(request, 'username'), false);
        assert.equal(Object.hasOwn(request, 'password'), false);
        result = { ok: true };
      } else {
        assert.equal(request.mode, 'fill');
        result = { ok: true, usernameFilled: Object.hasOwn(request, 'username'), passwordFilled: Object.hasOwn(request, 'password') };
      }
      return finish(request.mode === 'probe' ? `probe:${isTop ? 'top' : 'frame'}` : request.mode,
        [{ frameId: isTop ? 0 : 7, documentId, result }], { injection });
    } },
  };
  const run = signal => fillSelectedEntry(api, target, entry, { signal });
  return { api, target, entry, state, run };
}

function fills(state) {
  return state.injections.filter(call => call.args[0]?.mode === 'fill');
}

function assertSingleSecretTarget(state, documentId, stage) {
  const secretCalls = state.injections.filter(call => Object.hasOwn(call.args[0] ?? {}, 'username') || Object.hasOwn(call.args[0] ?? {}, 'password'));
  assert.equal(secretCalls.length, 1);
  const [call] = secretCalls;
  assert.deepEqual(call.target, { tabId: 42, documentIds: [documentId] });
  assert.equal(call.args[0].mode, 'fill');
  assert.equal(Object.hasOwn(call.args[0], 'username'), stage !== 'password');
  assert.equal(Object.hasOwn(call.args[0], 'password'), stage !== 'username');
  if (stage !== 'password') assert.equal(call.args[0].username, USERNAME);
  if (stage !== 'username') assert.equal(call.args[0].password, PASSWORD);
  assert.equal(state.permissionRequests.length, 0);
}

test('main-frame stages send only the required values to one probed document', async () => {
  for (const stage of ['both', 'username', 'password']) {
    const f = fixture({ url: 'https://accounts.google.com/signin', entryHostname: 'gmail.com', stage });
    const result = await f.run();
    assert.equal(result.usernameFilled, stage !== 'password');
    assert.equal(result.passwordFilled, stage !== 'username');
    assert.deepEqual(f.state.injections[0].target, { tabId: 42, frameIds: [0] });
    assertSingleSecretTarget(f.state, TOP_DOCUMENT, stage);
    assert.equal(f.state.permissionChecks.length, 0);
    assert.equal(f.state.injections.some(call => call.target.allFrames), false);
    assert.match(fillSuccessMessage(result), stage === 'username' ? /下一步/ : /登录/);
  }
});

test('same-origin login frames are identified without sending secrets to all frames', async () => {
  const f = fixture({ frame: true });
  await f.run();
  assertSingleSecretTarget(f.state, FRAME_DOCUMENT, 'both');
  assert.equal(f.state.permissionChecks.length, 0);
  const enumeration = f.state.injections.filter(call => call.target.allFrames);
  assert.equal(enumeration.length, 1);
  assert.equal(enumeration[0].func, describeFrame);
  assert.deepEqual(enumeration[0].args, []);
  const check = f.state.injections.find(call => call.args[0]?.mode === 'frame-check');
  assert.deepEqual(check.target.documentIds, [TOP_DOCUMENT]);
});

const trustedFrames = [
  ['https://mail.163.com/', 'https://dl.reg.163.com/webzj/v1.0.1/pub/index_dl2_new.html?product=mail163'],
  ['https://mail.126.com/', 'https://passport.126.com/webzj/v1.0.1/pub/index_dl2_new.html?product=mail126'],
  ['https://account.apple.com/', 'https://idmsa.apple.com/appleauth/auth/signin'],
];

test('trusted NetEase and Apple frames require only their exact optional origin', async () => {
  for (const [url, frameUrl] of trustedFrames) {
    const origins = [`${new URL(frameUrl).origin}/*`];
    const denied = fixture({ url, frameUrl, frame: true, permission: false });
    await assert.rejects(denied.run(), error => {
      assert.equal(error.code, 'LOGIN_FRAME_PERMISSION');
      assert.deepEqual(error.origins, origins);
      return true;
    });
    assert.deepEqual(denied.state.permissionChecks, [{ origins }]);
    assert.equal(denied.state.permissionRequests.length, 0);
    assert.equal(denied.state.injections.length, 1);
    assert.equal(fills(denied.state).length, 0);
    const granted = fixture({ url, frameUrl, frame: true });
    await granted.run();
    assert.deepEqual(granted.state.permissionChecks, [{ origins }]);
    assertSingleSecretTarget(granted.state, FRAME_DOCUMENT, 'both');
  }
});

test('untrusted or cross-provider frames never cause a permission request or receive credentials', async () => {
  for (const frameUrl of [
    'https://evil.example/login', 'https://dl.reg.163.com.evil.example/login',
    'http://dl.reg.163.com/login', 'https://dl.reg.163.com:8443/login',
    'https://idmsa.apple.com/login', 'https://passport.126.com/login',
    'https://user:pass@dl.reg.163.com/login', 'about:blank', 'javascript:alert(1)',
  ]) {
    const f = fixture({ url: 'https://mail.163.com/', frameUrl, frame: true });
    await assert.rejects(f.run());
    assert.equal(f.state.permissionChecks.length, 0, frameUrl);
    assert.equal(f.state.permissionRequests.length, 0, frameUrl);
    assert.equal(fills(f.state).length, 0, frameUrl);
  }
});

test('hidden and ambiguous direct frames are rejected before permission or enumeration', async () => {
  const frameUrl = trustedFrames[0][1];
  for (const frames of [
    [{ src: frameUrl, visible: false }],
    [{ src: frameUrl, visible: true }, { src: frameUrl, visible: true }],
    [{ src: frameUrl, visible: true }, { src: frameUrl, visible: false }],
    [{ src: frameUrl, visible: true }, { src: 'https://dl.reg.163.com/hidden', visible: false }],
  ]) {
    const f = fixture({ url: trustedFrames[0][0], frameUrl, frame: true, frames });
    await assert.rejects(f.run());
    assert.equal(f.state.permissionChecks.length, 0);
    assert.equal(f.state.injections.length, 1);
    assert.equal(fills(f.state).length, 0);
  }
});

test('frame redirects, duplicated metadata and missing document IDs never receive secrets', async () => {
  for (const change of [
    values => values.filter(item => item.frameId === 0),
    values => [...values, { ...values[1], frameId: 8, documentId: 'duplicate-document' }],
    values => [values[0], { ...values[1], result: metadata('https://example.com/redirected') }],
    values => [values[0], { ...values[1], documentId: undefined }],
    values => [values[0], { ...values[1], documentId: '' }],
    values => [values[0], { ...values[1], frameId: '7' }],
  ]) {
    const f = fixture({ frame: true, after: (event, value) => event.kind === 'describe' ? change(value) : undefined });
    await assert.rejects(f.run());
    assert.equal(fills(f.state).length, 0);
  }
  for (const kind of ['probe:top', 'probe:frame']) {
    const f = fixture({ frame: true, after: (event, value) => event.kind === kind ? [{ ...value[0], documentId: undefined }] : undefined });
    await assert.rejects(f.run());
    assert.equal(fills(f.state).length, 0);
  }
});

test('a removed document, failed visibility check or mismatched fill result fails closed', async () => {
  for (const [kind, response] of [
    ['probe:frame', []],
    ['frame-check', [{ frameId: 0, documentId: TOP_DOCUMENT, result: { ok: false } }]],
    ['frame-check', [{ frameId: 0, documentId: 'replacement', result: { ok: true } }]],
    ['fill', []],
    ['fill', [{ frameId: 7, documentId: 'replacement', result: { ok: true, passwordFilled: true } }]],
    ['fill', [{ frameId: 7, documentId: FRAME_DOCUMENT, result: { ok: true, usernameFilled: false, passwordFilled: false } }]],
  ]) {
    const f = fixture({ frame: true, after: event => event.kind === kind ? response : undefined });
    await assert.rejects(f.run());
    if (kind !== 'fill') assert.equal(fills(f.state).length, 0);
  }
});

test('metadata from a changed probed document is rejected before sending credentials', async () => {
  for (const kind of ['probe:top', 'probe:frame']) {
    for (const changed of [
      { url: 'https://example.com/changed' },
      { origin: 'https://evil.example' },
      { hostname: 'evil.example' },
    ]) {
      const f = fixture({ frame: true, after: (event, value) => event.kind === kind
        ? [{ ...value[0], result: { ...value[0].result, ...changed } }] : undefined });
      await assert.rejects(f.run());
      assert.equal(fills(f.state).length, 0);
    }
  }
});

test('matching account aliases do not authorize cross-provider credentials or tab navigation', async () => {
  for (const entryHostname of ['apple.com', 'icloud.com', 'openai.com', 'chatgpt.com', 'evil.example']) {
    const f = fixture({ url: 'https://accounts.google.com/signin', entryHostname });
    await assert.rejects(f.run(), /不属于/);
    assert.equal(f.state.calls.length, 0);
  }
  const sibling = fixture({ url: 'https://login.example.co.uk/sign-in', entryHostname: 'accounts.example.co.uk' });
  await sibling.run();
  assertSingleSecretTarget(sibling.state, TOP_DOCUMENT, 'both');
  for (const url of ['https://accounts.example.co.uk/sign-in', 'https://example.co.uk/sign-in',
    'https://login.example.co.uk/changed', 'https://login.example.co.uk/sign-in#changed',
    'http://login.example.co.uk/sign-in', 'https://login.example.co.uk:8443/sign-in']) {
    const f = fixture({ url: 'https://login.example.co.uk/sign-in', entryHostname: 'accounts.example.co.uk' });
    f.state.tab.url = url;
    await assert.rejects(f.run(), /跳转/);
    assert.equal(f.state.injections.length, 0);
  }
});

test('abort is checked before work and after every asynchronous boundary', async () => {
  const before = new AbortController();
  before.abort();
  const stopped = fixture();
  await assert.rejects(stopped.run(before.signal), /变化/);
  assert.equal(stopped.state.calls.length, 0);
  const options = { url: trustedFrames[0][0], frameUrl: trustedFrames[0][1], frame: true };
  const reference = fixture(options);
  await reference.run();
  for (let index = 0; index < reference.state.calls.length; index++) {
    const controller = new AbortController();
    let injectionsAtAbort;
    const f = fixture({ ...options, after: (_event, _value, state) => {
      if (state.calls.length === index + 1) {
        injectionsAtAbort = state.injections.length;
        controller.abort();
      }
    } });
    await assert.rejects(f.run(controller.signal), /变化/, `boundary ${index}: ${reference.state.calls[index].kind}`);
    assert.equal(f.state.injections.length, injectionsAtAbort, 'no injection may follow cancellation');
  }
});

test('navigation at each await prevents success, including same-origin path changes', async () => {
  const options = { url: trustedFrames[0][0], frameUrl: trustedFrames[0][1], frame: true };
  const reference = fixture(options);
  await reference.run();
  for (let index = 0; index < reference.state.calls.length; index++) {
    let fillsAtNavigation;
    const f = fixture({ ...options, after: (_event, _value, state) => {
      if (state.calls.length === index + 1) {
        fillsAtNavigation = fills(state).length;
        state.tab.url = `${options.url}changed`;
      }
    } });
    await assert.rejects(f.run(), /跳转|变化/, `boundary ${index}: ${reference.state.calls[index].kind}`);
    assert.equal(fills(f.state).length, fillsAtNavigation, 'no secret injection may follow an observed navigation');
  }
});

test('cancellation or navigation while checking permission never asks to grant access', async () => {
  for (const cancel of [true, false]) {
    const controller = new AbortController();
    const f = fixture({ url: trustedFrames[0][0], frameUrl: trustedFrames[0][1], frame: true, permission: false,
      after: (event, _value, state) => {
        if (event.kind === 'permission') {
          if (cancel) controller.abort();
          else state.tab.url = `${trustedFrames[0][0]}changed`;
        }
      } });
    await assert.rejects(f.run(controller.signal), error => {
      assert.notEqual(error.code, 'LOGIN_FRAME_PERMISSION');
      assert.match(error.message, /变化|跳转/);
      return true;
    });
    assert.equal(fills(f.state).length, 0);
  }
});
