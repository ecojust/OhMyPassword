import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { websiteFromUrl, checkedPort, checkedConnection, sameWebsite, extensionOrigin, validateEntries, canFillWebsite } from '../src/lib/model.js';
import { request, saveConnection } from '../src/lib/client.js';
import { fillSelectedEntry } from '../src/lib/fill.js';

test('website matching normalizes hostname and rejects non-web pages and URL credentials', () => {
  assert.deepEqual(websiteFromUrl('https://EXAMPLE.com:8443/login?q=1'), { hostname: 'example.com', origin: 'https://example.com:8443' });
  assert.equal(websiteFromUrl('https://sub.example.com').hostname, 'sub.example.com');
  assert.equal(websiteFromUrl('https://example.com.').hostname, 'example.com');
  for (const url of ['file:///secret', 'chrome://settings', 'javascript:alert(1)', 'https://user:pass@example.com', 'not a url']) assert.equal(websiteFromUrl(url), null);
});

test('only numeric unprivileged local ports and nonempty single-line tokens are accepted', () => {
  assert.equal(checkedPort('17841'), 17841);
  for (const port of ['http://evil.test', '17841/path', '1.5', 0, 80, 65536, NaN]) assert.throws(() => checkedPort(port));
  assert.throws(() => checkedConnection({ token: 'foo\r\nbar' }));
  assert.throws(() => checkedConnection({ token: '' }));
});

test('extension origin uses actual runtime URL including Firefox UUID', () => {
  assert.equal(extensionOrigin({ runtime: { getURL: () => 'chrome-extension://abcd/' } }), 'chrome-extension://abcd');
  assert.equal(extensionOrigin({ runtime: { getURL: () => 'moz-extension://browser-uuid/' } }), 'moz-extension://browser-uuid');
  assert.throws(() => extensionOrigin({ runtime: { getURL: () => 'https://evil.test/' } }));
});

test('request fixes loopback destination, omits cookies, disallows redirects, never fabricates Origin', async () => {
  let captured;
  const result = await request({ token: 'test-only-grant', port: 17841 }, '/v1/browser/connect', { method: 'POST', body: {} }, async (url, options) => {
    captured = { url, options };
    return { ok: true, text: async () => JSON.stringify({ connected: true, protocol: 1 }) };
  });
  assert.equal(result.connected, true);
  assert.equal(captured.url, 'http://127.0.0.1:17841/v1/browser/connect');
  assert.equal(captured.options.redirect, 'error');
  assert.equal(captured.options.mode, 'cors');
  assert.equal(captured.options.credentials, 'omit');
  assert.equal(captured.options.headers.Authorization, 'Bearer test-only-grant');
  assert.equal(captured.options.headers.Origin, undefined);
  await assert.rejects(request({ token: 'test-only-grant', port: 17841 }, '//evil.test/v1/credentials'), /不支持/);
});

test('locked, revoked and oversized client responses fail clearly', async () => {
  const conn = { token: 'test-only-grant', port: 17841 };
  await assert.rejects(request(conn, '/v1/credentials', {}, async () => ({ ok: false, status: 423, text: async () => '{}' })), /已锁定/);
  await assert.rejects(request(conn, '/v1/credentials', {}, async () => ({ ok: false, status: 401, text: async () => '{}' })), /撤销/);
  await assert.rejects(request(conn, '/v1/credentials', {}, async () => ({ ok: true, text: async () => 'x'.repeat(1048577) })), /过大/);
});

test('streaming response cap cancels an oversized stream without reading an unbounded body', async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(700000)); },
    cancel() { cancelled = true; },
  }));
  await assert.rejects(request({ token: 'test-only-grant', port: 17841 }, '/v1/credentials', {}, async () => response), /过大/);
  assert.equal(cancelled, true);
});

test('a locked-vault preflight failure uses only public status to explain the error', async () => {
  const calls = [];
  await assert.rejects(request({ token: 'test-only-grant', port: 17841 }, '/v1/credentials', {}, async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/v1/status')) return new Response(JSON.stringify({ protocol: 1, locked: true }));
    throw new TypeError('Failed to fetch');
  }), /已锁定/);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].options.headers, undefined);
  assert.equal(calls[1].url, 'http://127.0.0.1:17841/v1/status');
});

test('HTTP cannot receive passwords saved for its HTTPS hostname', async () => {
  assert.equal(canFillWebsite({ hostname: 'example.com', origin: 'http://example.com' }), false);
  assert.equal(canFillWebsite({ hostname: 'example.com', origin: 'https://example.com' }), true);
  assert.equal(canFillWebsite({ hostname: '127.0.0.1', origin: 'http://127.0.0.1:17841' }), true);
  let called = false;
  await assert.rejects(fillSelectedEntry({ tabs: { get: async () => { called = true; } } }, { id: 1, hostname: 'example.com', origin: 'http://example.com' }, { hostname: 'example.com', username: 'alice', password: 'test-only-secret' }), /HTTPS/);
  assert.equal(called, false);
});

test('entry validation rejects deleted and unrelated hosts including subdomains', () => {
  const sample = { id: 'id', hostname: 'example.com', title: 'Account', username: 'alice', password: 'test-only-password' };
  const result = validateEntries({ entries: [sample, { ...sample, hostname: 'sub.example.com' }, { ...sample, deleted: true }, { ...sample, password: null }] }, 'example.com');
  assert.deepEqual(result, [sample]);
});

test('connection storage contains only grant and port, never an accidentally supplied password', async () => {
  let stored;
  let access;
  await saveConnection({ storage: { local: { setAccessLevel: async value => { access = value; }, set: async value => { stored = value; } } } }, { token: 'test-only-grant', port: 17841, password: 'must-not-persist' });
  assert.deepEqual(stored, { connection: { token: 'test-only-grant', port: 17841 } });
  assert.deepEqual(access, { accessLevel: 'TRUSTED_CONTEXTS' });
});

test('fill rechecks tab ID, origin and hostname and targets only main frame', async () => {
  const target = { id: 42, origin: 'https://example.com', hostname: 'example.com' };
  let injection;
  const api = { tabs: { get: async () => ({ id: 42, url: 'https://example.com/login' }) }, scripting: { executeScript: async options => { injection = options; return [{ frameId: 0, result: { ok: true } }]; } } };
  const entry = { hostname: 'example.com', username: 'alice', password: 'test-only-password' };
  await fillSelectedEntry(api, target, entry);
  assert.deepEqual(injection.target, { tabId: 42, frameIds: [0] });
  assert.equal(injection.world, 'ISOLATED');
  assert.equal(sameWebsite(target, { id: 99, url: 'https://example.com' }), false);
  for (const url of ['https://evil.test', 'https://sub.example.com', 'http://example.com', 'https://example.com:8443']) {
    api.tabs.get = async () => ({ id: 42, url }); injection = undefined;
    await assert.rejects(fillSelectedEntry(api, target, entry), /跳转/);
    assert.equal(injection, undefined);
  }
});

test('manifest grants activeTab and loopback only, no all-sites access or content scripts', async () => {
  const manifest = JSON.parse(await readFile(new URL('../src/manifest.json', import.meta.url), 'utf8'));
  assert.deepEqual(manifest.permissions, ['activeTab', 'scripting', 'storage']);
  assert.deepEqual(manifest.host_permissions, ['http://127.0.0.1/*']);
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.manifest_version, 3);
});
