import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createHash, createPublicKey } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { websiteFromUrl, checkedPort, checkedConnection, sameWebsite, validateEntries, canFillWebsite, credentialForSave } from '../src/lib/model.js';
import { readConnection, request, saveConnection, searchCredentials } from '../src/lib/client.js';
import { fillInPage, fillSelectedEntry } from '../src/lib/fill.js';

test('website matching normalizes hostname and rejects non-web pages and URL credentials', () => {
  assert.deepEqual(websiteFromUrl('https://EXAMPLE.com:8443/login?q=1'), { hostname: 'example.com', origin: 'https://example.com:8443' });
  assert.equal(websiteFromUrl('https://sub.example.com').hostname, 'sub.example.com');
  assert.equal(websiteFromUrl('https://example.com.').hostname, 'example.com');
  for (const url of ['file:///secret', 'chrome://settings', 'javascript:alert(1)', 'https://user:pass@example.com', 'not a url']) assert.equal(websiteFromUrl(url), null);
});

test('only numeric unprivileged local ports are accepted, with a setup-free default', () => {
  assert.equal(checkedPort('17841'), 17841);
  for (const port of ['http://evil.test', '17841/path', '1.5', 0, 80, 65536, NaN]) assert.throws(() => checkedPort(port));
  assert.deepEqual(checkedConnection(), { port: 17841 });
  assert.deepEqual(checkedConnection({ token: 'discard-legacy-token', port: 23456 }), { port: 23456 });
});

test('request fixes loopback destination, omits cookies, disallows redirects, never fabricates Origin', async () => {
  let captured;
  const result = await request(undefined, '/v1/browser/connect', { method: 'POST', body: {} }, async (url, options) => {
    captured = { url, options };
    return { ok: true, text: async () => JSON.stringify({ connected: true, protocol: 2 }) };
  });
  assert.equal(result.connected, true);
  assert.equal(captured.url, 'http://127.0.0.1:17841/v1/browser/connect');
  assert.equal(captured.options.redirect, 'error');
  assert.equal(captured.options.mode, 'cors');
  assert.equal(captured.options.credentials, 'omit');
  assert.equal(captured.options.headers.Authorization, undefined);
  assert.equal(captured.options.headers.Origin, undefined);
  await assert.rejects(request({ port: 17841 }, '//evil.test/v1/credentials'), /不支持/);
});

test('locked, outdated and oversized client responses fail clearly', async () => {
  const conn = { port: 17841 };
  await assert.rejects(searchCredentials(conn, 'example.com', {}, async () => ({ ok: false, status: 423, text: async () => '{}' })), /已锁定/);
  await assert.rejects(searchCredentials(conn, 'example.com', {}, async () => ({ ok: false, status: 401, text: async () => '{}' })), /更新/);
  await assert.rejects(searchCredentials(conn, 'example.com', {}, async () => ({ ok: true, text: async () => 'x'.repeat(1048577) })), /过大/);
});

test('credential search sends hostname only in JSON POST body without authentication headers', async () => {
  let captured;
  await searchCredentials({ port: 17841 }, 'login.example.com', {}, async (url, options) => {
    captured = { url, options };
    return new Response('{"entries":[]}');
  });
  assert.equal(captured.url, 'http://127.0.0.1:17841/v1/credentials/search');
  assert.equal(captured.options.method, 'POST');
  assert.deepEqual(JSON.parse(captured.options.body), { hostname: 'login.example.com' });
  assert.equal(captured.options.headers['Content-Type'], 'application/json');
  assert.equal(captured.options.headers.Authorization, undefined);
  assert.equal(captured.options.headers.Origin, undefined);
});

test('streaming response cap cancels an oversized stream without reading an unbounded body', async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(700000)); },
    cancel() { cancelled = true; },
  }));
  await assert.rejects(searchCredentials({ port: 17841 }, 'example.com', {}, async () => response), /过大/);
  assert.equal(cancelled, true);
});

test('a locked-vault preflight failure uses only public status to explain the error', async () => {
  const calls = [];
  await assert.rejects(searchCredentials({ port: 17841 }, 'example.com', {}, async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/v1/status')) return new Response(JSON.stringify({ protocol: 2, locked: true }));
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

test('entry validation matches the registrable domain but rejects deleted, invalid and unrelated entries', () => {
  const sample = { id: 'id', hostname: 'example.com', title: 'Account', username: 'alice', password: 'test-only-password' };
  const sibling = { ...sample, id: 'sibling', hostname: 'accounts.example.com' };
  const result = validateEntries({ entries: [sample, sibling, { ...sample, hostname: 'example.net' }, { ...sample, hostname: 'example.com.evil.net' }, { ...sample, deleted: true }, { ...sample, password: null }] }, 'login.example.com');
  assert.deepEqual(result, [sample, sibling]);
});

test('credential matching respects multi-label suffixes, private tenants and exact IP or local hosts', () => {
  const sample = { id: 'id', title: 'Account', username: 'alice', password: 'test-only-password' };
  for (const [target, allowed, blocked] of [
    ['login.example.co.uk', ['example.co.uk', 'accounts.example.co.uk'], ['other.co.uk', 'co.uk', 'example.co.uk.evil.com']],
    ['login.alice.github.io', ['alice.github.io', 'accounts.alice.github.io'], ['bob.github.io', 'login.bob.github.io', 'github.io']],
    ['login.alice.appspot.com', ['alice.appspot.com'], ['bob.appspot.com', 'appspot.com']],
    ['192.168.1.5', ['192.168.1.5'], ['192.168.1.6', 'sub.192.168.1.5']],
    ['[::1]', ['[::1]'], ['[::2]', 'localhost']],
    ['localhost', ['localhost'], ['sub.localhost', '127.0.0.1']],
    ['vault.local', ['vault.local'], ['sub.vault.local', 'other.local']],
  ]) {
    const valid = allowed.map((hostname, index) => ({ ...sample, id: `allowed-${index}`, hostname }));
    const invalid = blocked.map((hostname, index) => ({ ...sample, id: `blocked-${index}`, hostname }));
    assert.deepEqual(validateEntries({ entries: [...valid, ...invalid] }, target), valid, target);
  }
});

test('saving a sibling-subdomain account preserves its original hostname and ID while new accounts use the current host', () => {
  const current = 'login.example.co.uk';
  const fields = { title: ' New title ', username: 'alice', password: 'test-only-new-password', notes: 'Updated notes', id: 'untrusted-id', hostname: 'untrusted.example.net' };
  const entry = { id: 'existing-account-id', hostname: 'accounts.example.co.uk', title: 'Old title', username: 'old-name', password: 'test-only-old-password' };
  assert.deepEqual(credentialForSave(current, entry, fields), {
    id: entry.id, hostname: entry.hostname, title: 'New title', username: fields.username, password: fields.password, notes: fields.notes,
  });
  assert.equal(entry.hostname, 'accounts.example.co.uk');
  assert.deepEqual(credentialForSave(current, null, fields), {
    id: null, hostname: current, title: 'New title', username: fields.username, password: fields.password, notes: fields.notes,
  });
  for (const hostname of ['other.co.uk', 'example.co.uk.evil.com']) {
    assert.throws(() => credentialForSave(current, { ...entry, hostname }, fields), /不属于/);
  }
  assert.throws(() => credentialForSave('alice.github.io', { ...entry, hostname: 'bob.github.io' }, fields), /不属于/);
  assert.throws(() => credentialForSave('192.168.1.5', { ...entry, hostname: '192.168.1.6' }, fields), /不属于/);
  assert.throws(() => credentialForSave(current, { ...entry, id: null }, fields), /不属于/);
  assert.throws(() => credentialForSave('', null, fields), /无效/);
});

test('connection storage contains only port, never an old grant or an accidentally supplied password', async () => {
  let stored;
  let access;
  let removed;
  await saveConnection({ storage: { local: { setAccessLevel: async value => { access = value; }, set: async value => { stored = value; }, remove: async value => { removed = value; } } } }, { token: 'legacy-test-only-grant', port: 17841, password: 'must-not-persist' });
  assert.deepEqual(stored, { connection: { port: 17841 } });
  assert.deepEqual(access, { accessLevel: 'TRUSTED_CONTEXTS' });
  assert.ok(removed.includes('token'));
  assert.ok(removed.includes('origin'));
});

function settingsApi(initial = {}) {
  const data = structuredClone(initial);
  return { data, storage: { local: {
    get: async () => structuredClone(data),
    set: async value => Object.assign(data, value),
    remove: async keys => keys.forEach(key => delete data[key]),
    setAccessLevel: async () => {},
  } } };
}

test('first use defaults to port 17841 without any saved connection setup', async () => {
  const api = settingsApi();
  assert.deepEqual(await readConnection(api), { port: 17841 });
  assert.deepEqual(api.data, { connection: { port: 17841 } });
});

test('migration removes old tokens and origin metadata while preserving a valid custom port', async () => {
  const api = settingsApi({ connection: { port: 23456, token: 'legacy-secret', origin: 'old-extension' }, token: 'legacy-secret', origin: 'old-extension', clientId: 'old-id', client_id: 'old-id', grant: 'legacy-secret' });
  assert.deepEqual(await readConnection(api), { port: 23456 });
  assert.deepEqual(api.data, { connection: { port: 23456 } });
  assert.equal(JSON.stringify(api.data).includes('legacy-secret'), false);
});

test('invalid old port settings reset to the safe local default and still remove tokens', async () => {
  const api = settingsApi({ connection: { port: 'https://outside.example', token: 'legacy-secret' } });
  assert.deepEqual(await readConnection(api), { port: 17841 });
  assert.deepEqual(api.data, { connection: { port: 17841 } });
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

test('a matching sibling-subdomain credential fills only the unchanged current tab', async () => {
  const target = { id: 42, origin: 'https://login.example.co.uk', hostname: 'login.example.co.uk' };
  const entry = { hostname: 'accounts.example.co.uk', username: 'alice', password: 'test-only-password' };
  let injection;
  const api = { tabs: { get: async () => ({ id: 42, url: 'https://login.example.co.uk/sign-in' }) }, scripting: { executeScript: async options => { injection = options; return [{ frameId: 0, result: { ok: true } }]; } } };
  await fillSelectedEntry(api, target, entry);
  assert.deepEqual(injection.args, [target.origin, target.hostname, entry.username, entry.password]);
  for (const hostname of ['other.co.uk', 'example.co.uk.evil.com']) {
    injection = undefined;
    await assert.rejects(fillSelectedEntry(api, target, { ...entry, hostname }), /不属于/);
    assert.equal(injection, undefined);
  }
  for (const url of ['https://accounts.example.co.uk', 'https://example.co.uk', 'http://login.example.co.uk', 'https://login.example.co.uk:8443']) {
    injection = undefined;
    api.tabs.get = async () => ({ id: 42, url });
    await assert.rejects(fillSelectedEntry(api, target, entry), /跳转/);
    assert.equal(injection, undefined);
  }
});

test('the injected fill function rejects same-domain navigation after the tab recheck before touching the page', () => {
  const target = { origin: 'https://login.example.com', hostname: 'login.example.com' };
  for (const url of ['https://accounts.example.com', 'https://example.com', 'https://login.example.com:8443', 'http://login.example.com']) {
    const location = new URL(url);
    const result = runInNewContext(`(${fillInPage.toString()})(...args)`, {
      location,
      args: [target.origin, target.hostname, 'alice', 'test-only-password'],
      // Any DOM access before rejecting a navigation would fail the test.
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /跳转/);
  }
});

test('manifest grants activeTab and loopback only, no all-sites access or content scripts', async () => {
  const manifest = JSON.parse(await readFile(new URL('../src/manifest.json', import.meta.url), 'utf8'));
  assert.deepEqual(manifest.permissions, ['activeTab', 'scripting', 'storage']);
  assert.deepEqual(manifest.host_permissions, ['http://127.0.0.1/*']);
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.manifest_version, 3);
});

test('public manifest key produces the stable Chrome identity used by the client', async () => {
  const manifest = JSON.parse(await readFile(new URL('../src/manifest.json', import.meta.url), 'utf8'));
  const der = Buffer.from(manifest.key, 'base64');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  assert.equal(key.asymmetricKeyType, 'rsa');
  assert.equal(key.asymmetricKeyDetails.modulusLength, 2048);
  const id = createHash('sha256').update(der).digest('hex').slice(0, 32).replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c, 16)));
  assert.equal(id, 'abnlejagphkafpbidkngaemnlfgbpdmb');
  const serviceOrigin = (await readFile(new URL('../../desktop/service/src/browser-origin.txt', import.meta.url), 'utf8')).trim();
  assert.equal(serviceOrigin, `chrome-extension://${id}`);
});
