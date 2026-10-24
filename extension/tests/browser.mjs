import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm, mkdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const extension = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist');
const manifest = JSON.parse(await readFile(path.join(extension, 'manifest.json'), 'utf8'));
const extensionId = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex').slice(0, 32).replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c, 16)));
const expectedOrigin = `chrome-extension://${extensionId}`;
assert.equal(expectedOrigin, 'chrome-extension://abnlejagphkafpbidkngaemnlfgbpdmb');
const profile = await mkdtemp(path.join(tmpdir(), 'omp-extension-test-'));
let extensionOrigin = '';
const calls = [];
let entries = [{ id: 'account-1', hostname: '127.0.0.1', title: '<b>Literal account title</b>', username: 'test-alice', password: 'test-only-secret', notes: '', deleted: false }];
let locked = false;
const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (!url.pathname.startsWith('/v1/')) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (url.pathname === '/frame') {
      res.end('<form><input autocomplete="username"><input type="password" autocomplete="current-password"></form>'); return;
    }
    if (url.pathname === '/ambiguous') {
      res.end('<form><input type="password"><input type="password"></form>'); return;
    }
    res.end(`<!doctype html><html><body><h1>Test login</h1><form id="login"><input id="user" autocomplete="username"><input id="secret" type="password" autocomplete="current-password"><button type="submit">Login</button></form><iframe src="http://localhost:${server.address().port}/frame"></iframe><script>window.submitted=0;window.changes=0;document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();window.submitted++});document.addEventListener('input',()=>window.changes++);</script></body></html>`); return;
  }
  // Capture request metadata only. Password request bodies are never logged.
  calls.push({ path: url.pathname, query: url.search, method: req.method, origin: req.headers.origin ?? '(absent)' });
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json');
  if (req.headers.origin !== extensionOrigin || !extensionOrigin) {
    res.writeHead(403); res.end(JSON.stringify({ error: 'forbidden_origin' })); return;
  }
  res.setHeader('Access-Control-Allow-Origin', extensionOrigin);
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    res.writeHead(204); res.end(); return;
  }
  if (req.headers.authorization !== undefined) { res.writeHead(400); res.end(JSON.stringify({ message: 'Unexpected authentication header' })); return; }
  if (locked) { res.writeHead(423); res.end('{}'); return; }
  if (url.pathname === '/v1/browser/connect') { res.end(JSON.stringify({ connected: true, protocol: 2 })); return; }
  if (url.pathname === '/v1/credentials/search' && req.method === 'POST') {
    let body = ''; for await (const chunk of req) body += chunk;
    const search = JSON.parse(body);
    res.end(JSON.stringify({ entries: entries.filter(entry => entry.hostname === search.hostname) })); return;
  }
  if (url.pathname === '/v1/credentials' && req.method === 'POST') {
    let body = ''; for await (const chunk of req) body += chunk;
    const input = JSON.parse(body);
    const entry = { ...input, id: input.id ?? `account-${entries.length + 1}`, deleted: false };
    entries = [...entries.filter(item => item.id !== entry.id), entry];
    res.end(JSON.stringify({ entry })); return;
  }
  res.writeHead(404); res.end('{}');
});
await new Promise(resolve => server.listen(0, '0.0.0.0', resolve));
const port = server.address().port;
let context;
try {
  context = await chromium.launchPersistentContext(profile, {
    ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : { channel: 'chromium' }),
    headless: true,
    ignoreDefaultArgs: ['--disable-extensions'],
    args: ['--no-sandbox', `--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker', { timeout: 20000 });
  extensionOrigin = worker.url().replace(/\/background\.js$/, '');
  assert.equal(extensionOrigin, expectedOrigin, 'Loaded extension identity must match the public manifest key.');
  const page = await context.newPage();
  await page.goto(`${extensionOrigin}/options.html`);
  assert.equal(await page.locator('#token').count(), 0);
  assert.equal(await page.locator('#origin').count(), 0);
  const defaults = await page.evaluate(async () => {
    await chrome.storage.local.clear();
    return (await import('./lib/client.js')).readConnection(chrome);
  });
  assert.deepEqual(defaults, { port: 17841 });
  console.log('PASS: a fresh extension has a working default port without token or origin setup.');
  await page.evaluate(async port => {
    await chrome.storage.local.set({ connection: { port, token: 'legacy-test-only-grant', origin: 'old-origin' }, token: 'legacy-test-only-grant', origin: 'old-origin' });
  }, port);
  await page.reload();
  await page.waitForFunction(port => Number(document.getElementById('port').value) === port, port);
  assert.deepEqual(await page.evaluate(() => chrome.storage.local.get(null)), { connection: { port } });
  console.log('PASS: updating the extension removes legacy grants and preserves its custom local port.');
  await page.locator('#connect').click();
  await page.waitForFunction(() => !document.getElementById('connect').disabled);
  const postCall = calls.find(call => call.path === '/v1/browser/connect' && call.method === 'POST');
  assert.ok(postCall, 'Extension never reached the local POST endpoint; check extension load and network permissions.');
  assert.equal(postCall.origin, extensionOrigin, `Real Chromium POST Origin was ${postCall.origin}`);
  assert.match(await page.locator('#status').innerText(), /连接成功/);
  const storage = await page.evaluate(() => chrome.storage.local.get(null));
  assert.deepEqual(storage, { connection: { port } });
  console.log('PASS: real Chromium extension POST connects without Authorization and stores only its local port.');

  const lookup = await page.evaluate(async () => {
    const { searchCredentials, readConnection } = await import('./lib/client.js');
    try { return { ok: true, result: await searchCredentials(await readConnection(chrome), '127.0.0.1') }; }
    catch (error) { return { ok: false, message: error.message }; }
  });
  const searchCall = calls.find(call => call.path === '/v1/credentials/search' && call.method === 'POST');
  assert.ok(searchCall, 'Extension never reached local POST search endpoint.');
  assert.equal(searchCall.origin, extensionOrigin, `Real Chromium search POST Origin was ${searchCall.origin}; client/server protocol must be corrected before shipping.`);
  assert.equal(searchCall.query, '', 'Credential search must not expose the hostname in the request URL.');
  assert.equal(lookup.ok, true, lookup.message);
  assert.equal(lookup.result.entries.length, 1);
  console.log('PASS: real Chromium search POST sends its Origin, needs no token and keeps hostname out of the URL.');

  const site = await context.newPage();
  await site.goto(`http://127.0.0.1:${port}/login`);
  await site.locator('iframe').waitFor();
  const target = await page.evaluate(async ({ port }) => {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find(tab => tab.url === `http://127.0.0.1:${port}/login`);
    return { id: tab.id, hostname: '127.0.0.1', origin: `http://127.0.0.1:${port}` };
  }, { port });
  const fill = await page.evaluate(async target => {
    const { fillSelectedEntry } = await import('./lib/fill.js');
    const { searchCredentials, readConnection } = await import('./lib/client.js');
    const { entries } = await searchCredentials(await readConnection(chrome), '127.0.0.1');
    return fillSelectedEntry(chrome, target, entries[0]);
  }, target);
  assert.equal(fill.ok, true);
  assert.equal(await site.locator('#user').inputValue(), 'test-alice');
  assert.equal(await site.locator('#secret').inputValue(), 'test-only-secret');
  assert.equal(await site.evaluate(() => window.submitted), 0);
  assert.equal(await site.evaluate(() => window.changes), 2);
  assert.equal(await site.frameLocator('iframe').locator('input[type=password]').inputValue(), '');
  console.log('PASS: native scripting fills main-frame inputs, emits events, never fills the iframe or submits.');

  await site.goto(`http://localhost:${port}/login`);
  const refused = await page.evaluate(async target => {
    const { fillSelectedEntry } = await import('./lib/fill.js');
    try {
      await fillSelectedEntry(chrome, target, { hostname: '127.0.0.1', username: 'test-alice', password: 'test-only-secret' });
      return false;
    } catch { return true; }
  }, target);
  assert.equal(refused, true);
  assert.equal(await site.locator('#secret').inputValue(), '');
  console.log('PASS: navigating the target tab to a different hostname prevents injection.');

  await page.evaluate(async () => {
    const { request, readConnection } = await import('./lib/client.js');
    const connection = await readConnection(chrome);
    await request(connection, '/v1/credentials', { method: 'POST', body: { id: 'account-1', hostname: '127.0.0.1', title: 'Updated', username: 'test-alice', password: 'changed-test-only-secret', notes: '' } });
  });
  assert.equal(entries.length, 1); assert.equal(entries[0].password, 'changed-test-only-secret');
  locked = true;
  const error = await page.evaluate(async () => {
    const { searchCredentials, readConnection } = await import('./lib/client.js');
    try { await searchCredentials(await readConnection(chrome), '127.0.0.1'); return ''; }
    catch (error) { return error.message; }
  });
  assert.match(error, /已锁定/);
  console.log('PASS: updates retain the entry ID, and a locked client refuses further password lookup.');
  if (process.env.OMP_EXT_CAPTURE_DIR) {
    await mkdir(process.env.OMP_EXT_CAPTURE_DIR, { recursive: true });
    await page.screenshot({ path: path.join(process.env.OMP_EXT_CAPTURE_DIR, 'extension-connected.png'), fullPage: true });
  }
  console.log('All real Chromium extension checks passed. Credentials in this test are synthetic.');
} finally {
  if (context) await context.close();
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true });
}
