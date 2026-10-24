import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { matchingDomain, sameCredentialSite } from '../src/lib/domains.js';

test('browser and vault use the same ICANN, private, wildcard, IDN and exact-host boundary fixtures', async () => {
  const fixtures = JSON.parse(await readFile(new URL('../../desktop/core/testdata/domain-matches.json', import.meta.url), 'utf8'));
  for (const { hostname, key } of fixtures) assert.equal(matchingDomain(hostname), key, hostname);
  // Also check every pair: unrelated registrable domains never share credentials.
  for (const left of fixtures) for (const right of fixtures) {
    assert.equal(sameCredentialSite(left.hostname, right.hostname), left.key !== null && left.key === right.key,
      `${left.hostname} vs ${right.hostname}`);
  }
});

test('domain comparison accepts only hostnames, without URL credentials, ports, paths or controls', () => {
  for (const value of [null, undefined, 123, 'https://example.com', 'example.com:443', 'example.com/path',
    'example.com?query', 'example.com#fragment', 'example.com\\evil.com', 'exa\nmple.com', 'example%2ecom']) {
    assert.equal(matchingDomain(value), null, String(value));
    assert.equal(sameCredentialSite(value, 'example.com'), false);
  }
});
