import { parse } from 'tldts';

// The vault keeps the complete hostname. Only account lookup uses this key.
// Bundle the pinned public suffix data locally, including PRIVATE tenant rules.
// tldts 7.4.19 and Rust psl 2.1.243 share PSL snapshot 52b71b3 (2026-10-17).
export function matchingDomain(value) {
  if (typeof value !== 'string' || !value || value.length > 2048 || /[\s/\\@?#%]/u.test(value)) return null;
  if (value.includes(':') && !(value.startsWith('[') && value.endsWith(']'))) return null;
  let hostname;
  try {
    const url = new URL(`https://${value}`);
    hostname = url.hostname.toLowerCase().replace(/\.+$/, '');
    if (url.username || url.password || url.port || url.pathname !== '/' || !hostname || hostname.length > 253) return null;
  } catch { return null; }
  if (!hostname.startsWith('[') && hostname.split('.').some(label =>
    label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
  const result = parse(hostname, { allowPrivateDomains: true, extractHostname: false });
  // Unknown suffixes, IPs, localhost and suffix-only names stay exact.
  return result.domain && (result.isIcann || result.isPrivate) ? result.domain : hostname;
}

export function sameCredentialSite(leftHostname, rightHostname) {
  const left = matchingDomain(leftHostname);
  return left !== null && left === matchingDomain(rightHostname);
}
