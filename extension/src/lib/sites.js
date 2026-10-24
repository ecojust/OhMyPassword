import { matchingDomain, sameCredentialSite } from './domains.js';

// Selectors are hints, not permission to fill. The DOM engine must still reject
// hidden/disabled inputs, registration forms, OTPs and ambiguous candidates.
const RULES = {
  apple: {
    usernameSelectors: ['input#account_name_text_field'],
    passwordSelectors: ['input#password_text_field[type="password"]'],
    allowUsernameOnly: true,
  },
  chatgpt: {
    usernameSelectors: ['input[name="username"][type="email"]'],
    passwordSelectors: [],
    allowUsernameOnly: true,
  },
  google: {
    usernameSelectors: ['input#identifierId', 'input[name="identifier"]'],
    passwordSelectors: [],
    allowUsernameOnly: true,
  },
  github: {
    usernameSelectors: ['input#login_field'],
    passwordSelectors: ['input#password[type="password"]'],
  },
  microsoft: {
    usernameSelectors: ['input#usernameEntry'],
    passwordSelectors: [],
    allowUsernameOnly: true,
  },
  gitee: {
    usernameSelectors: ['input#user_login[name="user[login]"]'],
    passwordSelectors: ['input#user_password[name="user[password]"][type="password"]'],
  },
  netease163: {
    usernameSelectors: ['input[name="email"]'],
    passwordSelectors: ['input[name="password"][type="password"]'],
  },
  netease126: {
    usernameSelectors: ['input[name="email"]'],
    passwordSelectors: ['input[name="password"][type="password"]'],
  },
  bilibili: {
    usernameSelectors: ['input[type="text"][placeholder="请输入账号"]'],
    passwordSelectors: ['input[type="password"][placeholder="请输入密码"]'],
  },
  baidu: {
    usernameSelectors: ['input[name="userName"]'],
    passwordSelectors: ['input[name="password"][type="password"]'],
  },
};

// Keep username-only steps on observed first-party login hosts. Unknown sites
// (including QQ, whose live login form could not be inspected) use DOM defaults.
const RULE_HOSTS = new Map([
  ...['account.apple.com', 'appleid.apple.com', 'idmsa.apple.com', 'icloud.com', 'www.icloud.com'].map(host => [host, 'apple']),
  ...['chatgpt.com', 'chat.openai.com', 'auth.openai.com', 'auth0.openai.com'].map(host => [host, 'chatgpt']),
  ...['accounts.google.com', 'mail.google.com'].map(host => [host, 'google']),
  ['github.com', 'github'],
  ['login.live.com', 'microsoft'],
  ['gitee.com', 'gitee'],
  ['mail.163.com', 'netease163'],
  ['dl.reg.163.com', 'netease163'],
  ['mail.126.com', 'netease126'],
  ['passport.126.com', 'netease126'],
  ['passport.bilibili.com', 'bilibili'],
  ['www.bilibili.com', 'bilibili'],
  ['passport.baidu.com', 'baidu'],
  ['www.baidu.com', 'baidu'],
]);

// These are directional aliases: credentials from these registrable domains
// may be used only on the listed login hosts. OAuth links never add aliases.
const LOGIN_ALIASES = new Map([
  ...['accounts.google.com', 'mail.google.com'].map(host => [host, ['gmail.com', 'google.com']]),
  ...['auth.openai.com', 'auth0.openai.com', 'chatgpt.com', 'chat.openai.com'].map(host => [host, ['chatgpt.com', 'openai.com']]),
  ...['account.apple.com', 'appleid.apple.com', 'idmsa.apple.com', 'icloud.com', 'www.icloud.com'].map(host => [host, ['apple.com', 'icloud.com']]),
]);

const LOGIN_FRAMES = new Map([
  ['mail.163.com', 'https://dl.reg.163.com'],
  ['mail.126.com', 'https://passport.126.com'],
  ...['account.apple.com', 'appleid.apple.com', 'icloud.com', 'www.icloud.com'].map(host => [host, 'https://idmsa.apple.com']),
]);

export const OPTIONAL_LOGIN_ORIGINS = Object.freeze([
  'https://dl.reg.163.com/*',
  'https://passport.126.com/*',
  'https://idmsa.apple.com/*',
]);

function normalizedHostname(value) {
  if (matchingDomain(value) === null) return null;
  return new URL(`https://${value}`).hostname.toLowerCase().replace(/\.+$/, '');
}

function httpsUrl(value) {
  if (typeof value !== 'string' || value.length > 8192 || /[\s\\]/u.test(value)) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.port && !url.username && !url.password ? url : null;
  } catch { return null; }
}

const NON_LOGIN_FLOW = /sign[-_ ]?up|register|registration|recover|reset|forgot|change[-_ ]?password|password[-_ ]?change|create[-_ ]?account/i;
const FLOW_QUERY_KEYS = new Set(['flow', 'flowtype', 'flowname', 'mode', 'action', 'screen', 'screenhint', 'authtype', 'type', 'view', 'intent']);

function usernameLoginContext(host, page) {
  if (!page || page.hostname !== host || page.hash) return false;
  let path;
  try { path = decodeURIComponent(page.pathname).toLowerCase().replace(/\/+$/, '') || '/'; }
  catch { return false; }
  if (NON_LOGIN_FLOW.test(path)) return false;
  // Check only explicit flow controls. OAuth redirect_uri, continue, state and
  // other opaque parameters can legitimately contain words such as "signup".
  for (const [key, value] of page.searchParams) {
    if (FLOW_QUERY_KEYS.has(key.toLowerCase().replace(/[-_]/g, '')) && NON_LOGIN_FLOW.test(value)) return false;
  }
  switch (host) {
    case 'chatgpt.com':
    case 'chat.openai.com':
      return path === '/auth/login';
    case 'auth.openai.com':
    case 'auth0.openai.com':
      return /^\/(?:log-in|login|u\/login(?:\/(?:identifier|password|identifier-and-password))?)$/.test(path);
    case 'accounts.google.com':
      return /^\/(?:v\d+\/)?signin\/(?:v\d+\/)?(?:identifier|login|challenge(?:\/[a-z0-9_-]+)?)$/.test(path);
    case 'account.apple.com':
    case 'appleid.apple.com':
      return path === '/sign-in' || path === '/signin';
    case 'idmsa.apple.com':
      return path === '/appleauth/auth/authorize/signin';
    case 'icloud.com':
    case 'www.icloud.com':
      return /^\/(?:mail|calendar|contacts|photos|iclouddrive|notes|reminders|find|pages|numbers|keynote)?$/.test(path);
    case 'login.live.com':
      return path === '/' || path === '/login' || path === '/login.srf';
    default:
      return false;
  }
}

/** Return serializable selector hints for the self-contained DOM engine. */
export function getLoginRules(hostname, { url, topHostname } = {}) {
  const host = normalizedHostname(hostname);
  const id = RULE_HOSTS.get(host) || 'generic';
  const rules = RULES[id];
  const frame = httpsUrl(url);
  const result = {
    id,
    usernameSelectors: [...(rules?.usernameSelectors || [])],
    passwordSelectors: [...(rules?.passwordSelectors || [])],
    allowUsernameOnly: rules?.allowUsernameOnly === true && usernameLoginContext(host, frame),
    loginPasswordSelectors: [],
  };

  // NetEase labels its real login password as new-password. The exception is
  // confined to the observed frame URL, its owning mail site and product. Never
  // trust an input's own attributes to turn a registration field into a login.
  const top = normalizedHostname(topHostname);
  const product = top === 'mail.163.com' ? 'mail163' : top === 'mail.126.com' ? 'mail126' : null;
  if (product && frame && frame.hostname === host && allowedLoginFrame(top, frame.origin)
      && frame.pathname === '/webzj/v1.0.1/pub/index_dl2_new.html'
      && !frame.hash && frame.searchParams.getAll('product').length === 1
      && frame.searchParams.get('product') === product) {
    result.loginPasswordSelectors = ['input[type="password"][name="password"]'];
  }
  return result;
}

/** Query the current host first, then at most two explicit first-party aliases. */
export function credentialLookupHosts(pageHostname) {
  const host = normalizedHostname(pageHostname);
  return host ? [...new Set([host, ...(LOGIN_ALIASES.get(host) || [])])] : [];
}

/** Match the normal PSL boundary, with directional official-login exceptions. */
export function credentialMatchesPage(entryHostname, pageHostname) {
  if (sameCredentialSite(entryHostname, pageHostname)) return true;
  const host = normalizedHostname(pageHostname);
  const entryDomain = matchingDomain(entryHostname);
  return entryDomain !== null && (LOGIN_ALIASES.get(host) || []).includes(entryDomain);
}

/** Same-origin frames are handled separately; this permits only known pairs. */
export function allowedLoginFrame(topHostname, frameOrigin) {
  const expected = LOGIN_FRAMES.get(normalizedHostname(topHostname));
  const frame = httpsUrl(frameOrigin);
  return !!expected && !!frame && frame.pathname === '/' && !frame.search && !frame.hash
    && frame.origin === expected;
}
