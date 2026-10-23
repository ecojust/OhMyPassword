// No password handling or polling in the worker. Limit the stored grant to trusted extension pages.
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' });
});
