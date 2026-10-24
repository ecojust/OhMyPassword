import { readConnection } from './lib/client.js';

// No password handling or polling in the worker. Upgrades remove old connection grants.
const migrateSettings = () => readConnection(chrome).catch(() => {});
chrome.runtime.onInstalled.addListener(migrateSettings);
chrome.runtime.onStartup.addListener(migrateSettings);
