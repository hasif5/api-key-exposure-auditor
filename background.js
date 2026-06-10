/*
 * background.js — service worker.
 *
 *  - Observes network requests to Google endpoints and extracts `key=` params
 *    (catches keys used only in dynamic requests, never present in the DOM).
 *  - Receives DOM/resource findings from content scripts.
 *  - Persists everything through lib/store.js and maintains the toolbar badge.
 *  - Runs the active key audit on demand and stores the results.
 */

import { upsertFinding, setAudits, getFinding, getDb, migrate } from './lib/store.js';
import { auditKey } from './lib/audit.js';
import { findKeysInText, isMapsContext } from './lib/keys.js';

// One-time cleanup: collapse any duplicates left by an earlier version.
migrate().catch((e) => console.error('[GAKS] migrate failed:', e));

const KEY_RE = /^AIza[0-9A-Za-z_\-]{35}$/;
const MAPS_HINTS = ['maps.googleapis.com', 'maps.google.com', 'maps.gstatic.com', '/maps/'];

// External-script scanning limits (keep it cheap and bounded).
const SCRIPT_FETCH_TIMEOUT = 10000;
const MAX_SCRIPT_BYTES = 4 * 1024 * 1024; // scan at most 4 MB per bundle
const MAX_SCRIPT_CACHE = 4000;            // distinct URLs remembered
const SCRIPT_CONCURRENCY = 4;
const fetchedScripts = new Set();
const scriptQueue = [];
let scriptActive = 0;

// tabId -> Set of distinct keys seen on that tab. Drives both the badge and the
// popup's "keys on this page" list. Mirrored to storage.session so it survives
// the service worker being suspended (the badge text persists on the tab even
// when the worker sleeps, so the popup must be able to recover the same list).
const TABKEYS_SESSION = 'gaks_tabkeys';
const tabKeys = new Map();

async function hydrateTabKeys() {
  try {
    const res = await chrome.storage.session.get(TABKEYS_SESSION);
    const obj = res[TABKEYS_SESSION] || {};
    for (const [tid, arr] of Object.entries(obj)) tabKeys.set(Number(tid), new Set(arr));
  } catch (e) { /* session storage unavailable */ }
}
const ready = hydrateTabKeys();

function persistTabKeys() {
  const obj = {};
  for (const [tid, set] of tabKeys) obj[tid] = Array.from(set);
  chrome.storage.session.set({ [TABKEYS_SESSION]: obj }).catch(() => {});
}

function isMapsUrl(url) {
  const lower = (url || '').toLowerCase();
  return MAPS_HINTS.some((h) => lower.indexOf(h) !== -1);
}

function updateBadge(tabId) {
  if (tabId == null || tabId < 0) return;
  const set = tabKeys.get(tabId);
  const count = set ? set.size : 0;
  chrome.action.setBadgeText({ tabId, text: count ? String(count) : '' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#c0392b' });
}

function noteKeyForTab(tabId, key) {
  if (tabId == null || tabId < 0) return;
  ready.then(() => {
    let set = tabKeys.get(tabId);
    if (!set) { set = new Set(); tabKeys.set(tabId, set); }
    if (set.has(key)) return;
    set.add(key);
    updateBadge(tabId);
    persistTabKeys();
  });
}

function clearTabKeys(tabId) {
  ready.then(() => {
    if (tabKeys.delete(tabId)) { updateBadge(tabId); persistTabKeys(); }
  });
}

// ---- Network observation ---------------------------------------------------

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    let url;
    try { url = new URL(details.url); } catch (e) { return; }
    const key = url.searchParams.get('key');
    if (!key || !KEY_RE.test(key)) return;

    const origin = details.initiator || url.origin;
    upsertFinding({
      key,
      origin,
      pageUrl: details.initiator || details.url,
      source: 'network',
      snippet: details.url.split('?')[0] + '?…key=' + key.slice(0, 10) + '…',
      mapsContext: isMapsUrl(details.url)
    });
    noteKeyForTab(details.tabId, key);
  },
  { urls: ['*://*.googleapis.com/*', '*://maps.google.com/*', '*://maps.gstatic.com/*'] },
  []
);

// Modern Google APIs (Routes, Places New, etc.) pass the key in the
// `X-Goog-Api-Key` request header rather than a `key=` query param.
const KEY_IN_TEXT_RE = /AIza[0-9A-Za-z_\-]{35}/;
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const headers = details.requestHeaders || [];
    for (const h of headers) {
      const name = (h.name || '').toLowerCase();
      const val = h.value || '';
      if (name !== 'x-goog-api-key' && !KEY_IN_TEXT_RE.test(val)) continue;
      const m = val.match(KEY_IN_TEXT_RE);
      if (!m) continue;
      const key = m[0];
      const origin = details.initiator || safeOrigin(details.url);
      upsertFinding({
        key,
        origin,
        pageUrl: details.initiator || details.url,
        source: 'network',
        snippet: details.url.split('?')[0] + ' — X-Goog-Api-Key header',
        mapsContext: isMapsUrl(details.url)
      });
      noteKeyForTab(details.tabId, key);
    }
  },
  { urls: ['*://*.googleapis.com/*'] },
  ['requestHeaders']
);

// ---- Messages from content scripts / popup / dashboard ---------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return false;

  if (msg.type === 'GAKS_FINDINGS') {
    const tabId = sender && sender.tab ? sender.tab.id : -1;
    const origin = msg.origin || (sender && sender.tab ? new URL(sender.tab.url).origin : 'unknown');
    const findings = Array.isArray(msg.findings) ? msg.findings : [];
    Promise.all(findings.map((f) => {
      noteKeyForTab(tabId, f.key);
      return upsertFinding({
        key: f.key,
        origin,
        pageUrl: msg.pageUrl,
        source: f.source || 'dom',
        snippet: f.snippet,
        mapsContext: f.mapsContext
      });
    })).then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true; // async response
  }

  if (msg.type === 'GAKS_SCRIPTS') {
    const tabId = sender && sender.tab ? sender.tab.id : -1;
    const origin = msg.origin || (sender && sender.tab ? safeOrigin(sender.tab.url) : 'unknown');
    (Array.isArray(msg.urls) ? msg.urls : []).forEach((u) =>
      enqueueScript(u, origin, msg.pageUrl, tabId));
    return false; // fire-and-forget
  }

  if (msg.type === 'GAKS_AUDIT') {
    runAudit(msg.findingId, !!msg.includeGenerate)
      .then((rec) => sendResponse({ ok: true, finding: rec }))
      .catch((e) => sendResponse({ ok: false, error: String(e && e.message || e) }));
    return true;
  }

  if (msg.type === 'GAKS_AUDIT_RAW') {
    const key = msg.key;
    if (!key || !KEY_RE.test(key)) { sendResponse({ ok: false, error: 'invalid key' }); return true; }
    auditKey(key, { includeGenerate: !!msg.includeGenerate })
      .then((audits) => sendResponse({ ok: true, audits }))
      .catch((e) => sendResponse({ ok: false, error: String(e && e.message || e) }));
    return true;
  }

  if (msg.type === 'GAKS_GET_TAB_KEYS') {
    ready.then(() => {
      const set = tabKeys.get(msg.tabId);
      sendResponse({ ok: true, keys: set ? Array.from(set) : [] });
    });
    return true;
  }

  if (msg.type === 'GAKS_GET_DB') {
    getDb().then((db) => sendResponse({ ok: true, db })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  return false;
});

async function runAudit(findingId, includeGenerate) {
  const finding = await getFinding(findingId);
  if (!finding) throw new Error('finding not found: ' + findingId);
  const audits = await auditKey(finding.key, { includeGenerate });
  return setAudits(findingId, audits);
}

// ---- External-script scanning ---------------------------------------------

function safeOrigin(u) {
  try { return new URL(u).origin; } catch (e) { return 'unknown'; }
}

function enqueueScript(rawUrl, origin, pageUrl, tabId) {
  let url;
  try { url = new URL(rawUrl); } catch (e) { return; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
  const norm = url.href;
  if (fetchedScripts.has(norm)) return;
  fetchedScripts.add(norm);
  if (fetchedScripts.size > MAX_SCRIPT_CACHE) {
    // Drop the oldest entry to keep the cache bounded.
    const first = fetchedScripts.values().next().value;
    fetchedScripts.delete(first);
  }
  scriptQueue.push({ url: norm, origin, pageUrl, tabId });
  pumpScriptQueue();
}

function pumpScriptQueue() {
  while (scriptActive < SCRIPT_CONCURRENCY && scriptQueue.length) {
    const job = scriptQueue.shift();
    scriptActive++;
    scanScript(job).catch(() => {}).finally(() => {
      scriptActive--;
      pumpScriptQueue();
    });
  }
}

async function scanScript(job) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCRIPT_FETCH_TIMEOUT);
  let text;
  try {
    const res = await fetch(job.url, { signal: controller.signal, credentials: 'omit' });
    if (!res.ok) return;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    // Only scan textual/script payloads.
    if (ct && !/javascript|ecmascript|json|text|application\/x-/.test(ct)) return;
    text = await res.text();
  } catch (e) {
    return;
  } finally {
    clearTimeout(timer);
  }
  if (!text) return;
  if (text.length > MAX_SCRIPT_BYTES) text = text.slice(0, MAX_SCRIPT_BYTES);

  const hits = findKeysInText(text);
  for (const h of hits) {
    noteKeyForTab(job.tabId, h.key);
    upsertFinding({
      key: h.key,
      origin: job.origin,
      pageUrl: job.pageUrl || job.url,
      source: 'script',
      snippet: 'in ' + shortUrl(job.url) + ' — ' + h.snippet,
      mapsContext: h.mapsContext || isMapsContext(job.url)
    });
  }
}

function shortUrl(u) {
  try {
    const p = new URL(u);
    const file = p.pathname.split('/').pop() || p.pathname;
    return p.host + '/…/' + file;
  } catch (e) {
    return u.slice(0, 80);
  }
}

// ---- Tab lifecycle: reset the badge set on navigation / close --------------

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  // A new top-level navigation starts a fresh per-tab key set.
  if (changeInfo.status === 'loading' && changeInfo.url) {
    clearTabKeys(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  clearTabKeys(tabId);
});
