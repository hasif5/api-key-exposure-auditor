/*
 * background.js — service worker.
 *
 *  - Observes network requests to Google endpoints and extracts `key=` params
 *    (catches keys used only in dynamic requests, never present in the DOM).
 *  - Receives DOM/resource findings from content scripts.
 *  - Persists everything through lib/store.js and maintains the toolbar badge.
 *  - Runs the active key audit on demand and stores the results.
 */

import { upsertFinding, setAudits, getFinding, getDb, migrate,
  getIgnoreDomains, purgeIgnored } from './lib/store.js';
import { isMapsContext } from './lib/keys.js';
import { detectKeys, getProvider, providerForKey } from './lib/providers.js';
import { urlHostIsIgnored } from './lib/ignore.js';

// One-time cleanup: collapse any duplicates left by an earlier version.
migrate().catch((e) => console.error('[GAKS] migrate failed:', e));

// Cache the user-added ignore list and purge any already-stored ignored keys.
let userIgnore = [];
getIgnoreDomains().then((l) => { userIgnore = l; return purgeIgnored(l); })
  .catch((e) => console.error('[GAKS] ignore init failed:', e));

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.gaks_ignore_domains) {
    userIgnore = Array.isArray(changes.gaks_ignore_domains.newValue)
      ? changes.gaks_ignore_domains.newValue : [];
    purgeIgnored(userIgnore).catch(() => {});
  }
});

function pageIgnored(urlOrOrigin) {
  return urlHostIsIgnored(urlOrOrigin, userIgnore);
}

const KEY_RE = /^(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})$/;
const MAPS_HINTS = ['maps.googleapis.com', 'maps.google.com', 'maps.gstatic.com', '/maps/'];

// Deep resource-scanning limits (keep it bounded but go deep).
const SCRIPT_FETCH_TIMEOUT = 12000;
const MAX_SCRIPT_BYTES = 8 * 1024 * 1024; // scan at most 8 MB per resource
const MAX_SCRIPT_CACHE = 8000;            // distinct URLs remembered
const SCRIPT_CONCURRENCY = 6;
const MAX_DEPTH = 3;                       // page → bundle → chunk/source-map → …
const DERIVED_PER_RESOURCE = 30;           // referenced assets followed per file
const fetchedScripts = new Set();
const scriptQueue = [];
let scriptActive = 0;

// Common server-side paths where secrets/config commonly leak. Probed once per
// page origin (a short, well-known list — not a brute-force scan).
const COMMON_PATHS = [
  '/.env', '/.env.local', '/.env.production', '/.env.development', '/.env.bak',
  '/config.json', '/config.js', '/app.config.js', '/appsettings.json',
  '/assets/config.json', '/static/config.json', '/env.js', '/env.json',
  '/firebase-config.json', '/firebaseConfig.js', '/manifest.json',
  '/.well-known/assetlinks.json',
  // Exposed configs/dumps that commonly carry live secrets — fetched and
  // scanned for keys like any other config asset.
  '/.git/config', '/wp-config.php.bak', '/config.php.bak',
  '/actuator/env', '/phpinfo.php'
];
const probedOrigins = new Set();

// Asset extensions we follow when extracting URLs from scanned files.
const FOLLOW_EXT_RE = /\.(?:js|mjs|cjs|json|map|css|txt|wasm)(?:[?#]|$)/i;

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
    // Drop entries for tabs that no longer exist (stale across worker restarts).
    const tabs = await chrome.tabs.query({});
    const alive = new Set(tabs.map((t) => t.id));
    let changed = false;
    for (const tid of Array.from(tabKeys.keys())) {
      if (!alive.has(tid)) { tabKeys.delete(tid); changed = true; }
    }
    if (changed) persistTabKeys();
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
  // These reject with "No tab with id" if the tab has since closed — ignore.
  Promise.resolve(chrome.action.setBadgeText({ tabId, text: count ? String(count) : '' })).catch(() => {});
  Promise.resolve(chrome.action.setBadgeBackgroundColor({ tabId, color: '#c0392b' })).catch(() => {});
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
    if (pageIgnored(details.initiator)) return; // skip ignored visiting domains

    const origin = details.initiator || url.origin;
    upsertFinding({
      key,
      provider: 'google',
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
const KEY_IN_TEXT_RE = /(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})/;
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (pageIgnored(details.initiator)) return; // skip ignored visiting domains
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
        provider: 'google',
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

// OpenAI / Anthropic keys travel in Authorization: Bearer / x-api-key headers.
const BEARER_KEY_RE = /(sk-ant-[A-Za-z0-9_-]{90,}|sk-or-(?:v1-)?[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})/;
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (pageIgnored(details.initiator)) return;
    for (const h of details.requestHeaders || []) {
      const name = (h.name || '').toLowerCase();
      if (name !== 'authorization' && name !== 'x-api-key') continue;
      const m = (h.value || '').match(BEARER_KEY_RE);
      if (!m) continue;
      const key = m[1];
      const provider = providerForKey(key);
      if (!provider) continue;
      const origin = details.initiator || safeOrigin(details.url);
      upsertFinding({
        key,
        provider,
        origin,
        pageUrl: details.initiator || details.url,
        source: 'network',
        snippet: details.url.split('?')[0] + ' — ' + (name === 'x-api-key' ? 'x-api-key' : 'Authorization') + ' header',
        mapsContext: false
      });
      noteKeyForTab(details.tabId, key);
    }
  },
  { urls: ['*://api.openai.com/*', '*://api.anthropic.com/*', '*://api.x.ai/*', '*://openrouter.ai/*'] },
  ['requestHeaders']
);

// ---- Response-header + cookie key scanning (per-origin, main-frame only) ---
// Response headers and cookies are two more places a key can leak; scan their
// values and feed any hits into the same findings DB.

const headerScanned = new Set();

chrome.webRequest.onHeadersReceived.addListener(
  (details) => { scanHeadersAndCookies(details).catch(() => {}); },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders']
);

async function scanHeadersAndCookies(details) {
  let origin;
  try { origin = new URL(details.url).origin; } catch (e) { return; }
  if (pageIgnored(origin)) return;
  if (headerScanned.has(origin)) return;
  headerScanned.add(origin);

  // Response header values.
  const hdrText = (details.responseHeaders || [])
    .map((h) => (h.name || '') + ': ' + (h.value || '')).join('\n');
  for (const h of detectKeys(hdrText)) {
    noteKeyForTab(details.tabId, h.key);
    upsertFinding({
      key: h.key, provider: h.provider || 'google', secret: h.secret,
      origin, pageUrl: details.url, source: 'header',
      snippet: 'response header — ' + h.snippet, mapsContext: h.mapsContext
    });
  }

  // Cookie values.
  try {
    const cookies = await chrome.cookies.getAll({ url: details.url });
    const cookieText = cookies.map((c) => c.name + '=' + c.value).join('\n');
    for (const h of detectKeys(cookieText)) {
      noteKeyForTab(details.tabId, h.key);
      upsertFinding({
        key: h.key, provider: h.provider || 'google', secret: h.secret,
        origin, pageUrl: details.url, source: 'cookie',
        snippet: 'cookie — ' + h.snippet, mapsContext: h.mapsContext
      });
    }
  } catch (e) { /* cookies API unavailable */ }
}

// ---- Messages from content scripts / popup / dashboard ---------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return false;

  if (msg.type === 'GAKS_FINDINGS') {
    const tabId = sender && sender.tab ? sender.tab.id : -1;
    const origin = msg.origin || (sender && sender.tab ? new URL(sender.tab.url).origin : 'unknown');
    if (pageIgnored(origin)) { sendResponse({ ok: true, ignored: true }); return true; }
    const findings = Array.isArray(msg.findings) ? msg.findings : [];
    Promise.all(findings.map((f) => {
      noteKeyForTab(tabId, f.key);
      return upsertFinding({
        key: f.key,
        provider: f.provider || 'google',
        secret: f.secret,
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
      enqueueScript(u, origin, msg.pageUrl, tabId, 0));
    probeCommonPaths(origin, msg.pageUrl, tabId);
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
    const providerId = msg.provider || providerForKey(key) || 'google';
    if (!key) { sendResponse({ ok: false, error: 'invalid key' }); return true; }
    getProvider(providerId).audit(key, { includeGenerate: !!msg.includeGenerate, secret: msg.secret })
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
  const provider = getProvider(finding.provider || providerForKey(finding.key) || 'google');
  const audits = await provider.audit(finding.key, { includeGenerate, secret: finding.secret });
  return setAudits(findingId, audits);
}

// ---- External-script scanning ---------------------------------------------

function safeOrigin(u) {
  try { return new URL(u).origin; } catch (e) { return 'unknown'; }
}

function enqueueScript(rawUrl, origin, pageUrl, tabId, depth) {
  depth = depth || 0;
  if (depth > MAX_DEPTH) return;
  if (pageIgnored(origin) || pageIgnored(pageUrl)) return; // ignored visiting domain
  let url;
  try { url = new URL(rawUrl); } catch (e) { return; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
  const norm = url.href;
  if (fetchedScripts.has(norm)) return;
  fetchedScripts.add(norm);
  if (fetchedScripts.size > MAX_SCRIPT_CACHE) {
    const first = fetchedScripts.values().next().value;
    fetchedScripts.delete(first);
  }
  scriptQueue.push({ url: norm, origin, pageUrl, tabId, depth });
  pumpScriptQueue();
}

// Probe a short list of well-known config/secret paths, once per page origin.
function probeCommonPaths(origin, pageUrl, tabId) {
  if (!origin || origin === 'unknown' || probedOrigins.has(origin)) return;
  if (pageIgnored(origin)) return;
  probedOrigins.add(origin);
  for (const p of COMMON_PATHS) enqueueScript(origin + p, origin, pageUrl, tabId, 0);
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

function recordHits(text, job, source, label) {
  const hits = detectKeys(text);
  for (const h of hits) {
    noteKeyForTab(job.tabId, h.key);
    upsertFinding({
      key: h.key,
      provider: h.provider || 'google',
      secret: h.secret,
      origin: job.origin,
      pageUrl: job.pageUrl || job.url,
      source: source,
      snippet: 'in ' + shortUrl(job.url) + (label ? ' (' + label + ')' : '') + ' — ' + h.snippet,
      mapsContext: h.mapsContext || (h.provider === 'google' && isMapsContext(job.url))
    });
  }
}

// Decode a JS source map and scan the ORIGINAL (un-minified) sources — keys that
// minification mangled often reappear here verbatim.
function scanSourceMap(text, job) {
  let map;
  try { map = JSON.parse(text); } catch (e) { return false; }
  if (!map || !Array.isArray(map.sourcesContent)) return false;
  const joined = map.sourcesContent.filter(Boolean).join('\n');
  if (joined) recordHits(joined, job, 'sourcemap', 'source map');
  return true;
}

// Follow references found inside a scanned file: its source map + any asset URLs
// it names (chunks, JSON config, CSS). Bounded by depth, per-file count, and host.
function followReferences(text, job) {
  const nextDepth = (job.depth || 0) + 1;
  if (nextDepth > MAX_DEPTH) return;
  let baseHost = '';
  try { baseHost = new URL(job.url).host; } catch (e) { /* ignore */ }
  let pageHost = '';
  try { pageHost = new URL(job.pageUrl || job.origin).host; } catch (e) { /* ignore */ }

  // Source map (//# sourceMappingURL=...).
  const sm = text.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/);
  if (sm && sm[1].indexOf('data:') !== 0) {
    try { enqueueScript(new URL(sm[1], job.url).href, job.origin, job.pageUrl, job.tabId, nextDepth); } catch (e) { /* ignore */ }
  }

  // Referenced asset URLs in string literals.
  const re = /["'`(]([a-zA-Z0-9_./\-]+\.(?:js|mjs|cjs|json|map|css|txt|wasm))(?:\?[^"'`)\s]*)?["'`)]/g;
  let m, count = 0;
  while ((m = re.exec(text)) !== null && count < DERIVED_PER_RESOURCE) {
    let abs;
    try { abs = new URL(m[1], job.url).href; } catch (e) { continue; }
    let host;
    try { host = new URL(abs).host; } catch (e) { continue; }
    // Stay within the page's host or the resource's own host (don't crawl the web).
    if (host !== baseHost && host !== pageHost) continue;
    enqueueScript(abs, job.origin, job.pageUrl, job.tabId, nextDepth);
    count++;
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
    const pathLooksTextual = FOLLOW_EXT_RE.test(job.url) || /\/\.env/.test(job.url);
    // Scan textual payloads (JS/CSS/JSON/text/xml/source maps), or anything whose
    // URL looks like a code/config asset even if the content-type is generic.
    if (ct && !pathLooksTextual &&
        !/javascript|ecmascript|json|text|css|xml|application\/x-|octet-stream/.test(ct)) return;
    text = await res.text();
  } catch (e) {
    return;
  } finally {
    clearTimeout(timer);
  }
  if (!text) return;
  if (text.length > MAX_SCRIPT_BYTES) text = text.slice(0, MAX_SCRIPT_BYTES);

  // 1) Scan the raw text for keys.
  recordHits(text, job, 'script', '');
  // 2) If it's a source map, also scan the decoded original sources.
  if (/\.map(\?|$)/i.test(job.url) || /"sourcesContent"\s*:/.test(text.slice(0, 2000))) {
    scanSourceMap(text, job);
  }
  // 3) Follow source maps + referenced assets deeper.
  followReferences(text, job);
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
