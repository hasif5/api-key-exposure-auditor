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
import { detectKeys, detectKeysWindowed, getProvider, providerForKey } from './lib/providers.js';
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

const MAPS_HINTS = ['maps.googleapis.com', 'maps.google.com', 'maps.gstatic.com', '/maps/'];

// Deep resource-scanning limits (keep it bounded but go deep). Peak service-
// worker memory is roughly SCRIPT_CONCURRENCY × MAX_SCRIPT_BYTES of text held
// at once. Unminified dev bundles with inline source maps routinely pass
// 4 MB, so the cap is 16 MB; the text is scanned in 1 MB windows.
const SCRIPT_FETCH_TIMEOUT = 12000;
const MAX_SCRIPT_BYTES = 16 * 1024 * 1024; // scan at most 16 MB per resource
const MAX_SCRIPT_CACHE = 8000;            // distinct URLs remembered
const SCRIPT_CONCURRENCY = 4;
const MAX_DEPTH = 3;                       // page → bundle → chunk/source-map → …
const DERIVED_PER_RESOURCE = 30;           // referenced assets followed per file
const DERIVED_PER_MANIFEST = 250;          // …or per build manifest (lists every route chunk)
const MAX_FETCHES_PER_ORIGIN = 1000;       // total crawl budget per page origin
const MAX_MAP_GUESSES_PER_ORIGIN = 40;     // blind "<file>.js.map" attempts
const fetchedScripts = new Set();
const originFetches = new Map();
const originMapGuesses = new Map();
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
  // Runtime-injected env files and build manifests. A manifest lists every
  // chunk of the build, including routes the user never opened.
  '/__ENV.js', '/env-config.js', '/runtime-config.json',
  '/asset-manifest.json', '/.vite/manifest.json',
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

// The in-page interceptor only sees fetch/XHR made by the page's own window.
// Requests from Web/Service Workers, <img>/<script> tags, and CSS are visible
// here only, so every request URL and request header is checked — for all
// hosts and all validated providers, not just Google and the AI APIs.

// One cheap regex decides whether the full detector runs at all.
const KEY_PREFILTER_RE = /AIza|AQ\.|sk-|xai-|AKIA|ASIA|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|[sr]k_(?:live|test)_|AC[0-9a-fA-F]{32}/;
const OWN_ORIGIN = 'chrome-extension://' + chrome.runtime.id;

// Record provider keys found in one piece of request metadata. Heuristic
// ('unknown') hits are left out: a request legitimately carries the user's own
// session tokens, which are not leaked secrets.
function sniffRequest(details, text, where) {
  for (const h of detectKeys(text)) {
    if (h.provider === 'unknown') continue;
    upsertFinding({
      key: h.key,
      provider: h.provider,
      secret: h.secret,
      origin: details.initiator || safeOrigin(details.url),
      pageUrl: details.initiator || details.url,
      source: 'network',
      snippet: details.url.split('?')[0] + ' — ' + where,
      mapsContext: h.provider === 'google' && isMapsUrl(details.url)
    });
    noteKeyForTab(details.tabId, h.key);
  }
}

// True for requests that must not be sniffed: the extension's own (audit
// probes and crawl fetches carry the keys being examined) and ignored pages.
function skipRequest(details) {
  if (details.initiator === OWN_ORIGIN) return true;
  return pageIgnored(details.initiator || details.url);
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!KEY_PREFILTER_RE.test(details.url) || skipRequest(details)) return;
    sniffRequest(details, details.url, 'request URL');
  },
  { urls: ['<all_urls>'] },
  []
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    let skip = null;
    for (const h of details.requestHeaders || []) {
      const val = h.value || '';
      if (!KEY_PREFILTER_RE.test(val)) continue;
      if (skip === null) skip = skipRequest(details);
      if (skip) return;
      sniffRequest(details, (h.name || '') + ': ' + val, (h.name || 'request') + ' header');
    }
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders']
);

// ---- Response-header + cookie key scanning (per-origin, main-frame only) ---
// Response headers and cookies are two more places a key can leak; scan their
// values and feed any hits into the same findings DB.

// origin -> keys found in its headers/cookies. Scanned once per origin; the
// cached keys are re-applied to the badge on later navigations.
const headerScanned = new Map();
// tabId -> { keys, ts }: header/cookie hits for a navigation in flight. They
// are recorded before tabs.onUpdated resets the tab's key set for that same
// navigation, so the reset handler puts them back.
const pendingNavKeys = new Map();

chrome.webRequest.onHeadersReceived.addListener(
  (details) => { scanHeadersAndCookies(details).catch(() => {}); },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders']
);

async function scanHeadersAndCookies(details) {
  let origin;
  try { origin = new URL(details.url).origin; } catch (e) { return; }
  if (pageIgnored(origin)) return;

  const pend = { keys: new Set(), ts: Date.now() };
  if (details.tabId >= 0) pendingNavKeys.set(details.tabId, pend);
  const note = (key) => { pend.keys.add(key); noteKeyForTab(details.tabId, key); };

  const cached = headerScanned.get(origin);
  if (cached) { cached.forEach(note); return; }
  const found = [];
  headerScanned.set(origin, found);
  if (headerScanned.size > 2000) headerScanned.delete(headerScanned.keys().next().value);

  // Response header values.
  const hdrText = (details.responseHeaders || [])
    .map((h) => (h.name || '') + ': ' + (h.value || '')).join('\n');
  for (const h of detectKeys(hdrText)) {
    found.push(h.key);
    note(h.key);
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
      found.push(h.key);
      note(h.key);
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

// Count against a per-origin budget held in `map`; false once it is spent.
function takeBudget(map, origin, max) {
  const n = map.get(origin) || 0;
  if (n >= max) return false;
  map.set(origin, n + 1);
  if (map.size > 2000) map.delete(map.keys().next().value);
  return true;
}

// `probe` marks a guessed URL (common config path, blind source-map guess)
// rather than one the page or a scanned file actually referenced.
function enqueueScript(rawUrl, origin, pageUrl, tabId, depth, probe) {
  depth = depth || 0;
  if (depth > MAX_DEPTH) return;
  if (pageIgnored(origin) || pageIgnored(pageUrl)) return; // ignored visiting domain
  let url;
  try { url = new URL(rawUrl); } catch (e) { return; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
  const norm = url.href;
  if (fetchedScripts.has(norm)) return;
  if (!takeBudget(originFetches, origin, MAX_FETCHES_PER_ORIGIN)) return;
  fetchedScripts.add(norm);
  if (fetchedScripts.size > MAX_SCRIPT_CACHE) {
    const first = fetchedScripts.values().next().value;
    fetchedScripts.delete(first);
  }
  scriptQueue.push({ url: norm, origin, pageUrl, tabId, depth, probe: !!probe });
  pumpScriptQueue();
}

// Probe a short list of well-known config/secret paths, once per page origin.
function probeCommonPaths(origin, pageUrl, tabId) {
  if (!origin || origin === 'unknown' || probedOrigins.has(origin)) return;
  if (pageIgnored(origin)) return;
  probedOrigins.add(origin);
  for (const p of COMMON_PATHS) enqueueScript(origin + p, origin, pageUrl, tabId, 0, true);
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
  const hits = detectKeysWindowed(text);
  for (const h of hits) {
    noteKeyForTab(job.tabId, h.key);
    upsertFinding({
      key: h.key,
      provider: h.provider || 'google',
      secret: h.secret,
      origin: job.origin,
      // Store the exact resource URL (the script/map/config the key lives in)
      // so the UI can link straight to it; the page domain is kept via `origin`.
      pageUrl: job.url,
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
  if (!map || typeof map !== 'object') return false;
  // A plain map carries sourcesContent directly; an indexed map nests one map
  // per section.
  const parts = [];
  const take = (m) => { if (m && Array.isArray(m.sourcesContent)) for (const s of m.sourcesContent) if (s) parts.push(s); };
  take(map);
  if (Array.isArray(map.sections)) for (const s of map.sections) take(s && s.map);
  if (!parts.length) return false;
  recordHits(parts.join('\n'), job, 'sourcemap', 'source map');
  return true;
}

// Decode an inline source map (sourceMappingURL=data:application/json;base64,…).
// Dev builds (webpack eval-source-map, Vite) ship maps this way, so on
// localhost this is usually the only copy of the original sources.
function decodeDataUri(uri) {
  const comma = uri.indexOf(',');
  if (comma === -1 || uri.length > 24 * 1024 * 1024) return null;
  const meta = uri.slice(5, comma).toLowerCase();
  const data = uri.slice(comma + 1);
  try {
    if (/;base64/.test(meta)) {
      const bin = atob(data);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    }
    return decodeURIComponent(data);
  } catch (e) { return null; }
}

// The file's source-map reference: the last "//# sourceMappingURL=" (JS) or
// "/*# sourceMappingURL= */" (CSS) comment, else the SourceMap response header.
function sourceMapRef(text, headerRef) {
  const mark = 'sourceMappingURL=';
  const i = text.lastIndexOf(mark);
  if (i !== -1 && /[#@]\s*$/.test(text.slice(Math.max(0, i - 4), i))) {
    let end = i + mark.length;
    while (end < text.length && !/[\s'"*]/.test(text[end])) end++;
    const ref = text.slice(i + mark.length, end);
    if (ref) return ref;
  }
  return headerRef || null;
}

// Base URL for a relative asset path named inside `url`. Build manifests list
// paths relative to the build root, not to the manifest's own folder.
function referenceBase(url, ref) {
  try {
    const p = new URL(url);
    const next = p.pathname.indexOf('/_next/static/');
    if (next !== -1 && ref.indexOf('static/') === 0) return p.origin + p.pathname.slice(0, next) + '/_next/';
    if (/\/\.vite\/manifest\.json$/.test(p.pathname)) return p.origin + p.pathname.replace(/\.vite\/manifest\.json$/, '');
  } catch (e) { /* ignore */ }
  return url;
}

// Follow references found inside a scanned file: its source map + any asset URLs
// it names (chunks, JSON config, CSS). Bounded by depth, per-file count, and host.
function followReferences(text, job, headerMapRef) {
  const nextDepth = (job.depth || 0) + 1;
  if (nextDepth > MAX_DEPTH) return;
  let base = null;
  try { base = new URL(job.url); } catch (e) { return; }
  const baseHost = base.host;
  let pageHost = '';
  try { pageHost = new URL(job.pageUrl || job.origin).host; } catch (e) { /* ignore */ }
  const isMap = /\.map(?:[?#]|$)/i.test(job.url);

  // Source map: referenced by comment or header, inline as a data: URI, or —
  // when the reference was stripped ("hidden" source maps are often still
  // deployed) — guessed as "<file>.map" for the page's own scripts.
  if (!isMap) {
    const ref = sourceMapRef(text, headerMapRef);
    if (ref && ref.indexOf('data:') === 0) {
      const inline = decodeDataUri(ref);
      if (inline) scanSourceMap(inline, job);
    } else if (ref) {
      try { enqueueScript(new URL(ref, job.url).href, job.origin, job.pageUrl, job.tabId, nextDepth); } catch (e) { /* ignore */ }
    } else if (!job.probe && baseHost === pageHost && /\.(?:js|mjs|css)$/i.test(base.pathname) &&
               takeBudget(originMapGuesses, job.origin, MAX_MAP_GUESSES_PER_ORIGIN)) {
      enqueueScript(base.origin + base.pathname + '.map', job.origin, job.pageUrl, job.tabId, nextDepth, true);
    }
  }

  // Referenced asset URLs in string literals.
  const limit = /manifest/i.test(base.pathname) ? DERIVED_PER_MANIFEST : DERIVED_PER_RESOURCE;
  const re = /["'`(]([a-zA-Z0-9_./\-]+\.(?:js|mjs|cjs|json|map|css|txt|wasm))(?:\?[^"'`)\s]*)?["'`)]/g;
  let m, count = 0;
  while ((m = re.exec(text)) !== null && count < limit) {
    let abs;
    try { abs = new URL(m[1], referenceBase(job.url, m[1])); } catch (e) { continue; }
    // Stay within the page's host or the resource's own host (don't crawl the web).
    if (abs.host !== baseHost && abs.host !== pageHost) continue;
    enqueueScript(abs.href, job.origin, job.pageUrl, job.tabId, nextDepth);
    count++;
  }
}

// A single-page app answers unknown paths with its index.html and HTTP 200.
// Without this check a guessed path (/.env, <file>.js.map) would "succeed",
// and every key on the page would be recorded as living in that file.
function isFallbackPage(text, job) {
  if (!/^\s*(?:<!doctype html|<html[\s>])/i.test(text.slice(0, 512))) return false;
  if (/\/phpinfo\.php$/i.test(job.url)) return !/phpinfo\(\)|PHP Version/i.test(text.slice(0, 20000));
  return job.probe || FOLLOW_EXT_RE.test(job.url);
}

async function scanScript(job) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCRIPT_FETCH_TIMEOUT);
  let text, headerMapRef = null;
  try {
    const res = await fetch(job.url, { signal: controller.signal, credentials: 'omit' });
    if (!res.ok) return;
    if (Number(res.headers.get('content-length')) > 2 * MAX_SCRIPT_BYTES) return; // don't buffer a huge download
    headerMapRef = res.headers.get('sourcemap') || res.headers.get('x-sourcemap');
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
  if (isFallbackPage(text, job)) return;

  // 1) Scan the raw text for keys.
  recordHits(text, job, 'script', '');
  // 2) If it's a source map, also scan the decoded original sources.
  if (/\.map(\?|$)/i.test(job.url) || /"sourcesContent"\s*:/.test(text.slice(0, 2000))) {
    scanSourceMap(text, job);
  }
  // 3) Follow source maps + referenced assets deeper.
  followReferences(text, job, headerMapRef);
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
    // Header/cookie hits for this navigation were noted before this reset.
    const pend = pendingNavKeys.get(tabId);
    if (pend) {
      pendingNavKeys.delete(tabId);
      if (Date.now() - pend.ts < 30000) pend.keys.forEach((k) => noteKeyForTab(tabId, k));
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pendingNavKeys.delete(tabId);
  clearTabKeys(tabId);
});
