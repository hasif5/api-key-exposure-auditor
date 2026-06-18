/*
 * content.js — scans the rendered page for exposed API keys.
 *
 * Surfaces covered:
 *   - Full serialized DOM (inline scripts, attributes, iframe/img/link URLs),
 *     open shadow roots, and <template> contents.
 *   - Resource-timing entries (URLs of resources the page fetched).
 *   - localStorage / sessionStorage, IndexedDB, and Cache Storage.
 *   - The page's own URL (query string + fragment).
 * (Runtime window.* globals live in the page's MAIN world and are scanned by
 * intercept.js, which bridges hits back here.)
 * Re-scans on DOM mutations (debounced) to catch late-injected keys, then
 * forwards de-duped findings to the service worker.
 */
(function () {
  if (window.__GAKS_CONTENT_LOADED__) return;
  window.__GAKS_CONTENT_LOADED__ = true;

  var pageUrl = location.href;
  var origin = location.origin;

  // key -> { source, snippet, mapsContext } already reported, to avoid resends.
  var reported = Object.create(null);
  var sentScripts = Object.create(null); // external script URLs already forwarded
  var pending = false;

  // Collect HTML inside open shadow roots (component frameworks hide markup here).
  function shadowHtml() {
    var parts = [];
    try {
      var all = document.querySelectorAll('*');
      var cap = Math.min(all.length, 8000);
      for (var i = 0; i < cap; i++) {
        var sr = all[i].shadowRoot;
        if (sr) { try { parts.push(sr.innerHTML); } catch (e) { /* closed */ } }
      }
    } catch (e) { /* ignore */ }
    return parts.join('\n');
  }

  // <template> contents live in an inert DocumentFragment that is NOT part of
  // document.documentElement.outerHTML — collect them explicitly.
  function templateHtml() {
    var parts = [];
    try {
      var tpls = document.querySelectorAll('template');
      var cap = Math.min(tpls.length, 2000);
      for (var i = 0; i < cap; i++) {
        try { parts.push(tpls[i].innerHTML); } catch (e) { /* skip */ }
      }
    } catch (e) { /* ignore */ }
    return parts.join('\n');
  }

  function collectDomFindings() {
    var html = '';
    try {
      html = document.documentElement ? document.documentElement.outerHTML : '';
    } catch (e) {
      html = '';
    }
    var shadow = shadowHtml();
    if (shadow) html += '\n' + shadow;
    var tpl = templateHtml();
    if (tpl) html += '\n' + tpl;
    return GAKS.findInText(html).map(function (r) {
      r.source = 'dom';
      return r;
    });
  }

  // Scan the page's own URL — query strings and especially the #fragment (which
  // never reaches the server) sometimes carry tokens (e.g. OAuth implicit flow).
  function collectUrlFindings() {
    var out = [];
    try {
      var text = location.href;
      try {
        var dec = decodeURIComponent(location.href);
        if (dec !== text) text += '\n' + dec;
      } catch (e) { /* malformed escape */ }
      GAKS.findInText(text).forEach(function (r) { r.source = 'url'; out.push(r); });
    } catch (e) { /* ignore */ }
    return out;
  }

  function collectResourceFindings() {
    var out = [];
    var entries;
    try {
      entries = performance.getEntriesByType('resource') || [];
    } catch (e) {
      return out;
    }
    // Join all resource URLs and scan once — snippet context is the URL itself.
    var urls = entries.map(function (e) { return e.name || ''; }).join('\n');
    GAKS.findInText(urls).forEach(function (r) {
      r.source = 'resource';
      out.push(r);
    });
    return out;
  }

  function collectStorageFindings() {
    var out = [];
    try {
      var blobs = [];
      [localStorage, sessionStorage].forEach(function (store) {
        if (!store) return;
        for (var i = 0; i < store.length; i++) {
          var k = store.key(i);
          try { blobs.push(k + '=' + store.getItem(k)); } catch (e) { /* skip */ }
        }
      });
      GAKS.findInText(blobs.join('\n')).forEach(function (r) {
        r.source = 'storage';
        out.push(r);
      });
    } catch (e) { /* storage access blocked */ }
    return out;
  }

  // Forward external script URLs to the worker, which fetches and scans the
  // bundle bodies (catches keys baked into minified JS, not just inline markup).
  function reportScripts() {
    var urls = [];
    function add(u) { if (u && !sentScripts[u]) { sentScripts[u] = true; urls.push(u); } }
    try {
      document.querySelectorAll('script[src]').forEach(function (s) { add(s.src); });
      // All linked resources: stylesheets, preloads, modulepreload, prefetch, manifest.
      document.querySelectorAll('link[href]').forEach(function (l) {
        var rel = (l.getAttribute('rel') || '').toLowerCase();
        if (/stylesheet|preload|modulepreload|prefetch|manifest/.test(rel)) add(l.href);
      });
    } catch (e) { return; }
    if (!urls.length) return;
    try {
      chrome.runtime.sendMessage(
        { type: 'GAKS_SCRIPTS', pageUrl: pageUrl, origin: origin, urls: urls },
        function () { void chrome.runtime.lastError; }
      );
    } catch (e) { /* context invalidated */ }
  }

  // De-dupe against already-seen keys and forward the fresh ones to the worker.
  function reportFindings(found) {
    var fresh = [];
    found.forEach(function (r) {
      var prev = reported[r.key];
      if (!prev) {
        reported[r.key] = r;
        fresh.push(r);
      } else if (!prev.mapsContext && r.mapsContext) {
        // Upgrade an already-reported key with maps context info.
        prev.mapsContext = true;
        prev.snippet = r.snippet;
        fresh.push(r);
      }
    });

    if (!fresh.length) return;

    var payload = {
      type: 'GAKS_FINDINGS',
      pageUrl: pageUrl,
      origin: origin,
      findings: fresh.map(function (r) {
        return {
          key: r.key,
          provider: r.provider || 'google',
          secret: r.secret,
          source: r.source,
          snippet: r.snippet,
          mapsContext: !!r.mapsContext
        };
      })
    };

    try {
      chrome.runtime.sendMessage(payload, function () {
        // Swallow "receiving end does not exist" during worker spin-up.
        void chrome.runtime.lastError;
      });
    } catch (e) {
      /* extension context invalidated (e.g. reload) — ignore */
    }
  }

  function scanAndReport() {
    pending = false;
    reportScripts();
    reportFindings(collectDomFindings()
      .concat(collectResourceFindings())
      .concat(collectStorageFindings())
      .concat(collectUrlFindings()));
  }

  function scheduleScan() {
    if (pending) return;
    pending = true;
    setTimeout(scanAndReport, 400);
  }

  // ---- Client-side stores (async): IndexedDB + Cache Storage ----------------
  // Both are partitioned by origin and reachable from the isolated world. Bound
  // the work hard so a large store can't stall the page.

  var STORE_BUDGET = 1024 * 1024; // max serialized text scanned per store type
  var storesScanned = false;

  function idbRequest(req) {
    return new Promise(function (resolve, reject) {
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  async function scanIndexedDb(sink) {
    if (!window.indexedDB || typeof indexedDB.databases !== 'function') return;
    var infos;
    try { infos = await indexedDB.databases(); } catch (e) { return; }
    var budget = STORE_BUDGET;
    for (var d = 0; d < infos.length && d < 15 && budget > 0; d++) {
      var name = infos[d] && infos[d].name;
      if (!name) continue;
      var db;
      try { db = await idbRequest(indexedDB.open(name)); } catch (e) { continue; }
      try {
        var stores = Array.prototype.slice.call(db.objectStoreNames);
        for (var s = 0; s < stores.length && budget > 0; s++) {
          try {
            var store = db.transaction(stores[s], 'readonly').objectStore(stores[s]);
            var rows = await idbRequest(store.getAll(undefined, 200));
            for (var r = 0; r < rows.length && budget > 0; r++) {
              var txt;
              try { txt = typeof rows[r] === 'string' ? rows[r] : JSON.stringify(rows[r]); }
              catch (e) { continue; }
              if (!txt) continue;
              if (txt.length > budget) txt = txt.slice(0, budget);
              budget -= txt.length;
              GAKS.findInText(txt).forEach(function (f) { f.source = 'indexeddb'; sink.push(f); });
            }
          } catch (e) { /* store unreadable */ }
        }
      } finally { try { db.close(); } catch (e) { /* ignore */ } }
    }
  }

  async function scanCacheStorage(sink) {
    if (!window.caches || typeof caches.keys !== 'function') return;
    var names;
    try { names = await caches.keys(); } catch (e) { return; }
    var budget = STORE_BUDGET;
    for (var n = 0; n < names.length && budget > 0; n++) {
      var cache;
      try { cache = await caches.open(names[n]); } catch (e) { continue; }
      var reqs;
      try { reqs = await cache.keys(); } catch (e) { continue; }
      for (var i = 0; i < reqs.length && i < 50 && budget > 0; i++) {
        try {
          GAKS.findInText(reqs[i].url).forEach(function (f) { f.source = 'cache'; sink.push(f); });
          var res = await cache.match(reqs[i]);
          if (!res) continue;
          var ct = (res.headers.get('content-type') || '').toLowerCase();
          if (/^(image|video|audio|font)\b/.test(ct) || /wasm|octet-stream/.test(ct)) continue;
          var t = await res.text();
          if (!t) continue;
          if (t.length > budget) t = t.slice(0, budget);
          budget -= t.length;
          GAKS.findInText(t).forEach(function (f) { f.source = 'cache'; sink.push(f); });
        } catch (e) { /* entry unreadable */ }
      }
    }
  }

  function scanClientStores() {
    if (storesScanned) return;
    storesScanned = true;
    var sink = [];
    Promise.resolve()
      .then(function () { return scanIndexedDb(sink); })
      .then(function () { return scanCacheStorage(sink); })
      .catch(function () { /* ignore */ })
      .then(function () { if (sink.length) reportFindings(sink); });
  }

  function start() {
    // Bridge network-interception findings from the MAIN-world interceptor.
    // Always forward to the background worker — even if the key was already seen
    // via DOM/storage, upsertFinding will merge the 'network' source tag.
    window.addEventListener('message', function (ev) {
      if (ev.source !== window) return;
      if (!ev.data || ev.data.type !== '__GAKS_NET_FINDING__') return;
      var d = ev.data;
      var key = d.key;
      if (!key) return;
      var netKey = 'net:' + key + ':' + (d.source || '');
      if (reported[netKey]) return;
      reported[netKey] = true;
      // Map the interceptor's fine-grained source to a stored source tag.
      // window.* globals / history.state → 'window'; closed shadow roots →
      // 'shadow'; everything else it sends is request/response traffic.
      var fSource = (d.source && d.source.indexOf('window') === 0) ? 'window'
        : (d.source === 'shadow' ? 'shadow' : 'network');
      if (!reported[key]) {
        reported[key] = { source: fSource, snippet: d.snippet, mapsContext: !!d.mapsContext };
      }
      try {
        chrome.runtime.sendMessage({
          type: 'GAKS_FINDINGS',
          pageUrl: pageUrl,
          origin: origin,
          findings: [{
            key: key,
            provider: d.provider || 'google',
            secret: d.secret || undefined,
            source: fSource,
            snippet: '[' + (d.source || 'network') + '] ' + (d.snippet || key.slice(0, 10) + '…'),
            mapsContext: !!d.mapsContext
          }]
        }, function () { void chrome.runtime.lastError; });
      } catch (e) { /* context invalidated */ }
    });
    // Flush any findings the interceptor captured before we were ready.
    try { window.postMessage({ type: '__GAKS_NET_FLUSH__' }, '*'); } catch (e) { /* ignore */ }

    // Initial scan once the page settles.
    scanAndReport();

    // Watch for dynamically injected scripts/markup.
    try {
      var observer = new MutationObserver(function () { scheduleScan(); });
      observer.observe(document.documentElement || document, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['src', 'href', 'data-src']
      });
    } catch (e) {
      /* no document element yet — fall back to a couple of timed scans */
    }

    // A few delayed sweeps catch async resource loads not tied to DOM mutations.
    setTimeout(scheduleScan, 1500);
    setTimeout(scheduleScan, 4000);

    // IndexedDB / Cache Storage settle after the app boots — scan once.
    setTimeout(scanClientStores, 2500);

    // Allow the popup/worker to force a re-scan (e.g. user clicked "rescan").
    chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
      if (msg && msg.type === 'GAKS_RESCAN') {
        reported = Object.create(null);
        sentScripts = Object.create(null);
        storesScanned = false;
        scanAndReport();
        scanClientStores();
        sendResponse({ ok: true });
      }
      return false;
    });
  }

  // Skip detection only on ignored domains; never let an ignore-check error
  // silently disable detection.
  function safeStart(extra) {
    try {
      if (GAKS.hostIsIgnored(location.hostname, extra || [])) return; // ignored page
    } catch (e) { /* ignore-check failed → don't block detection */ }
    try { start(); } catch (e) { /* ignore */ }
  }
  try {
    chrome.storage.local.get('gaks_ignore_domains', function (res) {
      void chrome.runtime.lastError;
      var extra = res && Array.isArray(res.gaks_ignore_domains) ? res.gaks_ignore_domains : [];
      safeStart(extra);
    });
  } catch (e) {
    safeStart([]);
  }
})();
