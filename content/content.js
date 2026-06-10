/*
 * content.js — scans the rendered page for Google API keys.
 *
 * Surfaces covered:
 *   - Full serialized DOM (inline scripts, attributes, iframe/img/link URLs).
 *   - Resource-timing entries (URLs of resources the page fetched).
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

  function collectDomFindings() {
    var html = '';
    try {
      html = document.documentElement ? document.documentElement.outerHTML : '';
    } catch (e) {
      html = '';
    }
    var shadow = shadowHtml();
    if (shadow) html += '\n' + shadow;
    return GAKS.findInText(html).map(function (r) {
      r.source = 'dom';
      return r;
    });
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

  function scanAndReport() {
    pending = false;
    reportScripts();
    var found = collectDomFindings()
      .concat(collectResourceFindings())
      .concat(collectStorageFindings());
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

  function scheduleScan() {
    if (pending) return;
    pending = true;
    setTimeout(scanAndReport, 400);
  }

  function start() {
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

    // Allow the popup/worker to force a re-scan (e.g. user clicked "rescan").
    chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
      if (msg && msg.type === 'GAKS_RESCAN') {
        reported = Object.create(null);
        sentScripts = Object.create(null);
        scanAndReport();
        sendResponse({ ok: true });
      }
      return false;
    });
  }

  // Skip detection entirely on ignored domains (e.g. google.com, youtube.com).
  try {
    chrome.storage.local.get('gaks_ignore_domains', function (res) {
      void chrome.runtime.lastError;
      var extra = res && Array.isArray(res.gaks_ignore_domains) ? res.gaks_ignore_domains : [];
      if (GAKS.hostIsIgnored(location.hostname, extra)) return; // do nothing on this page
      start();
    });
  } catch (e) {
    // storage unavailable — fall back to default-list check only.
    if (!GAKS.hostIsIgnored(location.hostname, [])) start();
  }
})();
