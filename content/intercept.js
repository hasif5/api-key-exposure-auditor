/*
 * intercept.js — MAIN-world network interceptor.
 *
 * Injected at document_start into the page's main JS world. Monkey-patches
 * fetch(), XMLHttpRequest, WebSocket, EventSource, and sendBeacon to scan
 * request/response bodies, headers, and URLs for exposed API keys. Findings
 * are posted to the extension's isolated-world content script via
 * window.postMessage.
 *
 * Detection patterns must stay in sync with content/patterns.js and
 * lib/providers.js (the test suite verifies parity).
 */
(function () {
  if (window.__GAKS_INTERCEPT__) return;
  window.__GAKS_INTERCEPT__ = true;

  var MSG_TYPE = '__GAKS_NET_FINDING__';
  var FLUSH_TYPE = '__GAKS_NET_FLUSH__';
  var MAX_BODY = 2 * 1024 * 1024;
  var LOG = '[GAKS-NET] ';
  // Per-request tracing — off by default so we don't clutter the host page's
  // console. Flip to true when debugging detection.
  var DEBUG = false;
  function dbg() { if (!DEBUG) return; try { console.log.apply(console, arguments); } catch (e) {} }

  try { dbg(LOG + 'interceptor loaded on', location.href); } catch (e) { /* test sandbox */ }

  // ---- Detection patterns (mirror of patterns.js / providers.js) ----
  function twilioSecret(text, index, sid) {
    var s = Math.max(0, index - 700), e = Math.min(text.length, index + 700);
    var re = /[0-9a-fA-F]{32}/g, m, slice = text.slice(s, e);
    while ((m = re.exec(slice)) !== null) { if (sid.indexOf(m[0]) === -1) return m[0]; }
    return null;
  }

  function awsSecret(text, index, id) {
    var slice = text.slice(Math.max(0, index - 500), Math.min(text.length, index + 500));
    var kw = /secret[_a-z]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})/i.exec(slice);
    if (kw && id.indexOf(kw[1]) === -1) return kw[1];
    var re = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g, m;
    while ((m = re.exec(slice)) !== null) { if (id.indexOf(m[0]) === -1) return m[0]; }
    return null;
  }

  var PATTERNS = [
    { id: 'google',     re: /(?<![A-Za-z0-9_-])(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})(?![A-Za-z0-9_-])/g },
    { id: 'anthropic',  re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{90,}/g },
    { id: 'openrouter', re: /(?<![A-Za-z0-9])sk-or-(?:v1-)?[A-Za-z0-9]{40,}/g },
    { id: 'xai',        re: /(?<![A-Za-z0-9])xai-[A-Za-z0-9]{40,}/g },
    { id: 'openai',     re: /(?<![A-Za-z0-9])(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})/g },
    { id: 'twilio',     re: /(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![0-9a-fA-F])/g, context: /twilio|account[\s_-]?sid|auth[\s_-]?token/i, secret: twilioSecret },
    { id: 'aws',        re: /(?<![A-Za-z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])/g, secret: awsSecret },
    { id: 'github',     re: /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{59,})(?![A-Za-z0-9])/g }
  ];

  var MAPS_HINTS = ['maps.googleapis.com', 'maps.google.com', 'maps.gstatic.com',
    '/maps/api/', 'staticmap', '/maps/embed', 'google.maps', 'gmaps'];

  function hasMapsCtx(text) {
    if (!text) return false;
    var l = text.toLowerCase();
    for (var i = 0; i < MAPS_HINTS.length; i++) { if (l.indexOf(MAPS_HINTS[i]) !== -1) return true; }
    return false;
  }

  // ---- Generic "looks like a secret" heuristics (provider: 'unknown') ----
  // MUST be kept in sync with lib/providers.js and content/patterns.js.
  var GENERIC_TOKEN_PATTERNS = [
    { label: 'GitLab token', re: /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])/g },
    { label: 'Slack token', re: /(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])/g },
    { label: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]+/g },
    { label: 'Stripe secret key', re: /(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])/g },
    { label: 'SendGrid API key', re: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9])/g },
    { label: 'Google OAuth client secret', re: /(?<![A-Za-z0-9])GOCSPX-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])/g },
    { label: 'npm access token', re: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g },
    { label: 'Shopify access token', re: /(?<![A-Za-z0-9])shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}(?![A-Za-z0-9])/g },
    { label: 'Twilio API key SID', re: /(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![0-9a-f])/g },
    { label: 'Mailgun API key', re: /(?<![A-Za-z0-9])key-[0-9a-f]{32}(?![A-Za-z0-9])/g },
    { label: 'JSON Web Token (JWT)', re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])/g },
    { label: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,4000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
    { label: 'Connection string with embedded credentials', re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|https?|ftp):\/\/[^\s:@/]+:[^\s:@/]{2,}@[^\s/?#"'`\\]+/gi },
    { label: 'HuggingFace token', re: /(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])/g },
    { label: 'Replicate API token', re: /(?<![A-Za-z0-9])r8_[A-Za-z0-9]{37,}(?![A-Za-z0-9])/g },
    { label: 'Groq API key', re: /(?<![A-Za-z0-9])gsk_[A-Za-z0-9]{48,}(?![A-Za-z0-9])/g },
    { label: 'DigitalOcean token', re: /(?<![A-Za-z0-9])dop_v1_[a-f0-9]{64}(?![A-Za-z0-9])/g },
    { label: 'Stripe webhook secret', re: /(?<![A-Za-z0-9])whsec_[A-Za-z0-9]{32,}(?![A-Za-z0-9])/g },
    { label: 'Notion token', re: /(?<![A-Za-z0-9])(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{43,})(?![A-Za-z0-9])/g },
    { label: 'Linear API key', re: /(?<![A-Za-z0-9])lin_api_[A-Za-z0-9]{40,}(?![A-Za-z0-9])/g },
    { label: 'Telegram bot token', re: /(?<![A-Za-z0-9])\d{8,10}:AA[A-Za-z0-9_-]{32,}(?![A-Za-z0-9])/g },
    { label: 'Discord bot token', re: /(?<![A-Za-z0-9])[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}(?![A-Za-z0-9])/g },
    { label: 'Sentry DSN', re: /https:\/\/[a-z0-9]+@[a-z0-9.-]*sentry\.io\/\d+/gi },
    { label: 'Mailchimp API key', re: /(?<![A-Za-z0-9])[0-9a-f]{32}-us\d{1,2}(?![A-Za-z0-9])/g }
  ];
  var GENERIC_ASSIGN_RE = /(?<![A-Za-z0-9_])(api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|access[_-]?key|password|passwd|token)["']?\s*[:=]\s*["']([^"'\s]{16,200})["']/gi;
  var GENERIC_PLACEHOLDER_RE = /your|example|placeholder|change[_-]?me|redacted|dummy|sample|xxxx|todo|insert|enter|^[A-Za-z]+$|<|\{|\$/i;
  var GENERIC_CHARSET_RE = /^[A-Za-z0-9_\-+/.=~]+$/;

  function genericEntropy(s) {
    var freq = Object.create(null), i;
    for (i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    var e = 0;
    for (var k in freq) { var p = freq[k] / s.length; e -= p * Math.log(p) / Math.LN2; }
    return e;
  }

  function looksSecret(v) {
    if (!v || v.length < 16 || v.length > 200) return false;
    if (!GENERIC_CHARSET_RE.test(v)) return false;
    if (GENERIC_PLACEHOLDER_RE.test(v)) return false;
    if (!/[A-Za-z]/.test(v) || !/[0-9]/.test(v)) return false;
    return genericEntropy(v) >= 3.0;
  }

  function genericSnippet(text, index, len) {
    var s = Math.max(0, index - 100), e = Math.min(text.length, index + len + 100);
    var out = text.slice(s, e).replace(/\s+/g, ' ').trim();
    if (s > 0) out = '…' + out;
    if (e < text.length) out += '…';
    return out;
  }

  // ---- Scan engine ----
  var reported = {};
  var queue = [];

  function scanText(text, source, url) {
    if (!text || typeof text !== 'string') return;
    if (text.length > MAX_BODY) text = text.slice(0, MAX_BODY);
    for (var p = 0; p < PATTERNS.length; p++) {
      var pat = PATTERNS[p];
      pat.re.lastIndex = 0;
      var m;
      while ((m = pat.re.exec(text)) !== null) {
        var key = m[0];
        if (reported[key]) continue;
        if (pat.context) {
          var ctx = text.slice(Math.max(0, m.index - 250), Math.min(text.length, m.index + 250));
          if (!pat.context.test(ctx)) continue;
        }
        reported[key] = true;
        var s = Math.max(0, m.index - 60), e = Math.min(text.length, m.index + key.length + 60);
        var snippet = text.slice(s, e).replace(/\s+/g, ' ').trim();
        if (s > 0) snippet = '…' + snippet;
        if (e < text.length) snippet += '…';
        var secret = pat.secret ? pat.secret(text, m.index, key) : null;
        if (secret) { snippet += ' · secret: ' + secret; reported[secret] = true; }
        var finding = {
          type: MSG_TYPE, key: key, provider: pat.id, source: source,
          snippet: snippet, secret: secret,
          mapsContext: pat.id === 'google' && hasMapsCtx(snippet + ' ' + (url || ''))
        };
        dbg(LOG + 'FOUND key [' + pat.id + '] via ' + source, key.slice(0, 14) + '…', url || '');
        try { window.postMessage(finding, '*'); } catch (ignore) {}
        queue.push(finding);
      }
    }
    scanGeneric(text, source, url);
  }

  // Emit 'unknown' findings for credentials we have no dedicated pattern for.
  function emitGeneric(key, reason, snippet, source, url) {
    if (reported[key]) return;
    reported[key] = true;
    var finding = {
      type: MSG_TYPE, key: key, provider: 'unknown', source: source,
      snippet: reason + ' — ' + snippet, secret: null, reason: reason, mapsContext: false
    };
    dbg(LOG + 'FOUND unknown [' + reason + '] via ' + source, key.slice(0, 14) + '…', url || '');
    try { window.postMessage(finding, '*'); } catch (ignore) {}
    queue.push(finding);
  }

  function scanGeneric(text, source, url) {
    for (var i = 0; i < GENERIC_TOKEN_PATTERNS.length; i++) {
      var pat = GENERIC_TOKEN_PATTERNS[i];
      pat.re.lastIndex = 0;
      var m;
      while ((m = pat.re.exec(text)) !== null) {
        if (reported[m[0]]) continue;
        emitGeneric(m[0], pat.label, genericSnippet(text, m.index, m[0].length), source, url);
      }
    }
    GENERIC_ASSIGN_RE.lastIndex = 0;
    var a;
    while ((a = GENERIC_ASSIGN_RE.exec(text)) !== null) {
      var kw = a[1], val = a[2];
      if (reported[val] || !looksSecret(val)) continue;
      var idx = a.index + a[0].lastIndexOf(val);
      emitGeneric(val, 'secret-like value assigned to "' + kw + '"', genericSnippet(text, idx, val.length), source, url);
    }
  }

  window.addEventListener('message', function (ev) {
    if (ev.source !== window || !ev.data || ev.data.type !== FLUSH_TYPE) return;
    for (var i = 0; i < queue.length; i++) {
      try { window.postMessage(queue[i], '*'); } catch (ignore) {}
    }
    queue = [];
  });

  // ---- Helpers ----
  var MAX_BIN = 256 * 1024;
  var _decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { fatal: false }) : null;

  function decodeBuffer(buf) {
    if (!_decoder || !buf) return null;
    try {
      var ab = buf instanceof ArrayBuffer ? buf : buf.buffer ? buf.buffer : null;
      if (!ab || ab.byteLength === 0 || ab.byteLength > MAX_BIN) return null;
      return _decoder.decode(ab);
    } catch (e) { return null; }
  }

  function decodeBlob(blob, cb) {
    if (!blob || blob.size === 0 || blob.size > MAX_BIN) return;
    try {
      var r = new FileReader();
      r.onload = function () { if (typeof r.result === 'string') cb(r.result); };
      r.readAsText(blob);
    } catch (e) { /* ignore */ }
  }

  function bodyStr(body) {
    if (!body) return null;
    if (typeof body === 'string') return body;
    if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) return body.toString();
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      var parts = [];
      try { body.forEach(function (v, k) { parts.push(k + '=' + v); }); } catch (ignore) {}
      return parts.length ? parts.join('&') : null;
    }
    return null;
  }

  function textualCt(ct) {
    return /json|text|javascript|xml|html|form-urlencoded|yaml|toml/.test(ct);
  }

  function scanHeaders(hdrs, url) {
    if (!hdrs) return;
    var ht = '';
    try {
      if (typeof Headers !== 'undefined' && hdrs instanceof Headers) {
        hdrs.forEach(function (v, k) { ht += k + ': ' + v + '\n'; });
      } else if (typeof hdrs === 'object' && !Array.isArray(hdrs)) {
        Object.keys(hdrs).forEach(function (k) { ht += k + ': ' + hdrs[k] + '\n'; });
      } else if (Array.isArray(hdrs)) {
        hdrs.forEach(function (pair) { if (Array.isArray(pair) && pair.length >= 2) ht += pair[0] + ': ' + pair[1] + '\n'; });
      }
    } catch (ignore) {}
    if (ht) scanText(ht, 'network-request', url);
  }

  // ---- Patch fetch() ----
  try {
    var _fetch = window.fetch;
    window.fetch = function () {
      var args = arguments, url = '', init;
      try {
        dbg(LOG + 'fetch intercepted:', String(args[0] && args[0].url ? args[0].url : args[0] || '').slice(0, 120));
        var isReq = typeof Request !== 'undefined' && args[0] instanceof Request;
        if (isReq) {
          url = args[0].url;
          scanText(url, 'network-request', url);
          scanHeaders(args[0].headers, url);
          // Request body can only be read once; reading it would break the
          // actual fetch, so we skip it and rely on the init override below.
        } else {
          url = String(args[0] || '');
          scanText(url, 'network-request', url);
        }
        init = args[1] || {};
        var b = bodyStr(init.body);
        if (b) scanText(b, 'network-request', url);
        if (init.headers) scanHeaders(init.headers, url);
      } catch (ignore) {}
      var promise = _fetch.apply(this, args);
      promise.then(function (res) {
        try {
          var ct = (res.headers.get('content-type') || '').toLowerCase();
          // Scan all responses that aren't obviously binary (images, video, audio, fonts, wasm)
          if (/^(image|video|audio|font)\b/.test(ct) || /wasm|octet-stream/.test(ct)) return;
          res.clone().text().then(function (t) {
            if (t && t.length < MAX_BODY) {
              dbg(LOG + 'fetch response scanned:', (res.url || url).slice(0, 120), '(' + t.length + ' bytes)');
              try { scanText(t, 'network-response', res.url || url); } catch (ignore) {}
            }
          }).catch(function () {});
        } catch (ignore) {}
      }).catch(function () {});
      return promise;
    };
  } catch (ignore) {}

  // ---- Patch XMLHttpRequest ----
  try {
    var _open = XMLHttpRequest.prototype.open;
    var _send = XMLHttpRequest.prototype.send;
    var _setH = XMLHttpRequest.prototype.setRequestHeader;

    XMLHttpRequest.prototype.open = function (method, u) {
      this.__gaks_url = String(u || '');
      this.__gaks_hdr = '';
      dbg(LOG + 'XHR intercepted:', method, String(u || '').slice(0, 120));
      try { scanText(this.__gaks_url, 'network-request', this.__gaks_url); } catch (ignore) {}
      return _open.apply(this, arguments);
    };

    XMLHttpRequest.prototype.setRequestHeader = function (n, v) {
      try { this.__gaks_hdr = (this.__gaks_hdr || '') + n + ': ' + v + '\n'; } catch (ignore) {}
      return _setH.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function (body) {
      try {
        var b = bodyStr(body);
        if (b) scanText(b, 'network-request', this.__gaks_url);
        if (this.__gaks_hdr) scanText(this.__gaks_hdr, 'network-request', this.__gaks_url);
      } catch (ignore) {}
      var xhr = this;
      xhr.addEventListener('load', function () {
        try {
          var ct = (xhr.getResponseHeader('content-type') || '').toLowerCase();
          if (/^(image|video|audio|font)\b/.test(ct) || /wasm|octet-stream/.test(ct)) return;
          if (xhr.responseText) {
            dbg(LOG + 'XHR response scanned:', (xhr.__gaks_url || '').slice(0, 120), '(' + xhr.responseText.length + ' bytes)');
            scanText(xhr.responseText, 'network-response', xhr.__gaks_url);
          }
        } catch (ignore) {}
      });
      return _send.apply(this, arguments);
    };
  } catch (ignore) {}

  // ---- Patch WebSocket ----
  try {
    var _WS = window.WebSocket;
    if (_WS) {
      window.WebSocket = function (u, protocols) {
        dbg(LOG + 'WebSocket intercepted:', String(u || '').slice(0, 120));
        try { scanText(String(u || ''), 'websocket', String(u || '')); } catch (ignore) {}
        var ws = arguments.length > 1 ? new _WS(u, protocols) : new _WS(u);
        var wsUrl = String(u || '');
        var origSend = ws.send;
        ws.send = function (data) {
          try {
            if (ws.readyState === _WS.OPEN) {
              if (typeof data === 'string') scanText(data, 'websocket', wsUrl);
              else if (data instanceof ArrayBuffer || (data && data.buffer instanceof ArrayBuffer)) {
                var t = decodeBuffer(data);
                if (t) scanText(t, 'websocket', wsUrl);
              } else if (typeof Blob !== 'undefined' && data instanceof Blob) {
                decodeBlob(data, function (t) { scanText(t, 'websocket', wsUrl); });
              }
            }
          } catch (ignore) {}
          try { return origSend.call(ws, data); } catch (e) {
            if (ws.readyState !== _WS.OPEN) return;
            throw e;
          }
        };
        ws.addEventListener('message', function (ev) {
          try {
            var d = ev.data;
            if (typeof d === 'string') scanText(d, 'websocket', wsUrl);
            else if (d instanceof ArrayBuffer) {
              var t = decodeBuffer(d);
              if (t) scanText(t, 'websocket', wsUrl);
            } else if (typeof Blob !== 'undefined' && d instanceof Blob) {
              decodeBlob(d, function (t) { scanText(t, 'websocket', wsUrl); });
            }
          } catch (ignore) {}
        });
        return ws;
      };
      window.WebSocket.prototype = _WS.prototype;
      window.WebSocket.CONNECTING = _WS.CONNECTING;
      window.WebSocket.OPEN = _WS.OPEN;
      window.WebSocket.CLOSING = _WS.CLOSING;
      window.WebSocket.CLOSED = _WS.CLOSED;
    }
  } catch (ignore) {}

  // ---- Patch EventSource (SSE) ----
  try {
    var _ES = window.EventSource;
    if (_ES) {
      window.EventSource = function (u, init) {
        dbg(LOG + 'EventSource intercepted:', String(u || '').slice(0, 120));
        try { scanText(String(u || ''), 'eventsource', String(u || '')); } catch (ignore) {}
        var es = arguments.length > 1 ? new _ES(u, init) : new _ES(u);
        es.addEventListener('message', function (ev) {
          try { if (typeof ev.data === 'string') scanText(ev.data, 'eventsource', String(u || '')); } catch (ignore) {}
        });
        return es;
      };
      window.EventSource.prototype = _ES.prototype;
      window.EventSource.CONNECTING = _ES.CONNECTING;
      window.EventSource.OPEN = _ES.OPEN;
      window.EventSource.CLOSED = _ES.CLOSED;
    }
  } catch (ignore) {}

  // ---- Patch navigator.sendBeacon ----
  try {
    var _beacon = navigator.sendBeacon;
    if (_beacon) {
      navigator.sendBeacon = function (u, data) {
        dbg(LOG + 'sendBeacon intercepted:', String(u || '').slice(0, 120));
        try {
          scanText(String(u || ''), 'beacon', String(u || ''));
          var b = bodyStr(data);
          if (b) scanText(b, 'beacon', String(u || ''));
        } catch (ignore) {}
        return _beacon.apply(navigator, arguments);
      };
    }
  } catch (ignore) {}

  // ---- Scan the page's runtime globals -------------------------------------
  // Config left on `window` (window.ENV, window.__APP_CONFIG__, firebase opts…)
  // never reaches the serialized DOM, so the isolated-world content script can't
  // see it. Object.keys(window) is just the page's own globals (plus id'd
  // elements), not the WebIDL built-ins, so this stays cheap. Found keys ride
  // the same postMessage bridge as network findings.
  var MAX_GLOBAL = 512 * 1024; // cap serialized size per global object

  // JSON.stringify with an early bail-out: throws once accumulated string
  // content exceeds MAX_GLOBAL, so a giant in-memory store can't stall the page.
  function boundedStringify(v) {
    var n = 0;
    return JSON.stringify(v, function (key, val) {
      if (typeof val === 'string') {
        n += val.length;
        if (n > MAX_GLOBAL) throw 0;
      }
      return val;
    });
  }

  function scanGlobals() {
    try {
      var keys = Object.keys(window);
      var cap = Math.min(keys.length, 2000);
      for (var i = 0; i < cap; i++) {
        var k = keys[i], v;
        try { v = window[k]; } catch (e) { continue; }
        if (v == null) continue;
        var t = typeof v;
        if (t === 'string') {
          if (v.length > 8) scanText(k + '=' + v, 'window-global', location.href);
        } else if (t === 'object') {
          if (v === window) continue;
          if (typeof Node !== 'undefined' && v instanceof Node) continue;
          if (typeof Window !== 'undefined' && v instanceof Window) continue;
          var s;
          try { s = boundedStringify(v); } catch (e) { continue; } // circular / too big / non-serializable
          if (s && s.length > 8) scanText(k + '=' + s, 'window-global', location.href);
        }
      }
    } catch (e) { /* ignore */ }
  }

  try {
    // Guard on `document` so the headless test sandbox never schedules timers.
    if (typeof document !== 'undefined') {
      setTimeout(scanGlobals, 2500);
      setTimeout(scanGlobals, 6000);
    }
  } catch (ignore) {}
})();
