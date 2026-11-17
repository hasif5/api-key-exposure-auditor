/*
 * intercept.js — MAIN-world network interceptor.
 *
 * Injected at document_start into the page's main JS world. Monkey-patches
 * fetch(), XMLHttpRequest, WebSocket, EventSource, and sendBeacon to scan
 * request/response bodies, headers, and URLs for exposed API keys. Findings
 * are handed to the extension's isolated-world scripts over a private
 * CustomEvent channel set up with content/bridge.js at document_start.
 *
 * Detection patterns must stay in sync with content/patterns.js and
 * lib/providers.js (the test suite verifies parity).
 */
(function () {
  if (window.__GAKS_INTERCEPT__) return;
  window.__GAKS_INTERCEPT__ = true;

  var MSG_TYPE = '__GAKS_NET_FINDING__';
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
    // Prefer a labelled auth token over the first unlabelled 32-hex run.
    var kw = /auth[\s_-]?token["']?\s*[:=]\s*["']?([0-9a-fA-F]{32})(?![0-9a-fA-F])/i.exec(slice);
    if (kw && sid.indexOf(kw[1]) === -1) return kw[1];
    while ((m = re.exec(slice)) !== null) { if (sid.indexOf(m[0]) === -1) return m[0]; }
    return null;
  }

  function awsSecret(text, index, id) {
    var slice = text.slice(Math.max(0, index - 1500), Math.min(text.length, index + 1500));
    var kw = /secret[_a-z]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})/i.exec(slice);
    if (kw && id.indexOf(kw[1]) === -1) return kw[1];
    var re = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g, m;
    // Mixed-case base64 with digits only: a 40-char hex run is a SHA-1, not a secret.
    while ((m = re.exec(slice)) !== null) {
      if (id.indexOf(m[0]) === -1 && /[a-z]/.test(m[0]) && /[A-Z]/.test(m[0]) && /[0-9]/.test(m[0])) return m[0];
    }
    var far = /aws[_-]?secret[_a-z]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})/i.exec(text);
    if (far && id.indexOf(far[1]) === -1) return far[1];
    return null;
  }

  var PATTERNS = [
    { id: 'google',     re: /(?<![A-Za-z0-9_-])(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})(?![A-Za-z0-9_-])/g },
    { id: 'anthropic',  re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{90,}/g },
    { id: 'openrouter', re: /(?<![A-Za-z0-9])sk-or-(?:v1-)?[A-Za-z0-9]{40,}/g },
    { id: 'xai',        re: /(?<![A-Za-z0-9])xai-[A-Za-z0-9]{40,}/g },
    { id: 'openai',     re: /(?<![A-Za-z0-9])(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})/g },
    { id: 'twilio',     re: /(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![0-9a-fA-F])/g, context: /twilio|account[\s_-]?sid|auth[\s_-]?token/i, secret: twilioSecret },
    { id: 'aws',        re: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z2-7]{16}(?![A-Za-z0-9])/g, secret: awsSecret },
    { id: 'github',     re: /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{59,})(?![A-Za-z0-9])/g },
    { id: 'gitlab',     re: /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])/g },
    { id: 'slack',      re: /(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])/g },
    { id: 'stripe',     re: /(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])/g }
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
    { label: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]+/g },
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
    { label: 'Mailchimp API key', re: /(?<![A-Za-z0-9])[0-9a-f]{32}-us\d{1,2}(?![A-Za-z0-9])/g }
  ];
  // Keyword-assignment heuristic: anchors on the keyword; the surrounding name
  // (REACT_APP_API_KEY, openaiApiKey, token_prod) is recovered in code.
  var GENERIC_ASSIGN_RE = /(api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|access[_-]?key|password|passwd|token)([A-Za-z0-9_-]{0,24})["']?\s*[:=]\s*["']([^"'\s]{16,200})["']/gi;
  var GENERIC_ENV_RE = /^[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]{0,60})[ \t]*=[ \t]*([^\s"'#]{16,200})[ \t]*(?:#.*)?\r?$/gm;
  var GENERIC_ENV_NAME_RE = /(?:^|_)(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY)(?:_|$)/;
  var GENERIC_NAME_DENY_RE = /csrf|xsrf|captcha|nonce|public|publishable|placeholder|(?:page|next|prev|continuation|cursor|sync|upload|resume)[_-]?token|(?:name|id|ref|type|url|uri|path|file|label|field|header|param|prefix|suffix|length|hash|salt|expiry|expires?|ttl)$/i;
  // A quote must precede the scheme, so a live request header is not matched.
  var BEARER_LITERAL_RE = /["'`]Bearer\s+([A-Za-z0-9._~+/=-]{20,400})["'`]/g;
  var BASIC_LITERAL_RE = /["'`]Basic\s+([A-Za-z0-9+/]{16,400}={0,2})["'`]/g;
  var GENERIC_PLACEHOLDER_RE = /your|example|placeholder|change[_-]?me|redacted|dummy|sample|xxxx|todo|insert|enter|^[A-Za-z]+$|<|\{|\$/i;
  var GENERIC_CHARSET_RE = /^[A-Za-z0-9_\-+/.=~]+$/;
  var PLACEHOLDER_KEY_RE = /example|placeholder|dummy|sample|redacted|change[_-]?me|insert|your[_-]?(?:api[_-]?)?key|not[_-]?a[_-]?real|x{6,}|0{8,}|1234567|abcdefgh/i;
  var PLACEHOLDER_PASSWORD_RE = /^(?:pass(?:word|wd)?|pwd|secret|change[_-]?me|\*+|x+|\.+)$|your|example|placeholder|[<{$[]|%s/i;
  var DOTTED_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$/;
  var WORDY_SEGMENT_RE = /^(?:[A-Za-z]+|[0-9]{1,4}|v[0-9]+)$/;

  function isPlaceholderKey(k) {
    if (PLACEHOLDER_KEY_RE.test(k)) return true;
    var freq = Object.create(null), max = 0;
    for (var i = 0; i < k.length; i++) { var n = freq[k[i]] = (freq[k[i]] || 0) + 1; if (n > max) max = n; }
    return max / k.length > 0.5;
  }

  function looksLikeIdentifier(v) {
    if (v.indexOf('eyJ') !== 0 && DOTTED_PATH_RE.test(v)) return true;
    if (/^\.{1,2}\//.test(v) || /\/[^/]*\.[A-Za-z]{2,5}$/.test(v)) return true;
    var segs = v.split(/[-_./]/);
    if (segs.length >= 3) {
      var wordy = true;
      for (var i = 0; i < segs.length; i++) { if (!WORDY_SEGMENT_RE.test(segs[i])) { wordy = false; break; } }
      if (wordy) return true;
    }
    return false;
  }

  // Per-shape triage for token-pattern hits: the label to report, or null to drop.
  function genericCheck(label, key) {
    if (label === 'JSON Web Token (JWT)') {
      var claims = null;
      try { var payload = b64decode(key.split('.')[1]); claims = payload ? JSON.parse(payload) : null; } catch (e) { claims = null; }
      if (!claims || typeof claims !== 'object') return label;
      if (typeof claims.exp === 'number' && claims.exp * 1000 < Date.now()) return null; // expired
      if (claims.role === 'anon') return null; // Supabase anon key — public by design
      if (claims.role === 'service_role') return 'Supabase service_role JWT (bypasses row-level security)';
      return label;
    }
    if (label === 'Connection string with embedded credentials') {
      var m = /^[a-z+]+:\/\/[^:@/]+:([^@]+)@/i.exec(key);
      return m && PLACEHOLDER_PASSWORD_RE.test(m[1]) ? null : label;
    }
    if (label === 'Private key block' || label === 'Slack webhook URL') return label;
    return isPlaceholderKey(key) ? null : label;
  }

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
    if (looksLikeIdentifier(v)) return false;
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
  // Dedupe is per surface group (network / window globals / shadow DOM), so a
  // key seen on several surfaces is reported once for each. `suppressed` holds
  // strings that must never be reported on their own: pair secrets already
  // attached to a finding, and placeholder-shaped matches.
  var reported = Object.create(null);
  var suppressed = Object.create(null);
  var curGroup = 'n';
  function isSeen(k) { return !!(suppressed[k] || reported[curGroup + '|' + k]); }
  function markSeen(k) { reported[curGroup + '|' + k] = true; }

  // ---- Private channel to the isolated world --------------------------------
  // Findings carry live credentials, so they must not be broadcast with
  // window.postMessage (every script on the page could read them, and any
  // script could forge them). content/bridge.js picks a random event name at
  // document_start and hands it over before any page script runs; findings are
  // then dispatched as CustomEvents under that name, using references to the
  // native DOM methods captured here so later page patches are not invoked.
  var _doc = typeof document !== 'undefined' ? document : null;
  var _CE = typeof CustomEvent !== 'undefined' ? CustomEvent : null;
  var _dispatch = _doc ? _doc.dispatchEvent : null;
  var _addL = _doc ? _doc.addEventListener : null;
  var _removeL = _doc ? _doc.removeEventListener : null;
  var _stringify = JSON.stringify;
  var channel = null;
  var handshakeOpen = !!(_doc && _CE);
  var queue = [];

  function send(obj) {
    try { _dispatch.call(_doc, new _CE(channel, { detail: _stringify(obj) })); } catch (ignore) {}
  }

  function emit(finding) {
    if (!_doc || !_CE) {
      // Headless test sandbox only (no DOM): surface findings to the harness.
      try { window.postMessage(finding, '*'); } catch (ignore) {}
      return;
    }
    if (channel) { send(finding); return; }
    if (handshakeOpen && queue.length < 500) queue.push(finding);
  }

  if (handshakeOpen) {
    try {
      var onInit = function (ev) {
        if (channel || !handshakeOpen) return;
        if (typeof ev.detail !== 'string' || !/^gaks-[0-9a-f]{32}$/.test(ev.detail)) return;
        channel = ev.detail;
        handshakeOpen = false;
        _removeL.call(_doc, '__gaks_init__', onInit, true);
        send({ type: '__GAKS_READY__' });
        for (var i = 0; i < queue.length; i++) send(queue[i]);
        queue = [];
      };
      _addL.call(_doc, '__gaks_init__', onInit, true);
      // If the bridge loaded first it is waiting for this.
      _dispatch.call(_doc, new _CE('__gaks_hello__'));
      // Both scripts are injected at document_start; once that turn is over,
      // stop accepting a channel name so a page script cannot supply its own.
      setTimeout(function () {
        if (channel) return;
        handshakeOpen = false;
        queue = [];
        try { _removeL.call(_doc, '__gaks_init__', onInit, true); } catch (ignore) {}
      }, 0);
    } catch (ignore) { handshakeOpen = false; }
  }

  // ---- Decode-and-rescan (mirror of lib/providers.js) ----
  var B64_BLOB_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])/g;
  function b64decode(s) {
    try {
      var t = s.replace(/-/g, '+').replace(/_/g, '/');
      var pad = t.length % 4;
      if (pad) t += new Array(5 - pad).join('=');
      var out = (typeof atob === 'function') ? atob(t) : null;
      if (!out) return null;
      var printable = 0;
      for (var i = 0; i < out.length; i++) { var c = out.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++; }
      return out.length >= 8 && printable / out.length > 0.85 ? out : null;
    } catch (e) { return null; }
  }
  var PCT_HIT_RE = /%[0-9A-Fa-f]{2}/g;
  var ESC_HIT_RE = /\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|u\{[0-9A-Fa-f]{1,6}\}|["'/])/g;
  var ENT_HIT_RE = /&(?:quot|apos|amp|lt|gt|#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6});/g;
  var ENT_NAMES = { quot: '"', apos: "'", amp: '&', lt: '<', gt: '>' };

  function pctDecode(tok) {
    return tok.replace(/(?:%[0-9A-Fa-f]{2})+/g, function (run) {
      try { return decodeURIComponent(run); } catch (e) { return run; }
    });
  }

  function escDecode(tok) {
    return tok.replace(/\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}|(["'/]))/g, function (all, a, b, c, d) {
      if (d) return d;
      var cp = parseInt(a || b || c, 16);
      return cp <= 0x10FFFF ? String.fromCodePoint(cp) : all;
    });
  }

  function entDecode(tok) {
    return tok.replace(/&(?:(quot|apos|amp|lt|gt)|#([0-9]{1,7})|#x([0-9A-Fa-f]{1,6}));/g, function (all, name, dec, hex) {
      if (name) return ENT_NAMES[name];
      var cp = dec ? parseInt(dec, 10) : parseInt(hex, 16);
      return cp > 0 && cp <= 0x10FFFF ? String.fromCodePoint(cp) : all;
    });
  }

  // Token boundary: whitespace, angle brackets, or an unescaped quote.
  function isDelimAt(text, i) {
    var c = text.charCodeAt(i);
    if (c === 32 || (c >= 9 && c <= 13) || c === 60 || c === 62) return true;
    if (c === 34 || c === 39 || c === 96) return !(i > 0 && text.charCodeAt(i - 1) === 92);
    return false;
  }

  // Decode only the tokens that contain an encoded sequence, not the whole
  // text: one stray "%" (width:100%) must not veto the layer.
  function decodeTokens(text, hitRe, decodeFn) {
    var parts = [], total = 0, tried = 0, lastEnd = 0, lastCapped = false, m;
    hitRe.lastIndex = 0;
    while (tried < 4000 && total < 524288 && (m = hitRe.exec(text)) !== null) {
      tried++;
      var s = m.index, e = m.index + m[0].length;
      var lim = Math.max(lastEnd, s - 2000);
      while (s > lim && !isDelimAt(text, s - 1)) s--;
      lim = Math.min(text.length, e + 2000);
      while (e < lim && !isDelimAt(text, e)) e++;
      var capped = e === lim && e < text.length;
      hitRe.lastIndex = e;
      var tok = text.slice(s, e), dec;
      try { dec = decodeFn(tok); } catch (err) { dec = null; }
      if (dec && dec !== tok) {
        if (lastCapped && s === lastEnd && parts.length) parts[parts.length - 1] += dec;
        else parts.push(dec);
        total += dec.length;
      }
      lastEnd = e;
      lastCapped = capped;
    }
    return parts.join('\n');
  }

  function decodeLayers(text) {
    var layers = [];
    if (text.length > 2000000) return layers;
    var pct = decodeTokens(text, PCT_HIT_RE, pctDecode);
    if (pct) layers.push(pct);
    var esc = decodeTokens(text, ESC_HIT_RE, escDecode);
    if (esc) layers.push(esc);
    var ent = decodeTokens(text, ENT_HIT_RE, entDecode);
    if (ent) layers.push(ent);
    // Shape filters first, so URL paths and long identifiers do not use up
    // the budget before a real blob is reached.
    B64_BLOB_RE.lastIndex = 0;
    var m, examined = 0, decoded = 0;
    while (examined < 4000 && decoded < 40 && (m = B64_BLOB_RE.exec(text)) !== null) {
      var c = m[0];
      if ((c.indexOf('/') !== -1 || c.indexOf('+') !== -1) && (c.indexOf('-') !== -1 || c.indexOf('_') !== -1)) continue;
      if (!/[a-z]/.test(c) || !/[A-Z]/.test(c) || !/[0-9]/.test(c)) continue;
      examined++;
      var d = b64decode(c);
      if (d) { layers.push(d.length > 65536 ? d.slice(0, 65536) : d); decoded++; }
    }
    return layers;
  }

  function scanText(text, source, url) {
    if (!text || typeof text !== 'string') return;
    if (text.length > MAX_BODY) text = text.slice(0, MAX_BODY);
    curGroup = source.indexOf('window') === 0 ? 'w' : (source === 'shadow' ? 's' : 'n');
    scanOne(text, source, url, '');
    var layers = decodeLayers(text);
    for (var i = 0; i < layers.length; i++) scanOne(layers[i], source, url, '[decoded] ');
  }

  function scanOne(text, source, url, pfx) {
    for (var p = 0; p < PATTERNS.length; p++) {
      var pat = PATTERNS[p];
      pat.re.lastIndex = 0;
      var m;
      while ((m = pat.re.exec(text)) !== null) {
        var key = m[0];
        if (isSeen(key)) continue;
        if (pat.context) {
          var ctx = text.slice(Math.max(0, m.index - 250), Math.min(text.length, m.index + 250));
          if (!pat.context.test(ctx)) continue;
        }
        if (isPlaceholderKey(key)) { suppressed[key] = true; continue; } // sk-xxxx…, AIza…EXAMPLE… — a stand-in, not a key
        markSeen(key);
        var s = Math.max(0, m.index - 60), e = Math.min(text.length, m.index + key.length + 60);
        var snippet = text.slice(s, e).replace(/\s+/g, ' ').trim();
        if (s > 0) snippet = '…' + snippet;
        if (e < text.length) snippet += '…';
        var secret = pat.secret ? pat.secret(text, m.index, key) : null;
        if (secret) { snippet += ' · secret: ' + secret; suppressed[secret] = true; }
        var finding = {
          type: MSG_TYPE, key: key, provider: pat.id, source: source,
          snippet: pfx + snippet, secret: secret,
          mapsContext: pat.id === 'google' && hasMapsCtx(snippet + ' ' + (url || ''))
        };
        dbg(LOG + 'FOUND key [' + pat.id + '] via ' + source, key.slice(0, 14) + '…', url || '');
        emit(finding);
      }
    }
    scanGeneric(text, source, url, pfx);
  }

  // Emit 'unknown' findings for credentials we have no dedicated pattern for.
  function emitGeneric(key, reason, snippet, source, url, pfx) {
    if (isSeen(key)) return;
    markSeen(key);
    var finding = {
      type: MSG_TYPE, key: key, provider: 'unknown', source: source,
      snippet: (pfx || '') + reason + ' — ' + snippet, secret: null, reason: reason, mapsContext: false
    };
    dbg(LOG + 'FOUND unknown [' + reason + '] via ' + source, key.slice(0, 14) + '…', url || '');
    emit(finding);
  }

  function scanGeneric(text, source, url, pfx) {
    for (var i = 0; i < GENERIC_TOKEN_PATTERNS.length; i++) {
      var pat = GENERIC_TOKEN_PATTERNS[i];
      pat.re.lastIndex = 0;
      var m;
      while ((m = pat.re.exec(text)) !== null) {
        if (isSeen(m[0])) continue;
        var label = genericCheck(pat.label, m[0]);
        if (!label) { suppressed[m[0]] = true; continue; }
        emitGeneric(m[0], label, genericSnippet(text, m.index, m[0].length), source, url, pfx);
      }
    }
    var name, val, idx;
    BEARER_LITERAL_RE.lastIndex = 0;
    while ((m = BEARER_LITERAL_RE.exec(text)) !== null) {
      var tok = m[1];
      if (isSeen(tok) || GENERIC_PLACEHOLDER_RE.test(tok) || !/[A-Za-z]/.test(tok) || !/[0-9]/.test(tok) ||
          looksLikeIdentifier(tok) || genericEntropy(tok) < 3.0) continue;
      emitGeneric(tok, 'Hard-coded Bearer token', genericSnippet(text, m.index + m[0].indexOf(tok), tok.length), source, url, pfx);
    }
    BASIC_LITERAL_RE.lastIndex = 0;
    while ((m = BASIC_LITERAL_RE.exec(text)) !== null) {
      var b64 = m[1];
      if (isSeen(b64)) continue;
      var pair = b64decode(b64);
      var pm = pair ? /^[^\s:]+:(\S{3,})$/.exec(pair) : null;
      if (!pm || PLACEHOLDER_PASSWORD_RE.test(pm[1])) continue;
      emitGeneric(b64, 'Hard-coded Basic auth credentials', genericSnippet(text, m.index + m[0].indexOf(b64), b64.length), source, url, pfx);
    }
    GENERIC_ASSIGN_RE.lastIndex = 0;
    while ((m = GENERIC_ASSIGN_RE.exec(text)) !== null) {
      var suffix = m[2];
      val = m[3];
      if (suffix && !/^[_\-0-9A-Z]/.test(suffix)) continue; // keyword must end its word
      if (isSeen(val) || !looksSecret(val)) continue;
      var s = m.index, lim = Math.max(0, s - 40);
      while (s > lim && /[A-Za-z0-9_.$-]/.test(text[s - 1])) s--;
      name = text.slice(s, m.index) + m[1] + suffix;
      if (GENERIC_NAME_DENY_RE.test(name)) continue;
      idx = m.index + m[0].lastIndexOf(val);
      emitGeneric(val, 'secret-like value assigned to "' + name + '"', genericSnippet(text, idx, val.length), source, url, pfx);
    }
    GENERIC_ENV_RE.lastIndex = 0;
    while ((m = GENERIC_ENV_RE.exec(text)) !== null) {
      name = m[1];
      val = m[2];
      if (isSeen(val) || !GENERIC_ENV_NAME_RE.test(name) || GENERIC_NAME_DENY_RE.test(name) || !looksSecret(val)) continue;
      idx = m.index + m[0].lastIndexOf(val);
      emitGeneric(val, 'secret-like value assigned to "' + name + '"', genericSnippet(text, idx, val.length), source, url, pfx);
    }
  }

  // ---- Helpers ----
  var MAX_BIN = 1024 * 1024;
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

  var BINARY_CT_RE = /^(?:image|video|audio|font)\b|wasm|octet-stream|zip|pdf/;

  // Scan a request body of any type fetch/XHR/sendBeacon accept. Strings,
  // URLSearchParams and FormData are read synchronously; Blobs (the usual
  // sendBeacon payload) and buffers are decoded as text.
  function scanBody(body, source, url) {
    if (!body) return;
    var b = bodyStr(body);
    if (b) { scanText(b, source, url); return; }
    if (typeof Blob !== 'undefined' && body instanceof Blob) {
      if (BINARY_CT_RE.test((body.type || '').toLowerCase())) return;
      decodeBlob(body, function (t) { try { scanText(t, source, url); } catch (ignore) {} });
      return;
    }
    if ((typeof ArrayBuffer !== 'undefined') && (body instanceof ArrayBuffer || (body.buffer instanceof ArrayBuffer))) {
      var t = decodeBuffer(body);
      if (t) scanText(t, source, url);
    }
  }

  // JSON.stringify with a budget. Past `limit` characters of string content
  // the remaining values are dropped, so a large store is scanned up to the
  // budget instead of being skipped whole; a pathological structure (hundreds
  // of thousands of nodes) still bails out by throwing.
  function boundedStringify(v, limit) {
    var n = 0, calls = 0;
    return JSON.stringify(v, function (key, val) {
      if (++calls > 200000) throw 0;
      if (n > limit) return undefined;
      n += key.length;
      if (typeof val === 'string') n += val.length;
      return val;
    });
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
        } else {
          url = String(args[0] || '');
          scanText(url, 'network-request', url);
        }
        init = args[1] || {};
        if (init.body) {
          scanBody(init.body, 'network-request', url);
        } else if (isReq && args[0].body && !args[0].bodyUsed) {
          // The Request's own body is single-use; read it from a clone so the
          // real fetch still gets an untouched stream.
          (function (reqUrl) {
            args[0].clone().text().then(function (t) {
              try { if (t) scanText(t, 'network-request', reqUrl); } catch (ignore) {}
            }).catch(function () {});
          })(url);
        }
        if (init.headers) scanHeaders(init.headers, url);
      } catch (ignore) {}
      var promise = _fetch.apply(this, args);
      promise.then(function (res) {
        try {
          // Response headers the page can read (API gateways echo keys here).
          var rh = '';
          res.headers.forEach(function (v, k) { rh += k + ': ' + v + '\n'; });
          if (rh) scanText(rh, 'network-response', res.url || url);
        } catch (ignore) {}
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
        scanBody(body, 'network-request', this.__gaks_url);
        if (this.__gaks_hdr) scanText(this.__gaks_hdr, 'network-request', this.__gaks_url);
      } catch (ignore) {}
      var xhr = this;
      xhr.addEventListener('load', function () {
        var u = xhr.__gaks_url;
        try {
          var rh = xhr.getAllResponseHeaders();
          if (rh) scanText(rh, 'network-response', u);
        } catch (ignore) {}
        try {
          var ct = (xhr.getResponseHeader('content-type') || '').toLowerCase();
          if (/^(image|video|audio|font)\b/.test(ct) || /wasm|octet-stream/.test(ct)) return;
          // responseText throws unless responseType is '' or 'text', so read
          // the body according to the type the page asked for.
          var rt = xhr.responseType, t = null;
          if (rt === '' || rt === 'text') t = xhr.responseText;
          else if (rt === 'json') { if (xhr.response != null) t = boundedStringify(xhr.response, MAX_BODY); }
          else if (rt === 'arraybuffer') t = decodeBuffer(xhr.response);
          else if (rt === 'blob') {
            decodeBlob(xhr.response, function (bt) { try { scanText(bt, 'network-response', u); } catch (ignore) {} });
          }
          if (t) {
            dbg(LOG + 'XHR response scanned:', (u || '').slice(0, 120), '(' + t.length + ' bytes)');
            scanText(t, 'network-response', u);
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
          // Native send() on a CLOSING/CLOSED socket just logs a console warning
          // ("WebSocket is already in CLOSING or CLOSED state.") and drops the
          // data. Replicate the silent drop without forwarding, so our wrapper
          // doesn't trigger that warning on the page's behalf.
          if (ws.readyState === _WS.CLOSING || ws.readyState === _WS.CLOSED) return;
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
        var esUrl = String(u || '');
        var onData = function (ev) {
          try { if (typeof ev.data === 'string') scanText(ev.data, 'eventsource', esUrl); } catch (ignore) {}
        };
        var esAdd = es.addEventListener;
        var watched = { message: true };
        esAdd.call(es, 'message', onData);
        // Named events ("event: token") only reach listeners registered for
        // that name, so attach a scanner the first time the page subscribes.
        es.addEventListener = function (type) {
          try {
            if (typeof type === 'string' && !watched[type] && type !== 'open' && type !== 'error') {
              watched[type] = true;
              esAdd.call(es, type, onData);
            }
          } catch (ignore) {}
          return esAdd.apply(es, arguments);
        };
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
          scanBody(data, 'beacon', String(u || ''));
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
  var MAX_GLOBAL = 512 * 1024; // serialized budget per global object (see boundedStringify)

  function scanGlobals() {
    try {
      var keys = Object.keys(window);
      var cap = Math.min(keys.length, 800);
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
          try { s = boundedStringify(v, MAX_GLOBAL); } catch (e) { continue; } // circular / non-serializable
          if (s && s.length > 8) scanText(k + '=' + s, 'window-global', location.href);
        }
      }
    } catch (e) { /* ignore */ }
    // window.name persists across navigations and history.state rides SPA route
    // changes — both are common stashes the DOM scan never sees.
    try { if (window.name && window.name.length > 8) scanText(String(window.name), 'window-global', location.href); } catch (e) { /* ignore */ }
    try { if (history && history.state != null) { var hs = boundedStringify(history.state, MAX_GLOBAL); if (hs && hs.length > 8) scanText(hs, 'window-global', location.href); } } catch (e) { /* ignore */ }
  }

  // ---- Capture closed shadow roots ------------------------------------------
  // Closed shadow DOM is invisible to the content script's querySelectorAll, so
  // hook attachShadow at document_start to keep a reference and scan its markup.
  try {
    var _attachShadow = Element.prototype.attachShadow;
    var _shadowRoots = [];
    Element.prototype.attachShadow = function () {
      var root = _attachShadow.apply(this, arguments);
      try { if (_shadowRoots.length < 500) _shadowRoots.push(root); } catch (e) { /* ignore */ }
      return root;
    };
    var scanShadowRoots = function () {
      for (var i = 0; i < _shadowRoots.length; i++) {
        try { var html = _shadowRoots[i].innerHTML; if (html) scanText(html, 'shadow', location.href); } catch (e) { /* ignore */ }
      }
    };
    if (typeof document !== 'undefined') { setTimeout(scanShadowRoots, 3000); setTimeout(scanShadowRoots, 6500); }
  } catch (ignore) {}

  try {
    // Guard on `document` so the headless test sandbox never schedules timers.
    if (typeof document !== 'undefined') {
      setTimeout(scanGlobals, 2500);
      setTimeout(scanGlobals, 6000);
    }
  } catch (ignore) {}
})();
