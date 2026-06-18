/*
 * patterns.js — shared detection helpers for the content-script world.
 *
 * Loaded as the first content script so `content.js` can use `GAKS` directly.
 * Declared with `var` (not const/let) so the binding is shared across the
 * content scripts that run in the same isolated world.
 */
var GAKS = (function () {
  // Google API keys, two formats:
  //   - legacy:  literal "AIza" + 35 chars from [A-Za-z0-9_-]
  //   - newer:   literal "AQ." + 40+ base64url chars (e.g. AQ.Ab8RN6J…)
  // Global + multiline so we can iterate every occurrence in a blob.
  var KEY_RE = /(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})/g;

  // Substrings that mark a Google Maps usage context near a key.
  var MAPS_HINTS = [
    'maps.googleapis.com',
    'maps.google.com',
    'maps.gstatic.com',
    '/maps/api/',
    'staticmap',
    '/maps/embed',
    'google.maps',
    'gmaps'
  ];

  // Single-key validity check (anchored), used to validate user/network input.
  var SINGLE_KEY_RE = /^(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})$/;

  // Domains whose pages we skip entirely (mirror of lib/ignore.js).
  var GOOGLE_HOST_RE = /(^|\.)google\.[a-z]{2,}(\.[a-z]{2,})?$/;
  var IGNORED_DOMAINS = [
    'gstatic.com', 'googleusercontent.com', 'googleapis.com', 'googlevideo.com',
    'googletagmanager.com', 'google-analytics.com', 'googlesyndication.com',
    'googleadservices.com', 'doubleclick.net', 'withgoogle.com', 'googlesource.com',
    'goo.gl', 'gmail.com', 'youtube.com', 'youtu.be', 'ytimg.com', 'ggpht.com',
    'android.com', 'chromium.org',
    'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
    'yahoo.com', 'yahooapis.com', 'yimg.com'
  ];

  function hostIsIgnored(host, extra) {
    if (!host) return false;
    host = String(host).toLowerCase();
    if (GOOGLE_HOST_RE.test(host)) return true;
    var list = IGNORED_DOMAINS.concat(Array.isArray(extra) ? extra : []);
    for (var i = 0; i < list.length; i++) {
      var d = list[i];
      if (d && (host === d || host.slice(-(d.length + 1)) === '.' + d)) return true;
    }
    return false;
  }

  function isMapsContext(text) {
    if (!text) return false;
    var lower = String(text).toLowerCase();
    for (var i = 0; i < MAPS_HINTS.length; i++) {
      if (lower.indexOf(MAPS_HINTS[i]) !== -1) return true;
    }
    return false;
  }

  function snippetAround(text, index, keyLen, radius) {
    radius = radius || 60;
    var start = Math.max(0, index - radius);
    var end = Math.min(text.length, index + keyLen + radius);
    var slice = text.slice(start, end).replace(/\s+/g, ' ').trim();
    return (start > 0 ? '…' : '') + slice + (end < text.length ? '…' : '');
  }

  // Multi-provider detection patterns (mirror of lib/providers.js).
  // Order matters: Anthropic (sk-ant-) before OpenAI (generic sk-).
  function twilioSecret(text, index, sid) {
    var start = Math.max(0, index - 700);
    var end = Math.min(text.length, index + 700);
    var re = /[0-9a-fA-F]{32}/g;
    var m;
    var slice = text.slice(start, end);
    while ((m = re.exec(slice)) !== null) {
      var tok = m[0];
      if (sid.indexOf(tok) !== -1) continue;
      return tok;
    }
    return null;
  }

  // AWS Secret Access Key found near the Access Key ID. Prefer a value
  // labelled as a secret (length-agnostic); fall back to a 40-char base64 run.
  function awsSecret(text, index, id) {
    var slice = text.slice(Math.max(0, index - 500), Math.min(text.length, index + 500));
    var kw = /secret[_a-z]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})/i.exec(slice);
    if (kw && id.indexOf(kw[1]) === -1) return kw[1];
    var re = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g;
    var m;
    while ((m = re.exec(slice)) !== null) {
      if (id.indexOf(m[0]) === -1) return m[0];
    }
    return null;
  }

  var PROVIDER_RES = [
    { id: 'google', re: /(?<![A-Za-z0-9_-])(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})(?![A-Za-z0-9_-])/g },
    { id: 'anthropic', re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{90,}/g },
    { id: 'openrouter', re: /(?<![A-Za-z0-9])sk-or-(?:v1-)?[A-Za-z0-9]{40,}/g },
    { id: 'xai', re: /(?<![A-Za-z0-9])xai-[A-Za-z0-9]{40,}/g },
    { id: 'openai', re: /(?<![A-Za-z0-9])(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})/g },
    { id: 'twilio', re: /(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![0-9a-fA-F])/g, secret: twilioSecret, context: /twilio|account[\s_-]?sid|auth[\s_-]?token/i },
    { id: 'aws', re: /(?<![A-Za-z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])/g, secret: awsSecret },
    { id: 'github', re: /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{59,})(?![A-Za-z0-9])/g },
    { id: 'gitlab', re: /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])/g },
    { id: 'slack', re: /(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])/g },
    { id: 'stripe', re: /(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])/g }
  ];

  // ---- Generic "looks like a secret" heuristics (provider: 'unknown') ------
  // MUST be kept in sync with lib/providers.js and content/intercept.js.
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

  function detectGeneric(text, seen, out, pfx) {
    pfx = pfx || '';
    for (var i = 0; i < GENERIC_TOKEN_PATTERNS.length; i++) {
      var pat = GENERIC_TOKEN_PATTERNS[i];
      pat.re.lastIndex = 0;
      var m;
      while ((m = pat.re.exec(text)) !== null) {
        var key = m[0];
        if (seen[key]) continue;
        seen[key] = true;
        out.push({ key: key, provider: 'unknown', reason: pat.label,
          snippet: pfx + pat.label + ' — ' + snippetAround(text, m.index, key.length, 100), mapsContext: false });
      }
    }
    GENERIC_ASSIGN_RE.lastIndex = 0;
    var a;
    while ((a = GENERIC_ASSIGN_RE.exec(text)) !== null) {
      var kw = a[1], val = a[2];
      if (seen[val] || !looksSecret(val)) continue;
      seen[val] = true;
      var idx = a.index + a[0].lastIndexOf(val);
      out.push({ key: val, provider: 'unknown', reason: 'secret-like value assigned to "' + kw + '"',
        snippet: pfx + 'assigned to "' + kw + '" — ' + snippetAround(text, idx, val.length, 100), mapsContext: false });
    }
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
  function decodeLayers(text) {
    var layers = [];
    if (text.length > 2000000) return layers;
    if (text.length < 100000 && text.indexOf('%') !== -1) {
      try { var u = decodeURIComponent(text); if (u !== text) layers.push(u); } catch (e) { /* malformed */ }
    }
    B64_BLOB_RE.lastIndex = 0;
    var m, examined = 0, decoded = 0;
    while ((m = B64_BLOB_RE.exec(text)) !== null && examined < 256 && decoded < 12) {
      examined++;
      var d = b64decode(m[0]);
      if (d) { layers.push(d.length > 65536 ? d.slice(0, 65536) : d); decoded++; }
    }
    return layers;
  }

  function scanInto(text, seen, out, pfx) {
    pfx = pfx || '';
    for (var p = 0; p < PROVIDER_RES.length; p++) {
      var prov = PROVIDER_RES[p];
      prov.re.lastIndex = 0;
      var m;
      while ((m = prov.re.exec(text)) !== null) {
        var key = m[0];
        if (seen[key]) continue;
        if (prov.context) {
          var ctx = text.slice(Math.max(0, m.index - 250), Math.min(text.length, m.index + 250));
          if (!prov.context.test(ctx)) continue; // not enough evidence — skip
        }
        seen[key] = true;
        var snippet = pfx + snippetAround(text, m.index, key.length);
        var secret = prov.secret ? prov.secret(text, m.index, key) : null;
        if (secret) { snippet += ' · secret: ' + secret; seen[secret] = true; }
        out.push({
          key: key,
          provider: prov.id,
          snippet: snippet,
          secret: secret || undefined,
          mapsContext: prov.id === 'google' && isMapsContext(snippet)
        });
      }
    }
    detectGeneric(text, seen, out, pfx);
  }

  // Returns [{ key, provider, snippet, mapsContext }] for every key in `text`.
  function findInText(text) {
    var out = [];
    if (!text) return out;
    var seen = Object.create(null);
    scanInto(text, seen, out, '');
    var layers = decodeLayers(text);
    for (var i = 0; i < layers.length; i++) scanInto(layers[i], seen, out, '[decoded] ');
    return out;
  }

  return {
    KEY_RE: KEY_RE,
    SINGLE_KEY_RE: SINGLE_KEY_RE,
    MAPS_HINTS: MAPS_HINTS,
    IGNORED_DOMAINS: IGNORED_DOMAINS,
    isMapsContext: isMapsContext,
    hostIsIgnored: hostIsIgnored,
    findInText: findInText,
    snippetAround: snippetAround
  };
})();
