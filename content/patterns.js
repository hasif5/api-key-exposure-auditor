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
    var slice = text.slice(Math.max(0, index - 700), Math.min(text.length, index + 700));
    // Prefer a value explicitly labelled as the auth token; an unlabelled
    // 32-hex run nearby is just as often an MD5/content hash.
    var kw = /auth[\s_-]?token["']?\s*[:=]\s*["']?([0-9a-fA-F]{32})(?![0-9a-fA-F])/i.exec(slice);
    if (kw && sid.indexOf(kw[1]) === -1) return kw[1];
    var re = /[0-9a-fA-F]{32}/g;
    var m;
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
    var slice = text.slice(Math.max(0, index - 1500), Math.min(text.length, index + 1500));
    var kw = /secret[_a-z]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})/i.exec(slice);
    if (kw && id.indexOf(kw[1]) === -1) return kw[1];
    var re = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g;
    var m;
    while ((m = re.exec(slice)) !== null) {
      // A real secret is mixed-case base64 with digits; a 40-char hex run is
      // a SHA-1 (git commit, integrity hash), not a secret.
      if (id.indexOf(m[0]) === -1 && /[a-z]/.test(m[0]) && /[A-Z]/.test(m[0]) && /[0-9]/.test(m[0])) return m[0];
    }
    // Last resort: an explicitly AWS-labelled secret anywhere in the blob (the
    // pair is often declared far apart; the "aws…secret" label pairs safely).
    var far = /aws[_-]?secret[_a-z]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})/i.exec(text);
    if (far && id.indexOf(far[1]) === -1) return far[1];
    return null;
  }

  var PROVIDER_RES = [
    { id: 'google', re: /(?<![A-Za-z0-9_-])(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})(?![A-Za-z0-9_-])/g },
    { id: 'anthropic', re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{90,}/g },
    { id: 'openrouter', re: /(?<![A-Za-z0-9])sk-or-(?:v1-)?[A-Za-z0-9]{40,}/g },
    { id: 'xai', re: /(?<![A-Za-z0-9])xai-[A-Za-z0-9]{40,}/g },
    { id: 'openai', re: /(?<![A-Za-z0-9])(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})/g },
    { id: 'twilio', re: /(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![0-9a-fA-F])/g, secret: twilioSecret, context: /twilio|account[\s_-]?sid|auth[\s_-]?token/i },
    // Only AKIA/ASIA are access keys (other IAM prefixes are entity IDs); the
    // 16-char tail is base32.
    { id: 'aws', re: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z2-7]{16}(?![A-Za-z0-9])/g, secret: awsSecret },
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
    { label: 'Mailchimp API key', re: /(?<![A-Za-z0-9])[0-9a-f]{32}-us\d{1,2}(?![A-Za-z0-9])/g }
  ];
  // Keyword-assignment heuristic. The keyword may sit inside a longer name
  // (REACT_APP_API_KEY, openaiApiKey, token_prod): the regex anchors on the
  // keyword and the surrounding name is recovered and validated in code.
  var GENERIC_ASSIGN_RE = /(api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|access[_-]?key|password|passwd|token)([A-Za-z0-9_-]{0,24})["']?\s*[:=]\s*["']([^"'\s]{16,200})["']/gi;
  // Unquoted dotenv-style lines (API_KEY=value). Upper-case names only.
  var GENERIC_ENV_RE = /^[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]{0,60})[ \t]*=[ \t]*([^\s"'#]{16,200})[ \t]*(?:#.*)?\r?$/gm;
  var GENERIC_ENV_NAME_RE = /(?:^|_)(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY)(?:_|$)/;
  // Names that contain a keyword but do not hold a credential.
  var GENERIC_NAME_DENY_RE = /csrf|xsrf|captcha|nonce|public|publishable|placeholder|(?:page|next|prev|continuation|cursor|sync|upload|resume)[_-]?token|(?:name|id|ref|type|url|uri|path|file|label|field|header|param|prefix|suffix|length|hash|salt|expiry|expires?|ttl)$/i;
  // Hard-coded Authorization values. A quote must precede the scheme, so a
  // live request header (the user's own session) is not matched.
  var BEARER_LITERAL_RE = /["'`]Bearer\s+([A-Za-z0-9._~+/=-]{20,400})["'`]/g;
  var BASIC_LITERAL_RE = /["'`]Basic\s+([A-Za-z0-9+/]{16,400}={0,2})["'`]/g;
  var GENERIC_PLACEHOLDER_RE = /your|example|placeholder|change[_-]?me|redacted|dummy|sample|xxxx|todo|insert|enter|^[A-Za-z]+$|<|\{|\$/i;
  var GENERIC_CHARSET_RE = /^[A-Za-z0-9_\-+/.=~]+$/;
  // Provider-shaped strings that are documentation placeholders, not keys.
  var PLACEHOLDER_KEY_RE = /example|placeholder|dummy|sample|redacted|change[_-]?me|insert|your[_-]?(?:api[_-]?)?key|not[_-]?a[_-]?real|x{6,}|0{8,}|1234567|abcdefgh/i;
  var PLACEHOLDER_PASSWORD_RE = /^(?:pass(?:word|wd)?|pwd|secret|change[_-]?me|\*+|x+|\.+)$|your|example|placeholder|[<{$[]|%s/i;
  var DOTTED_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$/;
  var WORDY_SEGMENT_RE = /^(?:[A-Za-z]+|[0-9]{1,4}|v[0-9]+)$/;

  function genericEntropy(s) {
    var freq = Object.create(null), i;
    for (i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
    var e = 0;
    for (var k in freq) { var p = freq[k] / s.length; e -= p * Math.log(p) / Math.LN2; }
    return e;
  }

  // A format-valid key that is obviously a stand-in: placeholder words, or one
  // character making up more than half of it.
  function isPlaceholderKey(k) {
    if (PLACEHOLDER_KEY_RE.test(k)) return true;
    var freq = Object.create(null), max = 0;
    for (var i = 0; i < k.length; i++) { var n = freq[k[i]] = (freq[k[i]] || 0) + 1; if (n > max) max = n; }
    return max / k.length > 0.5;
  }

  // A reference or identifier rather than a secret value: a dotted path, a
  // file path, or hyphen/underscore-joined plain words.
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

  function looksSecret(v) {
    if (!v || v.length < 16 || v.length > 200) return false;
    if (!GENERIC_CHARSET_RE.test(v)) return false;
    if (GENERIC_PLACEHOLDER_RE.test(v)) return false;
    if (!/[A-Za-z]/.test(v) || !/[0-9]/.test(v)) return false;
    if (looksLikeIdentifier(v)) return false;
    return genericEntropy(v) >= 3.0;
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

  function detectGeneric(text, seen, out, pfx) {
    pfx = pfx || '';
    function push(key, reason, lead, index) {
      seen[key] = true;
      out.push({ key: key, provider: 'unknown', reason: reason,
        snippet: pfx + lead + ' — ' + snippetAround(text, index, key.length, 100), mapsContext: false });
    }
    var m, name, val;
    for (var i = 0; i < GENERIC_TOKEN_PATTERNS.length; i++) {
      var pat = GENERIC_TOKEN_PATTERNS[i];
      pat.re.lastIndex = 0;
      while ((m = pat.re.exec(text)) !== null) {
        var key = m[0];
        if (seen[key]) continue;
        var label = genericCheck(pat.label, key);
        if (!label) { seen[key] = true; continue; }
        push(key, label, label, m.index);
      }
    }
    BEARER_LITERAL_RE.lastIndex = 0;
    while ((m = BEARER_LITERAL_RE.exec(text)) !== null) {
      var tok = m[1];
      if (seen[tok] || GENERIC_PLACEHOLDER_RE.test(tok) || !/[A-Za-z]/.test(tok) || !/[0-9]/.test(tok) ||
          looksLikeIdentifier(tok) || genericEntropy(tok) < 3.0) continue;
      push(tok, 'Hard-coded Bearer token', 'Hard-coded Bearer token', m.index + m[0].indexOf(tok));
    }
    BASIC_LITERAL_RE.lastIndex = 0;
    while ((m = BASIC_LITERAL_RE.exec(text)) !== null) {
      var b64 = m[1];
      if (seen[b64]) continue;
      var pair = b64decode(b64);
      var pm = pair ? /^[^\s:]+:(\S{3,})$/.exec(pair) : null;
      if (!pm || PLACEHOLDER_PASSWORD_RE.test(pm[1])) continue;
      push(b64, 'Hard-coded Basic auth credentials', 'Hard-coded Basic auth credentials', m.index + m[0].indexOf(b64));
    }
    GENERIC_ASSIGN_RE.lastIndex = 0;
    while ((m = GENERIC_ASSIGN_RE.exec(text)) !== null) {
      var suffix = m[2];
      val = m[3];
      // The keyword must end the word it sits in: "tokens"/"tokenizer" are
      // out, "token_prod"/"tokenV2" are in.
      if (suffix && !/^[_\-0-9A-Z]/.test(suffix)) continue;
      if (seen[val] || !looksSecret(val)) continue;
      var s = m.index, lim = Math.max(0, s - 40);
      while (s > lim && /[A-Za-z0-9_.$-]/.test(text[s - 1])) s--;
      name = text.slice(s, m.index) + m[1] + suffix;
      if (GENERIC_NAME_DENY_RE.test(name)) continue;
      push(val, 'secret-like value assigned to "' + name + '"', 'assigned to "' + name + '"', m.index + m[0].lastIndexOf(val));
    }
    GENERIC_ENV_RE.lastIndex = 0;
    while ((m = GENERIC_ENV_RE.exec(text)) !== null) {
      name = m[1];
      val = m[2];
      if (seen[val] || !GENERIC_ENV_NAME_RE.test(name) || GENERIC_NAME_DENY_RE.test(name) || !looksSecret(val)) continue;
      push(val, 'secret-like value assigned to "' + name + '"', 'assigned to "' + name + '"', m.index + m[0].lastIndexOf(val));
    }
  }

  // ---- Decode-and-rescan (mirror of lib/providers.js) ----
  var B64_BLOB_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])/g;
  var PCT_HIT_RE = /%[0-9A-Fa-f]{2}/g;
  var ESC_HIT_RE = /\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|u\{[0-9A-Fa-f]{1,6}\}|["'/])/g;
  var ENT_HIT_RE = /&(?:quot|apos|amp|lt|gt|#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6});/g;
  var ENT_NAMES = { quot: '"', apos: "'", amp: '&', lt: '<', gt: '>' };

  function pctDecode(tok) {
    return tok.replace(/(?:%[0-9A-Fa-f]{2})+/g, function (run) {
      try { return decodeURIComponent(run); } catch (e) { return run; }
    });
  }

  // JS string escapes: \x41, A, \u{41}, and escaped quotes/slashes.
  function escDecode(tok) {
    return tok.replace(/\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}|(["'/]))/g, function (all, a, b, c, d) {
      if (d) return d;
      var cp = parseInt(a || b || c, 16);
      return cp <= 0x10FFFF ? String.fromCodePoint(cp) : all;
    });
  }

  // HTML entities: serialized attributes carry JSON as {&quot;apiKey&quot;:…}.
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
        // A token longer than the window continues in the next piece: glue
        // them so a key straddling the cut is not split.
        if (lastCapped && s === lastEnd && parts.length) parts[parts.length - 1] += dec;
        else parts.push(dec);
        total += dec.length;
      }
      lastEnd = e;
      lastCapped = capped;
    }
    return parts.join('\n');
  }

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
    var pct = decodeTokens(text, PCT_HIT_RE, pctDecode);
    if (pct) layers.push(pct);
    var esc = decodeTokens(text, ESC_HIT_RE, escDecode);
    if (esc) layers.push(esc);
    var ent = decodeTokens(text, ENT_HIT_RE, entDecode);
    if (ent) layers.push(ent);
    // Base64 / base64url blobs. Cheap shape filters run first so URL paths and
    // long identifiers do not use up the budget before a real blob is reached.
    B64_BLOB_RE.lastIndex = 0;
    var m, examined = 0, decoded = 0;
    while (examined < 4000 && decoded < 40 && (m = B64_BLOB_RE.exec(text)) !== null) {
      var c = m[0];
      if ((c.indexOf('/') !== -1 || c.indexOf('+') !== -1) && (c.indexOf('-') !== -1 || c.indexOf('_') !== -1)) continue; // mixed alphabets: a path
      if (!/[a-z]/.test(c) || !/[A-Z]/.test(c) || !/[0-9]/.test(c)) continue; // encoded text has all three
      examined++;
      var d = b64decode(c);
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
        if (isPlaceholderKey(key)) continue; // sk-xxxx…, AIza…EXAMPLE… — a stand-in, not a key
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
