/*
 * patterns.js — shared detection helpers for the content-script world.
 *
 * Loaded as the first content script so `content.js` can use `GAKS` directly.
 * Declared with `var` (not const/let) so the binding is shared across the
 * content scripts that run in the same isolated world.
 */
var GAKS = (function () {
  // Google API keys: literal "AIza" followed by 35 chars from [A-Za-z0-9_-].
  // Global + multiline so we can iterate every occurrence in a blob.
  var KEY_RE = /AIza[0-9A-Za-z_\-]{35}/g;

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
  var SINGLE_KEY_RE = /^AIza[0-9A-Za-z_\-]{35}$/;

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

  var PROVIDER_RES = [
    { id: 'google', re: /AIza[0-9A-Za-z_\-]{35}/g },
    { id: 'anthropic', re: /sk-ant-[A-Za-z0-9_-]{90,}/g },
    { id: 'openrouter', re: /sk-or-(?:v1-)?[A-Za-z0-9]{40,}/g },
    { id: 'xai', re: /xai-[A-Za-z0-9]{40,}/g },
    { id: 'openai', re: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,}/g },
    { id: 'twilio', re: /AC[0-9a-fA-F]{32}/g, secret: twilioSecret, context: /twilio|account[\s_-]?sid|auth[\s_-]?token/i }
  ];

  // Returns [{ key, provider, snippet, mapsContext }] for every key in `text`.
  function findInText(text) {
    var out = [];
    if (!text) return out;
    var seen = Object.create(null);
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
        var snippet = snippetAround(text, m.index, key.length);
        var secret = prov.secret ? prov.secret(text, m.index, key) : null;
        if (secret) snippet += ' · token: ' + secret;
        out.push({
          key: key,
          provider: prov.id,
          snippet: snippet,
          secret: secret || undefined,
          mapsContext: prov.id === 'google' && isMapsContext(snippet)
        });
      }
    }
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
