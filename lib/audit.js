/*
 * audit.js — active probes that determine what a discovered key can reach,
 * how it is restricted, and whether it can incur billing.
 *
 * Runs from the service worker (extension host permissions bypass CORS).
 * Every probe resolves to a record:
 *   { service, endpoint, httpStatus, apiStatus, classification, detail,
 *     billable, costNote, ts }
 *
 * Why "enabled" == unrestricted: these requests carry NO HTTP Referer and come
 * from an arbitrary IP. If a probe still succeeds, the key is NOT locked to a
 * referrer or IP for that API — i.e. exploitable from anywhere.
 *
 * IMPORTANT — two response conventions:
 *   - Maps *web services* (maps.googleapis.com/maps/api/*) return HTTP 200 even
 *     when they DENY; the verdict is the JSON `status` field. Never infer
 *     "enabled" from the HTTP code for these.
 *   - Everything else (routes/places/roads/gemini/vertex, Static Maps image)
 *     uses honest HTTP status codes.
 *
 * Endpoints/models/prices verified against Google docs (June 2026).
 *
 * classification values:
 *   'enabled' 'restricted-referer' 'restricted-ip' 'api-not-enabled'
 *   'invalid-key' 'over-quota' 'denied' 'inconclusive' 'error'
 */

const TIMEOUT_MS = 12000;
const RETRIES = 2;                 // extra attempts on transient failures
const PROBE_CONCURRENCY = 5;       // simultaneous probes per key
const AI_MODEL = 'gemini-2.5-flash';

// Approximate public list prices (USD), June 2026. Awareness only — real cost
// depends on SKU tier, free monthly allowance, and token counts.
const COST = {
  staticMap: 'Billable ~$2 / 1,000 (10k/mo free)',
  geocoding: 'Billable ~$5 / 1,000 (10k/mo free)',
  directions: 'Billable ~$5 / 1,000 (legacy)',
  distanceMatrix: 'Billable ~$5–10 / 1,000 (legacy)',
  elevation: 'Billable ~$5 / 1,000',
  timezone: 'Billable ~$5 / 1,000',
  roads: 'Billable ~$10–20 / 1,000',
  streetviewMeta: 'Free — metadata only',
  placesLegacy: 'Billable ~$17–32 / 1,000 (Places legacy)',
  placesAutocomplete: 'Billable — per request/session (Places Autocomplete)',
  placesDetails: 'Billable ~$17 / 1,000 (Place Details)',
  routesNew: 'Billable ~$5 / 1,000 (Routes: Compute Routes)',
  placesNew: 'Billable ~$32 / 1,000 (Places API New)',
  mapsJs: 'Loader free; dynamic map loads billed separately',
  geminiList: 'Free — metadata only',
  geminiGen: 'Billable — tokens ~$0.30 in / $2.50 out per 1M (gemini-2.5-flash)',
  vertexCount: 'Free — token count only',
  vertexGen: 'Billable — tokens ~$0.30 in / $2.50 out per 1M (gemini-2.5-flash)',
  embed: 'Billable — token-based (Gemini embeddings)',
  translate: 'Billable ~$20 / 1M chars (Cloud Translation)',
  vision: 'Billable ~$1.50 / 1,000 images (Cloud Vision)',
  language: 'Billable ~$1 / 1,000 units (Natural Language)',
  tts: 'Billable ~$4–16 / 1M chars (Text-to-Speech)',
  stt: 'Billable ~$0.02 / 15s (Speech-to-Text)',
  firebaseAuth: 'Free — Firebase Identity Toolkit config',
  youtube: 'Billable (quota) — YouTube Data API',
  safeBrowsing: 'Free — Safe Browsing lookup',
  storage: 'Billable — Cloud Storage operations/egress'
};

// Google Maps JavaScript API runtime error tokens -> classification.
const MAPS_JS_ERRORS = [
  ['RefererNotAllowedMapError', 'restricted-referer'],
  ['InvalidKeyMapError', 'invalid-key'],
  ['ExpiredKeyMapError', 'invalid-key'],
  ['MissingKeyMapError', 'invalid-key'],
  ['ApiNotActivatedMapError', 'api-not-enabled'],
  ['ApiTargetBlockedMapError', 'api-not-enabled'],
  ['OverQuotaMapError', 'over-quota'],
  ['ApiProjectMapError', 'denied'],
  ['UrlAuthenticationCommonError', 'denied']
];

function nowIso() {
  return new Date().toISOString();
}

// Message-pattern classifier; returns null when nothing matches.
function classifyMessage(message) {
  const msg = (message || '').toLowerCase();
  if (!msg) return null;
  if (msg.includes('referer') || msg.includes('referrer')) return 'restricted-referer';
  if (msg.includes('ip address') || msg.includes('ip restriction') ||
      (msg.includes(' ip ') && msg.includes('not authorized'))) return 'restricted-ip';
  if (msg.includes('api key not valid') || msg.includes('api_key_invalid') ||
      msg.includes('invalid api key') || msg.includes('key is invalid') ||
      msg.includes('api key expired') || msg.includes('expired')) return 'invalid-key';
  if (msg.includes('quota') || msg.includes('billing') || msg.includes('over_query_limit') ||
      msg.includes('resource_exhausted')) return 'over-quota';
  if (msg.includes('has not been used') || msg.includes('is not activated') ||
      msg.includes('is not enabled') || msg.includes('not enabled for your project') ||
      msg.includes('legacy api') || msg.includes('legacyapinotactivated') ||
      msg.includes('not authorized to use this api') || msg.includes('api not activated') ||
      msg.includes('service is not enabled') || msg.includes('it is disabled') ||
      msg.includes('api_key_service_blocked') || msg.includes('blocked')) return 'api-not-enabled';
  return null;
}

// For endpoints whose HTTP status is meaningful (2xx == success).
function classify(httpStatus, message) {
  const byMsg = classifyMessage(message);
  if (byMsg) return byMsg;
  if (httpStatus >= 200 && httpStatus < 300) return 'enabled';
  if (httpStatus === 0) return 'error';
  return 'denied';
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// fetch with per-attempt timeout + bounded retry on transient failures.
//
// We deliberately send NO Referer (referrerPolicy 'no-referrer'). This models a
// real attacker calling the key from an arbitrary context and, crucially, makes
// the result deterministic: Google's HTTP-referrer restrictions only apply when
// a Referer is present, so omitting it reveals whether the key is usable (and
// thus whether the referrer restriction is bypassable).
async function doFetch(url, opts) {
  let last = { ok: false, status: 0, text: 'no attempt', contentType: '' };
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(url, Object.assign(
        { signal: controller.signal, credentials: 'omit', referrer: '', referrerPolicy: 'no-referrer' },
        opts || {}
      ));
      const text = await res.text();
      const contentType = res.headers.get('content-type') || '';
      last = { ok: true, status: res.status, text, contentType };
      // Retry only on rate-limit / server errors.
      if (res.status === 429 || res.status >= 500) {
        if (attempt < RETRIES) { clearTimeout(timer); await backoff(attempt); continue; }
      }
      clearTimeout(timer);
      return last;
    } catch (e) {
      last = { ok: false, status: 0, text: String(e && e.message || e), contentType: '' };
      clearTimeout(timer);
      if (attempt < RETRIES) { await backoff(attempt); continue; }
      return last;
    }
  }
  return last;
}

function backoff(attempt) {
  const base = 500 * Math.pow(2, attempt);
  const jitter = Math.floor(Math.random() * 250);
  return delay(base + jitter);
}

function parseJsonSafe(text) {
  try { return JSON.parse(text); } catch (e) { return null; }
}

function record(service, endpoint, httpStatus, apiStatus, classification, detail, meta) {
  meta = meta || {};
  return {
    service,
    endpoint,
    httpStatus,
    apiStatus: apiStatus || '',
    classification,
    detail: (detail || '').slice(0, 400),
    billable: !!meta.billable,
    costNote: meta.costNote || '',
    ts: nowIso()
  };
}

// Run probe thunks with a concurrency cap.
async function runPool(thunks, limit) {
  const results = new Array(thunks.length);
  let i = 0;
  async function worker() {
    while (i < thunks.length) {
      const idx = i++;
      try { results[idx] = await thunks[idx](); }
      catch (e) { results[idx] = record('Audit', 'probe', 0, '', 'error', String(e && e.message || e), {}); }
    }
  }
  const n = Math.min(limit, thunks.length);
  await Promise.all(Array.from({ length: n }, worker));
  return results;
}

// ---- Maps web-service probes (HTTP 200 even on denial) --------------------

async function probeMapsJson(service, endpoint, url, costNote, billable) {
  const r = await doFetch(url);
  const meta = { billable: billable !== false, costNote };
  if (!r.ok) return record(service, endpoint, 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  const apiStatus = json ? (json.status || '') : '';
  const message = json ? (json.error_message || '') : r.text.slice(0, 200);
  let classification;
  if (apiStatus === 'OK' || apiStatus === 'ZERO_RESULTS') classification = 'enabled';
  else if (apiStatus === 'OVER_QUERY_LIMIT') classification = 'over-quota';
  else classification = classifyMessage(message) || 'denied';
  return record(service, endpoint, r.status, apiStatus, classification, message, meta);
}

async function probeStaticMap(key) {
  const url = 'https://maps.googleapis.com/maps/api/staticmap?center=40.714728,-73.998672' +
    '&zoom=12&size=200x200&key=' + encodeURIComponent(key);
  const r = await doFetch(url);
  const meta = { billable: true, costNote: COST.staticMap };
  if (!r.ok) return record('Maps', 'Static Maps', 0, '', 'error', r.text, meta);
  const ct = (r.contentType || '').toLowerCase();
  // Only an actual image means the key worked. Google can return HTTP 200 with a
  // text/plain or text/html error body — never treat that as "enabled".
  if (r.status >= 200 && r.status < 300 && ct.indexOf('image/') === 0) {
    return record('Maps', 'Static Maps', r.status, '', 'enabled', 'Image returned (' + ct + ')', meta);
  }
  const message = r.text.slice(0, 300);
  return record('Maps', 'Static Maps', r.status, '', classifyMessage(message) || 'denied', message, meta);
}

// ---- Maps JavaScript API loader (parse runtime error tokens) --------------

async function probeMapsJs(key) {
  const url = 'https://maps.googleapis.com/maps/api/js?key=' + encodeURIComponent(key);
  const r = await doFetch(url);
  const meta = { billable: false, costNote: COST.mapsJs };
  if (!r.ok) return record('Maps', 'JS API loader', 0, '', 'error', r.text, meta);
  const token = MAPS_JS_ERRORS.find((t) => r.text.indexOf(t[0]) !== -1);
  if (token) {
    return record('Maps', 'JS API loader', r.status, token[0], token[1], 'Loader reported ' + token[0], meta);
  }
  if (r.status >= 200 && r.status < 300) {
    // Loader served JS with no embedded error. The referrer check happens at
    // runtime in a real browser, which we can't reproduce server-side.
    return record('Maps', 'JS API loader', r.status, '', 'inconclusive',
      'Loader served JS (runtime referrer check not performed server-side)', meta);
  }
  return record('Maps', 'JS API loader', r.status, '', classify(r.status, r.text.slice(0, 200)), r.text.slice(0, 200), meta);
}

// ---- Generic REST probe (honest HTTP codes) -------------------------------

async function probeRest(service, endpoint, url, opts, costNote, billable) {
  const r = await doFetch(url, opts);
  const meta = { billable: !!billable, costNote };
  if (!r.ok) return record(service, endpoint, 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record(service, endpoint, r.status, 'OK', 'enabled', 'Request succeeded', meta);
  }
  const err = json && json.error ? json.error : null;
  const message = err ? (err.message || err.status || '') : r.text.slice(0, 200);
  const apiStatus = err ? (err.status || String(err.code || '')) : '';
  return record(service, endpoint, r.status, apiStatus, classify(r.status, message), message, meta);
}

// ---- Gemini Developer API (AI Studio) -------------------------------------

async function probeGeminiModels(key) {
  const url = 'https://generativelanguage.googleapis.com/v1beta/models?key=' + encodeURIComponent(key);
  const r = await doFetch(url);
  const meta = { billable: false, costNote: COST.geminiList };
  if (!r.ok) return record('Gemini', 'ListModels', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const count = json && Array.isArray(json.models) ? json.models.length : 0;
    return record('Gemini', 'ListModels', r.status, 'OK', 'enabled', count + ' models accessible', meta);
  }
  const message = json && json.error ? (json.error.message || json.error.status || '') : r.text.slice(0, 200);
  return record('Gemini', 'ListModels', r.status, json && json.error ? json.error.status : '',
    classify(r.status, message), message, meta);
}

async function probeGeminiGenerate(key) {
  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' + AI_MODEL +
    ':generateContent?key=' + encodeURIComponent(key);
  const body = JSON.stringify({ contents: [{ parts: [{ text: 'ping' }] }], generationConfig: { maxOutputTokens: 1 } });
  const r = await doFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
  const meta = { billable: true, costNote: COST.geminiGen };
  if (!r.ok) return record('Gemini', 'generateContent', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record('Gemini', 'generateContent', r.status, 'OK', 'enabled',
      'Billable generation succeeded — key can incur token charges', meta);
  }
  const message = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('Gemini', 'generateContent', r.status, json && json.error ? json.error.status : '',
    classify(r.status, message), message, meta);
}

// ---- Vertex AI express mode -----------------------------------------------

async function probeVertexCount(key) {
  const url = 'https://aiplatform.googleapis.com/v1/publishers/google/models/' + AI_MODEL +
    ':countTokens?key=' + encodeURIComponent(key);
  const body = JSON.stringify({ contents: [{ role: 'user', parts: [{ text: 'ping' }] }] });
  const r = await doFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
  const meta = { billable: false, costNote: COST.vertexCount };
  if (!r.ok) return record('Vertex AI', 'countTokens', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const tok = json && (json.totalTokens != null) ? json.totalTokens : '?';
    return record('Vertex AI', 'countTokens', r.status, 'OK', 'enabled',
      'Express-mode access confirmed (' + tok + ' tokens)', meta);
  }
  const message = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('Vertex AI', 'countTokens', r.status, json && json.error ? json.error.status : '',
    classify(r.status, message), message, meta);
}

async function probeVertexGenerate(key) {
  const url = 'https://aiplatform.googleapis.com/v1/publishers/google/models/' + AI_MODEL +
    ':generateContent?key=' + encodeURIComponent(key);
  const body = JSON.stringify({ contents: [{ role: 'user', parts: [{ text: 'ping' }] }], generationConfig: { maxOutputTokens: 1 } });
  const r = await doFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
  const meta = { billable: true, costNote: COST.vertexGen };
  if (!r.ok) return record('Vertex AI', 'generateContent', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record('Vertex AI', 'generateContent', r.status, 'OK', 'enabled',
      'Billable generation succeeded — key can incur token charges', meta);
  }
  const message = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('Vertex AI', 'generateContent', r.status, json && json.error ? json.error.status : '',
    classify(r.status, message), message, meta);
}

// ---- Probe set builders ----------------------------------------------------

const enc = encodeURIComponent;

function mapsProbeThunks(key) {
  const placesNewHeaders = (mask) => ({
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, mask ? { 'X-Goog-FieldMask': mask } : {})
  });
  return [
    // --- Core Maps ---
    () => probeStaticMap(key),
    () => probeMapsJs(key),
    () => probeMapsJson('Maps', 'Geocoding',
      'https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key=' + enc(key), COST.geocoding),
    () => probeMapsJson('Maps', 'Directions',
      'https://maps.googleapis.com/maps/api/directions/json?origin=New+York&destination=Boston&key=' + enc(key), COST.directions),
    () => probeMapsJson('Maps', 'Distance Matrix',
      'https://maps.googleapis.com/maps/api/distancematrix/json?origins=New+York&destinations=Boston&key=' + enc(key), COST.distanceMatrix),
    () => probeMapsJson('Maps', 'Elevation',
      'https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=' + enc(key), COST.elevation),
    () => probeMapsJson('Maps', 'Time Zone',
      'https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=' + enc(key), COST.timezone),
    () => probeMapsJson('Maps', 'Street View (meta)',
      'https://maps.googleapis.com/maps/api/streetview/metadata?location=40.714728,-73.998672&key=' + enc(key), COST.streetviewMeta, false),
    () => probeRest('Maps', 'Roads (nearestRoads)',
      'https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795&key=' + enc(key), null, COST.roads, true),
    () => probeRest('Maps', 'Routes API (New)',
      'https://routes.googleapis.com/directions/v2:computeRoutes?key=' + enc(key),
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Goog-FieldMask': 'routes.duration,routes.distanceMeters' },
        body: JSON.stringify({ origin: { address: 'New York, NY' }, destination: { address: 'Boston, MA' }, travelMode: 'DRIVE' }) },
      COST.routesNew, true),

    // --- Places (legacy web service) ---
    () => probeMapsJson('Places', 'Find Place (legacy)',
      'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=museum&inputtype=textquery&fields=name&key=' + enc(key), COST.placesLegacy),
    () => probeMapsJson('Places', 'Text Search (legacy)',
      'https://maps.googleapis.com/maps/api/place/textsearch/json?query=museum+in+New+York&key=' + enc(key), COST.placesLegacy),
    () => probeMapsJson('Places', 'Nearby Search (legacy)',
      'https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=40.714728,-73.998672&radius=1500&type=museum&key=' + enc(key), COST.placesLegacy),
    () => probeMapsJson('Places', 'Place Details (legacy)',
      'https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name&key=' + enc(key), COST.placesDetails),
    () => probeMapsJson('Places', 'Autocomplete (legacy)',
      'https://maps.googleapis.com/maps/api/place/autocomplete/json?input=museum&key=' + enc(key), COST.placesAutocomplete),

    // --- Places API (New) ---
    () => probeRest('Places', 'Text Search (New)',
      'https://places.googleapis.com/v1/places:searchText?key=' + enc(key),
      Object.assign(placesNewHeaders('places.id'), { body: JSON.stringify({ textQuery: 'museum in New York' }) }),
      COST.placesNew, true),
    () => probeRest('Places', 'Nearby Search (New)',
      'https://places.googleapis.com/v1/places:searchNearby?key=' + enc(key),
      Object.assign(placesNewHeaders('places.id'), { body: JSON.stringify({
        locationRestriction: { circle: { center: { latitude: 40.714728, longitude: -73.998672 }, radius: 1000 } }, maxResultCount: 1 }) }),
      COST.placesNew, true),
    () => probeRest('Places', 'Place Details (New)',
      'https://places.googleapis.com/v1/places/ChIJN1t_tDeuEmsRUsoyG83frY4?key=' + enc(key),
      { method: 'GET', headers: { 'X-Goog-FieldMask': 'id,displayName' } },
      COST.placesDetails, true),
    () => probeRest('Places', 'Autocomplete (New)',
      'https://places.googleapis.com/v1/places:autocomplete?key=' + enc(key),
      Object.assign(placesNewHeaders(null), { body: JSON.stringify({ input: 'museum in New York' }) }),
      COST.placesAutocomplete, true)
  ];
}

// JSON POST helper for probeRest.
function jpost(obj, extraHeaders) {
  return {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {}),
    body: JSON.stringify(obj)
  };
}

// Google Cloud AI/ML + Firebase + data APIs that accept an AIza key.
function aiCloudProbeThunks(key) {
  return [
    // --- Cloud AI / ML ---
    () => probeRest('Translate', 'Translate v2',
      'https://translation.googleapis.com/language/translate/v2?key=' + enc(key),
      jpost({ q: 'hello world', target: 'es' }), COST.translate, true),
    () => probeRest('Vision', 'annotate',
      'https://vision.googleapis.com/v1/images:annotate?key=' + enc(key),
      jpost({ requests: [{ image: { source: { imageUri: 'https://www.gstatic.com/webp/gallery/1.jpg' } }, features: [{ type: 'LABEL_DETECTION', maxResults: 1 }] }] }),
      COST.vision, true),
    () => probeRest('Natural Language', 'analyzeSentiment',
      'https://language.googleapis.com/v1/documents:analyzeSentiment?key=' + enc(key),
      jpost({ document: { type: 'PLAIN_TEXT', content: 'I really love this product.' } }), COST.language, true),
    () => probeRest('Text-to-Speech', 'synthesize',
      'https://texttospeech.googleapis.com/v1/text:synthesize?key=' + enc(key),
      jpost({ input: { text: 'hi' }, voice: { languageCode: 'en-US' }, audioConfig: { audioEncoding: 'MP3' } }), COST.tts, true),
    () => probeRest('Speech-to-Text', 'recognize',
      'https://speech.googleapis.com/v1/speech:recognize?key=' + enc(key),
      jpost({ config: { encoding: 'LINEAR16', sampleRateHertz: 16000, languageCode: 'en-US' }, audio: { content: 'AAAAAAAAAAAAAAAAAAAAAA==' } }), COST.stt, true),
    () => probeRest('Gemini', 'embedContent',
      'https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent?key=' + enc(key),
      jpost({ content: { parts: [{ text: 'hello' }] } }), COST.embed, true),

    // --- Firebase / Cloud / data ---
    () => probeRest('Firebase', 'Identity Toolkit',
      'https://identitytoolkit.googleapis.com/v1/recaptchaParams?key=' + enc(key), null, COST.firebaseAuth, false),
    () => probeRest('YouTube', 'Data API v3',
      'https://youtube.googleapis.com/youtube/v3/videos?part=snippet&chart=mostPopular&maxResults=1&key=' + enc(key), null, COST.youtube, true),
    () => probeRest('Safe Browsing', 'threatMatches',
      'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + enc(key),
      jpost({ client: { clientId: 'gakea', clientVersion: '1.0' }, threatInfo: { threatTypes: ['MALWARE'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: 'http://malware.testing.google.test/testing/malware/' }] } }),
      COST.safeBrowsing, false),
    () => probeRest('Cloud Storage', 'buckets.get',
      'https://storage.googleapis.com/storage/v1/b/gcp-public-data-landsat?key=' + enc(key), null, COST.storage, true)
  ];
}

/**
 * Run the full audit for a key.
 *   opts.includeGenerate — also run billable generateContent probes (Gemini + Vertex).
 * Returns an array of audit records.
 */
export async function auditKey(key, opts) {
  opts = opts || {};
  const thunks = mapsProbeThunks(key)
    .concat(aiCloudProbeThunks(key))
    .concat([
      () => probeGeminiModels(key),
      () => probeVertexCount(key)
    ]);
  if (opts.includeGenerate) {
    thunks.push(() => probeGeminiGenerate(key));
    thunks.push(() => probeVertexGenerate(key));
  }
  return runPool(thunks, PROBE_CONCURRENCY);
}

/**
 * Summarize audit records into a risk assessment.
 * Returns { level, label, enabledServices, billableEnabled, restricted }.
 *   level: 'critical' | 'high' | 'restricted' | 'unknown'
 */
export function assessRisk(audits) {
  if (!audits || !audits.length) {
    return { level: 'unknown', label: 'Not audited', enabledServices: [], billableEnabled: false, restricted: false, bypass: false };
  }
  const enabled = audits.filter((a) => a.classification === 'enabled');
  const enabledServices = Array.from(new Set(enabled.map((a) => a.service)));
  const billableEnabled = enabled.some((a) => a.billable);
  const refererRestricted = audits.some((a) => a.classification === 'restricted-referer');
  const restricted = refererRestricted || audits.some((a) => a.classification === 'restricted-ip');

  if (enabled.length === 0) {
    return {
      level: restricted ? 'restricted' : 'unknown',
      label: restricted ? 'Restricted (referrer/IP locked)' : 'No reachable service',
      enabledServices, billableEnabled, restricted, bypass: false
    };
  }
  // Some endpoints enforce a referrer restriction, yet others are still reachable
  // with no Referer — i.e. the restriction is bypassable (the key is exploitable).
  const bypass = refererRestricted;
  const suffix = bypass ? ' — referrer restriction BYPASSED (works with no Referer)'
    : ' — reachable from anywhere';
  if (billableEnabled) {
    return { level: 'critical', label: 'UNRESTRICTED' + suffix,
      enabledServices, billableEnabled, restricted, bypass };
  }
  return { level: 'high', label: 'UNRESTRICTED' + suffix,
    enabledServices, billableEnabled, restricted, bypass };
}
