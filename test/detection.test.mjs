// Logic regression tests. Run: node test/detection.test.mjs
// Temporary comprehensive test harness (not committed).
let pass = 0, fail = 0;
const fails = [];
function ok(name, cond) { if (cond) { pass++; } else { fail++; fails.push(name); console.log('FAIL:', name); } }
function eq(name, a, b) { ok(name + ' (' + JSON.stringify(a) + ' === ' + JSON.stringify(b) + ')', a === b); }

// ---- Mock chrome for store.js ----
const local = {}, session = {};
globalThis.chrome = {
  storage: {
    local: {
      get: async (keys) => { const out = {}; const arr = Array.isArray(keys) ? keys : [keys]; for (const k of arr) if (k in local) out[k] = local[k]; return out; },
      set: async (obj) => { Object.assign(local, obj); },
    },
    session: {
      get: async (keys) => { const out = {}; const arr = Array.isArray(keys) ? keys : [keys]; for (const k of arr) if (k in session) out[k] = session[k]; return out; },
      set: async (obj) => { Object.assign(session, obj); },
    },
  },
};

const { detectKeys, providerForKey, assessRisk, getProvider, PROVIDERS } = await import('../lib/providers.js');
const { hostIsIgnored, urlHostIsIgnored } = await import('../lib/ignore.js');
const store = await import('../lib/store.js');

// ===================== DETECTION =====================
const KEYS = {
  google: 'AIza' + 'TESTKEYNOTREAL' + '0'.repeat(21), // synthetic placeholder (valid format, NOT a real key)
  openai_legacy: 'sk-' + 'A'.repeat(48),
  openai_proj: 'sk-proj-' + 'aB3'.repeat(20),
  openai_svc: 'sk-svcacct-' + 'aB3'.repeat(20),
  openai_admin: 'sk-admin-' + 'aB3'.repeat(20),
  anthropic: 'sk-ant-api03-' + 'aB-_'.repeat(25),
  openrouter: 'sk-or-v1-' + 'a'.repeat(64),
  openrouter_noV: 'sk-or-' + 'b'.repeat(48),
  xai: 'xai-' + 'X'.repeat(80),
};
for (const [name, key] of Object.entries(KEYS)) {
  const exp = name.split('_')[0];
  eq('providerForKey ' + name, providerForKey(key), exp === 'openrouter' ? 'openrouter' : exp);
}
eq('providerForKey junk', providerForKey('hello-world'), null);
eq('providerForKey shortsk', providerForKey('sk-abc'), null);

// detectKeys finds all, correct provider, no cross-match
{
  const blob = Object.values(KEYS).join('  xx  ');
  const hits = detectKeys(blob);
  eq('detectKeys count', hits.length, Object.keys(KEYS).length);
  const provs = hits.map(h => h.provider).sort().join(',');
  ok('detectKeys providers', provs === ['google','openai','openai','openai','openai','anthropic','openrouter','openrouter','xai'].sort().join(','));
}
// dedup same key
eq('detectKeys dedup', detectKeys(KEYS.google + ' ' + KEYS.google).length, 1);
// empty / null
eq('detectKeys empty', detectKeys('').length, 0);
eq('detectKeys null', detectKeys(null).length, 0);
// key inside URL / JSON / quotes
eq('detectKeys in url', detectKeys('https://x/?key=' + KEYS.google + '&z=1')[0].provider, 'google');
eq('detectKeys in json', detectKeys('{"apiKey":"' + KEYS.openai_proj + '"}')[0].provider, 'openai');

// ---- Twilio edge cases ----
const SID = 'AC' + 'a'.repeat(32);
const TOK = 'b'.repeat(32);
eq('twilio bare (no context) -> 0', detectKeys('id=' + SID + ';').length, 0);
eq('twilio with TWILIO_AUTH_TOKEN', detectKeys('TWILIO_AUTH_TOKEN=' + TOK + '\nTWILIO_ACCOUNT_SID=' + SID)[0].provider, 'twilio');
{
  const h = detectKeys('twilio sid ' + SID + ' token ' + TOK)[0];
  eq('twilio secret captured', h.secret, TOK);
}
{
  // SID with context but NO token nearby -> finding, secret undefined
  const h = detectKeys('twilio account_sid ' + SID + ' (no token here)')[0];
  ok('twilio no-token secret undefined', h && !h.secret);
}
{
  // token == SID hex tail should NOT be used as secret
  const sidTail = SID.slice(2); // 32 hex
  const h = detectKeys('twilio ' + SID + ' ' + sidTail)[0];
  ok('twilio skip self-hex as token', !h.secret || h.secret !== sidTail);
}
eq('providerForKey twilio sid', providerForKey(SID), 'twilio');

// ===================== RISK DISPATCH =====================
eq('risk google none', assessRisk([], 'google').level, 'unknown');
eq('risk google billable enabled', assessRisk([{classification:'enabled',billable:true,service:'Maps'}], 'google').level, 'critical');
eq('risk google enabled free', assessRisk([{classification:'enabled',billable:false,service:'Gemini'}], 'google').level, 'high');
eq('risk google restricted', assessRisk([{classification:'restricted-referer'}], 'google').level, 'restricted');
eq('risk google bypass', assessRisk([{classification:'restricted-referer'},{classification:'enabled',billable:true,service:'Maps'}], 'google').bypass, true);
for (const p of ['openai','anthropic','openrouter','xai']) {
  eq('risk ' + p + ' valid', assessRisk([{classification:'enabled',billable:false}], p).level, 'critical');
  eq('risk ' + p + ' invalid', assessRisk([{classification:'invalid-key'}], p).level, 'unknown');
  eq('risk ' + p + ' none', assessRisk([], p).level, 'unknown');
}
eq('risk twilio valid', assessRisk([{classification:'enabled'}], 'twilio').level, 'critical');
eq('risk twilio inconclusive', assessRisk([{classification:'inconclusive'}], 'twilio').level, 'unknown');
eq('risk unknown provider falls back to google', assessRisk([{classification:'enabled',billable:true,service:'x'}], 'zzz').level, 'critical');

// ===================== IGNORE =====================
ok('ignore google.com', hostIsIgnored('google.com'));
ok('ignore www.google.co.uk', hostIsIgnored('www.google.co.uk'));
ok('ignore maps.google.de', hostIsIgnored('maps.google.de'));
ok('ignore youtube', hostIsIgnored('m.youtube.com'));
ok('not ignore example', !hostIsIgnored('example.com'));
ok('not ignore notgoogle', !hostIsIgnored('notgoogle.com'));
ok('ignore extra', hostIsIgnored('sub.mysite.com', ['mysite.com']));
ok('ignore empty-extra safe', !hostIsIgnored('example.com', ['']));
ok('urlHostIsIgnored', urlHostIsIgnored('https://www.google.com/x'));
ok('urlHostIsIgnored bad url', !urlHostIsIgnored('not a url'));

// ===================== STORE =====================
await store.clearAll();
await store.upsertFinding({ key: KEYS.google, provider: 'google', origin: 'https://a.com', pageUrl: 'https://a.com/p', source: 'dom', mapsContext: true });
await store.upsertFinding({ key: KEYS.google, provider: 'google', origin: 'https://b.com', source: 'network' });
{
  const db = await store.getDb();
  eq('store dedup one finding', db.findings.length, 1);
  const f = db.findings[0];
  eq('store origins merged', f.origins.length, 2);
  eq('store sources merged', f.sources.sort().join(','), 'dom,network');
  eq('store provider', f.provider, 'google');
}
// twilio secret persisted
await store.upsertFinding({ key: SID, provider: 'twilio', secret: TOK, origin: 'https://c.com', source: 'script' });
{
  const f = (await store.getDb()).findings.find(x => x.key === SID);
  eq('store twilio secret', f.secret, TOK);
}
// provider backfill when not provided
await store.upsertFinding({ key: KEYS.openai_proj, origin: 'https://d.com', source: 'dom' });
{
  const f = (await store.getDb()).findings.find(x => x.key === KEYS.openai_proj);
  eq('store provider backfill', f.provider, 'openai');
}
// purgeIgnored removes google.com origin keys only
await store.clearAll();
await store.upsertFinding({ key: KEYS.google, provider: 'google', origin: 'https://google.com', source: 'dom' });
await store.upsertFinding({ key: KEYS.openai_legacy, provider: 'openai', origin: 'https://safe.com', source: 'dom' });
{
  const res = await store.purgeIgnored([]);
  const db = await store.getDb();
  eq('purge removed 1', res.removed, 1);
  eq('purge kept safe', db.findings.length, 1);
  eq('purge kept which', db.findings[0].origin || db.findings[0].origins[0], 'https://safe.com');
}
// key on BOTH ignored + safe origin -> kept (ignored origin stripped)
await store.clearAll();
await store.upsertFinding({ key: KEYS.google, provider: 'google', origin: 'https://google.com', source: 'dom' });
await store.upsertFinding({ key: KEYS.google, provider: 'google', origin: 'https://safe.com', source: 'dom' });
{
  await store.purgeIgnored([]);
  const db = await store.getDb();
  eq('purge mixed kept', db.findings.length, 1);
  ok('purge mixed stripped ignored origin', !db.findings[0].origins.includes('https://google.com'));
  ok('purge mixed kept safe origin', db.findings[0].origins.includes('https://safe.com'));
}
// migrate: legacy single-origin record + missing provider
await store.clearAll();
local['gaks_db'] = { findings: [
  { key: KEYS.anthropic, origin: 'https://leg.com', pageUrl: 'https://leg.com/x', sources: ['dom'], audits: [] },
  { key: KEYS.anthropic, origin: 'https://leg2.com', sources: ['network'], audits: [] }, // dup key
] };
{
  await store.migrate();
  const db = await store.getDb();
  eq('migrate dedup', db.findings.length, 1);
  const f = db.findings[0];
  eq('migrate provider backfill', f.provider, 'anthropic');
  eq('migrate origins merged', f.origins.sort().join(','), 'https://leg.com,https://leg2.com');
}
// collection
await store.clearCollection();
await store.saveToCollection({ key: SID, provider: 'twilio', secret: TOK, origins: ['https://c.com'], note: 'n' });
{
  const c = await store.getCollection();
  eq('collection saved', c.items.length, 1);
  eq('collection secret', c.items[0].secret, TOK);
  eq('collection provider', c.items[0].provider, 'twilio');
}
await store.removeFromCollection(SID);
eq('collection removed', (await store.getCollection()).items.length, 0);
// importDb merge
await store.clearAll();
await store.upsertFinding({ key: KEYS.google, provider: 'google', origin: 'https://a.com', source: 'dom' });
{
  const res = await store.importDb({ findings: [
    { key: KEYS.google, origins: ['https://b.com'], sources: ['network'], audits: [] },
    { key: KEYS.xai, provider: 'xai', origins: ['https://c.com'], sources: ['dom'], audits: [] },
  ] });
  const db = await store.getDb();
  eq('import merged count', db.findings.length, 2);
  const g = db.findings.find(f => f.key === KEYS.google);
  eq('import merged origins', g.origins.sort().join(','), 'https://a.com,https://b.com');
}

// ===================== PERFORMANCE / ReDoS =====================
{
  // adversarial: many "AC"+hex and "sk-" fragments + large random
  let big = '';
  for (let i = 0; i < 20000; i++) big += 'AC' + 'abcdef0123456789'.repeat(2) + ' sk-' + 'a'.repeat(39) + ' ';
  big += KEYS.google;
  const t0 = Date.now();
  const hits = detectKeys(big);
  const dt = Date.now() - t0;
  ok('perf adversarial < 2000ms (' + dt + 'ms)', dt < 2000);
  ok('perf still finds real google key', hits.some(h => h.key === KEYS.google));
  ok('perf no twilio false positives in adversarial', !hits.some(h => h.provider === 'twilio'));
}

// ===================== BOUNDARY / SUBSTRING =====================
const G = KEYS.google;
eq('boundary: =key" matches', detectKeys('x="' + G + '";').length, 1);
eq('boundary: space-delimited', detectKeys('  ' + G + '  ').length, 1);
eq('boundary: preceded by alnum -> no match', detectKeys('x' + G).length, 0);
eq('boundary: followed by alnum -> no match', detectKeys(G + 'x').length, 0);
eq('boundary: prefix of longer token -> no match', detectKeys('AIza' + '1'.repeat(40)).length, 0);
eq('boundary: at start', detectKeys(G + ' tail').length, 1);
eq('boundary: at end', detectKeys('head ' + G).length, 1);
// openai legacy preceded by alnum
eq('boundary openai suffix-of-token', detectKeys('word' + KEYS.openai_legacy).length, 0);
// length boundaries
eq('len: google 34 chars -> no', detectKeys('AIza' + 'a'.repeat(34)).length, 0);
eq('len: google 35 chars -> yes', detectKeys(' AIza' + 'a'.repeat(35) + ' ').length, 1);
eq('len: openai sk- 39 alnum -> no', detectKeys(' sk-' + 'a'.repeat(39) + ' ').length, 0);
eq('len: openai sk- 40 alnum -> yes', detectKeys(' sk-' + 'a'.repeat(40) + ' ').length, 1);
eq('len: anthropic 89 -> no', detectKeys(' sk-ant-' + 'a'.repeat(89) + ' ').length, 0);
eq('len: anthropic 90 -> yes', detectKeys(' sk-ant-' + 'a'.repeat(90) + ' ').length, 1);
eq('len: xai 39 -> no', detectKeys(' xai-' + 'a'.repeat(39) + ' ').length, 0);
eq('len: xai 40 -> yes', detectKeys(' xai-' + 'a'.repeat(40) + ' ').length, 1);
// twilio: AC+hex as prefix of a longer hash (64 hex) with context -> no match (trailing hex)
eq('twilio not prefix-of-hash', detectKeys('twilio ' + 'AC' + 'a'.repeat(62)).filter(h=>h.provider==='twilio').length, 0);
// twilio token far away (>700) not captured
{
  const farPad = 'z'.repeat(800);
  const h = detectKeys('TWILIO_ACCOUNT_SID=' + SID + farPad + TOK)[0];
  ok('twilio far token not captured', h && !h.secret);
}
// mapsContext
ok('mapsContext true in maps url', detectKeys('src="https://maps.googleapis.com/maps/api/js?key=' + G + '"')[0].mapsContext === true);
ok('mapsContext false otherwise', detectKeys('var k="' + G + '"')[0].mapsContext === false);

// ===================== CLASSIFY (audit.js) =====================
const audit = await import('../lib/audit.js');
eq('classifyMessage referer', audit.classifyMessage('API keys with referer restrictions cannot be used'), 'restricted-referer');
eq('classifyMessage ip', audit.classifyMessage('The provided IP address is not authorized'), 'restricted-ip');
eq('classifyMessage not-enabled legacy', audit.classifyMessage("You're calling a legacy API, which is not enabled for your project"), 'api-not-enabled');
eq('classifyMessage has-not-been-used', audit.classifyMessage('Places API has not been used in project 123 before or it is disabled'), 'api-not-enabled');
eq('classifyMessage invalid', audit.classifyMessage('API key not valid. Please pass a valid API key.'), 'invalid-key');
eq('classifyMessage quota', audit.classifyMessage('You have exceeded your rate-limit / quota'), 'over-quota');
eq('classifyMessage none', audit.classifyMessage('something totally unrelated'), null);
eq('classify 200', audit.classify(200, ''), 'enabled');
eq('classify 401 unknown msg', audit.classify(401, 'nope'), 'denied');
eq('classify 0', audit.classify(0, ''), 'error');
eq('classify referer wins over 200', audit.classify(200, 'referer restriction'), 'restricted-referer');

// ===================== STORE: remaining ops =====================
await store.clearAll();
const rec = await store.upsertFinding({ key: G, provider: 'google', origin: 'https://a.com', source: 'dom', mapsContext: false });
// addAudit + setAudits + getFinding + deleteFinding
await store.addAudit(rec.id, { service: 'Maps', endpoint: 'Geocoding', httpStatus: 200, classification: 'enabled', billable: true });
{
  const f = await store.getFinding(rec.id);
  eq('addAudit appended', f.audits.length, 1);
}
await store.setAudits(rec.id, [{ service: 'X', endpoint: 'Y', httpStatus: 403, classification: 'restricted-referer' }]);
{
  const f = await store.getFinding(rec.id);
  eq('setAudits replaced', f.audits.length, 1);
  eq('setAudits content', f.audits[0].classification, 'restricted-referer');
}
// mapsContext upgrade on re-upsert
await store.upsertFinding({ key: G, provider: 'google', origin: 'https://a.com', source: 'resource', mapsContext: true });
eq('mapsContext upgraded', (await store.getFinding(rec.id)).mapsContext, true);
await store.deleteFinding(rec.id);
eq('deleteFinding', (await store.getDb()).findings.length, 0);
// ignore domains normalization
{
  const saved = await store.setIgnoreDomains(['https://Foo.com/path', '*.bar.com', '  BAZ.com  ', '', 'foo.com']);
  ok('setIgnoreDomains normalized', saved.includes('foo.com') && saved.includes('bar.com') && saved.includes('baz.com'));
  ok('setIgnoreDomains deduped', saved.filter(d => d === 'foo.com').length === 1);
  ok('setIgnoreDomains no empties', !saved.includes(''));
  const got = await store.getIgnoreDomains();
  eq('getIgnoreDomains roundtrip', got.length, saved.length);
}
// collection note + audits
await store.clearCollection();
await store.saveToCollection({ key: G, provider: 'google', origins: ['https://a.com'] });
await store.setCollectionNote(G, 'hello');
await store.setCollectionAudits(G, [{ service: 'Maps', classification: 'enabled' }]);
{
  const c = await store.getCollection();
  eq('collection note', c.items[0].note, 'hello');
  eq('collection audits', c.items[0].audits.length, 1);
}
// importCollection merge
{
  const res = await store.importCollection({ items: [{ key: KEYS.xai, provider: 'xai', origins: ['https://z.com'] }] });
  eq('importCollection merged', (await store.getCollection()).items.length, 2);
}

// ===================== FINAL EDGE CASES =====================
// realistic URL delimiters
eq('url & delimiter', detectKeys('https://maps.googleapis.com/maps/api/js?key=' + G + '&libraries=places').length, 1);
eq('json + concat', detectKeys('var k="' + KEYS.openai_proj + '"+x;').length, 1);
// twilio error -> unknown
eq('risk twilio error', assessRisk([{classification:'error'}], 'twilio').level, 'unknown');
// assessRisk null/undefined audits
eq('risk null audits', assessRisk(null, 'google').level, 'unknown');
eq('risk undefined audits openai', assessRisk(undefined, 'openai').level, 'unknown');
// every provider has required shape
for (const p of PROVIDERS) {
  ok('provider ' + p.id + ' shape', typeof p.audit === 'function' && typeof p.assess === 'function' && p.keyRe instanceof RegExp && p.singleRe instanceof RegExp);
}
// concurrent upserts of same key -> exactly one finding (write-chain serialization)
await store.clearAll();
await Promise.all(Array.from({ length: 25 }, (_, i) =>
  store.upsertFinding({ key: G, provider: 'google', origin: 'https://o' + (i % 5) + '.com', source: 'dom' })));
{
  const db = await store.getDb();
  eq('concurrent upsert single finding', db.findings.length, 1);
  eq('concurrent upsert origins', db.findings[0].origins.length, 5);
}
// getDb normalization is idempotent
{
  const a = JSON.stringify(await store.getDb());
  const b = JSON.stringify(await store.getDb());
  eq('getDb idempotent', a, b);
}
// performance with many real keys interleaved
{
  let s = '';
  for (let i = 0; i < 5000; i++) s += ' noise' + i + ' ' + KEYS.openai_proj.slice(0, 30) + ' ';
  s += ' ' + G + ' ' + KEYS.anthropic + ' ';
  const t0 = Date.now();
  const hits = detectKeys(s);
  const dt = Date.now() - t0;
  ok('perf realistic < 1500ms (' + dt + 'ms)', dt < 1500);
  ok('perf finds embedded real keys', hits.some(h => h.key === G) && hits.some(h => h.key === KEYS.anthropic));
}

// ===================== CONTENT-WORLD (patterns.js) PARITY =====================
import { readFileSync } from 'node:fs';
const patternsSrc = readFileSync(new URL('../content/patterns.js', import.meta.url), 'utf8');
// Evaluate the IIFE to obtain GAKS (it references no DOM/chrome APIs).
const GAKS = (0, eval)(patternsSrc + '\n;GAKS');
ok('patterns GAKS loaded', GAKS && typeof GAKS.findInText === 'function');
const parityInputs = [
  Object.values(KEYS).join(' '),
  'TWILIO_ACCOUNT_SID=' + SID + ' TWILIO_AUTH_TOKEN=' + TOK,
  'id=' + SID + ' (no twilio context)',
  'x' + G, G + 'x', 'AIza' + '1'.repeat(40),
  'https://maps.googleapis.com/maps/api/js?key=' + G + '&libraries=places',
  '{"k":"' + KEYS.openai_proj + '"}',
  ' sk-' + 'a'.repeat(39) + ' ', ' sk-' + 'a'.repeat(40) + ' ',
];
for (let i = 0; i < parityInputs.length; i++) {
  const inp = parityInputs[i];
  const a = detectKeys(inp).map(h => h.provider + ':' + h.key + ':' + (h.secret || '')).sort().join('|');
  const b = GAKS.findInText(inp).map(h => h.provider + ':' + h.key + ':' + (h.secret || '')).sort().join('|');
  eq('parity[' + i + ']', a, b);
}
// hostIsIgnored parity
for (const host of ['google.com', 'example.com', 'm.youtube.com', 'notgoogle.com', 'www.google.co.uk']) {
  eq('ignore parity ' + host, !!hostIsIgnored(host), !!GAKS.hostIsIgnored(host, []));
}

console.log('\n=== ' + pass + ' passed, ' + fail + ' failed ===');
if (fail) { console.log('Failures:', fails); process.exit(1); }
