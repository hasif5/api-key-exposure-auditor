/*
 * logic.mjs - logic-layer evidence for research case study 001.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * Runs the REAL extension modules (lib/providers.js, lib/audit.js, lib/store.js,
 * content/patterns.js, content/intercept.js) in Node with `chrome` and `fetch`
 * mocked. It never touches the network: any fetch() is answered by a local mock
 * and recorded, and a fetch with no registered mock throws.
 *
 * Sections
 *   A  fixture self-check          (runtime-assembled keys are not in static markup)
 *   B  detection variants          (provider x presentation format)
 *   C  three-engine parity         (providers.js vs patterns.js vs intercept.js)
 *   D  false-positive corpus       (S12 negatives through the module-world detector)
 *   E  risk classification         (SIMULATED provider responses -> real assessRisk)
 *   F  audit probe inventory       (what an audit sends: hosts, billable flags, referrer)
 *   G  audit-gate source facts     (where the consent gate lives in the code)
 *
 * Usage: node research/harness/logic.mjs
 * Output: research/evidence/results/logic-results.json, research/evidence/transcripts/logic-run.txt
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { execSync } from 'node:child_process';
import vm from 'node:vm';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const OUT = join(ROOT, 'research', 'evidence');
mkdirSync(join(OUT, 'results'), { recursive: true });
mkdirSync(join(OUT, 'transcripts'), { recursive: true });

const logLines = [];
function log(...a) { const s = a.join(' '); logLines.push(s); console.log(s); }

// ---------------------------------------------------------------- mocks
const store = {};
globalThis.chrome = {
  storage: {
    local: {
      get: async (k) => { const o = {}; for (const x of (Array.isArray(k) ? k : [k])) if (x in store) o[x] = store[x]; return o; },
      set: async (o) => { Object.assign(store, o); }
    },
    session: { get: async () => ({}), set: async () => {} }
  }
};

const requests = [];
let handler = null;
globalThis.fetch = async (url, opts) => {
  opts = opts || {};
  const u = new URL(url);
  requests.push({
    method: opts.method || 'GET', host: u.host, path: u.pathname, search: u.search,
    headerNames: Object.keys(opts.headers || {}), referrerPolicy: opts.referrerPolicy,
    credentials: opts.credentials, hasBody: !!opts.body
  });
  if (!handler) throw new Error('real network blocked: no mock handler registered');
  return handler(u, opts);
};
const json = (status, obj, headers) => new Response(JSON.stringify(obj), { status, headers: Object.assign({ 'content-type': 'application/json' }, headers || {}) });
const text = (status, body, ct) => new Response(body, { status, headers: { 'content-type': ct || 'text/plain' } });

const { make, pemBlock, redact, fingerprint } = await import(pathToFileURL(join(ROOT, 'research/fixtures/synthetic.mjs')).href);
const { buildScenarios, selfCheck, allExpectations } = await import(pathToFileURL(join(ROOT, 'research/fixtures/scenarios.mjs')).href);
const prov = await import(pathToFileURL(join(ROOT, 'lib/providers.js')).href);
const { detectKeys, PROVIDERS, getProvider, assessRisk } = prov;

const results = { meta: {}, sections: {} };
function git(cmd) { try { return execSync('git ' + cmd, { cwd: ROOT }).toString().trim(); } catch (e) { return 'unavailable'; } }
results.meta = {
  generatedAt: new Date().toISOString(),
  node: process.version,
  extensionVersion: JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8')).version,
  gitCommit: git('rev-parse HEAD'),
  gitDirtyPaths: git('status --short').split('\n').filter(Boolean).length,
  note: 'All credentials are synthetic. Provider responses in sections E and F are SIMULATED by local mocks.'
};

// ---------------------------------------------------------------- A. fixture self-check
{
  const scenarios = buildScenarios({ port: 1 });
  const problems = selfCheck(scenarios, detectKeys);
  results.sections.A_fixtureSelfCheck = { scenarios: scenarios.length, problems };
  log('A  fixture self-check: ' + scenarios.length + ' scenarios, ' + problems.length + ' problems');
  for (const p of problems) log('   PROBLEM ' + p);
}

// ---------------------------------------------------------------- B. detection variants
const SUBJECTS = [
  { id: 'google', provider: 'google', key: make.google('B') },
  { id: 'google-new', provider: 'google', key: make.googleNew('B') },
  { id: 'openai-proj', provider: 'openai', key: make.openaiProj('B') },
  { id: 'openai-legacy', provider: 'openai', key: make.openaiLegacy('B') },
  { id: 'openai-svcacct', provider: 'openai', key: make.openaiSvc('B') },
  { id: 'anthropic', provider: 'anthropic', key: make.anthropic('B') },
  { id: 'openrouter', provider: 'openrouter', key: make.openrouter('B') },
  { id: 'xai', provider: 'xai', key: make.xai('B') },
  { id: 'github', provider: 'github', key: make.github('B') },
  { id: 'gitlab', provider: 'gitlab', key: make.gitlab('B') },
  { id: 'slack', provider: 'slack', key: make.slack('B') },
  { id: 'stripe-test', provider: 'stripe', key: make.stripeTest('B') },
  (() => { const k = make.twilioSid('B'), s = make.twilioToken('B'); return { id: 'twilio-pair', provider: 'twilio', key: k, secret: s, text: 'TWILIO_ACCOUNT_SID=' + k + ';TWILIO_AUTH_TOKEN=' + s, pair: true }; })(),
  (() => { const k = make.awsId('B'), s = make.awsSecret('B'); return { id: 'aws-pair', provider: 'aws', key: k, secret: s, text: 'awsAccessKeyId=' + k + ';awsSecretAccessKey=' + s, pair: true }; })()
];

const pct = (t) => Array.from(t).map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
const VARIANTS = {
  plain: (t) => t,
  surrounded: (t) => 'Note: use ' + t + ', then rotate.',
  json: (t) => JSON.stringify({ a: { note: 'x', v: t } }),
  jsAssign: (t) => 'var cfg = "' + t + '"; // end',
  urlQuery: (t, s) => s.pair ? null : 'https://api.example.test/v1/x?foo=1&key=' + encodeURIComponent(t) + '&bar=2',
  htmlAttr: (t) => '<div data-x="1" data-token="' + t + '"></div>',
  minified: (t) => '!function(){var a={k:"' + t.replace(/\s+/g, '') + '",z:1};return a}();',
  base64: (t) => 'cfg:' + Buffer.from(t).toString('base64'),
  percentEncoded: (t) => 'next=' + pct(t)
};

function norm(hits) {
  return hits.map((h) => h.key + '|' + h.provider + '|' + (h.secret || '')).sort();
}

const trials = [];
for (const s of SUBJECTS) {
  const base = s.text || s.key;
  for (const [vn, fn] of Object.entries(VARIANTS)) {
    const txt = fn(base, s);
    if (txt == null) continue;
    const hits = detectKeys(txt);
    const hit = hits.find((h) => h.key === s.key);
    const ok = !!hit && hit.provider === s.provider && (!s.secret || hit.secret === s.secret);
    trials.push({ subject: s.id, variant: vn, text: txt, expected: s, ok, got: hit ? hit.provider : null });
  }
}
{
  const byVariant = {}, byProvider = {};
  for (const t of trials) {
    (byVariant[t.variant] = byVariant[t.variant] || { n: 0, ok: 0 }).n++;
    (byProvider[t.subject] = byProvider[t.subject] || { n: 0, ok: 0 }).n++;
    if (t.ok) { byVariant[t.variant].ok++; byProvider[t.subject].ok++; }
  }
  const failed = trials.filter((t) => !t.ok).map((t) => ({ subject: t.subject, variant: t.variant, got: t.got }));
  results.sections.B_detectionVariants = {
    trials: trials.length, detected: trials.filter((t) => t.ok).length, byVariant, byProvider, failed
  };
  log('B  detection variants: ' + results.sections.B_detectionVariants.detected + '/' + trials.length + ' detected with correct provider (+secret for pairs)');
  for (const f of failed) log('   MISS ' + f.subject + ' / ' + f.variant + ' (got ' + f.got + ')');
}

// ---------------------------------------------------------------- C. three-engine parity
function loadPatterns() {
  const src = readFileSync(join(ROOT, 'content/patterns.js'), 'utf8');
  const ctx = vm.createContext({ atob: globalThis.atob, decodeURIComponent, console });
  vm.runInContext(src, ctx);
  return ctx;
}
function runIntercept(textIn) {
  const src = readFileSync(join(ROOT, 'content/intercept.js'), 'utf8');
  const sent = [];
  const sandbox = { console, atob: globalThis.atob, TextDecoder, URLSearchParams, setTimeout, decodeURIComponent };
  sandbox.window = sandbox;
  sandbox.location = { href: 'http://fixture.test/' };
  sandbox.navigator = { sendBeacon() { return true; } };
  sandbox.history = {};
  sandbox.XMLHttpRequest = function () {};
  sandbox.XMLHttpRequest.prototype = { open() {}, send() {}, setRequestHeader() {} };
  sandbox.fetch = () => new Promise(() => {});
  sandbox.addEventListener = () => {};
  sandbox.postMessage = (m) => { if (m && m.type === '__GAKS_NET_FINDING__') sent.push({ key: m.key, provider: m.provider, secret: m.secret || undefined }); };
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  sandbox.fetch(textIn); // patched fetch() scans its URL argument
  return sent;
}
{
  const gaks = loadPatterns().GAKS;
  const corpus = trials.map((t) => t.text);
  const exp = allExpectations(buildScenarios({ port: 1 }));
  for (const n of exp.negatives) corpus.push(n.embedded || n.text);
  let compared = 0, diffsPatterns = [], diffsIntercept = [];
  for (const t of corpus) {
    const a = norm(detectKeys(t));
    const b = norm(gaks.findInText(t));
    const c = norm(runIntercept(t));
    compared++;
    if (a.join('\n') !== b.join('\n')) diffsPatterns.push({ text: redact(t.slice(0, 60)), providers: a.length, patterns: b.length });
    if (a.join('\n') !== c.join('\n')) diffsIntercept.push({ text: redact(t.slice(0, 60)), providers: a.length, intercept: c.length });
  }
  results.sections.C_parity = { compared, patternsJsDiffs: diffsPatterns.length, interceptJsDiffs: diffsIntercept.length, detailsPatterns: diffsPatterns, detailsIntercept: diffsIntercept };
  log('C  parity over ' + compared + ' texts: patterns.js differs on ' + diffsPatterns.length + ', intercept.js differs on ' + diffsIntercept.length);
}

// ---------------------------------------------------------------- C2. harness negative control
// A parity check that can never fail proves nothing. Mutate an in-memory copy of
// patterns.js (Anthropic minimum length 90 -> 91, Stripe prefix test -> tst) and
// require the same comparison to report differences. The repo files are not touched.
{
  const orig = readFileSync(join(ROOT, 'content/patterns.js'), 'utf8');
  const mutated = orig.replace('sk-ant-[A-Za-z0-9_-]{90,}', 'sk-ant-[A-Za-z0-9_-]{91,}').replace('(?:sk|rk)_(?:live|test)_', '(?:sk|rk)_(?:live|tst)_');
  const mutationApplied = mutated !== orig;
  const ctx = vm.createContext({ atob: globalThis.atob, decodeURIComponent, console });
  vm.runInContext(mutated, ctx);
  let diffs = 0;
  for (const t of trials.map((x) => x.text)) {
    if (norm(detectKeys(t)).join('\n') !== norm(ctx.GAKS.findInText(t)).join('\n')) diffs++;
  }
  results.sections.C2_negativeControl = { mutationApplied, diffsDetected: diffs, controlWorks: mutationApplied && diffs > 0 };
  log('C2 negative control: mutation applied=' + mutationApplied + ', parity diffs reported=' + diffs + ' (must be > 0) -> ' + (mutationApplied && diffs > 0 ? 'OK' : 'CONTROL FAILED'));
  if (!(mutationApplied && diffs > 0)) { log('   The parity check did not react to a deliberate regression; do not trust section C.'); }
}

// ---------------------------------------------------------------- D. false-positive corpus
{
  const exp = allExpectations(buildScenarios({ port: 1 }));
  const rows = exp.negatives.map((n) => {
    const hits = detectKeys(n.embedded || n.text);
    return { id: n.id, cls: n.cls, note: n.note, flagged: hits.length > 0, as: hits.map((h) => h.provider + (h.reason ? ' (' + h.reason + ')' : '')) };
  });
  const sum = (cls) => ({ total: rows.filter((r) => r.cls === cls).length, flagged: rows.filter((r) => r.cls === cls && r.flagged).length });
  results.sections.D_falsePositiveCorpus = { invalid: sum('invalid'), lookalike: sum('lookalike'), rows };
  log('D  false-positive corpus: invalid ' + sum('invalid').flagged + '/' + sum('invalid').total + ' flagged; lookalike ' + sum('lookalike').flagged + '/' + sum('lookalike').total + ' flagged');
  for (const r of rows.filter((x) => x.flagged)) log('   FLAGGED ' + r.id + ' -> ' + r.as.join(', '));
}

// ---------------------------------------------------------------- E. risk classification (simulated responses)
const HOST_RE = (h) => (u) => u.host === h;
function levelOf(providerId, audits) { return assessRisk(audits, providerId); }
async function runAudit(providerId, key, opts) { return getProvider(providerId).audit(key, opts || {}); }

const E = [];
async function scenario(name, providerId, key, opts, h, expectLevel, extra) {
  handler = h;
  const before = requests.length;
  const audits = await runAudit(providerId, key, opts);
  const a = levelOf(providerId, audits);
  const ok = a.level === expectLevel && (!extra || !extra.check || extra.check(a, audits));
  E.push({ name, provider: providerId, expectedLevel: expectLevel, observedLevel: a.level, observedLabel: a.label, bypass: !!a.bypass,
    probes: requests.length - before, classifications: Array.from(new Set(audits.map((x) => x.classification))), ok, note: extra && extra.note });
}

const okModels = (u) => json(200, { data: [{ id: 'm1' }, { id: 'm2' }] });
const unauth = () => json(401, { error: { message: 'Incorrect API key provided.', type: 'invalid_request_error' } });

// Bearer-token providers
for (const [pid, kf] of [['openai', make.openaiProj], ['anthropic', make.anthropic], ['openrouter', make.openrouter], ['xai', make.xai]]) {
  const k = kf('E');
  await scenario(pid + ': valid key (all probes 200)', pid, k, {}, okModels, 'critical');
  await scenario(pid + ': revoked key (all probes 401)', pid, k, {}, unauth, 'unknown', { check: (a) => /Invalid/.test(a.label) });
}
await scenario('openai: models 401 but another probe 200 (partial scope)', 'openai', make.openaiProj('E2'), {},
  (u) => u.pathname === '/v1/models' ? unauth() : json(200, { ok: true }), 'critical');
await scenario('openai: every probe 403 insufficient permissions', 'openai', make.openaiProj('E3'), {},
  () => json(403, { error: { message: 'You have insufficient permissions for this operation.', type: 'invalid_request_error' } }), 'unknown',
  { note: 'OBSERVATION: HTTP 403 is classified invalid-key, so a valid key that lacks scope on every probe is labelled invalid/revoked.' });
await scenario('openai: every probe 429 (quota exceeded)', 'openai', make.openaiProj('E4'), {},
  () => json(429, { error: { message: 'You exceeded your current quota.', type: 'insufficient_quota' } }), 'unknown',
  { note: 'OBSERVATION: over-quota means the key authenticated, but the bearer assessor reports "Not reachable" (level unknown).' });

// Pair providers
{
  const sid = make.twilioSid('E'), tok = make.twilioToken('E');
  await scenario('twilio: valid pair', 'twilio', sid, { secret: tok }, () => json(200, { sid }), 'critical');
  await scenario('twilio: wrong token (401)', 'twilio', sid, { secret: tok }, () => json(401, { message: 'Authenticate' }), 'unknown');
  await scenario('twilio: SID found but no token nearby', 'twilio', sid, {}, () => { throw new Error('must not be called'); }, 'unknown',
    { check: (a, au) => au.length === 1 && au[0].classification === 'inconclusive', note: 'No network call is made when the pair is incomplete.' });
  const id = make.awsId('E'), sec = make.awsSecret('E');
  await scenario('aws: valid pair (STS 200)', 'aws', id, { secret: sec },
    () => text(200, '<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::000000000000:user/fixture</Arn><Account>000000000000</Account></GetCallerIdentityResult></GetCallerIdentityResponse>', 'text/xml'), 'critical');
  await scenario('aws: invalid pair (403 InvalidClientTokenId)', 'aws', id, { secret: sec },
    () => text(403, '<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>', 'text/xml'), 'unknown');
  await scenario('aws: ID found but no secret nearby', 'aws', id, {}, () => { throw new Error('must not be called'); }, 'unknown',
    { check: (a, au) => au.length === 1 && au[0].classification === 'inconclusive' });
}
// Token providers
await scenario('github: valid (200 login)', 'github', make.github('E'), {}, () => json(200, { login: 'fixture-user' }), 'critical');
await scenario('github: bad credentials (401)', 'github', make.github('E'), {}, () => json(401, { message: 'Bad credentials' }), 'unknown');
await scenario('gitlab: valid (200 username)', 'gitlab', make.gitlab('E'), {}, () => json(200, { username: 'fixture' }), 'critical');
await scenario('gitlab: 401', 'gitlab', make.gitlab('E'), {}, () => json(401, { message: '401 Unauthorized' }), 'unknown');
await scenario('slack: ok:true', 'slack', make.slack('E'), {}, () => json(200, { ok: true, team: 'fixture', user: 'bot' }), 'critical');
await scenario('slack: HTTP 200 with ok:false invalid_auth', 'slack', make.slack('E'), {}, () => json(200, { ok: false, error: 'invalid_auth' }), 'unknown',
  { note: 'Slack returns HTTP 200 for bad tokens; the verdict must come from the JSON body.' });
await scenario('stripe: valid (200 account)', 'stripe', make.stripeTest('E'), {}, () => json(200, { id: 'acct_fixture' }), 'critical');
await scenario('stripe: 401', 'stripe', make.stripeTest('E'), {}, () => json(401, { error: { message: 'Invalid API Key provided', type: 'invalid_request_error' } }), 'unknown');

// Google (delegates to audit.js; many probes, URL-routed mock)
function googleMock(cfg) {
  const mapsJsonPaths = /^\/maps\/api\/(geocode|directions|distancematrix|elevation|timezone|streetview|place)\b/;
  const msgs = {
    REFERER: 'API keys with referer restrictions cannot be used with this API.',
    INVALID: 'API key not valid. Please pass a valid API key.',
    NOTENABLED: 'This API is not activated on your API project.'
  };
  const restErr = {
    REFERER: [403, 'Requests from referer <empty> are blocked.', 'PERMISSION_DENIED'],
    INVALID: [400, 'API key not valid. Please pass a valid API key.', 'INVALID_ARGUMENT'],
    NOTENABLED: [403, 'Generative Language API has not been used in project 1 before or it is disabled.', 'PERMISSION_DENIED']
  };
  return (u) => {
    const p = u.pathname;
    if (u.host === 'maps.googleapis.com' && p === '/maps/api/staticmap') {
      if (cfg.staticMap === 'OK') return new Response(new Uint8Array([137, 80, 78, 71]), { status: 200, headers: { 'content-type': 'image/png' } });
      return text(200, cfg.staticMap === 'TEXT_ERROR' ? 'The Google Maps Platform server rejected your request. API key not valid.' : msgs[cfg.maps] || '', 'text/plain');
    }
    if (u.host === 'maps.googleapis.com' && p === '/maps/api/js') {
      const tok = { OK: '', REFERER: 'RefererNotAllowedMapError', INVALID: 'InvalidKeyMapError', NOTENABLED: 'ApiNotActivatedMapError' }[cfg.maps];
      return text(200, '/* loader */ ' + tok, 'application/javascript');
    }
    if (u.host === 'maps.googleapis.com' && mapsJsonPaths.test(p)) {
      if (cfg.maps === 'OK') return json(200, { status: 'OK', results: [] });
      return json(200, { status: 'REQUEST_DENIED', error_message: msgs[cfg.maps] });
    }
    const mode = typeof cfg.rest === 'function' ? cfg.rest(u) : cfg.rest;
    if (mode === 'OK') return json(200, { ok: true });
    const e = restErr[mode];
    return json(e[0], { error: { code: e[0], message: e[1], status: e[2] } });
  };
}
const gKey = make.google('E');
await scenario('google: invalid/revoked key everywhere', 'google', gKey, {}, googleMock({ maps: 'INVALID', rest: 'INVALID', staticMap: 'TEXT_ERROR' }), 'unknown');
await scenario('google: referrer-restricted everywhere', 'google', gKey, {}, googleMock({ maps: 'REFERER', rest: 'REFERER', staticMap: 'REFERER' }), 'restricted');
await scenario('google: APIs not enabled everywhere', 'google', gKey, {}, googleMock({ maps: 'NOTENABLED', rest: 'NOTENABLED', staticMap: 'NOTENABLED' }), 'unknown');
await scenario('google: unrestricted, billable Maps reachable', 'google', gKey, {}, googleMock({ maps: 'OK', rest: 'INVALID', staticMap: 'OK' }), 'critical');
await scenario('google: referrer-locked Maps but non-billable Gemini listing open', 'google', gKey, {},
  googleMock({ maps: 'REFERER', staticMap: 'REFERER', rest: (u) => (u.host === 'generativelanguage.googleapis.com' && u.pathname.indexOf(':') === -1) ? 'OK' : 'REFERER' }),
  'high', { check: (a) => a.bypass === true, note: 'Referrer restriction is bypassable: some endpoints answer with no Referer.' });
{
  handler = googleMock({ maps: 'INVALID', rest: 'INVALID', staticMap: 'TEXT_ERROR' });
  const au = await runAudit('google', gKey, {});
  const sm = au.find((x) => x.endpoint === 'Static Maps');
  E.push({ name: 'google: Static Maps HTTP 200 text/plain error must not count as enabled', provider: 'google', expectedLevel: 'n/a',
    observedLevel: sm.classification, observedLabel: sm.detail.slice(0, 60), ok: sm.classification !== 'enabled', probes: 0 });
}
results.sections.E_riskClassification = { simulated: true, total: E.length, passed: E.filter((x) => x.ok).length, rows: E };
log('E  risk classification (simulated responses): ' + E.filter((x) => x.ok).length + '/' + E.length + ' scenarios matched expectation');
for (const r of E.filter((x) => !x.ok)) log('   MISMATCH ' + r.name + ' expected ' + r.expectedLevel + ' got ' + r.observedLevel);

// ---------------------------------------------------------------- F. audit probe inventory
const ALLOWED_HOSTS = [/\.googleapis\.com$/, /^api\.openai\.com$/, /^api\.anthropic\.com$/, /^api\.x\.ai$/, /^openrouter\.ai$/,
  /^api\.twilio\.com$/, /^sts\.amazonaws\.com$/, /^api\.github\.com$/, /^gitlab\.com$/, /^slack\.com$/, /^api\.stripe\.com$/];
const INV = [];
const invSubjects = [
  ['google', make.google('F'), {}], ['openai', make.openaiProj('F'), {}], ['anthropic', make.anthropic('F'), {}],
  ['openrouter', make.openrouter('F'), {}], ['xai', make.xai('F'), {}],
  ['twilio', make.twilioSid('F'), { secret: make.twilioToken('F') }], ['aws', make.awsId('F'), { secret: make.awsSecret('F') }],
  ['github', make.github('F'), {}], ['gitlab', make.gitlab('F'), {}], ['slack', make.slack('F'), {}], ['stripe', make.stripeTest('F'), {}]
];
for (const [pid, key, base] of invSubjects) {
  for (const gen of [false, true]) {
    // Neutral "bad credential" answer shaped per provider family (Slack answers
    // 200 + {ok:false,error:string}; AWS answers XML; most others answer 401 JSON).
    handler = (u) => {
      if (u.host === 'slack.com') return json(200, { ok: false, error: 'invalid_auth' });
      if (u.host === 'sts.amazonaws.com') return text(403, '<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>', 'text/xml');
      if (/twilio|github|gitlab/.test(u.host)) return json(401, { message: 'Unauthorized' });
      return json(401, { error: { message: 'Invalid API key', type: 'invalid_request_error' } });
    };
    const before = requests.length;
    const audits = await runAudit(pid, key, Object.assign({}, base, { includeGenerate: gen }));
    const reqs = requests.slice(before);
    const badHosts = Array.from(new Set(reqs.map((r) => r.host))).filter((h) => !ALLOWED_HOSTS.some((re) => re.test(h)));
    INV.push({
      provider: pid, includeGenerate: gen, requests: reqs.length, probes: audits.length,
      billableProbes: audits.filter((a) => a.billable).length,
      billableEndpoints: audits.filter((a) => a.billable).map((a) => a.service + ' / ' + a.endpoint),
      allNoReferrer: reqs.every((r) => r.referrerPolicy === 'no-referrer'),
      allCredentialsOmitted: reqs.every((r) => r.credentials === 'omit'),
      hosts: Array.from(new Set(reqs.map((r) => r.host))).sort(),
      unexpectedHosts: badHosts
    });
  }
}
results.sections.F_auditProbeInventory = {
  simulated: true,
  totalRequests: INV.reduce((n, r) => n + r.requests, 0),
  unexpectedHostRequests: INV.reduce((n, r) => n + r.unexpectedHosts.length, 0),
  rows: INV
};
log('F  audit probe inventory (default = includeGenerate false):');
for (const r of INV.filter((x) => !x.includeGenerate)) {
  log('   ' + r.provider.padEnd(10) + ' probes=' + String(r.probes).padStart(2) + ' billable-in-default=' + String(r.billableProbes).padStart(2) +
    ' no-referrer=' + r.allNoReferrer + ' creds-omitted=' + r.allCredentialsOmitted + ' unexpected-hosts=' + r.unexpectedHosts.length);
}

// ---------------------------------------------------------------- G. audit gate source facts
function lineOf(file, re) {
  const lines = readFileSync(join(ROOT, file), 'utf8').split('\n');
  const out = [];
  lines.forEach((l, i) => { if (re.test(l)) out.push({ line: i + 1, text: l.trim().slice(0, 140) }); });
  return out;
}
{
  const bg = readFileSync(join(ROOT, 'background.js'), 'utf8');
  const auditHandlers = ['GAKS_AUDIT', 'GAKS_AUDIT_RAW'].map((t) => {
    const i = bg.indexOf("msg.type === '" + t + "'");
    const block = bg.slice(i, i + 700);
    return { type: t, referencesConsent: /ack|consent|confirm|authori[sz]/i.test(block) };
  });
  results.sections.G_auditGate = {
    popupGate: lineOf('popup/popup.js', /disabled = !els\.ack\.checked/),
    dashboardConfirm: lineOf('dashboard/dashboard.js', /confirm\(|own keys/),
    workerHandlers: auditHandlers,
    summary: 'Consent is enforced in the UI layer (popup checkbox, dashboard confirm). The service-worker audit message handlers contain no consent check.'
  };
  log('G  audit gate: popup lines ' + results.sections.G_auditGate.popupGate.map((x) => x.line).join(',') +
    '; dashboard lines ' + results.sections.G_auditGate.dashboardConfirm.map((x) => x.line).join(',') +
    '; worker handlers reference consent: ' + auditHandlers.map((h) => h.type + '=' + h.referencesConsent).join(', '));
}

// ---------------------------------------------------------------- write outputs
// Redact every credential-shaped substring (by the extension's own detector) before writing evidence.
const { scrubDeep } = await import(pathToFileURL(join(ROOT, 'research/harness/scrub.mjs')).href);
results.sections.B_detectionVariants.perTrial = trials.map((t) => ({ subject: t.subject, variant: t.variant, ok: t.ok }));
writeFileSync(join(OUT, 'results', 'logic-results.json'), JSON.stringify(scrubDeep(results, detectKeys), null, 2) + '\n');
writeFileSync(join(OUT, 'transcripts', 'logic-run.txt'), logLines.join('\n') + '\n');
log('wrote research/evidence/results/logic-results.json and transcripts/logic-run.txt');
process.exit(0);
