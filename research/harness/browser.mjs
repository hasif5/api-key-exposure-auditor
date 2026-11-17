/*
 * browser.mjs - end-to-end run of the real extension against the fixtures.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * What it does
 *   1. starts the local fixture server (127.0.0.1 only)
 *   2. launches Chromium with the unpacked extension and a DNS policy that
 *      resolves ONLY loopback (plus one provider hostname mapped to loopback);
 *      every other hostname fails with ERR_NAME_NOT_RESOLVED
 *   3. visits one origin per scenario, waits for the extension's scan cycles,
 *      and records the extension's own findings database (chrome.storage.local)
 *   4. scores the database against the ground truth declared in scenarios.mjs
 *   5. captures dashboard screenshots
 *
 * The audit feature is NOT exercised here (it would contact real provider
 * APIs with synthetic keys). Audit logic is covered, with simulated responses,
 * by logic.mjs.
 *
 * Usage: node research/harness/browser.mjs
 * Env:   CHROMIUM_PATH   path to a Chromium build that supports --load-extension
 *                        (default: newest Playwright Chromium under ms-playwright)
 *        SETTLE_MS       per-scenario wait, default 8000
 *        HEADED=1        run with a visible window
 */

import { spawn, execSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { tmpdir, homedir, platform } from 'node:os';
import { Cdp, sleep } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const OUT = join(ROOT, 'research', 'evidence');
mkdirSync(join(OUT, 'results'), { recursive: true });
mkdirSync(join(OUT, 'transcripts'), { recursive: true });
mkdirSync(join(OUT, 'screenshots'), { recursive: true });

const SETTLE_MS = Number(process.env.SETTLE_MS) || 8000;
// Probe mode (ONLY / DIRECT_NAV): visit a subset, or open the target directly on the
// scenario URL instead of about:blank -> navigate. Probe runs never touch the main
// result files; they write research/evidence/results/probe-<tag>.json instead.
const ONLY = process.env.ONLY ? process.env.ONLY.split(',') : null;
const DIRECT_NAV = !!process.env.DIRECT_NAV;
const PROBE = !!(ONLY || DIRECT_NAV);
const logLines = [];
function log(...a) { const s = a.join(' '); logLines.push(s); console.log(s); }

const { redact } = await import(pathToFileURL(join(ROOT, 'research/fixtures/synthetic.mjs')).href);
const { allExpectations, DUP_KEY } = await import(pathToFileURL(join(ROOT, 'research/fixtures/scenarios.mjs')).href);
const { startServer } = await import(pathToFileURL(join(ROOT, 'research/fixtures/server.mjs')).href);

function findChromium() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH;
  const bases = [
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'ms-playwright'),
    join(homedir(), '.cache', 'ms-playwright'),
    join(homedir(), 'Library', 'Caches', 'ms-playwright')
  ].filter(Boolean);
  const rel = { win32: ['chrome-win64', 'chrome.exe'], linux: ['chrome-linux64', 'chrome'], darwin: ['chrome-mac', 'Chromium.app/Contents/MacOS/Chromium'] }[platform()];
  for (const b of bases) {
    if (!existsSync(b)) continue;
    const dirs = readdirSync(b).filter((d) => /^chromium-\d+$/.test(d)).sort((x, y) => Number(y.split('-')[1]) - Number(x.split('-')[1]));
    for (const d of dirs) { const p = join(b, d, ...rel); if (existsSync(p)) return p; }
  }
  throw new Error('No Chromium found. Set CHROMIUM_PATH to a Chromium build (branded Chrome 137+ ignores --load-extension).');
}

const server = await startServer(0);
const scenarios = server.scenarios;
const exp = allExpectations(scenarios);
log('fixture server: 127.0.0.1:' + server.port + ', ' + scenarios.length + ' scenarios');

const chromePath = findChromium();
const userData = mkdtempSync(join(tmpdir(), 'gaks-research-'));
const args = [
  '--user-data-dir=' + userData,
  '--remote-debugging-port=0',
  '--no-first-run', '--no-default-browser-check',
  '--disable-extensions-except=' + ROOT, '--load-extension=' + ROOT,
  '--disable-features=DisableLoadExtensionCommandLineSwitch',
  '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps',
  // DNS policy: loopback only. The provider hostname used by scenario S10 is mapped to
  // loopback; everything else cannot resolve, so no request can leave this machine.
  '--host-resolver-rules=MAP maps.googleapis.com 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE *.localhost, EXCLUDE 127.0.0.1',
  '--window-size=1500,1100',
  'about:blank'
];
if (!process.env.HEADED) args.unshift('--headless=new');
const proc = spawn(chromePath, args, { stdio: 'ignore' });
let killed = false;
function cleanup() {
  if (killed) return; killed = true;
  try { if (platform() === 'win32') execSync('taskkill /PID ' + proc.pid + ' /T /F', { stdio: 'ignore' }); else proc.kill('SIGKILL'); } catch (e) { /* gone */ }
  try { rmSync(userData, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch (e) { /* best effort */ }
}
process.on('exit', cleanup);

async function main() {
  // --- connect
  let port, path;
  for (let i = 0; i < 100; i++) {
    const f = join(userData, 'DevToolsActivePort');
    if (existsSync(f)) { [port, path] = readFileSync(f, 'utf8').split('\n'); if (port && path) break; }
    await sleep(200);
  }
  if (!port) throw new Error('Chromium did not publish DevToolsActivePort');
  const cdp = await Cdp.connect('ws://127.0.0.1:' + port + path);
  const version = await cdp.send('Browser.getVersion');
  log('browser: ' + version.product);

  // --- network attempt log (every request any attached target makes)
  const attempts = [];
  cdp.onEvent((m) => {
    if (m.method === 'Network.requestWillBeSent') {
      try { attempts.push({ url: m.params.request.url, session: m.sessionId }); } catch (e) { /* ignore */ }
    }
  });
  const failures = [];
  cdp.onEvent((m) => {
    if (m.method === 'Network.loadingFailed') failures.push({ error: m.params.errorText, session: m.sessionId });
  });

  async function attach(targetId) {
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Network.enable', {}, sessionId);
    return sessionId;
  }

  // --- find the extension service worker
  let sw = null;
  for (let i = 0; i < 100 && !sw; i++) {
    const { targetInfos } = await cdp.send('Target.getTargets');
    sw = targetInfos.find((t) => t.type === 'service_worker' && /^chrome-extension:\/\/[a-p]{32}\/background\.js$/.test(t.url));
    if (!sw) await sleep(200);
  }
  if (!sw) throw new Error('Extension service worker not found; the extension did not load');
  const extId = sw.url.split('/')[2];
  const swSession = await attach(sw.targetId);
  log('extension loaded, id ' + extId);

  async function swEval(expression) {
    const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, swSession);
    if (r.exceptionDetails) throw new Error('swEval: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text));
    return r.result.value;
  }

  const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
  const swManifest = await swEval('chrome.runtime.getManifest().version');
  if (swManifest !== manifest.version) throw new Error('loaded extension version mismatch');

  // --- clean state; user ignore list for scenario S14
  await swEval("chrome.storage.local.clear().then(() => chrome.storage.local.set({ gaks_ignore_domains: ['s14-ignored.localhost'] }))");
  await sleep(800);

  // --- visit each scenario
  const perScenario = [];
  for (const sc of scenarios.filter((s) => !ONLY || ONLY.indexOf(s.id) !== -1)) {
    const origin = server.origin(sc);
    const t0 = Date.now();
    let targetId;
    if (DIRECT_NAV) {
      ({ targetId } = await cdp.send('Target.createTarget', { url: origin + '/' }));
    } else {
      ({ targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' }));
      const session = await attach(targetId);
      await cdp.send('Page.enable', {}, session);
      await cdp.send('Page.navigate', { url: origin + '/' }, session);
    }
    await sleep(SETTLE_MS);
    const tab = await swEval("(async () => { const t = await chrome.tabs.query({ url: '" + origin + "/*' }); if (!t.length) return null;" +
      " const badge = await chrome.action.getBadgeText({ tabId: t[0].id });" +
      " return { tabId: t[0].id, badge }; })()");
    await cdp.send('Target.closeTarget', { targetId });
    perScenario.push({ id: sc.id, origin, title: sc.title, badge: tab ? tab.badge : null, ms: Date.now() - t0 });
    log('visited ' + sc.id + ' ' + sc.host + ' badge=' + (tab ? JSON.stringify(tab.badge) : 'n/a'));
  }
  await sleep(1500);

  // --- read the extension's database
  // One record per finding under "gaks_f:<key>" (lib/store.js REC_PREFIX); an old build's single "gaks_db" blob is still read.
  const db = await swEval("chrome.storage.local.get(null).then((r) => ({ findings: Object.keys(r).filter((k) => k.indexOf('gaks_f:') === 0).map((k) => r[k]).concat((r.gaks_db && r.gaks_db.findings) || []) }))");
  log('extension database: ' + db.findings.length + ' distinct records');

  if (PROBE) {
    const metaNetP = { attemptedRequests: attempts.length, distinctHosts: [] };
    cdp.close();
    return { db, perScenario, version: version.product, extId, metaNet: metaNetP, failures: failures.length };
  }

  // --- screenshots of the extension's own dashboard
  async function shot(name, prep) {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'chrome-extension://' + extId + '/dashboard/dashboard.html' });
    const s = await attach(targetId);
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1500, height: 1100, deviceScaleFactor: 1, mobile: false }, s);
    await sleep(2500);
    if (prep) { await cdp.send('Runtime.evaluate', { expression: prep }, s); await sleep(800); }
    const png = await cdp.send('Page.captureScreenshot', { format: 'png' }, s);
    writeFileSync(join(OUT, 'screenshots', name), Buffer.from(png.data, 'base64'));
    await cdp.send('Target.closeTarget', { targetId });
    log('screenshot ' + name);
  }
  await shot('dashboard-all-findings.png', null);
  await shot('dashboard-unknown-heuristic.png', "document.querySelector('[data-tab=unknown]').click()");
  await shot('dashboard-filter-openai.png', "(() => { const s = document.querySelector('select[id*=rovider], #providerFilter'); if (s) { s.value = 'openai'; s.dispatchEvent(new Event('change', { bubbles: true })); } })()");

  const metaNet = {
    attemptedRequests: attempts.length,
    distinctHosts: Array.from(new Set(attempts.map((a) => { try { return new URL(a.url).host.replace(/:\d+$/, ''); } catch (e) { return 'unparsable'; } }))).sort()
  };
  cdp.close();
  return { db, perScenario, version: version.product, extId, metaNet, failures: failures.length };
}

let run;
try {
  run = await main();
} finally {
  cleanup();
}
const serverLog = server.log.slice();
await server.close();

if (PROBE) {
  const tag = (DIRECT_NAV ? 'directnav' : 'aboutblank') + (ONLY ? '-' + ONLY.join('+') : '');
  const probe = {
    generatedAt: new Date().toISOString(), browser: run.version, directNav: DIRECT_NAV, only: ONLY,
    perScenario: run.perScenario.map((p) => ({ id: p.id, badge: p.badge })),
    records: run.db.findings.map((f) => ({ key: redact(f.key), provider: f.provider, sources: f.sources }))
  };
  writeFileSync(join(OUT, 'results', 'probe-' + tag + '.json'), JSON.stringify(probe, null, 2) + '\n');
  log('probe ' + tag + ': ' + JSON.stringify(probe.perScenario));
  process.exit(0);
}

// ---------------------------------------------------------------- scoring
const byKey = new Map(run.db.findings.map((f) => [f.key, f]));
const originOf = (id) => server.origin(scenarios.find((s) => s.id === id));
const rows = exp.positives.map((e) => {
  const rec = byKey.get(e.key);
  const sc = scenarios.find((s) => s.id === e.scenario);
  return {
    id: e.id, scenario: e.scenario, how: e.how, expectedProvider: e.provider, expectedVia: e.via,
    detected: !!rec,
    providerOk: !!rec && rec.provider === e.provider,
    secretOk: e.secret ? (!!rec && rec.secret === e.secret) : null,
    viaOk: !!rec && rec.sources.some((s) => e.via.indexOf(s) !== -1),
    originOk: !!rec && rec.origins.some((o) => o === server.origin(sc)),
    // Where the key was read from: the stored pageUrl for crawled assets is the exact resource URL.
    urlOk: e.urlIncludes ? (!!rec && rec.pageUrls.some((u) => u.indexOf(e.urlIncludes) !== -1)) : null,
    // Entries marked onlyVia must be found by the expected path alone (no raw-text 'script' hit).
    exclusiveOk: e.onlyVia ? (!!rec && rec.sources.every((s) => e.via.indexOf(s) !== -1 || s === 'window')) : null,
    gotSources: rec ? rec.sources : [],
    key: redact(e.key)
  };
});
const detected = rows.filter((r) => r.detected).length;
const exactly = rows.filter((r) => r.detected && r.providerOk && r.viaOk && r.originOk && r.secretOk !== false && r.urlOk !== false && r.exclusiveOk !== false).length;

const expectedKeys = new Set([].concat(exp.positives, exp.knownMiss, exp.ignoreProbes).map((e) => e.key));
const secrets = new Set(exp.positives.filter((e) => e.secret).map((e) => e.secret));
const unexpected = run.db.findings.filter((f) => !expectedKeys.has(f.key) && !secrets.has(f.key));
const unexpectedRows = unexpected.map((f) => {
  const neg = exp.negatives.find((n) => f.key === n.text || n.text.indexOf(f.key) !== -1 || f.key.indexOf(n.text) !== -1);
  return { key: redact(f.key), provider: f.provider, sources: f.sources, origins: f.origins, attributedTo: neg ? neg.id : null, cls: neg ? neg.cls : 'unattributed',
    snippet: f.snippet.split(f.key).join('<key>') };
});

const missRows = exp.knownMiss.map((e) => ({ id: e.id, how: e.how, detected: byKey.has(e.key), key: redact(e.key) }));
const ignored = exp.ignoreProbes.map((e) => ({ id: e.id, how: e.how, stored: byKey.has(e.key) }));
const dup = byKey.get(DUP_KEY);
const dedup = {
  records: run.db.findings.filter((f) => f.key === DUP_KEY).length,
  origins: dup ? dup.origins : [],
  sources: dup ? dup.sources : [],
  ok: !!dup && run.db.findings.filter((f) => f.key === DUP_KEY).length === 1 &&
    dup.origins.indexOf(originOf('S01')) !== -1 && dup.origins.indexOf(originOf('S04')) !== -1 &&
    dup.sources.indexOf('script') !== -1 && dup.sources.indexOf('storage') !== -1
};

const negRows = exp.negatives.map((n) => {
  const hit = unexpectedRows.find((u) => u.attributedTo === n.id);
  return { id: n.id, cls: n.cls, note: n.note, flagged: !!hit, flaggedAs: hit ? hit.provider : null };
});
const negSum = (cls) => ({ total: negRows.filter((r) => r.cls === cls).length, flagged: negRows.filter((r) => r.cls === cls && r.flagged).length });

// Badge check: scenarios that should show N distinct keys on their tab.
const expectedPerScenario = {};
for (const e of exp.positives) expectedPerScenario[e.scenario] = (expectedPerScenario[e.scenario] || 0) + (e.dedupWith ? 1 : 1);
const badgeRows = run.perScenario.map((p) => ({ scenario: p.id, badge: p.badge, expectedDistinctKeys: expectedPerScenario[p.id] || 0 }));

// Network containment evidence.
const nonLocalServerHits = serverLog.filter((l) => !(l.host.endsWith('.localhost') || l.host === 'maps.googleapis.com')).length;
const sinkHits = serverLog.filter((l) => l.sink).length;
const nonLocalAttempts = run.metaNet.distinctHosts.filter((h) => !(h.endsWith('.localhost') || h === '127.0.0.1' || h === 'localhost' || h === 'maps.googleapis.com' || h === '' || h.startsWith('chrome-extension') || /^[a-p]{32}$/.test(h) || h === 'unparsable'));

const summary = {
  scenariosVisited: run.perScenario.length,
  positives: { expected: rows.length, detected, detectedPct: +(100 * detected / rows.length).toFixed(1),
    fullyCorrect: exactly, fullyCorrectPct: +(100 * exactly / rows.length).toFixed(1),
    missed: rows.filter((r) => !r.detected).map((r) => r.id),
    wrongProvider: rows.filter((r) => r.detected && !r.providerOk).map((r) => r.id),
    wrongSource: rows.filter((r) => r.detected && (!r.viaOk || r.urlOk === false || r.exclusiveOk === false)).map((r) => r.id) },
  knownMisses: { expectedMissed: missRows.length, actuallyMissed: missRows.filter((r) => !r.detected).length, surprisingDetections: missRows.filter((r) => r.detected).map((r) => r.id) },
  negatives: { invalid: negSum('invalid'), lookalike: negSum('lookalike') },
  unexpectedRecords: { total: unexpectedRows.length, unattributed: unexpectedRows.filter((u) => !u.attributedTo).length },
  recordLevelPrecision: +(100 * detected / (detected + unexpectedRows.length + missRows.filter((r) => r.detected).length)).toFixed(1),
  ignoreList: { stored: ignored.filter((i) => i.stored).length, of: ignored.length },
  dedup: dedup.ok
};

const results = {
  meta: {
    generatedAt: new Date().toISOString(),
    browser: run.version,
    extensionVersion: JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8')).version,
    gitCommit: (() => { try { return execSync('git rev-parse HEAD', { cwd: ROOT }).toString().trim(); } catch (e) { return 'unavailable'; } })(),
    settleMsPerScenario: SETTLE_MS,
    note: 'All credentials are synthetic. Keys are redacted below (prefix, tail, length, sha256 fingerprint). The audit feature was not run in the browser.'
  },
  summary,
  containment: {
    dnsPolicy: 'MAP maps.googleapis.com 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE localhost, *.localhost, 127.0.0.1',
    requestsAttemptedByPagesAndWorker: run.metaNet.attemptedRequests,
    distinctHostsAttempted: run.metaNet.distinctHosts,
    nonLoopbackHostsAttempted: nonLocalAttempts,
    loadingFailures: run.failures,
    fixtureServerRequests: serverLog.length,
    fixtureServerNonLocalHostHits: nonLocalServerHits,
    providerHostnameSinkHits: sinkHits
  },
  positives: rows,
  knownMisses: missRows,
  negatives: negRows,
  unexpectedRecords: unexpectedRows,
  ignoreProbe: ignored,
  dedup,
  badges: badgeRows,
  databaseSnapshot: run.db.findings.map((f) => ({
    key: redact(f.key), provider: f.provider, sources: f.sources, origins: f.origins.map((o) => o.replace(/:\d+$/, ':<port>')),
    hasSecret: !!f.secret, snippet: String(f.snippet || '').split(f.key).join('<key>').split(f.secret || '\u0000').join('<secret>')
  }))
};
const { scrubDeep } = await import(pathToFileURL(join(ROOT, 'research/harness/scrub.mjs')).href);
const { detectKeys } = await import(pathToFileURL(join(ROOT, 'lib/providers.js')).href);
writeFileSync(join(OUT, 'results', 'browser-results.json'), JSON.stringify(scrubDeep(results, detectKeys), null, 2) + '\n');

log('---- summary ----');
log('positives detected: ' + detected + '/' + rows.length + ' (' + summary.positives.detectedPct + '%); fully correct (provider+source+origin+pair): ' + exactly + '/' + rows.length);
if (summary.positives.missed.length) log('  missed: ' + summary.positives.missed.join(', '));
if (summary.positives.wrongProvider.length) log('  wrong provider: ' + summary.positives.wrongProvider.join(', '));
if (summary.positives.wrongSource.length) log('  unexpected source tag: ' + summary.positives.wrongSource.join(', '));
log('known misses: ' + summary.knownMisses.actuallyMissed + '/' + summary.knownMisses.expectedMissed + ' missed as predicted' + (summary.knownMisses.surprisingDetections.length ? '; SURPRISING detections: ' + summary.knownMisses.surprisingDetections.join(', ') : ''));
log('negatives flagged: invalid ' + summary.negatives.invalid.flagged + '/' + summary.negatives.invalid.total + ', lookalike ' + summary.negatives.lookalike.flagged + '/' + summary.negatives.lookalike.total);
log('unexpected records: ' + summary.unexpectedRecords.total + ' (unattributed to a negative: ' + summary.unexpectedRecords.unattributed + ')');
log('ignore list: ' + summary.ignoreList.stored + '/' + summary.ignoreList.of + ' ignored-origin keys stored; dedup ok: ' + summary.dedup);
log('containment: non-loopback hosts attempted=' + JSON.stringify(nonLocalAttempts) + '; server non-local hits=' + nonLocalServerHits + '; provider-name sink hits=' + sinkHits);
writeFileSync(join(OUT, 'transcripts', 'browser-run.txt'), logLines.join('\n') + '\n');
process.exit(0);
