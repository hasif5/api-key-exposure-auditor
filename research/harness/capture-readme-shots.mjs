/*
 * capture-readme-shots.mjs - capture the popup and dashboard screenshots used in the
 * top-level README, from the real extension running in Chromium against the local
 * synthetic-credential fixture site.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * What is real: the extension (loaded unpacked), its service worker, its detection,
 * its stored findings, and the popup/dashboard UI.
 * What is arranged: a browser popup normally reads the active tab, which would be the
 * popup page itself when it is opened as a tab. Before the popup scripts run, this
 * script overrides chrome.tabs.query for the "active tab" call only, so it returns
 * the fixture tab. No audit is run (that would send keys to real provider endpoints),
 * so the screenshots show detection, not audit results.
 *
 * Network: same DNS policy as browser.mjs. Only loopback resolves.
 *
 * Usage: node research/harness/capture-readme-shots.mjs
 * Output: docs/screenshots/popup.png, docs/screenshots/dashboard.png
 */

import { spawn, execSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { tmpdir, homedir, platform } from 'node:os';
import { Cdp, sleep } from './cdp.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const OUT = join(ROOT, 'docs', 'screenshots');
mkdirSync(OUT, { recursive: true });

const SETTLE_MS = Number(process.env.SETTLE_MS) || 8000;
// Scenario shown in the popup (the active tab), and the extra scenarios visited so the
// dashboard shows findings from several surfaces. All use synthetic credentials.
const POPUP_SCENARIO = 'S01';
const EXTRA_SCENARIOS = ['S05', 'S03'];

const { startServer } = await import(pathToFileURL(join(ROOT, 'research/fixtures/server.mjs')).href);

// Same lookup as research/harness/browser.mjs (kept local so that harness stays untouched).
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
const byId = Object.fromEntries(server.scenarios.map((s) => [s.id, s]));
const userData = mkdtempSync(join(tmpdir(), 'gaks-shots-'));
const args = [
  '--user-data-dir=' + userData,
  '--remote-debugging-port=0',
  '--no-first-run', '--no-default-browser-check',
  '--disable-extensions-except=' + ROOT, '--load-extension=' + ROOT,
  '--disable-features=DisableLoadExtensionCommandLineSwitch',
  '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps',
  '--host-resolver-rules=MAP maps.googleapis.com 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE *.localhost, EXCLUDE 127.0.0.1',
  '--window-size=1500,1100',
  'about:blank'
];
if (!process.env.HEADED) args.unshift('--headless=new');
const proc = spawn(findChromium(), args, { stdio: 'ignore' });
let killed = false;
function cleanup() {
  if (killed) return; killed = true;
  try { if (platform() === 'win32') execSync('taskkill /PID ' + proc.pid + ' /T /F', { stdio: 'ignore' }); else proc.kill('SIGKILL'); } catch (e) { /* gone */ }
  try { rmSync(userData, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch (e) { /* best effort */ }
}
process.on('exit', cleanup);

async function main() {
  let port, path;
  for (let i = 0; i < 100; i++) {
    const f = join(userData, 'DevToolsActivePort');
    if (existsSync(f)) { [port, path] = readFileSync(f, 'utf8').split('\n'); if (port && path) break; }
    await sleep(200);
  }
  if (!port) throw new Error('Chromium did not publish DevToolsActivePort');
  const cdp = await Cdp.connect('ws://127.0.0.1:' + port + path);

  const attempts = [];
  cdp.onEvent((m) => {
    if (m.method === 'Network.requestWillBeSent') { try { attempts.push(m.params.request.url); } catch (e) { /* ignore */ } }
  });
  async function attach(targetId) {
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Network.enable', {}, sessionId);
    return sessionId;
  }

  let sw = null;
  for (let i = 0; i < 100 && !sw; i++) {
    const { targetInfos } = await cdp.send('Target.getTargets');
    sw = targetInfos.find((t) => t.type === 'service_worker' && /^chrome-extension:\/\/[a-p]{32}\/background\.js$/.test(t.url));
    if (!sw) await sleep(200);
  }
  if (!sw) throw new Error('Extension service worker not found; the extension did not load');
  const extId = sw.url.split('/')[2];
  const swSession = await attach(sw.targetId);
  async function swEval(expression) {
    const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, swSession);
    if (r.exceptionDetails) throw new Error('swEval: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text));
    return r.result.value;
  }
  await swEval('chrome.storage.local.clear()');
  await sleep(800);

  // Visit the extra scenarios first (tabs closed afterwards), then the popup scenario, which stays open.
  async function visit(id, keepOpen) {
    const origin = server.origin(byId[id]);
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const session = await attach(targetId);
    await cdp.send('Page.enable', {}, session);
    await cdp.send('Page.navigate', { url: origin + '/' }, session);
    await sleep(SETTLE_MS);
    if (!keepOpen) await cdp.send('Target.closeTarget', { targetId });
    return { origin, targetId };
  }
  for (const id of EXTRA_SCENARIOS) await visit(id, false);
  const main = await visit(POPUP_SCENARIO, true);
  await sleep(1500);

  const tab = await swEval("chrome.tabs.query({ url: '" + main.origin + "/*' }).then((t) => t.length ? { id: t[0].id, url: t[0].url } : null)");
  if (!tab) throw new Error('fixture tab not found');
  const db = await swEval("chrome.storage.local.get('gaks_db').then((r) => r.gaks_db || { findings: [] })");
  console.log('findings stored: ' + db.findings.length + '; popup tab: ' + tab.url);

  // --- popup: real popup.html as a page, with the active-tab lookup pointed at the fixture tab
  {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const s = await attach(targetId);
    await cdp.send('Page.enable', {}, s);
    const stub = '(() => { const real = chrome.tabs.query.bind(chrome.tabs);' +
      ' chrome.tabs.query = (q) => (q && q.active && q.currentWindow) ? Promise.resolve([' + JSON.stringify(tab) + ']) : real(q); })();';
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: stub }, s);
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 380, height: 560, deviceScaleFactor: 2, mobile: false }, s);
    await cdp.send('Page.navigate', { url: 'chrome-extension://' + extId + '/popup/popup.html' }, s);
    await sleep(3500);
    const shown = await cdp.send('Runtime.evaluate', { expression: 'document.getElementById("count") ? document.getElementById("count").textContent : document.body.innerText.slice(0, 80)', returnByValue: true }, s);
    console.log('popup shows: ' + JSON.stringify(shown.result.value));
    // Crop to the last visible element so no empty viewport strip is captured.
    const bottom = await cdp.send('Runtime.evaluate', { expression: 'Math.ceil(Math.max(...Array.from(document.body.children).map((e) => e.getBoundingClientRect().bottom)))', returnByValue: true }, s);
    const h = Math.min(560, Number(bottom.result.value) || 560);
    const png = await cdp.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: 380, height: h, scale: 1 } }, s);
    writeFileSync(join(OUT, 'popup.png'), Buffer.from(png.data, 'base64'));
    await cdp.send('Target.closeTarget', { targetId });
    console.log('wrote docs/screenshots/popup.png (380x' + h + ' css px, 2x)');
  }

  // --- dashboard
  {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'chrome-extension://' + extId + '/dashboard/dashboard.html' });
    const s = await attach(targetId);
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 860, deviceScaleFactor: 1, mobile: false }, s);
    await sleep(3000);
    const png = await cdp.send('Page.captureScreenshot', { format: 'png' }, s);
    writeFileSync(join(OUT, 'dashboard.png'), Buffer.from(png.data, 'base64'));
    await cdp.send('Target.closeTarget', { targetId });
    console.log('wrote docs/screenshots/dashboard.png (1280x860)');
  }

  const hosts = Array.from(new Set(attempts.map((u) => { try { return new URL(u).host.replace(/:\d+$/, ''); } catch (e) { return 'unparsable'; } })));
  const nonLoopback = hosts.filter((h) => !/(^|\.)localhost$|^127\.0\.0\.1$|^maps\.googleapis\.com$|^[a-p]{32}$/.test(h));
  console.log('hosts attempted: ' + hosts.length + '; non-loopback: ' + JSON.stringify(nonLoopback));
  cdp.close();
  if (nonLoopback.length) throw new Error('unexpected non-loopback host attempted');
}

main().then(async () => { await server.close(); cleanup(); process.exit(0); },
  async (e) => { console.error(e); try { await server.close(); } catch (x) { /* ignore */ } cleanup(); process.exit(1); });
