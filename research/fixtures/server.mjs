/*
 * server.mjs - zero-dependency static/dynamic server for the research fixtures.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * Listens on 127.0.0.1 only. The Host header selects the scenario:
 *   s01-bundle.localhost:<port>      -> scenario S01 (each scenario = own origin)
 *   maps.googleapis.com:<port>       -> loopback sink for scenario S10 (the
 *                                       harness maps this name to 127.0.0.1)
 *
 * It records every request so the harness can prove that no request addressed
 * to a real third-party host was ever answered or forwarded by this process.
 *
 * Run standalone for manual inspection:  node research/fixtures/server.mjs [port]
 */

import { createServer } from 'node:http';
import { buildScenarios } from './scenarios.mjs';

// 1x1 transparent GIF (the loopback sink answer for the S10 image request).
const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

export function startServer(port) {
  const log = [];
  let scenarios = [];
  const byHost = new Map();

  const server = createServer((req, res) => {
    const hostHeader = String(req.headers.host || '');
    const host = hostHeader.replace(/:\d+$/, '').toLowerCase();
    const path = (req.url || '/').split('?')[0];
    const entry = { t: Date.now(), host, method: req.method, path, status: 0 };
    log.push(entry);

    // Loopback sink for provider-host names (never forwarded anywhere).
    if (host === 'maps.googleapis.com') {
      entry.status = 200; entry.sink = true;
      res.writeHead(200, { 'Content-Type': 'image/gif' });
      res.end(GIF);
      return;
    }

    const label = host.endsWith('.localhost') ? host.slice(0, -'.localhost'.length) : '';
    const sc = byHost.get(label);
    if (!sc) { entry.status = 404; res.writeHead(404); res.end('no scenario'); return; }
    const route = sc.routes[path];
    if (!route) { entry.status = 404; res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found'); return; }

    // Drain any request body (POST bodies are part of the S05 test).
    req.on('data', () => {});
    req.on('end', () => {
      const out = route();
      entry.status = 200;
      res.writeHead(200, Object.assign({ 'Content-Type': out.type, 'Cache-Control': 'no-store' }, out.headers || {}));
      res.end(out.body);
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port || 0, '127.0.0.1', () => {
      const actual = server.address().port;
      scenarios = buildScenarios({ port: actual });
      for (const sc of scenarios) byHost.set(sc.host, sc);
      resolve({
        port: actual,
        scenarios,
        log,
        close: () => new Promise((r) => server.close(() => r())),
        origin: (sc) => 'http://' + sc.host + '.localhost:' + actual
      });
    });
  });
}

// Standalone mode.
if (process.argv[1] && process.argv[1].endsWith('server.mjs')) {
  const p = Number(process.argv[2]) || 8765;
  startServer(p).then((s) => {
    console.log('Fixture server on 127.0.0.1:' + s.port);
    for (const sc of s.scenarios) console.log('  ' + sc.id + '  ' + s.origin(sc) + '/   ' + sc.title);
  });
}
