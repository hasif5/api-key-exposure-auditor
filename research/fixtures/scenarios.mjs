/*
 * scenarios.mjs - the controlled test matrix for research case study 001.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * Each scenario is one origin (http://<host>.localhost:<port>) that exposes
 * synthetic credentials through exactly ONE surface. Expected outcomes are
 * declared HERE, before any run, so results are compared to a fixed ground truth
 * rather than to whatever the extension happened to report:
 *
 *   positives  - credentials the extension is expected to find, with the code
 *                path (`via`, a stored source tag) that should find them.
 *   knownMiss  - credentials that ARE exposed to the client but that a
 *                regex-based scanner is not expected to see (documented limits).
 *   negatives  - strings that must not be reported as credentials, split into
 *                structurally-invalid ("invalid") and format-valid-but-fake
 *                ("lookalike") so the two failure modes are not conflated.
 *
 * Credentials that must be found at runtime-only surfaces (storage, network,
 * window globals, ...) are assembled in the browser from two halves, so the
 * served HTML/JS never contains the full string. `selfCheck()` enforces this.
 */

import { make, pemBlock } from './synthetic.mjs';

// Source tags written by the extension (see lib/store.js `sources`).
export const SRC = {
  script: 'script', dom: 'dom', sourcemap: 'sourcemap', storage: 'storage',
  indexeddb: 'indexeddb', network: 'network', window: 'window',
  resource: 'resource', header: 'header', cookie: 'cookie'
};

// JS expression that rebuilds `key` at runtime from two halves. The split is at
// 3 chars so neither half can satisfy any detector regex on its own.
export function jsJoin(key) {
  return '[' + JSON.stringify(key.slice(0, 3)) + ',' + JSON.stringify(key.slice(3)) + '].join("")';
}

function pos(scenario, name, provider, key, via, how, extra) {
  return Object.assign({ id: scenario + '-' + name, scenario, provider, key, via, how, expectDetect: true }, extra || {});
}

function html(title, body) {
  return '<!doctype html><html><head><meta charset="utf-8"><title>' + title + '</title></head><body>' +
    '<h1>' + title + '</h1><p>Research fixture page. Every credential on this origin is synthetic.</p>' +
    body + '</body></html>';
}

export const DUP_KEY = make.openaiLegacy('dup');

export function buildScenarios(ctx) {
  const port = ctx.port;
  const S = [];

  // ---------------------------------------------------------------- S01
  {
    const id = 'S01';
    const google = make.google(id), openai = make.openaiProj(id), anth = make.anthropic(id);
    const sid = make.twilioSid(id), tok = make.twilioToken(id);
    const awsId = make.awsId(id), awsSec = make.awsSecret(id);
    const chunk = make.openrouter(id + 'chunk');
    const bundle =
      '!function(){var CFG={region:"us-east-1",mapsKey:"' + google + '",llm:{provider:"openai",apiKey:"' + openai + '"},' +
      'assistant:{key:"' + anth + '"},dupKey:"' + DUP_KEY + '"};' +
      'var TWILIO_ACCOUNT_SID="' + sid + '",TWILIO_AUTH_TOKEN="' + tok + '";' +
      'var awsConfig={accessKeyId:"' + awsId + '",secretAccessKey:"' + awsSec + '"};' +
      'window.__app={cfg:CFG,lazy:function(){return import("/assets/chunk-lazy.js")}};' +
      'console.log("bundle ready",Object.keys(CFG).length,TWILIO_ACCOUNT_SID.length,awsConfig.accessKeyId.length)}();';
    S.push({
      id, host: 's01-bundle', title: 'Credentials in a JavaScript bundle',
      routes: {
        '/': () => ({ type: 'text/html', body: html('S01 bundle', '<script src="/assets/app.bundle.js"></script>') }),
        '/assets/app.bundle.js': () => ({ type: 'application/javascript', body: bundle }),
        '/assets/chunk-lazy.js': () => ({ type: 'application/javascript', body: 'export const lazy={token:"' + chunk + '"};' })
      },
      positives: [
        pos(id, 'google', 'google', google, [SRC.script], 'literal in external bundle'),
        pos(id, 'openai', 'openai', openai, [SRC.script], 'literal in external bundle'),
        pos(id, 'anthropic', 'anthropic', anth, [SRC.script], 'literal in external bundle'),
        pos(id, 'dup', 'openai', DUP_KEY, [SRC.script], 'literal in bundle; ALSO placed in localStorage by S04 (dedup check)'),
        pos(id, 'twilio', 'twilio', sid, [SRC.script], 'SID with Auth Token nearby (pair)', { secret: tok }),
        pos(id, 'aws', 'aws', awsId, [SRC.script], 'Access Key ID with Secret Access Key nearby (pair)', { secret: awsSec }),
        pos(id, 'chunk', 'openrouter', chunk, [SRC.script], 'literal in a lazy chunk referenced only by the bundle (recursive asset graph)', { urlIncludes: '/assets/chunk-lazy.js' })
      ],
      literal: true
    });
  }

  // ---------------------------------------------------------------- S02
  {
    const id = 'S02';
    const gh = make.github(id), slack = make.slack(id), gl = make.gitlab(id);
    S.push({
      id, host: 's02-inline', title: 'Credentials in inline script and DOM attribute',
      routes: {
        '/': () => ({
          type: 'text/html',
          body: html('S02 inline',
            '<script>window.addEventListener("load",function(){var ghToken="' + gh + '";var slackBot="' + slack + '";console.log(ghToken.length,slackBot.length)});</script>' +
            '<div id="widget" data-config-token="' + gl + '">widget</div>')
        })
      },
      positives: [
        pos(id, 'github', 'github', gh, [SRC.dom], 'literal in inline <script>'),
        pos(id, 'slack', 'slack', slack, [SRC.dom], 'literal in inline <script>'),
        pos(id, 'gitlab', 'gitlab', gl, [SRC.dom], 'literal in an HTML attribute')
      ],
      literal: true
    });
  }

  // ---------------------------------------------------------------- S03
  {
    const id = 'S03';
    const orKey = make.openrouter(id), stripe = make.stripeTest(id);
    const orig1 = '// src/config.js\nexport const OPENROUTER_KEY = "' + orKey + '";\nexport const APP = "demo";\n';
    const orig2 = '// src/billing.js\nexport const BILLING = { secret: "' + stripe + '" };\n';
    const minified = '!function(){console.log("app v1.0")}();\n//# sourceMappingURL=app.min.js.map\n';
    let map = JSON.stringify({ version: 3, file: 'app.min.js', sources: ['src/config.js', 'src/billing.js'], sourcesContent: [orig1, orig2], names: [], mappings: 'AAAA' });
    // The Stripe-shaped key is written into the map with its underscores JSON-escaped
    // (\u005f). Decoded it is identical, but the RAW map text no longer matches any
    // detector regex, so only the source-map decode step can find it. The OpenRouter
    // key stays plain: the raw scan of the .map file finds it too (documented).
    map = map.split(stripe).join(stripe.replace(/_/g, '\\u005f'));
    S.push({
      id, host: 's03-sourcemap', title: 'Credentials only present in a source map',
      routes: {
        '/': () => ({ type: 'text/html', body: html('S03 source map', '<script src="/assets/app.min.js"></script>') }),
        '/assets/app.min.js': () => ({ type: 'application/javascript', body: minified }),
        '/assets/app.min.js.map': () => ({ type: 'application/json', body: map })
      },
      positives: [
        pos(id, 'openrouter', 'openrouter', orKey, [SRC.sourcemap], 'in sourcesContent of the .map (plain); absent from the minified bundle', { urlIncludes: '/assets/app.min.js.map' }),
        pos(id, 'stripe', 'stripe', stripe, [SRC.sourcemap], 'in sourcesContent with JSON-escaped underscores: invisible to a raw text scan, visible only after map decoding',
          { urlIncludes: '/assets/app.min.js.map', onlyVia: true })
      ],
      literal: false // the keys must not be in the served bundle; they ARE in the map (checked in selfCheck)
    });
  }

  // ---------------------------------------------------------------- S04
  {
    const id = 'S04';
    const xai = make.xai(id), ss = make.gitlab(id + 'ss'), idb = make.github(id + 'idb');
    const script =
      'localStorage.setItem("user_settings",JSON.stringify({theme:"dark",xai:' + jsJoin(xai) + ',backup:' + jsJoin(DUP_KEY) + '}));' +
      'sessionStorage.setItem("tmp_session",' + jsJoin(ss) + ');' +
      'var rq=indexedDB.open("appdb",1);rq.onupgradeneeded=function(){rq.result.createObjectStore("cache",{keyPath:"id"})};' +
      'rq.onsuccess=function(){var tx=rq.result.transaction("cache","readwrite");tx.objectStore("cache").put({id:1,blob:' + jsJoin(idb) + '});};';
    S.push({
      id, host: 's04-storage', title: 'Credentials in localStorage, sessionStorage and IndexedDB',
      routes: { '/': () => ({ type: 'text/html', body: html('S04 storage', '<script>' + script + '</script>') }) },
      positives: [
        pos(id, 'xai', 'xai', xai, [SRC.storage], 'localStorage (JSON value)'),
        pos(id, 'session', 'gitlab', ss, [SRC.storage], 'sessionStorage'),
        pos(id, 'idb', 'github', idb, [SRC.indexeddb], 'IndexedDB object store'),
        pos(id, 'dup', 'openai', DUP_KEY, [SRC.storage], 'localStorage; same string as S01 bundle (must dedup to ONE record)', { dedupWith: 'S01-dup' })
      ],
      literal: false
    });
  }

  // ---------------------------------------------------------------- S05
  {
    const id = 'S05';
    const fetchResp = make.openrouter(id + 'f'), xhrResp = make.stripeTest(id + 'x');
    const reqHdr = make.openaiSvc(id), reqBody = make.google(id + 'b');
    const script =
      'fetch("/api/config").then(function(r){return r.json()}).then(function(j){console.log(Object.keys(j))});' +
      'var x=new XMLHttpRequest();x.open("GET","/api/legacy");x.onload=function(){console.log(x.status)};x.send();' +
      'fetch("/api/echo",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+' + jsJoin(reqHdr) + '},body:JSON.stringify({maps:' + jsJoin(reqBody) + '})});';
    S.push({
      id, host: 's05-network', title: 'Credentials in network responses and requests',
      routes: {
        '/': () => ({ type: 'text/html', body: html('S05 network', '<script>' + script + '</script>') }),
        '/api/config': () => ({ type: 'application/json', body: JSON.stringify({ feature: 'x', llmKey: fetchResp }) }),
        '/api/legacy': () => ({ type: 'application/json', body: JSON.stringify({ billingSecret: xhrResp }) }),
        '/api/echo': () => ({ type: 'application/json', body: '{"ok":true}' })
      },
      positives: [
        pos(id, 'fetch-response', 'openrouter', fetchResp, [SRC.network], 'JSON body of a fetch() response'),
        pos(id, 'xhr-response', 'stripe', xhrResp, [SRC.network], 'JSON body of an XMLHttpRequest response'),
        pos(id, 'request-header', 'openai', reqHdr, [SRC.network], 'Authorization header set on a fetch() request'),
        pos(id, 'request-body', 'google', reqBody, [SRC.network], 'JSON body of a fetch() request')
      ],
      literal: false
    });
  }

  // ---------------------------------------------------------------- S06
  {
    const id = 'S06';
    const awsId = make.awsId(id), awsSec = make.awsSecret(id);
    const sid = make.twilioSid(id), tok = make.twilioToken(id);
    const nm = make.googleNew(id);
    const script =
      'window.__RT_CONFIG__={awsAccessKeyId:' + jsJoin(awsId) + ',awsSecretAccessKey:' + jsJoin(awsSec) + ',twilioAccountSid:' + jsJoin(sid) + ',twilioAuthToken:' + jsJoin(tok) + '};' +
      'window.name=' + jsJoin(nm) + ';';
    S.push({
      id, host: 's06-globals', title: 'Credentials in runtime window globals',
      routes: { '/': () => ({ type: 'text/html', body: html('S06 window globals', '<script>' + script + '</script>') }) },
      positives: [
        pos(id, 'aws', 'aws', awsId, [SRC.window], 'window.__RT_CONFIG__ (runtime-assembled; not in served markup)', { secret: awsSec }),
        pos(id, 'twilio', 'twilio', sid, [SRC.window], 'window.__RT_CONFIG__ (runtime-assembled)', { secret: tok }),
        pos(id, 'window-name', 'google', nm, [SRC.window], 'window.name')
      ],
      literal: false
    });
  }

  // ---------------------------------------------------------------- S07
  {
    const id = 'S07';
    const k = make.openrouter(id);
    const blob = Buffer.from(JSON.stringify({ service: 'llm', token: k, note: 'base64 wrapped config' })).toString('base64');
    S.push({
      id, host: 's07-encoded', title: 'Credential nested inside a base64 config blob',
      routes: {
        '/': () => ({
          type: 'text/html',
          body: html('S07 encoded', '<script type="application/json" id="boot">{"cfg":"' + blob + '"}</script>')
        })
      },
      positives: [pos(id, 'b64', 'openrouter', k, [SRC.dom], 'key exists only inside a base64 blob (decode-and-rescan)')],
      literal: false
    });
  }

  // ---------------------------------------------------------------- S08
  {
    const id = 'S08';
    const cfgKey = make.googleNew(id), sid = make.twilioSid(id), tok = make.twilioToken(id), stripe = make.stripeTest(id);
    S.push({
      id, host: 's08-config', title: 'Credentials in exposed config files (.env, config.json)',
      routes: {
        '/': () => ({ type: 'text/html', body: html('S08 config paths', '<script src="/assets/noop.js"></script>') }),
        '/assets/noop.js': () => ({ type: 'application/javascript', body: 'void 0;' }),
        '/config.json': () => ({ type: 'application/json', body: JSON.stringify({ env: 'prod', mapsKey: cfgKey }) }),
        '/.env': () => ({ type: 'text/plain', body: 'TWILIO_ACCOUNT_SID=' + sid + '\nTWILIO_AUTH_TOKEN=' + tok + '\nSTRIPE_SECRET_KEY=' + stripe + '\n' })
      },
      positives: [
        pos(id, 'config-json', 'google', cfgKey, [SRC.script], '/config.json probed from the common-path list', { urlIncludes: '/config.json' }),
        pos(id, 'env-twilio', 'twilio', sid, [SRC.script], '/.env probed from the common-path list (pair)', { secret: tok, urlIncludes: '/.env' }),
        pos(id, 'env-stripe', 'stripe', stripe, [SRC.script], '/.env probed from the common-path list', { urlIncludes: '/.env' })
      ],
      literal: false // never referenced from the page; only reachable by path probing
    });
  }

  // ---------------------------------------------------------------- S09
  {
    const id = 'S09';
    const hdrKey = make.anthropic(id), cookieKey = make.slack(id);
    S.push({
      id, host: 's09-headers', title: 'Credentials in a response header and a cookie',
      routes: {
        '/': () => ({
          type: 'text/html',
          headers: { 'X-Debug-Config': 'build=1; key=' + hdrKey, 'Set-Cookie': 'session_blob=' + cookieKey + '; Path=/' },
          body: html('S09 headers and cookies', '<p>No credentials in the markup.</p>')
        })
      },
      positives: [
        pos(id, 'header', 'anthropic', hdrKey, [SRC.header], 'custom response header on the main document'),
        pos(id, 'cookie', 'slack', cookieKey, [SRC.cookie, SRC.header], 'Set-Cookie value (cookie jar scan; Set-Cookie header scan also acceptable)')
      ],
      literal: false
    });
  }

  // ---------------------------------------------------------------- S10
  {
    const id = 'S10';
    const k = make.google(id);
    // The key travels only in an <img>-style request that never enters the DOM;
    // the hostname is a provider host mapped to loopback by the harness.
    const script = 'var i=new Image();i.src="http://maps.googleapis.com:' + port + '/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key="+' + jsJoin(k) + ';';
    S.push({
      id, host: 's10-webrequest', title: 'Credential in a request URL seen only by webRequest',
      routes: { '/': () => ({ type: 'text/html', body: html('S10 webRequest', '<script>' + script + '</script>') }) },
      positives: [pos(id, 'img-key-param', 'google', k, [SRC.network], 'key= query parameter on a detached Image() request to a Google API host (loopback-mapped)')],
      literal: false
    });
  }

  // ---------------------------------------------------------------- S11
  {
    const id = 'S11';
    const sg = make.sendgrid(id), jwt = make.jwt(id), db = make.dbUrl(id), npm = make.npmToken(id), asg = make.assignSecret(id);
    const pem = pemBlock(id);
    S.push({
      id, host: 's11-generic', title: 'Heuristic (non-provider) credential shapes',
      routes: {
        '/': () => ({
          type: 'text/html',
          body: html('S11 generic',
            '<script>var mailer={sg:"' + sg + '"};var session={jwt:"' + jwt + '"};var store={url:"' + db + '"};var pkg={npm:"' + npm + '"};var cfg={clientSecret:"' + asg + '"};</script>' +
            '<script type="text/plain" id="pem">' + pem + '</script>')
        })
      },
      positives: [
        pos(id, 'sendgrid', 'unknown', sg, [SRC.dom], 'SendGrid-shaped token (heuristic, not validated)'),
        pos(id, 'jwt', 'unknown', jwt, [SRC.dom], 'JWT-shaped token (heuristic)'),
        pos(id, 'dburl', 'unknown', db, [SRC.dom], 'connection string with embedded credentials (heuristic)'),
        pos(id, 'npm', 'unknown', npm, [SRC.dom], 'npm-token-shaped value (heuristic)'),
        pos(id, 'assign', 'unknown', asg, [SRC.dom], 'high-entropy value assigned to "clientSecret" (heuristic)'),
        pos(id, 'pem', 'unknown', pem, [SRC.dom], 'PEM private-key block (heuristic; random body, not a key)')
      ],
      literal: true
    });
  }

  // ---------------------------------------------------------------- S12 negatives
  const negatives = [];
  {
    const id = 'S12';
    const hex = (n, s) => make.twilioToken(s).repeat(2).slice(0, n);
    const lines = [];
    // `embedded` is the exact snippet served in the page (assignment context
    // included), so detectors are tested the way the browser run presents them.
    const addNeg = (nid, cls, text, note, inScript) => {
      negatives.push({ id: id + '-' + nid, cls, text, note, embedded: inScript });
      lines.push(inScript);
    };
    // --- "invalid": structurally not a credential; must NOT be reported.
    const longG = make.google('neg-long') + 'ZZZZZZZZ'; // 8 chars too long: trailing boundary guard
    addNeg('google-too-long', 'invalid', longG, 'Google-shaped but 8 chars too long (trailing boundary guard)', 'var n1="' + longG + '";');
    const shortG = make.google('neg-short').slice(0, 24);
    addNeg('google-too-short', 'invalid', shortG, 'Google prefix with a body that is too short', 'var n2="' + shortG + '";');
    const shortA = make.anthropic('neg-short').slice(0, 44);
    addNeg('anthropic-too-short', 'invalid', shortA, 'sk-ant- prefix with a body under the 90-char minimum', 'var n3="' + shortA + '";');
    const embedded = 'abc' + make.openaiLegacy('neg-embedded');
    addNeg('openai-embedded', 'invalid', embedded, 'OpenAI-shaped value glued to a preceding alphanumeric run (lookbehind guard)', 'var n4="' + embedded + '";');
    const shortGh = make.github('neg-short').slice(0, 24);
    addNeg('github-too-short', 'invalid', shortGh, 'ghp_ prefix with too few characters', 'var n5="' + shortGh + '";');
    const awsLong = 'AK' + 'IA' + 'ABCDEFGHIJKLMNOPQRSTUVWX';
    addNeg('aws-id-too-long', 'invalid', awsLong, 'AWS-shaped ID with extra trailing capitals (trailing guard)', 'var n6="' + awsLong + '";');
    const twNoCtx = make.twilioSid('neg-noctx');
    addNeg('twilio-sid-no-context', 'invalid', twNoCtx, 'AC + 32 hex with no Twilio wording nearby (context gate)', '<!-- ' + twNoCtx + ' -->');
    addNeg('md5', 'invalid', hex(32, 'md5'), '32-hex digest (content hash)', 'var n7="' + hex(32, 'md5') + '";');
    addNeg('sha256', 'invalid', hex(64, 'sha'), '64-hex digest (content hash)', 'var n8="' + hex(64, 'sha') + '";');
    addNeg('uuid', 'invalid', '3f2504e0-4f89-41d3-9a0c-0305e82c3301', 'RFC 4122 UUID', 'var n9="3f2504e0-4f89-41d3-9a0c-0305e82c3301";');
    addNeg('chunk-name', 'invalid', 'chunk-3f9a1c7e5b.js', 'webpack-style chunk filename', 'var n10="chunk-3f9a1c7e5b.js";');
    addNeg('low-entropy-assign', 'invalid', 'aaaaaaaaaaaa1111aaaa', 'low-entropy value assigned to "token" (entropy gate)', 'var c1={token:"aaaaaaaaaaaa1111aaaa"};');
    addNeg('placeholder-assign', 'invalid', 'YOUR_API_KEY_HERE_1234', 'placeholder assigned to "apiKey" (placeholder filter)', 'var c2={apiKey:"YOUR_API_KEY_HERE_1234"};');
    addNeg('changeme-assign', 'invalid', 'changeme-please-9999', 'changeme-style placeholder assigned to "password"', 'var c3={password:"changeme-please-9999"};');
    addNeg('short-assign', 'invalid', 'hunter2', 'short value assigned to "password" (length gate)', 'var c4={password:"hunter2"};');
    // --- "lookalike": format-valid or keyword-assigned strings that are not secrets.
    const xs = 'sk' + '-' + 'x'.repeat(48);
    addNeg('openai-xxxx-placeholder', 'lookalike', xs, 'OpenAI-format placeholder made of x characters', 'var l1="' + xs + '";');
    // Body padded to exactly 35 chars so the value is genuinely format-valid.
    const docG = 'AI' + 'za' + 'SyEXAMPLE-NOT-A-REAL-KEY-'.padEnd(35, '0');
    addNeg('google-docs-example', 'lookalike', docG, 'Google-format documentation example', 'var l2="' + docG + '";');
    // Assembled at runtime so this source file itself does not trip the extension's heuristic.
    const envRef = 'process.env.' + ['STRIPE', 'API', 'KEY', 'V2'].join('_');
    addNeg('env-reference', 'lookalike', envRef, 'environment-variable reference assigned to "apiKey"', 'var c5={apiKey:"' + envRef + '"};');
    // Must not contain placeholder words ("example", "sample", ...), or the placeholder filter would reject it.
    const appId = ['org', 'acme', 'mobile', 'build2026x'].join('.');
    addNeg('app-identifier', 'lookalike', appId, 'reverse-DNS app identifier assigned to "apiKey"', 'var c6={apiKey:"' + appId + '"};');
    S.push({
      id, host: 's12-negatives', title: 'False-positive corpus (strings that are not credentials)',
      routes: {
        '/': () => ({
          type: 'text/html',
          body: html('S12 negatives', '<script>' + lines.filter((l) => l.charAt(0) === 'v').join('\n') + '</script>' +
            lines.filter((l) => l.charAt(0) === '<').join('\n'))
        })
      },
      positives: [],
      negatives: negatives,
      literal: true
    });
  }

  // ---------------------------------------------------------------- S13 known misses
  const knownMiss = [];
  {
    const id = 'S13';
    const concat = make.openaiProj(id + 'cat'), codes = make.anthropic(id + 'codes'), worker = make.openrouter(id + 'wk');
    const charCodes = JSON.stringify(Array.from(codes).map((c) => c.charCodeAt(0)));
    // Closure-local only: assembled from fragments and never sent, stored or
    // attached to window. The page still ships the means to rebuild the key.
    const script =
      '(function(){var p=' + jsJoin(concat) + ';if(p.length<0){console.log(p)}})();' +
      '(function(){var a=' + charCodes + ';var s=a.map(function(c){return String.fromCharCode(c)}).join("");if(s.length<0){console.log(s)}})();' +
      'try{new Worker("/assets/worker.js")}catch(e){}';
    knownMiss.push(
      pos(id, 'fragments', 'openai', concat, [], 'assembled from two string fragments inside a closure; never stored, sent or attached to window', { expectDetect: false }),
      pos(id, 'charcodes', 'anthropic', codes, [], 'stored as an array of char codes; rebuilt only inside a closure', { expectDetect: false }),
      pos(id, 'worker', 'openrouter', worker, [], 'literal in a Web Worker script referenced only from an inline script', { expectDetect: false })
    );
    S.push({
      id, host: 's13-limits', title: 'Known limitations (expected misses)',
      routes: {
        '/': () => ({ type: 'text/html', body: html('S13 limits', '<script>' + script + '</script>') }),
        '/assets/worker.js': () => ({ type: 'application/javascript', body: 'var WORKER_KEY="' + worker + '";self.postMessage(WORKER_KEY.length);' })
      },
      positives: [],
      knownMiss,
      literal: false
    });
  }

  // ---------------------------------------------------------------- S14 ignored
  {
    const id = 'S14';
    const k = make.github(id);
    S.push({
      id, host: 's14-ignored', title: 'Domain on the user ignore list',
      routes: { '/': () => ({ type: 'text/html', body: html('S14 ignored domain', '<script>var t="' + k + '";</script>') }) },
      positives: [],
      ignoreProbe: pos(id, 'ignored', 'github', k, [], 'literal key on an origin the user added to the ignore list; nothing may be stored', { expectDetect: false }),
      literal: true,
      ignored: true
    });
  }

  return S;
}

// Fixture self-check: runtime-assembled credentials must not appear verbatim in
// any served body (otherwise the DOM/bundle scan, not the intended surface,
// would be what finds them and the attribution would be meaningless).
export function selfCheck(scenarios, detectKeys) {
  const problems = [];
  for (const sc of scenarios) {
    const bodies = Object.keys(sc.routes).map((p) => ({ p, text: sc.routes[p]().body }));
    const all = (sc.positives || []).concat(sc.knownMiss || [], sc.ignoreProbe ? [sc.ignoreProbe] : []);
    for (const e of all) {
      const literalExpected = sc.literal === true;
      if (e.onlyVia) {
        // Raw text must be invisible to the detector; the decoded sourcesContent must not be.
        const mapBody = bodies.find((b) => b.p.endsWith('.map'));
        if (!mapBody) { problems.push(e.id + ': onlyVia entry but scenario has no .map route'); continue; }
        if (mapBody.text.indexOf(e.key) !== -1) problems.push(e.id + ': key appears verbatim in the raw map');
        if (detectKeys(mapBody.text).some((h) => h.key === e.key)) problems.push(e.id + ': detector finds the key in the RAW map text');
        let decoded = '';
        try { decoded = JSON.parse(mapBody.text).sourcesContent.join('\n'); } catch (err) { problems.push(e.id + ': map is not valid JSON'); }
        if (!detectKeys(decoded).some((h) => h.key === e.key)) problems.push(e.id + ': detector does not find the key in decoded sourcesContent');
      }
      for (const b of bodies) {
        const has = b.text.indexOf(e.key) !== -1;
        const isMapOnly = sc.id === 'S03';
        const allowed = literalExpected || (isMapOnly && b.p.endsWith('.map')) ||
          (sc.id === 'S08' && (b.p === '/config.json' || b.p === '/.env')) ||
          (sc.id === 'S05' && (b.p === '/api/config' || b.p === '/api/legacy')) ||
          (sc.id === 'S09') || (sc.id === 'S13' && b.p === '/assets/worker.js') ||
          (sc.id === 'S01' && b.p === '/assets/chunk-lazy.js') || (sc.id === 'S01' && b.p === '/assets/app.bundle.js');
        if (has && !allowed) problems.push(e.id + ': key appears verbatim in ' + sc.id + b.p);
      }
      // The main page markup (and for S03 the minified bundle) must not let the
      // detector find an assembled-at-runtime key.
      // S07 is exempt: decode-and-rescan finding the key in the static markup is the intended path.
      if (!literalExpected && sc.id !== 'S09' && sc.id !== 'S07') {
        for (const b of bodies) {
          if (sc.id === 'S08' && b.p !== '/') continue;
          if (sc.id === 'S05' && (b.p === '/api/config' || b.p === '/api/legacy')) continue;
          if (sc.id === 'S03' && b.p.endsWith('.map')) continue;
          if (sc.id === 'S13' && b.p === '/assets/worker.js') continue;
          if (detectKeys(b.text).some((h) => h.key === e.key || h.secret === e.key)) {
            problems.push(e.id + ': detector finds the key in static ' + sc.id + b.p);
          }
        }
      }
    }
  }
  return problems;
}

export function allExpectations(scenarios) {
  const out = { positives: [], knownMiss: [], negatives: [], ignoreProbes: [] };
  for (const sc of scenarios) {
    out.positives.push(...(sc.positives || []));
    out.knownMiss.push(...(sc.knownMiss || []));
    out.negatives.push(...(sc.negatives || []));
    if (sc.ignoreProbe) out.ignoreProbes.push(sc.ignoreProbe);
  }
  return out;
}
