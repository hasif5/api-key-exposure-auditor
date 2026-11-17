/*
 * synthetic.mjs - deterministic synthetic credential factory for the research
 * fixtures.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * Every value produced here is FAKE. It matches the *format* the extension's
 * detectors look for, but it was never issued by any provider and cannot
 * authenticate anywhere. Values are derived from a fixed seed so that every run
 * of the harness produces the same strings (reproducible), and wherever the
 * format has room for it the body carries the visible marker "SYNTHFIXTURE".
 *
 * IMPORTANT: no complete credential literal is stored in this repository.
 * Prefixes and bodies are assembled at runtime, which keeps the fixtures from
 * tripping secret scanners / push protection and means there is nothing real
 * to leak. Do not replace this with hard-coded sample keys.
 */

import { createHash } from 'node:crypto';

export const MARKER = 'SYNTHFIXTURE';

const CS = {
  alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  b64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  hex: '0123456789abcdef',
  b64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+',
  digits: '0123456789'
};

// Deterministic filler: sha256 chain over `seed`, mapped into `charset`.
function filler(seed, len, charset) {
  let out = '';
  let block = createHash('sha256').update('gaks-research:' + seed).digest();
  let i = 0;
  while (out.length < len) {
    if (i >= block.length) { block = createHash('sha256').update(block).digest(); i = 0; }
    out += charset[block[i++] % charset.length];
  }
  return out;
}

// body(seed, total, charset, withMarker): `total` chars, marker first if it fits.
function body(seed, total, charset, withMarker) {
  const head = withMarker ? MARKER : '';
  return head + filler(seed, total - head.length, charset);
}

function b64url(str) {
  return Buffer.from(str, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Each factory takes a seed so the same provider can yield several distinct
// values (one per scenario) without ever repeating a string.
export const make = {
  google: (s) => 'AI' + 'za' + body('google:' + s, 35, CS.b64url, true),
  googleNew: (s) => 'AQ' + '.' + body('googleNew:' + s, 40, CS.b64url, true),
  openaiProj: (s) => 'sk-' + 'proj-' + body('openaiProj:' + s, 48, CS.b64url, true),
  openaiLegacy: (s) => 'sk' + '-' + body('openaiLegacy:' + s, 48, CS.alnum, true),
  openaiSvc: (s) => 'sk-' + 'svcacct-' + body('openaiSvc:' + s, 48, CS.b64url, true),
  anthropic: (s) => 'sk-' + 'ant-' + 'api03-' + body('anthropic:' + s, 95, CS.b64url, true),
  openrouter: (s) => 'sk-' + 'or-' + 'v1-' + body('openrouter:' + s, 64, CS.alnum, true),
  xai: (s) => 'xa' + 'i-' + body('xai:' + s, 80, CS.alnum, true),
  github: (s) => 'gh' + 'p_' + body('github:' + s, 36, CS.alnum, true),
  gitlab: (s) => 'gl' + 'pat-' + body('gitlab:' + s, 26, CS.b64url, true),
  slack: (s) => 'xo' + 'xb-' + '000000000000-' + body('slack:' + s, 24, CS.alnum, true),
  stripeTest: (s) => 'sk' + '_test_' + body('stripeTest:' + s, 28, CS.alnum, true),
  // Pairs: Twilio is hex-only (no room for the marker); AWS carries a marker.
  twilioSid: (s) => 'A' + 'C' + filler('twilioSid:' + s, 32, CS.hex),
  twilioToken: (s) => filler('twilioToken:' + s, 32, CS.hex),
  awsId: (s) => 'AK' + 'IA' + 'SYNTHFX' + filler('awsId:' + s, 9, CS.upper),
  awsSecret: (s) => body('awsSecret:' + s, 40, CS.b64, false)
    .replace(/^.{19}/, 'SynthFixtureNotReal'),
  // Generic (heuristic / "unknown" provider) shapes.
  sendgrid: (s) => 'S' + 'G.' + filler('sg1:' + s, 22, CS.b64url) + '.' + filler('sg2:' + s, 43, CS.b64url),
  jwt: (s) => b64url('{"alg":"HS256","typ":"JWT"}') + '.' +
    b64url('{"sub":"synthetic-fixture","note":"not a real token","id":"' + s + '"}') + '.' +
    filler('jwt:' + s, 43, CS.b64url),
  dbUrl: (s) => 'postgres' + '://fixture_user:' + filler('db:' + s, 18, CS.alnum) + '@db.fixture.invalid:5432',
  npmToken: (s) => 'np' + 'm_' + filler('npm:' + s, 36, CS.alnum),
  // Assignment-heuristic value: letters+digits, entropy >= 3.0, 24 chars.
  assignSecret: (s) => filler('assign:' + s, 24, CS.alnum),
  // Random base64 body that is NOT a key; wrapped as a PEM block by the caller.
  pemBody: (s) => filler('pem:' + s, 64, CS.b64)
};

export function pemBlock(s) {
  const dash = '-----';
  const label = 'RSA PRIV' + 'ATE KEY';
  return dash + 'BEGIN ' + label + dash + '\n' + make.pemBody(s + 'a') + '\n' +
    make.pemBody(s + 'b') + '\n' + dash + 'END ' + label + dash;
}

// Redaction used for everything written into research/evidence: shows enough to
// correlate (prefix, tail, hash) without reproducing a full credential string.
export function redact(value) {
  const v = String(value);
  const fp = createHash('sha256').update(v).digest('hex').slice(0, 12);
  if (v.length <= 14) return v.slice(0, 3) + '...(' + v.length + ' chars) #' + fp;
  return v.slice(0, 7) + '...' + v.slice(-4) + ' (' + v.length + ' chars) #' + fp;
}

export function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}
