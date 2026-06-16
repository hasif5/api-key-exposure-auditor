/*
 * providers.js — multi-provider registry (module world).
 *
 * Each provider supplies how its keys are detected, audited, and risk-assessed.
 * Google delegates to the existing logic in audit.js (unchanged). OpenAI and
 * Anthropic are bearer-token providers: a key has no IP/referrer restriction
 * mechanism, so any VALID key is unconditionally CRITICAL.
 *
 * The content-script world keeps its own copy of the detection regexes in
 * content/patterns.js (content scripts can't import modules) — keep in sync.
 */

import { doFetch, record, runPool, auditKey, assessRisk as assessGoogle } from './audit.js';
import { isMapsContext, snippetAround } from './keys.js';

// ---- Detection patterns ----------------------------------------------------
// Order matters: Anthropic (sk-ant-) is tested before OpenAI (generic sk-).
// Boundary guards: a key must be a complete token, not a substring of a longer
// alphanumeric blob (which would otherwise yield false positives).
// Google keys come in two formats: legacy "AIza"+35 and newer "AQ."+40+ base64url.
const GOOGLE_RE = /(?<![A-Za-z0-9_-])(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})(?![A-Za-z0-9_-])/g;
const ANTHROPIC_RE = /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{90,}/g;
const OPENROUTER_RE = /(?<![A-Za-z0-9])sk-or-(?:v1-)?[A-Za-z0-9]{40,}/g;
const XAI_RE = /(?<![A-Za-z0-9])xai-[A-Za-z0-9]{40,}/g;
const OPENAI_RE = /(?<![A-Za-z0-9])(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})/g;
const TWILIO_RE = /(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![0-9a-fA-F])/g; // SID; Auth Token captured separately

const GOOGLE_SINGLE = /^(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})$/;
const ANTHROPIC_SINGLE = /^sk-ant-[A-Za-z0-9_-]{90,}$/;
const OPENROUTER_SINGLE = /^sk-or-(?:v1-)?[A-Za-z0-9]{40,}$/;
const XAI_SINGLE = /^xai-[A-Za-z0-9]{40,}$/;
const OPENAI_SINGLE = /^(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})$/;
const TWILIO_SINGLE = /^AC[0-9a-fA-F]{32}$/;

// Twilio auth needs BOTH the Account SID and a 32-hex Auth Token. Given an SID
// match, look for a 32-hex token nearby (the usual "set" leaked together).
function twilioSecret(text, index, sid) {
  const start = Math.max(0, index - 700);
  const end = Math.min(text.length, index + 700);
  const re = /[0-9a-fA-F]{32}/g;
  let m;
  while ((m = re.exec(text.slice(start, end))) !== null) {
    const tok = m[0];
    if (sid.indexOf(tok) !== -1) continue; // that's the SID's own hex tail
    return tok;
  }
  return null;
}

// Classify a bearer-token validation response.
function bearerClassify(status, message) {
  const msg = (message || '').toLowerCase();
  if (status === 0) return 'error';
  if (status >= 200 && status < 300) return 'enabled';
  if (msg.includes('incorrect api key') || msg.includes('invalid api key') ||
      msg.includes('api key not valid') || msg.includes('user not found') ||
      msg.includes('no api key') || msg.includes('unauthorized')) return 'invalid-key';
  if (status === 401 || status === 403) return 'invalid-key';
  if (status === 429) return 'over-quota';
  return 'denied';
}

function parseJsonSafe(text) { try { return JSON.parse(text); } catch (e) { return null; } }

function bearerAssess(audits, providerName) {
  if (!audits || !audits.length) {
    return { level: 'unknown', label: 'Not validated', enabledServices: [], billableEnabled: false, restricted: false, bypass: false };
  }
  const valid = audits.some((a) => a.classification === 'enabled');
  if (valid) {
    return {
      level: 'critical',
      label: 'VALID KEY — full account access (bearer token; no IP/referrer restriction possible)',
      enabledServices: [providerName],
      billableEnabled: true,
      restricted: false,
      bypass: false
    };
  }
  const invalid = audits.some((a) => a.classification === 'invalid-key');
  return {
    level: 'unknown',
    label: invalid ? 'Invalid / revoked key' : 'Not reachable',
    enabledServices: [],
    billableEnabled: false,
    restricted: false,
    bypass: false
  };
}

// ---- Bearer probe helper (avoids repeating the same response-handling) -----
function bearerOpts(key, method, body, extraHeaders) {
  const h = Object.assign({ Authorization: 'Bearer ' + key }, extraHeaders || {});
  if (body) h['Content-Type'] = 'application/json';
  const o = { headers: h };
  if (method) o.method = method;
  if (body) o.body = typeof body === 'string' ? body : JSON.stringify(body);
  return o;
}

async function probeBearer(service, endpoint, url, opts, meta) {
  const r = await doFetch(url, opts);
  if (!r.ok) return record(service, endpoint, 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record(service, endpoint, r.status, 'OK', 'enabled', meta._okDetail || 'Request succeeded', meta);
  }
  const err = json && json.error;
  const msg = err ? (typeof err === 'string' ? err : err.message || err.type || '') : r.text.slice(0, 200);
  const apiStatus = err ? (typeof err === 'string' ? '' : err.type || err.code || '') : '';
  return record(service, endpoint, r.status, apiStatus, bearerClassify(r.status, msg), msg, meta);
}

// ---- OpenAI ----------------------------------------------------------------
async function openaiAudit(key, opts) {
  opts = opts || {};
  const tasks = [
    () => openaiModels(key),
    () => probeBearer('OpenAI', 'Moderations', 'https://api.openai.com/v1/moderations',
      bearerOpts(key, 'POST', { input: 'test' }),
      { billable: false, costNote: 'Free — content moderation', _okDetail: 'Moderation API accessible' }),
    () => probeBearer('OpenAI', 'Embeddings', 'https://api.openai.com/v1/embeddings',
      bearerOpts(key, 'POST', { model: 'text-embedding-3-small', input: 'test' }),
      { billable: true, costNote: 'Billable ~$0.02 / 1M tokens (text-embedding-3-small)', _okDetail: 'Embedding generation succeeded' })
  ];
  if (opts.includeGenerate) {
    tasks.push(() => openaiChat(key));
    tasks.push(() => probeBearer('OpenAI', 'Images (DALL-E)', 'https://api.openai.com/v1/images/generations',
      bearerOpts(key, 'POST', { model: 'dall-e-2', prompt: 'a white dot', size: '256x256', n: 1 }),
      { billable: true, costNote: 'Billable ~$0.016 / image (DALL-E 2 256x256)', _okDetail: 'Image generation succeeded — key can generate images' }));
    tasks.push(() => probeBearer('OpenAI', 'Audio TTS', 'https://api.openai.com/v1/audio/speech',
      bearerOpts(key, 'POST', { model: 'tts-1', input: 'hi', voice: 'alloy', response_format: 'opus' }),
      { billable: true, costNote: 'Billable ~$15 / 1M chars (tts-1)', _okDetail: 'Text-to-speech succeeded — key can generate audio' }));
  }
  return runPool(tasks, 3);
}

async function openaiModels(key) {
  const r = await doFetch('https://api.openai.com/v1/models', { headers: { Authorization: 'Bearer ' + key } });
  const meta = { billable: false, costNote: 'Free — lists account models' };
  if (!r.ok) return record('OpenAI', 'ListModels', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const n = json && Array.isArray(json.data) ? json.data.length : 0;
    return record('OpenAI', 'ListModels', r.status, 'OK', 'enabled', n + ' models accessible — key is VALID', meta);
  }
  const msg = json && json.error ? (json.error.message || json.error.code || '') : r.text.slice(0, 200);
  return record('OpenAI', 'ListModels', r.status, json && json.error ? (json.error.type || '') : '',
    bearerClassify(r.status, msg), msg, meta);
}

async function openaiChat(key) {
  const body = JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: 'ping' }], max_tokens: 1 });
  const r = await doFetch('https://api.openai.com/v1/chat/completions',
    { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }, body });
  const meta = { billable: true, costNote: 'Billable — token-based (gpt-4o-mini)' };
  if (!r.ok) return record('OpenAI', 'chat/completions', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record('OpenAI', 'chat/completions', r.status, 'OK', 'enabled', 'Billable inference succeeded — key can incur charges', meta);
  }
  const msg = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('OpenAI', 'chat/completions', r.status, json && json.error ? (json.error.type || '') : '',
    bearerClassify(r.status, msg), msg, meta);
}

// ---- Anthropic -------------------------------------------------------------
function anthropicHeaders(key) {
  return { 'x-api-key': key, 'anthropic-version': '2023-06-01' };
}

async function anthropicAudit(key, opts) {
  opts = opts || {};
  const aH = anthropicHeaders(key);
  const tasks = [
    () => anthropicModels(key),
    () => probeBearer('Anthropic', 'Count Tokens',
      'https://api.anthropic.com/v1/messages/count_tokens',
      { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, aH),
        body: JSON.stringify({ model: 'claude-3-5-haiku-latest', messages: [{ role: 'user', content: 'ping' }] }) },
      { billable: false, costNote: 'Free — token counting', _okDetail: 'Token counting accessible' })
  ];
  if (opts.includeGenerate) tasks.push(() => anthropicMessages(key));
  return runPool(tasks, 3);
}

async function anthropicModels(key) {
  const r = await doFetch('https://api.anthropic.com/v1/models',
    { headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } });
  const meta = { billable: false, costNote: 'Free — lists available models' };
  if (!r.ok) return record('Anthropic', 'ListModels', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const n = json && Array.isArray(json.data) ? json.data.length : 0;
    return record('Anthropic', 'ListModels', r.status, 'OK', 'enabled', n + ' models accessible — key is VALID', meta);
  }
  const msg = json && json.error ? (json.error.message || json.error.type || '') : r.text.slice(0, 200);
  return record('Anthropic', 'ListModels', r.status, json && json.error ? (json.error.type || '') : '',
    bearerClassify(r.status, msg), msg, meta);
}

async function anthropicMessages(key) {
  const body = JSON.stringify({ model: 'claude-3-5-haiku-latest', max_tokens: 1, messages: [{ role: 'user', content: 'ping' }] });
  const r = await doFetch('https://api.anthropic.com/v1/messages',
    { method: 'POST', headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' }, body });
  const meta = { billable: true, costNote: 'Billable — token-based (claude-3-5-haiku)' };
  if (!r.ok) return record('Anthropic', 'messages', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record('Anthropic', 'messages', r.status, 'OK', 'enabled', 'Billable inference succeeded — key can incur charges', meta);
  }
  const msg = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('Anthropic', 'messages', r.status, json && json.error ? (json.error.type || '') : '',
    bearerClassify(r.status, msg), msg, meta);
}

// ---- xAI (Grok) ------------------------------------------------------------
async function xaiAudit(key, opts) {
  opts = opts || {};
  const tasks = [
    () => xaiModels(key),
    () => probeBearer('xAI', 'Embeddings', 'https://api.x.ai/v1/embeddings',
      bearerOpts(key, 'POST', { model: 'embedding-beta', input: 'test' }),
      { billable: true, costNote: 'Billable — token-based (xAI embeddings)', _okDetail: 'Embedding generation succeeded' })
  ];
  if (opts.includeGenerate) tasks.push(() => xaiChat(key));
  return runPool(tasks, 3);
}

async function xaiModels(key) {
  const r = await doFetch('https://api.x.ai/v1/models', { headers: { Authorization: 'Bearer ' + key } });
  const meta = { billable: false, costNote: 'Free — lists account models' };
  if (!r.ok) return record('xAI', 'ListModels', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const n = json && Array.isArray(json.data) ? json.data.length : 0;
    return record('xAI', 'ListModels', r.status, 'OK', 'enabled', n + ' models accessible — key is VALID', meta);
  }
  const msg = json && json.error ? (typeof json.error === 'string' ? json.error : json.error.message || '') : r.text.slice(0, 200);
  return record('xAI', 'ListModels', r.status, '', bearerClassify(r.status, msg), msg, meta);
}

async function xaiChat(key) {
  const body = JSON.stringify({ model: 'grok-2-latest', messages: [{ role: 'user', content: 'ping' }], max_tokens: 1 });
  const r = await doFetch('https://api.x.ai/v1/chat/completions',
    { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }, body });
  const meta = { billable: true, costNote: 'Billable — token-based (Grok)' };
  if (!r.ok) return record('xAI', 'chat/completions', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record('xAI', 'chat/completions', r.status, 'OK', 'enabled', 'Billable inference succeeded — key can incur charges', meta);
  }
  const msg = json && json.error ? (typeof json.error === 'string' ? json.error : json.error.message || '') : r.text.slice(0, 200);
  return record('xAI', 'chat/completions', r.status, '', bearerClassify(r.status, msg), msg, meta);
}

// ---- OpenRouter ------------------------------------------------------------
async function openrouterAudit(key, opts) {
  opts = opts || {};
  const tasks = [
    () => openrouterKey(key),
    () => openrouterCredits(key),
    () => probeBearer('OpenRouter', 'ListModels', 'https://openrouter.ai/api/v1/models',
      bearerOpts(key), { billable: false, costNote: 'Free — lists available models', _okDetail: 'Model catalog accessible' })
  ];
  if (opts.includeGenerate) tasks.push(() => openrouterChat(key));
  return runPool(tasks, 3);
}

async function openrouterKey(key) {
  const r = await doFetch('https://openrouter.ai/api/v1/key', { headers: { Authorization: 'Bearer ' + key } });
  const meta = { billable: false, costNote: 'Free — key info / limits' };
  if (!r.ok) return record('OpenRouter', 'key info', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const d = json && json.data ? json.data : {};
    const detail = 'VALID — ' + (d.label || 'key') + (d.limit != null ? ' (limit ' + d.limit + ')' : ' (limit: none)');
    return record('OpenRouter', 'key info', r.status, 'OK', 'enabled', detail, meta);
  }
  const msg = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('OpenRouter', 'key info', r.status, '', bearerClassify(r.status, msg), msg, meta);
}

async function openrouterCredits(key) {
  const r = await doFetch('https://openrouter.ai/api/v1/credits', { headers: { Authorization: 'Bearer ' + key } });
  const meta = { billable: false, costNote: 'Free — credit balance check' };
  if (!r.ok) return record('OpenRouter', 'Credits', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const d = json && json.data ? json.data : {};
    const bal = d.total_credits != null ? '$' + Number(d.total_credits).toFixed(2) : '?';
    const used = d.total_usage != null ? '$' + Number(d.total_usage).toFixed(2) : '?';
    return record('OpenRouter', 'Credits', r.status, 'OK', 'enabled',
      'Balance: ' + bal + ' total, ' + used + ' used', meta);
  }
  const msg = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('OpenRouter', 'Credits', r.status, '', bearerClassify(r.status, msg), msg, meta);
}

async function openrouterChat(key) {
  const body = JSON.stringify({ model: 'openai/gpt-4o-mini', messages: [{ role: 'user', content: 'ping' }], max_tokens: 1 });
  const r = await doFetch('https://openrouter.ai/api/v1/chat/completions',
    { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }, body });
  const meta = { billable: true, costNote: 'Billable — token-based (routed model)' };
  if (!r.ok) return record('OpenRouter', 'chat/completions', 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record('OpenRouter', 'chat/completions', r.status, 'OK', 'enabled', 'Billable inference succeeded — key can incur charges', meta);
  }
  const msg = json && json.error ? (json.error.message || '') : r.text.slice(0, 200);
  return record('OpenRouter', 'chat/completions', r.status, '', bearerClassify(r.status, msg), msg, meta);
}

// ---- Twilio (Account SID + Auth Token, HTTP Basic auth) --------------------
function twilioBasic(sid, token) {
  return { Authorization: 'Basic ' + btoa(sid + ':' + token) };
}

async function twilioProbe(sid, token, endpoint, path, meta) {
  const url = 'https://api.twilio.com/2010-04-01/Accounts/' + sid + path;
  const r = await doFetch(url, { headers: twilioBasic(sid, token) });
  if (!r.ok) return record('Twilio', endpoint, 0, '', 'error', r.text, meta);
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return record('Twilio', endpoint, r.status, 'OK', 'enabled', meta._okDetail || 'Accessible', meta);
  }
  const msg = json && json.message ? json.message : r.text.slice(0, 200);
  return record('Twilio', endpoint, r.status, '',
    r.status === 401 ? 'invalid-key' : bearerClassify(r.status, msg), msg, meta);
}

async function twilioAudit(key, opts) {
  opts = opts || {};
  const token = opts.secret;
  const noTokenMeta = { billable: false, costNote: 'Free — account fetch' };
  if (!token) {
    return [record('Twilio', 'Account SID', 0, '', 'inconclusive',
      'Account SID exposed, but no Auth Token was found nearby to validate the pair', noTokenMeta)];
  }
  const tasks = [
    () => twilioProbe(key, token, 'Account', '.json',
      { billable: false, costNote: 'Free — account info',
        _okDetail: 'VALID — SID + Auth Token confirmed' }),
    () => twilioProbe(key, token, 'SMS (Messages)', '/Messages.json?PageSize=1',
      { billable: false, costNote: 'Free — lists recent messages',
        _okDetail: 'SMS/Messages accessible — can read message history' }),
    () => twilioProbe(key, token, 'Voice (Calls)', '/Calls.json?PageSize=1',
      { billable: false, costNote: 'Free — lists recent calls',
        _okDetail: 'Voice/Calls accessible — can read call history' }),
    () => twilioProbe(key, token, 'Phone Numbers', '/IncomingPhoneNumbers.json?PageSize=1',
      { billable: false, costNote: 'Free — lists owned numbers',
        _okDetail: 'Phone numbers accessible — can list owned numbers' }),
    () => twilioProbe(key, token, 'Balance', '/Balance.json',
      { billable: false, costNote: 'Free — balance check',
        _okDetail: 'Account balance readable' }),
    () => twilioProbe(key, token, 'Usage Records', '/Usage/Records.json?Category=totalprice&StartDate=2020-01-01&PageSize=1',
      { billable: false, costNote: 'Free — usage history',
        _okDetail: 'Usage records accessible — can read spending history' })
  ];
  return runPool(tasks, 3);
}

function twilioAssess(audits) {
  if (!audits || !audits.length) {
    return { level: 'unknown', label: 'Not validated', enabledServices: [], billableEnabled: false, restricted: false, bypass: false };
  }
  if (audits.some((a) => a.classification === 'enabled')) {
    return { level: 'critical', label: 'VALID — full Twilio account (SMS/voice/numbers + billing)',
      enabledServices: ['Twilio'], billableEnabled: true, restricted: false, bypass: false };
  }
  const inconclusive = audits.some((a) => a.classification === 'inconclusive');
  return { level: 'unknown',
    label: inconclusive ? 'Account SID exposed (no Auth Token found nearby)' : 'Invalid / not reachable',
    enabledServices: [], billableEnabled: false, restricted: false, bypass: false };
}

// ---- Registry --------------------------------------------------------------
export const PROVIDERS = [
  {
    id: 'google', name: 'Google', badgeClass: 'prov-google',
    keyRe: GOOGLE_RE, singleRe: GOOGLE_SINGLE,
    audit: (key, opts) => auditKey(key, opts),
    assess: (audits) => assessGoogle(audits)
  },
  {
    id: 'anthropic', name: 'Anthropic', badgeClass: 'prov-anthropic',
    keyRe: ANTHROPIC_RE, singleRe: ANTHROPIC_SINGLE,
    audit: anthropicAudit,
    assess: (audits) => bearerAssess(audits, 'Anthropic')
  },
  {
    id: 'openrouter', name: 'OpenRouter', badgeClass: 'prov-openrouter',
    keyRe: OPENROUTER_RE, singleRe: OPENROUTER_SINGLE,
    audit: openrouterAudit,
    assess: (audits) => bearerAssess(audits, 'OpenRouter')
  },
  {
    id: 'xai', name: 'xAI', badgeClass: 'prov-xai',
    keyRe: XAI_RE, singleRe: XAI_SINGLE,
    audit: xaiAudit,
    assess: (audits) => bearerAssess(audits, 'xAI')
  },
  {
    id: 'openai', name: 'OpenAI', badgeClass: 'prov-openai',
    keyRe: OPENAI_RE, singleRe: OPENAI_SINGLE,
    audit: openaiAudit,
    assess: (audits) => bearerAssess(audits, 'OpenAI')
  },
  {
    id: 'twilio', name: 'Twilio', badgeClass: 'prov-twilio',
    keyRe: TWILIO_RE, singleRe: TWILIO_SINGLE,
    context: /twilio|account[\s_-]?sid|auth[\s_-]?token/i,
    extractSecret: twilioSecret,
    audit: twilioAudit,
    assess: twilioAssess
  }
];

const BY_ID = new Map(PROVIDERS.map((p) => [p.id, p]));

export function getProvider(id) { return BY_ID.get(id) || BY_ID.get('google'); }

export function providerForKey(key) {
  for (const p of PROVIDERS) { if (p.singleRe.test(key)) return p.id; }
  return null;
}

// Provider-aware risk dispatcher (used by the UIs).
export function assessRisk(audits, providerId) {
  return getProvider(providerId).assess(audits);
}

// Scan text for any provider's keys. Returns [{ key, provider, snippet, mapsContext }].
export function detectKeys(text) {
  const out = [];
  if (!text) return out;
  const seen = Object.create(null);
  for (const p of PROVIDERS) {
    p.keyRe.lastIndex = 0;
    let m;
    while ((m = p.keyRe.exec(text)) !== null) {
      const key = m[0];
      if (seen[key]) continue;
      // Providers whose pattern is false-positive-prone (e.g. Twilio's AC+hex)
      // require a context hint nearby before we emit a finding.
      if (p.context) {
        const ctx = text.slice(Math.max(0, m.index - 250), Math.min(text.length, m.index + 250));
        if (!p.context.test(ctx)) continue; // not enough evidence — skip (don't mark seen)
      }
      seen[key] = true;
      let snippet = snippetAround(text, m.index, key.length);
      // Paired-credential providers (e.g. Twilio) also capture a nearby secret.
      const secret = p.extractSecret ? p.extractSecret(text, m.index, key) : null;
      if (secret) snippet += ' · token: ' + secret;
      out.push({ key, provider: p.id, snippet, secret: secret || undefined, mapsContext: p.id === 'google' && isMapsContext(snippet) });
    }
  }
  return out;
}
