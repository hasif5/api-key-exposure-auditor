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
const GITHUB_RE = /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{59,})(?![A-Za-z0-9])/g;
const GITLAB_RE = /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])/g;
const SLACK_RE = /(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])/g;
const STRIPE_RE = /(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9])/g;

const GOOGLE_SINGLE = /^(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})$/;
const ANTHROPIC_SINGLE = /^sk-ant-[A-Za-z0-9_-]{90,}$/;
const OPENROUTER_SINGLE = /^sk-or-(?:v1-)?[A-Za-z0-9]{40,}$/;
const XAI_SINGLE = /^xai-[A-Za-z0-9]{40,}$/;
const OPENAI_SINGLE = /^(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})$/;
const TWILIO_SINGLE = /^AC[0-9a-fA-F]{32}$/;
const GITHUB_SINGLE = /^(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{59,})$/;
const GITLAB_SINGLE = /^glpat-[A-Za-z0-9_-]{20,}$/;
const SLACK_SINGLE = /^xox[baprs]-[A-Za-z0-9-]{10,}$/;
const STRIPE_SINGLE = /^(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}$/;

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

// ---- AWS (Access Key ID + Secret Access Key, SigV4 → STS) ------------------
// AWS credentials leak as a pair: a 20-char Access Key ID (AKIA…/ASIA…/…) and a
// 40-char Secret Access Key. Like Twilio, we capture the secret found nearby and
// validate the pair by SigV4-signing a free sts:GetCallerIdentity call. AWS keys
// carry IAM permissions with no IP/referrer restriction, so a valid pair is
// unconditionally critical.
const AWS_RE = /(?<![A-Za-z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])/g;
const AWS_SINGLE = /^(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}$/;

// Find a 40-char Secret Access Key near the Access Key ID (the pair usually
// leaks together). Skips the ID itself.
function awsSecret(text, index, id) {
  const slice = text.slice(Math.max(0, index - 500), Math.min(text.length, index + 500));
  // Prefer a value explicitly labelled as a secret (secretAccessKey,
  // aws_secret_access_key, awsLocationSecret, …) — length-agnostic, since
  // not every AWS-flavoured secret is exactly 40 chars.
  const kw = /secret[_a-z]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})/i.exec(slice);
  if (kw && id.indexOf(kw[1]) === -1) return kw[1];
  // Fallback: the first standalone 40-char base64 run that isn't the ID.
  const re = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g;
  let m;
  while ((m = re.exec(slice)) !== null) {
    if (id.indexOf(m[0]) === -1) return m[0];
  }
  return null;
}

function toHex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
async function sha256Hex(str) {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)));
}
async function hmac256(keyBytes, msg) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg)));
}

async function awsAudit(key, opts) {
  opts = opts || {};
  const secret = opts.secret;
  const meta = { billable: false, costNote: 'Free — sts:GetCallerIdentity (read-only identity check)' };
  if (!secret) {
    return [record('AWS', 'STS GetCallerIdentity', 0, '', 'inconclusive',
      'Access Key ID exposed, but no Secret Access Key was found nearby to validate the pair', meta)];
  }
  const region = 'us-east-1', service = 'sts', host = 'sts.amazonaws.com';
  const body = 'Action=GetCallerIdentity&Version=2011-06-15';
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.slice(0, 8);
  const ct = 'application/x-www-form-urlencoded; charset=utf-8';

  const canonicalHeaders = 'content-type:' + ct + '\nhost:' + host + '\nx-amz-date:' + amzDate + '\n';
  const signedHeaders = 'content-type;host;x-amz-date';
  const canonicalRequest = ['POST', '/', '', canonicalHeaders, signedHeaders, await sha256Hex(body)].join('\n');
  const scope = dateStamp + '/' + region + '/' + service + '/aws4_request';
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonicalRequest)].join('\n');

  const enc = new TextEncoder();
  const kDate = await hmac256(enc.encode('AWS4' + secret), dateStamp);
  const kRegion = await hmac256(kDate, region);
  const kService = await hmac256(kRegion, service);
  const kSigning = await hmac256(kService, 'aws4_request');
  const signature = toHex(await hmac256(kSigning, stringToSign));
  const authz = 'AWS4-HMAC-SHA256 Credential=' + key + '/' + scope +
    ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;

  const r = await doFetch('https://' + host + '/', {
    method: 'POST',
    headers: { 'Content-Type': ct, 'X-Amz-Date': amzDate, 'Authorization': authz },
    body
  });
  if (!r.ok) return [record('AWS', 'STS GetCallerIdentity', 0, '', 'error', r.text, meta)];
  if (r.status >= 200 && r.status < 300) {
    const arn = (r.text.match(/<Arn>([^<]+)<\/Arn>/) || [])[1] || '';
    const acct = (r.text.match(/<Account>([^<]+)<\/Account>/) || [])[1] || '';
    return [record('AWS', 'STS GetCallerIdentity', r.status, 'OK', 'enabled',
      'VALID — ' + (arn || 'caller identity confirmed') + (acct ? ' (account ' + acct + ')' : ''), meta)];
  }
  const code = (r.text.match(/<Code>([^<]+)<\/Code>/) || [])[1] || '';
  const cls = (r.status === 403 || /InvalidClientTokenId|SignatureDoesNotMatch|IncompleteSignature|MissingAuthentication/i.test(code))
    ? 'invalid-key' : 'denied';
  return [record('AWS', 'STS GetCallerIdentity', r.status, code, cls, code || r.text.slice(0, 200), meta)];
}

function awsAssess(audits) {
  if (!audits || !audits.length) {
    return { level: 'unknown', label: 'Not validated', enabledServices: [], billableEnabled: false, restricted: false, bypass: false };
  }
  if (audits.some((a) => a.classification === 'enabled')) {
    return { level: 'critical',
      label: 'VALID AWS credentials — programmatic account access (IAM-scoped; no IP/referrer restriction)',
      enabledServices: ['AWS'], billableEnabled: true, restricted: false, bypass: false };
  }
  const inconclusive = audits.some((a) => a.classification === 'inconclusive');
  return { level: 'unknown',
    label: inconclusive ? 'Access Key ID exposed (no Secret Access Key found nearby)' : 'Invalid / not reachable',
    enabledServices: [], billableEnabled: false, restricted: false, bypass: false };
}

// ---- GitHub (personal access / OAuth / fine-grained tokens) ----------------
// A token grants repo/org/account access with no IP restriction, so a valid
// one is critical. Validated by a free GET /user.
async function githubAudit(key) {
  const meta = { billable: false, costNote: 'Free — GET /user' };
  const r = await doFetch('https://api.github.com/user', {
    headers: { Authorization: 'Bearer ' + key, Accept: 'application/vnd.github+json', 'User-Agent': 'gaks' }
  });
  if (!r.ok) return [record('GitHub', 'user', 0, '', 'error', r.text, meta)];
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const login = json && json.login ? '@' + json.login : 'account';
    return [record('GitHub', 'user', r.status, 'OK', 'enabled', 'VALID — ' + login + ' (full token access)', meta)];
  }
  const msg = json && json.message ? json.message : r.text.slice(0, 200);
  return [record('GitHub', 'user', r.status, '', (r.status === 401 || r.status === 403) ? 'invalid-key' : bearerClassify(r.status, msg), msg, meta)];
}

// ---- GitLab (personal/project access tokens) -------------------------------
async function gitlabAudit(key) {
  const meta = { billable: false, costNote: 'Free — GET /api/v4/user' };
  const r = await doFetch('https://gitlab.com/api/v4/user', { headers: { 'PRIVATE-TOKEN': key } });
  if (!r.ok) return [record('GitLab', 'user', 0, '', 'error', r.text, meta)];
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    return [record('GitLab', 'user', r.status, 'OK', 'enabled',
      'VALID — ' + (json && json.username ? '@' + json.username : 'account') + ' (API access)', meta)];
  }
  const msg = json && json.message ? json.message : r.text.slice(0, 200);
  return [record('GitLab', 'user', r.status, '', (r.status === 401 || r.status === 403) ? 'invalid-key' : bearerClassify(r.status, msg), msg, meta)];
}

// ---- Slack (bot/user/app tokens) -------------------------------------------
async function slackAudit(key) {
  const meta = { billable: false, costNote: 'Free — auth.test' };
  // Slack returns HTTP 200 even for bad tokens; the verdict is the JSON `ok`.
  const r = await doFetch('https://slack.com/api/auth.test', { method: 'POST', headers: { Authorization: 'Bearer ' + key } });
  if (!r.ok) return [record('Slack', 'auth.test', 0, '', 'error', r.text, meta)];
  const json = parseJsonSafe(r.text) || {};
  if (json.ok) {
    return [record('Slack', 'auth.test', r.status, 'OK', 'enabled',
      'VALID — ' + (json.team || 'team') + ' / ' + (json.user || 'user'), meta)];
  }
  const err = json.error || 'invalid';
  return [record('Slack', 'auth.test', r.status, err,
    /invalid_auth|not_authed|token_revoked|account_inactive|token_expired/.test(err) ? 'invalid-key' : 'denied', err, meta)];
}

// ---- Stripe (secret / restricted keys, HTTP Basic auth) --------------------
async function stripeAudit(key) {
  const meta = { billable: false, costNote: 'Free — GET /v1/account' };
  const r = await doFetch('https://api.stripe.com/v1/account', { headers: { Authorization: 'Basic ' + btoa(key + ':') } });
  if (!r.ok) return [record('Stripe', 'account', 0, '', 'error', r.text, meta)];
  const json = parseJsonSafe(r.text);
  if (r.status >= 200 && r.status < 300) {
    const mode = /_live_/.test(key) ? 'LIVE' : 'test';
    return [record('Stripe', 'account', r.status, 'OK', 'enabled',
      'VALID ' + mode + ' key — ' + (json && json.id ? json.id : 'account'), meta)];
  }
  const msg = json && json.error ? (json.error.message || json.error.type || '') : r.text.slice(0, 200);
  return [record('Stripe', 'account', r.status, '', (r.status === 401) ? 'invalid-key' : bearerClassify(r.status, msg), msg, meta)];
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
  },
  {
    id: 'aws', name: 'AWS', badgeClass: 'prov-aws',
    keyRe: AWS_RE, singleRe: AWS_SINGLE,
    extractSecret: awsSecret,
    audit: awsAudit,
    assess: awsAssess
  },
  {
    id: 'github', name: 'GitHub', badgeClass: 'prov-github',
    keyRe: GITHUB_RE, singleRe: GITHUB_SINGLE,
    audit: githubAudit,
    assess: (audits) => bearerAssess(audits, 'GitHub')
  },
  {
    id: 'gitlab', name: 'GitLab', badgeClass: 'prov-gitlab',
    keyRe: GITLAB_RE, singleRe: GITLAB_SINGLE,
    audit: gitlabAudit,
    assess: (audits) => bearerAssess(audits, 'GitLab')
  },
  {
    id: 'slack', name: 'Slack', badgeClass: 'prov-slack',
    keyRe: SLACK_RE, singleRe: SLACK_SINGLE,
    audit: slackAudit,
    assess: (audits) => bearerAssess(audits, 'Slack')
  },
  {
    id: 'stripe', name: 'Stripe', badgeClass: 'prov-stripe',
    keyRe: STRIPE_RE, singleRe: STRIPE_SINGLE,
    audit: stripeAudit,
    assess: (audits) => bearerAssess(audits, 'Stripe')
  }
];

// ---- Generic "looks like a secret" heuristics (provider: 'unknown') --------
// Catch credentials we have no dedicated auditor for. Reported under the
// 'unknown' provider and never auto-validated. Two tiers: (1) well-known token
// shapes from other vendors, (2) a keyword-assignment heuristic gated on
// charset/entropy/placeholder checks to keep noise down.
// MUST be kept in sync with the copies in content/patterns.js and
// content/intercept.js (the test suite checks parity).
const GENERIC_TOKEN_PATTERNS = [
  { label: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]+/g },
  { label: 'SendGrid API key', re: /(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9])/g },
  { label: 'Google OAuth client secret', re: /(?<![A-Za-z0-9])GOCSPX-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])/g },
  { label: 'npm access token', re: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g },
  { label: 'Shopify access token', re: /(?<![A-Za-z0-9])shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}(?![A-Za-z0-9])/g },
  { label: 'Twilio API key SID', re: /(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![0-9a-f])/g },
  { label: 'Mailgun API key', re: /(?<![A-Za-z0-9])key-[0-9a-f]{32}(?![A-Za-z0-9])/g },
  { label: 'JSON Web Token (JWT)', re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])/g },
  { label: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,4000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { label: 'Connection string with embedded credentials', re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|https?|ftp):\/\/[^\s:@/]+:[^\s:@/]{2,}@[^\s/?#"'`\\]+/gi },
  { label: 'HuggingFace token', re: /(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])/g },
  { label: 'Replicate API token', re: /(?<![A-Za-z0-9])r8_[A-Za-z0-9]{37,}(?![A-Za-z0-9])/g },
  { label: 'Groq API key', re: /(?<![A-Za-z0-9])gsk_[A-Za-z0-9]{48,}(?![A-Za-z0-9])/g },
  { label: 'DigitalOcean token', re: /(?<![A-Za-z0-9])dop_v1_[a-f0-9]{64}(?![A-Za-z0-9])/g },
  { label: 'Stripe webhook secret', re: /(?<![A-Za-z0-9])whsec_[A-Za-z0-9]{32,}(?![A-Za-z0-9])/g },
  { label: 'Notion token', re: /(?<![A-Za-z0-9])(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{43,})(?![A-Za-z0-9])/g },
  { label: 'Linear API key', re: /(?<![A-Za-z0-9])lin_api_[A-Za-z0-9]{40,}(?![A-Za-z0-9])/g },
  { label: 'Telegram bot token', re: /(?<![A-Za-z0-9])\d{8,10}:AA[A-Za-z0-9_-]{32,}(?![A-Za-z0-9])/g },
  { label: 'Discord bot token', re: /(?<![A-Za-z0-9])[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}(?![A-Za-z0-9])/g },
  { label: 'Sentry DSN', re: /https:\/\/[a-z0-9]+@[a-z0-9.-]*sentry\.io\/\d+/gi },
  { label: 'Mailchimp API key', re: /(?<![A-Za-z0-9])[0-9a-f]{32}-us\d{1,2}(?![A-Za-z0-9])/g }
];

const GENERIC_ASSIGN_RE = /(?<![A-Za-z0-9_])(api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|access[_-]?key|password|passwd|token)["']?\s*[:=]\s*["']([^"'\s]{16,200})["']/gi;
const GENERIC_PLACEHOLDER_RE = /your|example|placeholder|change[_-]?me|redacted|dummy|sample|xxxx|todo|insert|enter|^[A-Za-z]+$|<|\{|\$/i;
const GENERIC_CHARSET_RE = /^[A-Za-z0-9_\-+/.=~]+$/;

function genericEntropy(s) {
  const freq = Object.create(null);
  for (let i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
  let e = 0;
  for (const k in freq) { const p = freq[k] / s.length; e -= p * Math.log2(p); }
  return e;
}

// A captured assignment value only counts if it really looks like a secret:
// key-ish charset, not a placeholder, mixed letters+digits, decent entropy.
function looksSecret(v) {
  if (!v || v.length < 16 || v.length > 200) return false;
  if (!GENERIC_CHARSET_RE.test(v)) return false;
  if (GENERIC_PLACEHOLDER_RE.test(v)) return false;
  if (!/[A-Za-z]/.test(v) || !/[0-9]/.test(v)) return false;
  return genericEntropy(v) >= 3.0;
}

// Append 'unknown' findings to `out`, skipping anything a real provider already
// matched (tracked in `seen`). `pfx` is prepended to snippets (e.g. "[decoded] ").
export function detectGeneric(text, seen, out, pfx) {
  pfx = pfx || '';
  for (const p of GENERIC_TOKEN_PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(text)) !== null) {
      const key = m[0];
      if (seen[key]) continue;
      seen[key] = true;
      out.push({ key, provider: 'unknown', reason: p.label,
        snippet: pfx + p.label + ' — ' + snippetAround(text, m.index, key.length, 100), mapsContext: false });
    }
  }
  GENERIC_ASSIGN_RE.lastIndex = 0;
  let a;
  while ((a = GENERIC_ASSIGN_RE.exec(text)) !== null) {
    const kw = a[1], val = a[2];
    if (seen[val] || !looksSecret(val)) continue;
    seen[val] = true;
    const idx = a.index + a[0].lastIndexOf(val);
    out.push({ key: val, provider: 'unknown', reason: 'secret-like value assigned to "' + kw + '"',
      snippet: pfx + 'assigned to "' + kw + '" — ' + snippetAround(text, idx, val.length, 100), mapsContext: false });
  }
}

// ---- Decode-and-rescan -----------------------------------------------------
// Keys are often nested inside encoded blobs (base64 config, percent-encoded
// URLs, JWT claims). Decode common wrappers (depth 1) and return extra text
// layers to scan. Bounded so a large minified bundle can't blow up.
// MUST be kept in sync with content/patterns.js and content/intercept.js.
const B64_BLOB_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])/g;

function b64decode(s) {
  try {
    let t = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = t.length % 4;
    if (pad) t += '='.repeat(4 - pad);
    const out = (typeof atob === 'function') ? atob(t) : null;
    if (!out) return null;
    let printable = 0;
    for (let i = 0; i < out.length; i++) { const c = out.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++; }
    return out.length >= 8 && printable / out.length > 0.85 ? out : null; // skip binary noise
  } catch (e) { return null; }
}

function decodeLayers(text) {
  const layers = [];
  // Percent-encoding (bounded to smaller texts so we don't re-scan huge bundles).
  if (text.length < 100000 && text.indexOf('%') !== -1) {
    try { const u = decodeURIComponent(text); if (u !== text) layers.push(u); } catch (e) { /* malformed */ }
  }
  // Base64 / base64url blobs (cap how many we examine and decode).
  B64_BLOB_RE.lastIndex = 0;
  let m, examined = 0, decoded = 0;
  while ((m = B64_BLOB_RE.exec(text)) !== null && examined < 600 && decoded < 25) {
    examined++;
    const d = b64decode(m[0]);
    if (d) { layers.push(d.length > 100000 ? d.slice(0, 100000) : d); decoded++; }
  }
  return layers;
}

// Provider + generic scan of one text blob into out/seen. `pfx` tags snippets.
function scanInto(text, seen, out, pfx) {
  pfx = pfx || '';
  for (const p of PROVIDERS) {
    p.keyRe.lastIndex = 0;
    let m;
    while ((m = p.keyRe.exec(text)) !== null) {
      const key = m[0];
      if (seen[key]) continue;
      if (p.context) {
        const ctx = text.slice(Math.max(0, m.index - 250), Math.min(text.length, m.index + 250));
        if (!p.context.test(ctx)) continue;
      }
      seen[key] = true;
      let snippet = pfx + snippetAround(text, m.index, key.length);
      const secret = p.extractSecret ? p.extractSecret(text, m.index, key) : null;
      if (secret) { snippet += ' · secret: ' + secret; seen[secret] = true; }
      out.push({ key, provider: p.id, snippet, secret: secret || undefined, mapsContext: p.id === 'google' && isMapsContext(snippet) });
    }
  }
  detectGeneric(text, seen, out, pfx);
}

const UNKNOWN_PROVIDER = {
  id: 'unknown', name: 'Unknown', badgeClass: 'prov-unknown', auditable: false,
  audit: async () => [],
  assess: () => ({ level: 'unknown',
    label: 'Heuristic match — unrecognized credential type; cannot be validated',
    enabledServices: [], billableEnabled: false, restricted: false, bypass: false })
};

const BY_ID = new Map(PROVIDERS.map((p) => [p.id, p]));
BY_ID.set('unknown', UNKNOWN_PROVIDER);

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
  scanInto(text, seen, out, '');
  // Re-scan decoded layers (base64 / percent-encoded blobs) for nested keys.
  for (const layer of decodeLayers(text)) scanInto(layer, seen, out, '[decoded] ');
  return out;
}
