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
const GOOGLE_RE = /AIza[0-9A-Za-z_\-]{35}/g;
const ANTHROPIC_RE = /sk-ant-[A-Za-z0-9_-]{90,}/g;
const OPENAI_RE = /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,}/g;

const GOOGLE_SINGLE = /^AIza[0-9A-Za-z_\-]{35}$/;
const ANTHROPIC_SINGLE = /^sk-ant-[A-Za-z0-9_-]{90,}$/;
const OPENAI_SINGLE = /^(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})$/;

// Classify a bearer-token validation response.
function bearerClassify(status, message) {
  if (status === 0) return 'error';
  if (status >= 200 && status < 300) return 'enabled';
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

// ---- OpenAI ----------------------------------------------------------------
async function openaiAudit(key, opts) {
  opts = opts || {};
  const tasks = [() => openaiModels(key)];
  if (opts.includeGenerate) tasks.push(() => openaiChat(key));
  return runPool(tasks, 2);
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
async function anthropicAudit(key, opts) {
  opts = opts || {};
  const tasks = [() => anthropicModels(key)];
  if (opts.includeGenerate) tasks.push(() => anthropicMessages(key));
  return runPool(tasks, 2);
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
    id: 'openai', name: 'OpenAI', badgeClass: 'prov-openai',
    keyRe: OPENAI_RE, singleRe: OPENAI_SINGLE,
    audit: openaiAudit,
    assess: (audits) => bearerAssess(audits, 'OpenAI')
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
      seen[key] = true;
      const snippet = snippetAround(text, m.index, key.length);
      out.push({ key, provider: p.id, snippet, mapsContext: p.id === 'google' && isMapsContext(snippet) });
    }
  }
  return out;
}
