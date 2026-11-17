/*
 * store.js — normalized findings database on top of chrome.storage.local.
 *
 * One storage record per finding, under REC_PREFIX + key:
 *   {
 *     id, key, provider, secret, origins:[], pageUrls:[], sources:[], snippet,
 *     snippets:{source: text}, mapsContext, firstSeen, lastSeen,
 *     audits:[ { service, endpoint, httpStatus, apiStatus, classification, detail, ts } ]
 *   }
 * A write therefore costs one record, not the whole database. The earlier
 * layout (a single { findings: [...] } blob under DB_KEY) was rewritten in full
 * for every sighting, which got slower in step with the size of the database;
 * it is split into per-key records on first access (see ensureMigrated).
 *
 * Writes are serialized through a promise chain so concurrent updates from the
 * webRequest listener and content-script messages don't clobber each other.
 *
 * Author: Hasif Ahmed (hasif5@gmail.com, www.hasif.info)
 */

import { urlHostIsIgnored } from './ignore.js';
import { providerForKey } from './providers.js';

const DB_KEY = 'gaks_db';                 // legacy single-blob layout (migrated away)
export const REC_PREFIX = 'gaks_f:';      // current layout: one record per finding
const IGNORE_KEY = 'gaks_ignore_domains';
const BATCH = 200;                        // records per storage get/set during bulk work
// An unchanged re-sighting only refreshes lastSeen; skipping the write when the
// stored value is this recent keeps crawl/webRequest repeats from hammering
// storage (and from firing storage.onChanged in every open dashboard).
const LAST_SEEN_REFRESH_MS = 60000;
let writeChain = Promise.resolve();

const recKey = (key) => REC_PREFIX + key;

// A single key can be seen across thousands of pages/resources; left unbounded
// these lists grow the stored record until chrome.storage.local overflows its
// quota and every write starts failing. Cap them (keeping the most recent) so
// the DB stays small regardless of how much browsing it observes.
const MAX_ORIGINS = 50;
const MAX_PAGE_URLS = 50;
const MAX_SOURCES = 20;   // sources are a small tag set, but cap defensively

// Dedup-append `val` into `arr`, dropping the oldest entry once `max` is reached.
// Returns true when the array was modified.
function addCapped(arr, val, max) {
  if (val == null || val === '') return false;
  if (arr.indexOf(val) !== -1) return false;   // already present — no churn
  arr.push(val);
  if (arr.length > max) arr.shift();            // stay bounded; oldest falls off
  return true;
}

// Keep the first snippet seen for each source tag, so a key found on several
// surfaces (bundle, source map, network…) shows where it sits on each of them
// instead of only the first sighting.
const MAX_SNIPPET_CHARS = 600;
function addSnippet(rec, source, snippet) {
  if (!source || !snippet || typeof snippet !== 'string') return false;
  if (!rec.snippets || typeof rec.snippets !== 'object') rec.snippets = {};
  if (rec.snippets[source] || Object.keys(rec.snippets).length >= MAX_SOURCES) return false;
  rec.snippets[source] = snippet.length > MAX_SNIPPET_CHARS ? snippet.slice(0, MAX_SNIPPET_CHARS) + '…' : snippet;
  return true;
}

// Merge a stored/imported { source: snippet } map into `rec`.
function mergeSnippets(rec, snippets) {
  if (!snippets || typeof snippets !== 'object') return;
  for (const s of Object.keys(snippets)) addSnippet(rec, s, snippets[s]);
}

function nowIso() {
  return new Date().toISOString();
}

// A key is logged exactly once, regardless of how many origins/pages it
// appears on — the key string itself is the identity.
export function findingId(key) {
  return key;
}

// Every finding record currently in storage. get(null) is the one call that
// enumerates keys; it also returns the small non-finding entries, which are
// skipped here by prefix.
async function readAllRecords() {
  await ensureMigrated();
  const all = await chrome.storage.local.get(null);
  const out = [];
  for (const k of Object.keys(all)) {
    if (k.startsWith(REC_PREFIX) && all[k] && all[k].key) out.push(all[k]);
  }
  return out;
}

// Records now come back from storage as stored (the old read path re-normalized
// the whole DB), so guarantee the shape every caller relies on: arrays and maps
// exist even on a record written by an older build, hand-edited, or imported.
function shapeRecord(f) {
  if (!Array.isArray(f.origins)) f.origins = f.origin ? [f.origin] : [];
  if (!Array.isArray(f.pageUrls)) f.pageUrls = f.pageUrl ? [f.pageUrl] : [];
  if (!Array.isArray(f.sources)) f.sources = [];
  if (!Array.isArray(f.audits)) f.audits = [];
  if (!f.snippets || typeof f.snippets !== 'object') f.snippets = {};
  if (!f.id) f.id = f.key;
  return f;
}

// Self-heal classification: a key previously logged as 'unknown' (or with no
// provider) is re-checked against the current provider list, so keys that became
// first-class providers later (e.g. AWS) upgrade on reload. Never downgrades a
// key that already has a real provider. Also normalizes the record's shape.
// Returns true if the provider changed.
export function healRecord(f) {
  shapeRecord(f);
  if (f.provider && f.provider !== 'unknown') return false;
  const provider = providerForKey(f.key) || f.provider || 'google';
  if (provider === f.provider) return false;
  f.provider = provider;
  return true;
}

export async function getDb() {
  const findings = await readAllRecords();
  for (const f of findings) healRecord(f);
  // Storage enumerates keys in its own order; keep the stable logged order the
  // UI has always seen (earliest first).
  findings.sort((a, b) => (a.firstSeen < b.firstSeen ? -1 : a.firstSeen > b.firstSeen ? 1 : 0) ||
    (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return { findings };
}

// Write records in bounded batches so one huge set() never has to be built.
async function setRecords(byKey) {
  const keys = Object.keys(byKey);
  for (let i = 0; i < keys.length; i += BATCH) {
    const part = {};
    for (const k of keys.slice(i, i + BATCH)) part[k] = byKey[k];
    await chrome.storage.local.set(part);
  }
}

// Read specific records by finding key: Map(key -> record) for those that exist.
async function readRecords(keys) {
  const found = new Map();
  for (let i = 0; i < keys.length; i += BATCH) {
    const part = keys.slice(i, i + BATCH);
    const res = await chrome.storage.local.get(part.map(recKey));
    for (const k of part) {
      const v = res[recKey(k)];
      if (v && typeof v === 'object') { if (!v.key) v.key = k; found.set(k, shapeRecord(v)); }
    }
  }
  return found;
}

// One-time split of the legacy { findings: [...] } blob into per-key records.
// Idempotent and safe to interrupt: records that already exist are never
// overwritten, and the legacy blob is only removed after every batch is written.
let migrating = null;
let migrateRetryAt = 0;
const MIGRATE_RETRY_MS = 60000;
function ensureMigrated() {
  if (!migrating) {
    // After a failure (e.g. storage quota) don't redo the whole pass on every
    // single write; the legacy blob stays untouched and is retried after a pause.
    if (Date.now() < migrateRetryAt) return Promise.resolve();
    migrating = doMigrateLegacy().catch((e) => {
      migrating = null;
      migrateRetryAt = Date.now() + MIGRATE_RETRY_MS;
      console.error('[GAKS] legacy DB migration failed:', e);
    });
  }
  return migrating;
}

async function doMigrateLegacy() {
  const res = await chrome.storage.local.get(DB_KEY);
  const legacy = res[DB_KEY];
  if (!legacy || !Array.isArray(legacy.findings)) return;
  const recs = normalizeFindings(legacy.findings);
  const existing = await readRecords(recs.map((r) => r.key));
  const fresh = {};
  for (const r of recs) if (!existing.has(r.key)) fresh[recKey(r.key)] = r;
  await setRecords(fresh);
  await chrome.storage.local.remove(DB_KEY);
}

// Collapse records to one per key, upgrading the legacy single-origin shape
// (origin/pageUrl) to the current arrays and merging everything that shares a key.
// Used for the one-time legacy migration.
function normalizeFindings(findings) {
  const byKey = new Map();
  for (const f of findings) {
    if (!f || !f.key) continue;
    const origins = Array.isArray(f.origins) ? f.origins : (f.origin ? [f.origin] : []);
    const pageUrls = Array.isArray(f.pageUrls) ? f.pageUrls : (f.pageUrl ? [f.pageUrl] : []);
    let rec = byKey.get(f.key);
    if (!rec) {
      // Self-heal classification: a key previously logged as 'unknown' (or with
      // no provider) is re-checked against the current provider list, so keys
      // that became first-class providers later (e.g. AWS) upgrade on reload.
      // Never downgrade a key that already has a real provider.
      let provider = f.provider || 'google';
      if (!f.provider || f.provider === 'unknown') {
        provider = providerForKey(f.key) || f.provider || 'google';
      }
      rec = {
        id: f.key,
        key: f.key,
        provider,
        secret: f.secret || null,
        origins: [],
        pageUrls: [],
        sources: [],
        snippet: f.snippet || '',
        snippets: {},
        mapsContext: !!f.mapsContext,
        firstSeen: f.firstSeen || nowIso(),
        lastSeen: f.lastSeen || nowIso(),
        audits: []
      };
      byKey.set(f.key, rec);
    }
    mergeSnippets(rec, f.snippets);
    for (const o of origins) addCapped(rec.origins, o, MAX_ORIGINS);
    for (const p of pageUrls) addCapped(rec.pageUrls, p, MAX_PAGE_URLS);
    for (const s of (f.sources || [])) addCapped(rec.sources, s, MAX_SOURCES);
    if (Array.isArray(f.audits) && f.audits.length) rec.audits = rec.audits.concat(f.audits);
    if (f.mapsContext) rec.mapsContext = true;
    if (!rec.snippet && f.snippet) rec.snippet = f.snippet;
    // ISO strings sort lexicographically: keep the earliest first / latest last.
    if (f.firstSeen && f.firstSeen < rec.firstSeen) rec.firstSeen = f.firstSeen;
    if (f.lastSeen && f.lastSeen > rec.lastSeen) rec.lastSeen = f.lastSeen;
  }
  return Array.from(byKey.values());
}

/**
 * Run on service-worker startup: pick up any legacy single-blob database (a
 * fresh check on every call). Deliberately cheap when there is nothing to
 * migrate — one small read — because the worker restarts often and must not
 * walk the whole database each time. Provider back-fills for old records are
 * applied on read (getDb / getFinding), so they need no persisting pass.
 */
export function migrate() {
  return serialized(async () => {
    await migrating;      // let any pass already in flight finish first
    migrating = null;     // then look again for a legacy blob...
    migrateRetryAt = 0;   // ...even if an earlier attempt failed
    await ensureMigrated();
    return true;
  });
}

// Serialize a storage task behind earlier ones. Pass propagate=true to have a
// failure (e.g. storage quota exceeded) reject the returned promise instead of
// being swallowed — used where the caller needs to report the error (the audit
// path) rather than fire-and-forget.
function serialized(task, propagate) {
  const run = writeChain.then(task);
  // The chain itself must never settle rejected, or the next queued write would
  // inherit the rejection and skip its task. Keep a swallowed copy for it.
  writeChain = run.catch(() => {});
  return run.catch((e) => {
    console.error('[GAKS] store write failed:', e);
    if (propagate) throw e;
  });
}

// Read-modify-write ONE record. `mutator(rec|null)` returns { rec, result }:
// rec = object to store, null to delete the record, undefined to leave storage
// untouched (nothing changed).
function withRecord(id, mutator, propagate) {
  return serialized(async () => {
    await ensureMigrated();
    const rk = recKey(id);
    const res = await chrome.storage.local.get(rk);
    // A stored value that isn't a usable record is treated as absent (an upsert
    // then overwrites it with a fresh one); a usable one gets its shape guaranteed.
    let cur = res[rk];
    if (!cur || typeof cur !== 'object' || !cur.key) cur = null; else shapeRecord(cur);
    const out = mutator(cur);
    if (out.rec === null) await chrome.storage.local.remove(rk);
    else if (out.rec !== undefined) await chrome.storage.local.set({ [rk]: out.rec });
    return out.result;
  }, propagate);
}

/**
 * Insert or update a finding. `entry` = { key, origin, pageUrl, source,
 * snippet, mapsContext }. A given key is only ever stored once; subsequent
 * sightings merge their origin/source/timestamp into the existing record
 * instead of creating a duplicate. Returns the resulting finding record.
 */
export function upsertFinding(entry) {
  const id = findingId(entry.key);
  return withRecord(id, (existing) => {
    let rec = existing;
    let changed = false;
    const ts = nowIso();
    if (!rec) {
      changed = true;
      rec = {
        id,
        key: entry.key,
        provider: entry.provider || providerForKey(entry.key) || 'google',
        secret: entry.secret || null,
        origins: [],
        pageUrls: [],
        sources: [],
        snippet: entry.snippet || '',
        snippets: {},
        mapsContext: !!entry.mapsContext,
        firstSeen: ts,
        lastSeen: ts,
        audits: []
      };
    }
    if (addSnippet(rec, entry.source, entry.snippet)) changed = true;
    if (!rec.provider) { rec.provider = entry.provider || providerForKey(entry.key) || 'google'; changed = true; }
    if (!rec.secret && entry.secret) { rec.secret = entry.secret; changed = true; }
    if (addCapped(rec.origins, entry.origin, MAX_ORIGINS)) changed = true;
    if (addCapped(rec.pageUrls, entry.pageUrl, MAX_PAGE_URLS)) changed = true;
    if (entry.snippet && !rec.snippet) { rec.snippet = entry.snippet; changed = true; }
    if (entry.mapsContext && !rec.mapsContext) { rec.mapsContext = true; changed = true; }
    if (addCapped(rec.sources, entry.source, MAX_SOURCES)) changed = true;
    // Nothing new about this key and lastSeen is already fresh: skip the write.
    if (!changed && (Date.parse(ts) - Date.parse(rec.lastSeen)) < LAST_SEEN_REFRESH_MS) {
      return { rec: undefined, result: rec };
    }
    rec.lastSeen = ts;
    return { rec, result: rec };
  });
}

/** Append an audit result to a finding identified by its id. */
export function addAudit(id, audit) {
  return withRecord(id, (rec) => {
    if (!rec) return { rec: undefined, result: null };
    audit.ts = audit.ts || nowIso();
    if (!Array.isArray(rec.audits)) rec.audits = [];
    rec.audits.push(audit);
    return { rec, result: rec };
  });
}

/** Replace all audits for a finding (used when re-running a full audit pass). */
export function setAudits(id, audits) {
  return withRecord(id, (rec) => {
    if (!rec) return { rec: undefined, result: null };
    rec.audits = audits;
    return { rec, result: rec };
  }, true); // surface write failures (e.g. quota) so the audit UI can report them
}

export async function getFinding(id) {
  await ensureMigrated();
  const rk = recKey(id);
  const res = await chrome.storage.local.get(rk);
  const f = res[rk];
  if (!f || !f.key) return null;
  healRecord(f);
  return f;
}

// Several findings by key in one targeted read (the popup's tab keys), without
// enumerating the whole store. Keys with no record are simply absent.
export async function getFindings(ids) {
  await ensureMigrated();
  const found = await readRecords(Array.from(new Set(ids)));
  const out = [];
  for (const f of found.values()) { healRecord(f); out.push(f); }
  return out;
}

export function deleteFinding(id) {
  return withRecord(id, () => ({ rec: null, result: true }));
}

export function clearAll() {
  return serialized(async () => {
    await ensureMigrated();
    const all = await chrome.storage.local.get(null);
    const doomed = Object.keys(all).filter((k) => k.startsWith(REC_PREFIX));
    for (let i = 0; i < doomed.length; i += BATCH) {
      await chrome.storage.local.remove(doomed.slice(i, i + BATCH));
    }
    await chrome.storage.local.remove(DB_KEY); // any legacy blob that could not migrate
    return true;
  });
}

/** Merge an imported DB (from JSON) into the current one, deduped by key. */
export function importDb(incoming) {
  return serialized(async () => {
    await ensureMigrated();
    if (!incoming || !Array.isArray(incoming.findings)) return { merged: 0 };
    // Only the records an import touches are read back and rewritten.
    const incKeys = Array.from(new Set(incoming.findings.filter((i) => i && i.key).map((i) => i.key)));
    const byKey = await readRecords(incKeys);
    const touched = new Set();
    let merged = 0;
    for (const inc of incoming.findings) {
      if (!inc || !inc.key) continue;
      const existing = byKey.get(inc.key);
      const incOrigins = importedOrigins(inc);
      const incPages = importedPages(inc);
      touched.add(inc.key);
      if (!existing) {
        byKey.set(inc.key, normalizeImported(inc, incOrigins, incPages));
        merged++;
      } else {
        // Same key already known — union everything onto the one record.
        // Same caps as a live sighting, so a large import can't grow a record unbounded.
        for (const o of incOrigins) addCapped(existing.origins, o, MAX_ORIGINS);
        for (const p of incPages) addCapped(existing.pageUrls, p, MAX_PAGE_URLS);
        for (const s of inc.sources || []) addCapped(existing.sources, s, MAX_SOURCES);
        if (!existing.secret && typeof inc.secret === 'string' && inc.secret) existing.secret = inc.secret;
        existing.audits = (existing.audits || []).concat(inc.audits || []);
        if (inc.mapsContext) existing.mapsContext = true;
        mergeSnippets(existing, inc.snippets);
        merged++;
      }
    }
    const out = {};
    for (const k of touched) out[recKey(k)] = byKey.get(k);
    await setRecords(out);
    return { merged };
  });
}

// Accept both the current shape (origins[]) and the legacy single-origin shape.
function importedOrigins(inc) {
  if (Array.isArray(inc.origins)) return inc.origins.slice();
  return inc.origin ? [inc.origin] : [];
}
function importedPages(inc) {
  if (Array.isArray(inc.pageUrls)) return inc.pageUrls.slice();
  return inc.pageUrl ? [inc.pageUrl] : [];
}

function normalizeImported(inc, origins, pages) {
  return {
    id: inc.key,
    key: inc.key,
    // Carry the provider and pair secret through: without them an imported
    // heuristic ('unknown') finding is re-labelled 'google' on read, and a
    // Twilio/AWS finding can no longer be audited.
    provider: typeof inc.provider === 'string' && inc.provider ? inc.provider : (providerForKey(inc.key) || 'google'),
    secret: typeof inc.secret === 'string' && inc.secret ? inc.secret : null,
    origins: origins.slice(-MAX_ORIGINS),
    pageUrls: pages.slice(-MAX_PAGE_URLS),
    sources: Array.isArray(inc.sources) ? inc.sources.slice() : [],
    snippet: inc.snippet || '',
    snippets: (inc.snippets && typeof inc.snippets === 'object') ? inc.snippets : {},
    mapsContext: !!inc.mapsContext,
    firstSeen: inc.firstSeen || nowIso(),
    lastSeen: inc.lastSeen || nowIso(),
    audits: Array.isArray(inc.audits) ? inc.audits.slice() : []
  };
}

// =========================================================================
// Ignored domains — user-added extras (combined with the built-in defaults).
// =========================================================================

export async function getIgnoreDomains() {
  const res = await chrome.storage.local.get(IGNORE_KEY);
  return Array.isArray(res[IGNORE_KEY]) ? res[IGNORE_KEY] : [];
}

export async function setIgnoreDomains(list) {
  const clean = (Array.isArray(list) ? list : []).map((s) =>
    String(s).trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '')
      .replace(/^\*?\.*/, '')
  ).filter(Boolean);
  const unique = Array.from(new Set(clean));
  await chrome.storage.local.set({ [IGNORE_KEY]: unique });
  return unique;
}

/**
 * Remove findings that belong to ignored domains. A finding's ignored origins
 * are stripped; if none remain, the whole finding is dropped. Keys also seen on
 * a non-ignored site are kept (with only the non-ignored origins). `extra` is
 * the user-added ignore list; the built-in defaults always apply.
 */
export function purgeIgnored(extra) {
  return serialized(async () => {
    const recs = await readAllRecords();
    let removed = 0;
    const doomed = [];
    const changed = {};
    for (const f of recs) {
      const origins = f.origins || [];
      const pageUrls = f.pageUrls || [];
      const keptOrigins = origins.filter((o) => !urlHostIsIgnored(o, extra));
      const keptPages = pageUrls.filter((p) => !urlHostIsIgnored(p, extra));
      if (origins.length > 0 && keptOrigins.length === 0) { removed++; doomed.push(recKey(f.key)); continue; }
      // Runs on every worker start and ignore-list edit: write only what changed.
      if (keptOrigins.length !== origins.length || keptPages.length !== pageUrls.length) {
        f.origins = keptOrigins;
        f.pageUrls = keptPages;
        changed[recKey(f.key)] = f;
      }
    }
    await setRecords(changed);
    for (let i = 0; i < doomed.length; i += BATCH) {
      await chrome.storage.local.remove(doomed.slice(i, i + BATCH));
    }
    return { removed };
  });
}

// =========================================================================
// Personal collection — a user-curated, persistent set of saved keys that is
// independent of the auto-detected findings DB (survives "Clear all").
// Stored under COLLECTION_KEY as { items: [ { key, note, savedAt, updatedAt,
// origins, pageUrls, sources, mapsContext, snippet, audits } ] }.
// =========================================================================

const COLLECTION_KEY = 'gaks_collection';

function normalizeCollection(c) {
  return c && Array.isArray(c.items) ? c : { items: [] };
}

export async function getCollection() {
  const res = await chrome.storage.local.get(COLLECTION_KEY);
  return normalizeCollection(res[COLLECTION_KEY]);
}

// Serialized read-modify-write on the collection (shares the global chain).
function withCollection(mutator) {
  writeChain = writeChain.then(async () => {
    const res = await chrome.storage.local.get(COLLECTION_KEY);
    const c = normalizeCollection(res[COLLECTION_KEY]);
    const result = await mutator(c);
    await chrome.storage.local.set({ [COLLECTION_KEY]: c });
    return result;
  }).catch((e) => {
    console.error('[GAKS] collection write failed:', e);
  });
  return writeChain;
}

function unionInto(target, source) {
  for (const v of source || []) if (target.indexOf(v) === -1) target.push(v);
  return target;
}

/** Add a key to the collection (or refresh its snapshot if already saved). */
export function saveToCollection(entry) {
  return withCollection((c) => {
    const ts = nowIso();
    let item = c.items.find((i) => i.key === entry.key);
    if (!item) {
      item = {
        key: entry.key,
        provider: entry.provider || providerForKey(entry.key) || 'google',
        secret: entry.secret || null,
        note: entry.note || '',
        savedAt: ts,
        updatedAt: ts,
        origins: Array.isArray(entry.origins) ? entry.origins.slice() : [],
        pageUrls: Array.isArray(entry.pageUrls) ? entry.pageUrls.slice() : [],
        sources: Array.isArray(entry.sources) ? entry.sources.slice() : [],
        mapsContext: !!entry.mapsContext,
        snippet: entry.snippet || '',
        audits: Array.isArray(entry.audits) ? entry.audits.slice() : []
      };
      c.items.push(item);
    } else {
      item.updatedAt = ts;
      unionInto(item.origins, entry.origins);
      unionInto(item.pageUrls, entry.pageUrls);
      unionInto(item.sources, entry.sources);
      if (entry.mapsContext) item.mapsContext = true;
      if (!item.snippet && entry.snippet) item.snippet = entry.snippet;
      if (Array.isArray(entry.audits) && entry.audits.length) item.audits = entry.audits.slice();
    }
    return item;
  });
}

export function removeFromCollection(key) {
  return withCollection((c) => {
    c.items = c.items.filter((i) => i.key !== key);
    return true;
  });
}

export function setCollectionNote(key, note) {
  return withCollection((c) => {
    const item = c.items.find((i) => i.key === key);
    if (!item) return null;
    item.note = note || '';
    item.updatedAt = nowIso();
    return item;
  });
}

export function setCollectionAudits(key, audits) {
  return withCollection((c) => {
    const item = c.items.find((i) => i.key === key);
    if (!item) return null;
    item.audits = Array.isArray(audits) ? audits : [];
    item.updatedAt = nowIso();
    return item;
  });
}

export function clearCollection() {
  return withCollection((c) => {
    c.items = [];
    return true;
  });
}

/** Merge an imported collection (from JSON), deduped by key. */
export function importCollection(incoming) {
  return withCollection((c) => {
    if (!incoming || !Array.isArray(incoming.items)) return { merged: 0 };
    const byKey = new Map(c.items.map((i) => [i.key, i]));
    let merged = 0;
    for (const inc of incoming.items) {
      if (!inc || !inc.key) continue;
      const existing = byKey.get(inc.key);
      if (!existing) {
        byKey.set(inc.key, {
          key: inc.key,
          note: inc.note || '',
          savedAt: inc.savedAt || nowIso(),
          updatedAt: inc.updatedAt || nowIso(),
          origins: Array.isArray(inc.origins) ? inc.origins.slice() : [],
          pageUrls: Array.isArray(inc.pageUrls) ? inc.pageUrls.slice() : [],
          sources: Array.isArray(inc.sources) ? inc.sources.slice() : [],
          mapsContext: !!inc.mapsContext,
          snippet: inc.snippet || '',
          audits: Array.isArray(inc.audits) ? inc.audits.slice() : []
        });
        merged++;
      } else {
        unionInto(existing.origins, inc.origins);
        unionInto(existing.pageUrls, inc.pageUrls);
        unionInto(existing.sources, inc.sources);
        if (inc.note && !existing.note) existing.note = inc.note;
        if (Array.isArray(inc.audits) && inc.audits.length) existing.audits = inc.audits.slice();
        merged++;
      }
    }
    c.items = Array.from(byKey.values());
    return { merged };
  });
}
