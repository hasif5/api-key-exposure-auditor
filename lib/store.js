/*
 * store.js — normalized findings database on top of chrome.storage.local.
 *
 * A single record under DB_KEY:
 *   { findings: [ {
 *       id, key, origin, pageUrl, sources:[], snippet, mapsContext,
 *       firstSeen, lastSeen, audits:[ { service, endpoint, httpStatus,
 *                                       apiStatus, classification, detail, ts } ]
 *   } ] }
 *
 * Writes are serialized through a promise chain so concurrent updates from the
 * webRequest listener and content-script messages don't clobber each other.
 */

import { urlHostIsIgnored } from './ignore.js';
import { providerForKey } from './providers.js';

const DB_KEY = 'gaks_db';
const IGNORE_KEY = 'gaks_ignore_domains';
let writeChain = Promise.resolve();

function nowIso() {
  return new Date().toISOString();
}

// A key is logged exactly once, regardless of how many origins/pages it
// appears on — the key string itself is the identity.
export function findingId(key) {
  return key;
}

export async function getDb() {
  const res = await chrome.storage.local.get(DB_KEY);
  const db = res[DB_KEY];
  if (db && Array.isArray(db.findings)) {
    // Always hand back normalized + deduped data, so any duplicates left over
    // from the old key+origin scheme collapse on read.
    return { findings: normalizeFindings(db.findings) };
  }
  return { findings: [] };
}

// Collapse records to one per key, upgrading the legacy single-origin shape
// (origin/pageUrl) to the current arrays and merging everything that shares a key.
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
        mapsContext: !!f.mapsContext,
        firstSeen: f.firstSeen || nowIso(),
        lastSeen: f.lastSeen || nowIso(),
        audits: []
      };
      byKey.set(f.key, rec);
    }
    for (const o of origins) if (rec.origins.indexOf(o) === -1) rec.origins.push(o);
    for (const p of pageUrls) if (rec.pageUrls.indexOf(p) === -1) rec.pageUrls.push(p);
    for (const s of (f.sources || [])) if (rec.sources.indexOf(s) === -1) rec.sources.push(s);
    if (Array.isArray(f.audits) && f.audits.length) rec.audits = rec.audits.concat(f.audits);
    if (f.mapsContext) rec.mapsContext = true;
    if (!rec.snippet && f.snippet) rec.snippet = f.snippet;
    // ISO strings sort lexicographically: keep the earliest first / latest last.
    if (f.firstSeen && f.firstSeen < rec.firstSeen) rec.firstSeen = f.firstSeen;
    if (f.lastSeen && f.lastSeen > rec.lastSeen) rec.lastSeen = f.lastSeen;
  }
  return Array.from(byKey.values());
}

/** Persist the normalized/deduped form once (e.g. on service-worker startup). */
export function migrate() {
  return withDb((db) => {
    db.findings = normalizeFindings(db.findings);
    return db.findings.length;
  });
}

async function setDb(db) {
  await chrome.storage.local.set({ [DB_KEY]: db });
}

// Serialize a read-modify-write against the DB.
function withDb(mutator) {
  writeChain = writeChain.then(async () => {
    const db = await getDb();
    const result = await mutator(db);
    await setDb(db);
    return result;
  }).catch((e) => {
    console.error('[GAKS] store write failed:', e);
  });
  return writeChain;
}

/**
 * Insert or update a finding. `entry` = { key, origin, pageUrl, source,
 * snippet, mapsContext }. A given key is only ever stored once; subsequent
 * sightings merge their origin/source/timestamp into the existing record
 * instead of creating a duplicate. Returns the resulting finding record.
 */
export function upsertFinding(entry) {
  return withDb((db) => {
    const id = findingId(entry.key);
    let rec = db.findings.find((f) => f.id === id);
    const ts = nowIso();
    if (!rec) {
      rec = {
        id,
        key: entry.key,
        provider: entry.provider || providerForKey(entry.key) || 'google',
        secret: entry.secret || null,
        origins: [],
        pageUrls: [],
        sources: [],
        snippet: entry.snippet || '',
        mapsContext: !!entry.mapsContext,
        firstSeen: ts,
        lastSeen: ts,
        audits: []
      };
      db.findings.push(rec);
    }
    if (!rec.provider) rec.provider = entry.provider || providerForKey(entry.key) || 'google';
    if (!rec.secret && entry.secret) rec.secret = entry.secret;
    rec.lastSeen = ts;
    if (entry.origin && rec.origins.indexOf(entry.origin) === -1) rec.origins.push(entry.origin);
    if (entry.pageUrl && rec.pageUrls.indexOf(entry.pageUrl) === -1) rec.pageUrls.push(entry.pageUrl);
    if (entry.snippet && !rec.snippet) rec.snippet = entry.snippet;
    if (entry.mapsContext) rec.mapsContext = true;
    if (entry.source && rec.sources.indexOf(entry.source) === -1) rec.sources.push(entry.source);
    return rec;
  });
}

/** Append an audit result to a finding identified by its id. */
export function addAudit(id, audit) {
  return withDb((db) => {
    const rec = db.findings.find((f) => f.id === id);
    if (!rec) return null;
    audit.ts = audit.ts || nowIso();
    rec.audits.push(audit);
    return rec;
  });
}

/** Replace all audits for a finding (used when re-running a full audit pass). */
export function setAudits(id, audits) {
  return withDb((db) => {
    const rec = db.findings.find((f) => f.id === id);
    if (!rec) return null;
    rec.audits = audits;
    return rec;
  });
}

export function getFinding(id) {
  return getDb().then((db) => db.findings.find((f) => f.id === id) || null);
}

export function deleteFinding(id) {
  return withDb((db) => {
    db.findings = db.findings.filter((f) => f.id !== id);
    return true;
  });
}

export function clearAll() {
  return withDb((db) => {
    db.findings = [];
    return true;
  });
}

/** Merge an imported DB (from JSON) into the current one, deduped by key. */
export function importDb(incoming) {
  return withDb((db) => {
    if (!incoming || !Array.isArray(incoming.findings)) return { merged: 0 };
    const byKey = new Map(db.findings.map((f) => [f.key, f]));
    let merged = 0;
    for (const inc of incoming.findings) {
      if (!inc || !inc.key) continue;
      const existing = byKey.get(inc.key);
      const incOrigins = importedOrigins(inc);
      const incPages = importedPages(inc);
      if (!existing) {
        byKey.set(inc.key, normalizeImported(inc, incOrigins, incPages));
        merged++;
      } else {
        // Same key already known — union everything onto the one record.
        for (const o of incOrigins) if (existing.origins.indexOf(o) === -1) existing.origins.push(o);
        for (const p of incPages) if (existing.pageUrls.indexOf(p) === -1) existing.pageUrls.push(p);
        for (const s of inc.sources || []) if (existing.sources.indexOf(s) === -1) existing.sources.push(s);
        existing.audits = (existing.audits || []).concat(inc.audits || []);
        if (inc.mapsContext) existing.mapsContext = true;
        merged++;
      }
    }
    db.findings = Array.from(byKey.values());
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
    origins,
    pageUrls: pages,
    sources: Array.isArray(inc.sources) ? inc.sources.slice() : [],
    snippet: inc.snippet || '',
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
  return withDb((db) => {
    let removed = 0;
    const kept = [];
    for (const f of db.findings) {
      const hadOrigins = (f.origins || []).length > 0;
      f.origins = (f.origins || []).filter((o) => !urlHostIsIgnored(o, extra));
      f.pageUrls = (f.pageUrls || []).filter((p) => !urlHostIsIgnored(p, extra));
      if (hadOrigins && f.origins.length === 0) { removed++; continue; }
      kept.push(f);
    }
    db.findings = kept;
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
