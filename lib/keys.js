/*
 * keys.js — shared key-detection helpers for the module world
 * (service worker, popup, dashboard). The content-script world uses its own
 * copy in content/patterns.js because content scripts can't import modules.
 */

// Google keys in two formats: legacy "AIza"+35 chars, and newer "AQ."+40+
// base64url chars (e.g. AQ.Ab8RN6J…).
export const KEY_RE = /(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})/g;
export const SINGLE_KEY_RE = /^(?:AIza[0-9A-Za-z_-]{35}|AQ\.[A-Za-z0-9_-]{40,})$/;

const MAPS_HINTS = [
  'maps.googleapis.com', 'maps.google.com', 'maps.gstatic.com',
  'routes.googleapis.com', 'places.googleapis.com', 'roads.googleapis.com',
  '/maps/api/', 'staticmap', '/maps/embed', 'google.maps', 'gmaps'
];

export function isMapsContext(text) {
  if (!text) return false;
  const lower = String(text).toLowerCase();
  return MAPS_HINTS.some((h) => lower.indexOf(h) !== -1);
}

export function snippetAround(text, index, keyLen, radius) {
  radius = radius || 60;
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + keyLen + radius);
  const slice = text.slice(start, end).replace(/\s+/g, ' ').trim();
  return (start > 0 ? '…' : '') + slice + (end < text.length ? '…' : '');
}

// Returns [{ key, snippet, mapsContext }] for every distinct key in `text`.
export function findKeysInText(text) {
  const out = [];
  if (!text) return out;
  const seen = Object.create(null);
  KEY_RE.lastIndex = 0;
  let m;
  while ((m = KEY_RE.exec(text)) !== null) {
    const key = m[0];
    const snippet = snippetAround(text, m.index, key.length);
    if (seen[key]) {
      if (!seen[key].mapsContext && isMapsContext(snippet)) {
        seen[key].mapsContext = true;
        seen[key].snippet = snippet;
      }
      continue;
    }
    const rec = { key, snippet, mapsContext: isMapsContext(snippet) };
    seen[key] = rec;
    out.push(rec);
  }
  return out;
}
