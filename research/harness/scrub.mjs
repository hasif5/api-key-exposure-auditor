/*
 * scrub.mjs - redact credential-shaped substrings before anything is written
 * into research/evidence.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * The extension's own detector (lib/providers.js detectKeys) decides what is
 * credential-shaped, so evidence cannot contain anything the extension itself
 * would flag. Snippets are the main risk: a snippet for one key often contains
 * the full text of a neighbouring key.
 */

import { redact } from '../fixtures/synthetic.mjs';

// Shapes that external secret scanners (for example GitHub push protection) flag on
// their own, but that the extension's detector deliberately ignores without context.
// The S12 "Twilio-shaped SID without Twilio context" negative is one: it is served on
// purpose, and appears as neighbouring text inside evidence snippets. GitHub rejected a
// push for exactly this, so it is redacted here and checked in scan-leaks.mjs.
export const BARE_SHAPES = [
  { name: 'twilio-sid', re: /(?<![A-Za-z0-9])AC[0-9a-fA-F]{32}(?![A-Za-z0-9])/g },
];

export function scrubText(str, detectKeys) {
  let out = str;
  for (const s of BARE_SHAPES) out = out.replace(s.re, (m) => '<' + redact(m) + '>');
  // Two passes: redacting one key can expose another that was previously part of a longer match.
  for (let pass = 0; pass < 2; pass++) {
    for (const h of detectKeys(out)) {
      out = out.split(h.key).join('<' + redact(h.key) + '>');
      if (h.secret) out = out.split(h.secret).join('<' + redact(h.secret) + '>');
    }
  }
  return out;
}

export function scrubDeep(value, detectKeys) {
  if (typeof value === 'string') return scrubText(value, detectKeys);
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v, detectKeys));
  if (value && typeof value === 'object') {
    const o = {};
    for (const [k, v] of Object.entries(value)) o[k] = scrubDeep(v, detectKeys);
    return o;
  }
  return value;
}
