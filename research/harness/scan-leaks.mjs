/*
 * scan-leaks.mjs - confirm nothing credential-shaped is committed under research/.
 *
 * Author: Hasif Ahmed <hasif5@gmail.com> (www.hasif.info)
 *
 * Runs the extension's own detector (lib/providers.js detectKeys) over every
 * text file in research/ (docs, fixtures, harness, evidence). Any hit means a
 * full credential-shaped string was written to disk. Exit code 1 on any hit.
 *
 * Usage: node research/harness/scan-leaks.mjs
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve, extname, relative } from 'node:path';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { detectKeys } = await import(pathToFileURL(join(ROOT, 'lib/providers.js')).href);

const TEXT_EXT = new Set(['.md', '.mjs', '.js', '.json', '.log', '.txt', '.html', '.ps1', '.sh']);
function walk(dir, out) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) { if (name !== 'node_modules') walk(p, out); } else if (TEXT_EXT.has(extname(name))) out.push(p);
  }
  return out;
}

const { BARE_SHAPES } = await import(pathToFileURL(join(ROOT, 'research/harness/scrub.mjs')).href);

const files = walk(join(ROOT, 'research'), []);
let hits = 0;
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  // The bare-shape definitions live in scrub.mjs itself as regex source, not as literals, so it does not self-match.
  for (const s of BARE_SHAPES) {
    for (const m of text.matchAll(s.re)) {
      hits++;
      console.log('LEAK ' + relative(ROOT, f) + ' -> ' + s.name + ' ' + m[0].slice(0, 6) + '... (' + m[0].length + ' chars)');
    }
  }
  const found = detectKeys(text);
  for (const h of found) {
    hits++;
    console.log('LEAK ' + relative(ROOT, f) + ' -> ' + h.provider + ' ' + h.key.slice(0, 6) + '... (' + h.key.length + ' chars)');
  }
}
console.log('scanned ' + files.length + ' text files under research/: ' + hits + ' credential-shaped strings found');
process.exit(hits ? 1 : 0);
