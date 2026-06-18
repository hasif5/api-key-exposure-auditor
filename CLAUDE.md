# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A vanilla Manifest V3 Chrome/Edge extension (**API Key Exposure Auditor**) that
passively detects exposed API keys on visited pages and, on demand, actively
audits each key's access/billing/restriction posture. **No build step, no
bundler, no runtime npm dependencies** — the repo folder *is* the extension.
Built for self-project security — helping developers find and fix their own
leaked keys. The active audit makes live requests to provider APIs.

## Commands

```bash
# Run the full logic regression suite (detection / providers / store / ignore / parity).
# NOTE: test/ is intentionally git-ignored and NOT in the repo or CI — its synthetic
# key fixtures trip secret scanners. Keep it local-only; run it before committing.
node test/detection.test.mjs

# Syntax-check before committing (mirrors the CI release workflow)
node --check content/patterns.js content/content.js          # plain content scripts
node --input-type=module --check < lib/audit.js              # ES modules (lib/*, background.js, popup/dashboard/collection .js)

# Build the store-ready upload zip (runtime files only)
./build.sh         # macOS/Linux
.\build.ps1        # Windows (produces forward-slash zip entries the Web Store accepts)
```

There is no test runner/framework — `test/detection.test.mjs` is a self-contained
Node script that mocks `chrome.storage` and imports the `lib/` modules directly.
It has no single-test filter; edit/comment sections to narrow. Add cases here when
you change detection or provider logic, and run it locally — it is git-ignored
(not committed, not run in CI), so it can't gate releases automatically.

To run the extension: load the repo folder unpacked via `chrome://extensions` →
Developer mode → **Load unpacked**. Reload from that page to pick up changes. Use
the dashboard's **Clear all** to reset stored findings while testing.

## Architecture

Two JavaScript worlds that **cannot share imports** — content scripts can't use ES
modules, so detection logic is deliberately duplicated and **must be kept in sync**:

- **Content world** (`content/patterns.js` → exposes `var GAKS`, then `content/content.js`):
  scans the rendered page (DOM, open shadow roots, web storage, resource-timing),
  forwards linked-asset URLs to the worker, and posts findings. Detection regexes
  live in `patterns.js`.
- **Module world** (`background.js` + `lib/*.js`, popup, dashboard, collection):
  ES modules. Detection regexes live in `lib/providers.js` and `lib/keys.js`.

> If you touch a detection regex or the provider list, change it in **both**
> `content/patterns.js` and `lib/providers.js`. The test suite has a parity check,
> but the duplication is intentional and easy to miss.

### Data flow

```
content.js  ──GAKS_FINDINGS / GAKS_SCRIPTS──▶  background.js (service worker)
                                                  │
  webRequest listeners sniff key= params,         ├─ fetch & scan linked assets,
  X-Goog-Api-Key, Authorization/x-api-key  ───────┤   source maps, recursive
                                                  │   same-origin asset graph,
                                                  │   common config paths
                                                  ▼
                                          lib/store.js  (chrome.storage.local)
                                                  ▲
       popup/ (current tab) · dashboard/ (all keys, audit, export) · collection/ (saved keys)
```

### Key modules

- **`background.js`** — the orchestrator. Owns: webRequest sniffing, the bounded
  recursive asset-crawl queue (`MAX_DEPTH = 3`, `SCRIPT_CONCURRENCY = 4`,
  `MAX_SCRIPT_BYTES = 4 MB`), source-map following (`scanSourceMap` /
  `followReferences`), common-config-path probing, per-tab badge counts, and the
  `chrome.runtime.onMessage` router (`GAKS_FINDINGS`, `GAKS_SCRIPTS`, `GAKS_AUDIT`,
  `GAKS_AUDIT_RAW`, `GAKS_GET_TAB_KEYS`, `GAKS_GET_DB`).
- **`lib/providers.js`** — provider registry: each provider declares its detection
  regex, how a key is audited, and how risk is assessed. Bearer-token providers
  (OpenAI, Anthropic, OpenRouter, xAI) have no IP/referrer restriction mechanism,
  so any **valid** key is unconditionally `critical`. Twilio needs an `AC…` SID +
  a nearby 32-hex Auth Token pair. Google delegates to `audit.js`.
- **`lib/audit.js`** — Google-specific probes (Maps/Places/Cloud/AI endpoints) and
  risk assessment, plus shared fetch helpers (`doFetch`, `runPool`, retry/backoff).
- **`lib/store.js`** — normalized, deduped findings DB. **Identity is the key string
  itself** (`findingId(key) === key`): a key is logged once and enriched with every
  origin/page/source it's seen on. `normalizeFindings` collapses duplicates and
  upgrades legacy record shapes on read. Writes are serialized through a promise
  chain so concurrent webRequest + content-script updates don't clobber each other.
- **`lib/ignore.js`** — domain ignore-list (Google/YouTube/Facebook/etc. by default,
  user-extendable). `content/patterns.js` mirrors this list for the content world.
- **`lib/keys.js`** — shared detection helpers for the module world (mirror of the
  helper subset in `content/patterns.js`).

### Detection regex conventions

Patterns use lookbehind/lookahead boundary guards (`(?<![A-Za-z0-9_-])…(?![…])`)
so a key must be a complete token, not a substring of a longer blob. **Order
matters**: Anthropic (`sk-ant-`) is tested before OpenAI's generic `sk-`. When
adding/loosening a pattern, add regression cases (including false-positive
guards) to `test/detection.test.mjs` — past regressions here broke detection
(see git history: Twilio false-positive flood).

## Conventions

- Vanilla JS only — no frameworks, bundlers, or runtime npm deps. Match
  surrounding style (naming, comment density).
- Keep everything on-device: no telemetry/analytics, and no network calls beyond
  the page's own linked assets and the user-triggered audit.
- `manifest.json` `description` must stay ≤ 132 chars (CI enforces this on release).
- Releases: bump `manifest.json` `version`, then `git tag vX.Y.Z && git push origin vX.Y.Z`
  — the release workflow builds and attaches the zips.
