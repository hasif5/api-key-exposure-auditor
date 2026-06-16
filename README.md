# API Key Exposure Auditor

[![CI](https://github.com/hasif5/api-key-exposure-auditor/actions/workflows/release.yml/badge.svg)](https://github.com/hasif5/api-key-exposure-auditor/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/hasif5/api-key-exposure-auditor?color=blue)](https://github.com/hasif5/api-key-exposure-auditor/releases/latest)
[![License: MIT](https://img.shields.io/github/license/hasif5/api-key-exposure-auditor)](./LICENSE)
[![Chrome MV3](https://img.shields.io/badge/Chrome-Manifest_V3-4285F4?logo=googlechrome&logoColor=white)]()
[![Stars](https://img.shields.io/github/stars/hasif5/api-key-exposure-auditor?style=social)](https://github.com/hasif5/api-key-exposure-auditor/stargazers)

**Browser extension that helps you find API keys accidentally exposed in your own web projects -- before someone else does.**

Point it at your own site, app, or localhost and it passively detects leaked credentials across the DOM, JavaScript bundles, source maps, network traffic, and more. Then audit each key in one click to see what it can reach and whether it's properly restricted.

Supports **Google** (`AIza...` / `AQ....`), **OpenAI** (`sk-...`), **Anthropic** (`sk-ant-...`), **OpenRouter** (`sk-or-...`), **xAI** (`xai-...`), and **Twilio** (`AC...` + Auth Token). All data stays local, no backend, no telemetry.

> If this tool helps you secure your projects, consider giving it a star -- it helps others find it.

<!-- Replace with actual screenshots:
     1. Take a popup screenshot showing detected keys
     2. Take a dashboard screenshot showing audit results
     3. Save to docs/screenshots/ and uncomment below

<p align="center">
  <img src="docs/screenshots/popup.png" alt="Popup showing detected keys" width="340" />
  &nbsp;&nbsp;
  <img src="docs/screenshots/dashboard.png" alt="Dashboard with audit results" width="560" />
</p>
-->

---

## Quick Start

No build step required -- three steps and you're running:

```bash
# Option A: one-command install (downloads + unpacks)
# Windows PowerShell:
iwr -useb https://raw.githubusercontent.com/hasif5/api-key-exposure-auditor/main/install.ps1 | iex
# macOS / Linux:
curl -fsSL https://raw.githubusercontent.com/hasif5/api-key-exposure-auditor/main/install.sh | bash

# Option B: clone it
git clone https://github.com/hasif5/api-key-exposure-auditor.git
```

Then load it once:

1. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge)
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select the extension folder

The toolbar badge shows the number of distinct keys found on the active tab. Click to see details and run audits.

> Or grab the latest `.zip` from [Releases](https://github.com/hasif5/api-key-exposure-auditor/releases/latest) and unzip it.

---

## What It Detects

| Provider | Key format | Audit |
|---|---|---|
| **Google** | `AIza...` (legacy) / `AQ....` (newer) | Maps, Places, Routes, Gemini, Vertex AI, Cloud AI/ML, Firebase, YouTube |
| **OpenAI** | `sk-...` / `sk-proj-...` / `sk-svcacct-...` | Models list + optional chat completion |
| **Anthropic** | `sk-ant-...` | Models list + optional messages |
| **OpenRouter** | `sk-or-...` | Key info + optional chat completion |
| **xAI** | `xai-...` | Models list + optional chat completion |
| **Twilio** | `AC...` SID + 32-hex Auth Token | Account validation via Basic Auth |
| **Unknown** (heuristic) | Other vendor token shapes (AWS, GitHub, GitLab, Slack, Stripe, SendGrid, npm, Shopify, Mailgun, JWT, private keys…) and high-entropy `secret`/`token`/`apiKey` assignments | Not auto-validated — flagged for manual review with where/how context |

Bearer-token providers (OpenAI, Anthropic, OpenRouter, xAI) have no IP/referrer restriction mechanism -- any valid key is unconditionally **critical**. **Unknown** findings are heuristic "looks-like-a-secret" matches with no dedicated auditor; each records what pattern matched and which surface it came from.

## Where It Looks

Detection runs across every surface a key can hide in:

| Surface | How |
|---|---|
| **DOM / inline scripts** | Full page HTML + open shadow-DOM markup |
| **JavaScript bundles** | All `<script src>`, preloads, and modulepreloads are fetched and scanned |
| **Source maps** | `sourceMappingURL` files are followed; original un-minified source is scanned |
| **Recursive asset graph** | Referenced chunks, JSON, and CSS followed up to 3 levels deep (same-origin) |
| **Common config paths** | `/.env`, `/config.json`, `/firebase-config.json`, plus exposed dumps (`/.git/config`, `/wp-config.php.bak`, `/actuator/env`, `/phpinfo.php`) probed once per origin |
| **Web storage** | `localStorage` and `sessionStorage` |
| **IndexedDB & Cache Storage** | The origin's IndexedDB object stores and Service Worker `caches` entries (bounded) |
| **Runtime globals** | The page's own `window.*` properties (e.g. `window.ENV`, injected config) scanned in the MAIN world |
| **`<template>` contents** | Inert template fragments that never appear in the serialized DOM |
| **Page URL** | The current URL's query string and `#fragment` (catches OAuth-style tokens) |
| **Network traffic** | Live interception of `fetch()`, `XMLHttpRequest`, `WebSocket`, `EventSource`, and `sendBeacon` request/response bodies, headers, and URLs |
| **webRequest headers** | `key=` params, `X-Goog-Api-Key`, `Authorization: Bearer`, `x-api-key` |
| **Response headers & cookies** | Top-level response header values and the origin's cookies are scanned for keys |
| **Resource timing** | URLs from `performance.getEntriesByType('resource')` |

A key is logged **once** and enriched with every origin, page, and source it's seen on -- no duplicates.

---

## How It Works

```
  content scripts (isolated world)          service worker (background.js)
 +---------------------------------+      +--------------------------------------+
 | patterns.js  + content.js       |      | webRequest: sniff headers & params   |
 | - scan DOM / storage / timing   | ---> | fetch & scan linked JS/CSS/JSON      |
 | - forward <script src> URLs     |      | source maps + recursive asset crawl  |
 +---------------------------------+      | common config path probes            |
                                          | dedup + persist (chrome.storage)     |
  intercept.js (main world)               | run audits on demand                 |
 +---------------------------------+      +------------------+-------------------+
 | monkey-patch fetch / XHR / WS   |               |
 | - scan request & response bodies| ------------> |
 +---------------------------------+               v
                                      popup / dashboard / collection UIs
```

All data stays **local** in `chrome.storage.local`. The extension contacts the network only to (a) fetch a page's own linked scripts for scanning, and (b) reach provider endpoints during an audit you trigger. There is no telemetry and no backend server.

---

## Usage

1. **Browse.** Detection runs automatically; the badge counts distinct keys per tab.
2. **Popup** -- click the toolbar icon to see keys found on the current page, their sources, and provider.
3. **Audit** -- tick the authorization acknowledgment, then click **Audit key**. The default run uses free access checks. Tick "include billable generation probes" to also test token-billing inference.
4. **Dashboard** -- full findings view sorted by risk, with per-endpoint detail, domain grouping, and **JSON / CSV export + import**.
5. **Collection** -- save any key for later; a dedicated persistent page lets you revisit, annotate, re-audit, and export.

### Reading the Results

| Classification | Meaning |
|---|---|
| `enabled` | Key worked from a referrer-less, arbitrary-IP request -- **not** referrer/IP restricted |
| `restricted-referer` / `restricted-ip` | Rejected due to an HTTP-referrer / IP restriction (properly locked down) |
| `api-not-enabled` | The API/service is not activated for the key's project |
| `invalid-key` | Key string rejected as invalid/expired |
| `over-quota` | Valid but quota/billing exceeded |
| `denied` | Rejected for another reason |
| `inconclusive` | Could not be determined server-side |
| `error` | Network/transport error |

| Risk badge | Trigger |
|---|---|
| **CRITICAL** | An unrestricted **billable** service is reachable |
| **UNRESTRICTED** | A service is reachable from anywhere (no referrer/IP lock) |
| **RESTRICTED** | All reachable probes were referrer/IP-locked |
| **UNKNOWN** | Not audited, or nothing reachable |

---

## Permissions

| Permission | Why |
|---|---|
| `<all_urls>` host access | Read page DOM/network on any site and fetch its scripts for scanning |
| `webRequest` | Observe `key=` params and API-key headers on requests |
| `cookies` | Read the current origin's cookies to scan their values for keys |
| `storage` | Persist findings locally |
| `scripting`, `tabs` | Per-tab badge and content coordination |
| `downloads` | Export findings as JSON/CSV |

## Project Structure

```
manifest.json              MV3 manifest
background.js              service worker: network sniff, bundle scan, audit runner, badge
content/
  intercept.js            MAIN-world network interceptor (fetch/XHR/WS/SSE/beacon)
  patterns.js             shared key regex + helpers (content world)
  content.js              DOM / storage / resource scanner + script-URL forwarder
lib/
  keys.js                 shared detection helpers (module world)
  providers.js            provider registry: detect, audit, risk-assess
  store.js                normalized, deduped findings DB (chrome.storage.local)
  audit.js                Google Maps / Places / Cloud / AI probes + risk assessment
  ignore.js               domain ignore-list
popup/                    current-tab UI
dashboard/                all-findings UI, audit, JSON/CSV export-import
collection/               saved-keys page (revisit, annotate, re-audit, export)
icons/                    extension icons
```

## Limitations

- The audit reproduces server-side requests; it cannot replay a real browser's runtime referrer check, so a referrer-locked key used only via the Maps JS API may show as `inconclusive` rather than `restricted-referer`.
- Cost figures are indicative, not billing-accurate.

---

> [!WARNING]
> **Use on your own projects only.** The active audit makes live requests to
> provider APIs using discovered keys, which may incur cost. Only audit keys
> that belong to you or your organization. Passive detection is read-only;
> the audit is not.

## Contributing

Issues, bug reports, and PRs are welcome -- see [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions and coding conventions.

**Looking for a place to start?** Check out issues labeled [`good first issue`](https://github.com/hasif5/api-key-exposure-auditor/labels/good%20first%20issue) or [`help wanted`](https://github.com/hasif5/api-key-exposure-auditor/labels/help%20wanted).

Report vulnerabilities privately per [SECURITY.md](./SECURITY.md).

## Privacy

The extension runs entirely on your device -- no backend, no analytics, no telemetry. See [PRIVACY.md](./PRIVACY.md).

## Publishing to the Stores

A complete, copy-paste submission package (listing copy, permission justifications, build step) is in [docs/STORE_SUBMISSION.md](./docs/STORE_SUBMISSION.md). Build the upload zip with `./build.sh` (or `.\build.ps1`).

## License

[MIT](./LICENSE) &copy; 2026 hasif5.

## Disclaimer

This project is provided for educational and self-project security purposes. Use it to audit your own deployments and learn about API key security. The authors accept no liability for misuse.
