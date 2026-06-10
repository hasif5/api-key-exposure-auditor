# API Key Exposure Auditor

A Chrome / Microsoft Edge (Manifest V3) browser extension that detects exposed
**API keys** — **Google** (`AIza…`), **OpenAI** (`sk-…`), and **Anthropic**
(`sk-ant-…`) — in the pages you visit (rendered DOM, web storage, loaded
JavaScript bundles, and network traffic), and, on demand, **audits** each key to
determine what it can reach, how it is restricted, and whether it can incur
billing. Google keys are tested across Maps/Places/Cloud/AI; OpenAI and Anthropic
keys are validated against their APIs — and since those are bearer tokens with no
restriction mechanism, any valid one is unconditionally **critical**.

Built for **academic and authorized security-research** use: surfacing keys that
are exposed in public page source so their restriction posture (HTTP-referrer /
IP / API enablement) can be assessed and reported.

> [!WARNING]
> **Authorized use only.** This tool can perform live requests to Google APIs
> using keys it discovers. Those requests may incur cost to the key's owner.
> Only run the active **audit** against keys you own or are explicitly
> authorized to test (e.g. your own property, a sanctioned pentest, a CTF, or a
> coordinated disclosure). Passive detection is read-only; the audit is not.
> You are responsible for complying with all applicable laws and the
> [Google APIs Terms of Service](https://developers.google.com/terms).

---

## Features

- **Multi-provider detection** — Google `AIza…`, OpenAI `sk-…` / `sk-proj-…`, and Anthropic `sk-ant-…` keys, each tagged with a provider badge.
- **Passive detection across every surface** a key can hide in:
  - Rendered DOM / inline scripts / element attributes (`<script>`, `<iframe>`, `<img>`, `<link>`)
  - **External JavaScript bundles** — linked `.js` files are fetched and scanned (most leaked keys live in minified bundles, not inline HTML)
  - **Web storage** — `localStorage` and `sessionStorage`
  - **Network traffic** — `key=` query params *and* `X-Goog-Api-Key` request headers (used by the modern Routes / Places APIs)
  - Resource-timing entries
- **One finding per key.** A key is logged once and enriched with every origin, page, and source it was seen on — no duplicates.
- **Active key audit** (opt-in, user-triggered) against current Google endpoints:
  - **Maps web services** — Static Maps, Geocoding, Directions, Distance Matrix, Elevation, Time Zone, Street View metadata, Places (legacy)
  - **Maps JavaScript API loader** — parses runtime error tokens (`RefererNotAllowedMapError`, `ApiNotActivatedMapError`, …)
  - **Modern APIs** — Routes API (New), Places API (New), Roads
  - **AI APIs** — Gemini Developer API (AI Studio), Vertex AI express mode, Gemini embeddings
  - **Cloud AI/ML** — Cloud Translation, Vision, Natural Language, Text-to-Speech, Speech-to-Text
  - **Other Google Cloud / Firebase** — Firebase Identity Toolkit (Auth), YouTube Data API, Safe Browsing, Cloud Storage
- **Restriction &amp; risk assessment.** Because probes carry no referrer and come from an arbitrary IP, any success means the key is **not** referrer/IP-locked. Unrestricted keys are flagged prominently (**CRITICAL / UNRESTRICTED**) and sorted to the top.
- **Billing awareness.** Each probe is marked free vs billable with an approximate cost note. The default audit uses only **free** access checks; token-billing calls are strictly opt-in.
- **Research dashboard** with a live progress bar, per-key detail, and **JSON / CSV export + import** for record-keeping.
- **My Collection** — bookmark any key with a **Save** button; a dedicated, persistent collection page lets you revisit, annotate, re-audit, and export saved keys. It's stored separately, so it survives "Clear all".
- **Domain ignore-list** — detection is skipped on noisy first-party domains (all **google.\*** & Google services, YouTube, Facebook, Instagram, Yahoo by default; extend it in the dashboard). Saving the list also purges any already-stored keys from those domains.
- **Grouped dashboard** — findings are grouped under collapsible, **numbered domain** headers (key count + unrestricted-key warning) in stable logged order, each with an **"Audit all in domain"** button. Rows and groups never reorder when you audit, so nothing jumps around.
- **Resilient** — bounded retries with backoff on transient errors, concurrency limits, and size caps on bundle scanning.

## How it works

```
┌─ content scripts ─────────────┐     ┌─ service worker (background.js) ──────────┐
│ patterns.js  + content.js     │     │ • webRequest: key= params & X-Goog-Api-Key │
│ • scan DOM / storage / timing │ ──▶ │ • fetch & scan external JS bundles         │
│ • forward <script src> URLs   │     │ • dedup + persist (chrome.storage.local)   │
└───────────────────────────────┘     │ • run audits (lib/audit.js)                │
                                       └───────────────┬────────────────────────────┘
        popup/  (current tab)  ◀──────────────────────┤
        dashboard/ (all keys, audit, export) ◀────────┘
```

All data stays **local** in `chrome.storage.local`. The extension contacts the
network only to (a) fetch a page's own linked scripts for scanning, and (b)
reach Google endpoints during an audit you trigger. There is no telemetry and no
backend server.

## Install

No build step — this is an unpacked Manifest V3 extension. Pick whichever path
you prefer; all three end with the same one-time **Load unpacked** step.

> **Why Developer mode?** Chrome and Edge only allow one-click installs from their
> official stores. Any unpacked extension requires Developer mode — this is normal
> and the extension runs entirely on your machine (no backend, no telemetry).

### Option 1 — one command (downloads + unpacks for you)

**Windows (PowerShell):**
```powershell
iwr -useb https://raw.githubusercontent.com/hasif5/api-key-exposure-auditor/main/install.ps1 | iex
```
**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/hasif5/api-key-exposure-auditor/main/install.sh | bash
```
The script drops the extension in your home folder and prints the load steps.

### Option 2 — download the zip (no terminal)

1. Grab the latest `.zip` from the [**Releases**](https://github.com/hasif5/api-key-exposure-auditor/releases/latest) page and unzip it.

### Option 3 — clone (for developers)

```bash
git clone https://github.com/hasif5/api-key-exposure-auditor.git
```

### Then, in any case — load it (one time)

1. Open `chrome://extensions` (Chrome) or `edge://extensions` (Edge).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the extension folder.
4. Pin the extension and browse — the toolbar badge shows the number of distinct keys found on the active tab.

> **One-click install** (no Developer mode) requires publishing to the Chrome Web
> Store / Edge Add-ons — see the [Roadmap](#roadmap).

## Roadmap

- [ ] Publish to the **Chrome Web Store** and **Edge Add-ons** for one-click install (requires a developer account, store review, and a privacy-policy URL).
- [ ] Optional screenshots / demo GIF in this README.

## Usage

1. **Browse.** Detection runs automatically; the badge counts distinct keys per tab.
2. **Popup** — click the toolbar icon to see keys found on the current page, their sources, and a Maps-context flag.
3. **Audit** — tick the *authorization* acknowledgment, then click **Audit key**. The default run uses free access checks. Tick *"include billable generation probes"* to also test token-billing AI generation.
4. **Dashboard** — open the full dashboard to see all logged keys, sorted by risk, with a progress bar during audits, full per-endpoint detail, and **Export JSON / CSV** (or **Import JSON**).

### Reading the results

| Classification | Meaning |
|---|---|
| `enabled` | Key worked from a referrer-less, arbitrary-IP request → **not** referrer/IP restricted for that API |
| `restricted-referer` / `restricted-ip` | Rejected due to an HTTP-referrer / IP restriction (properly locked down) |
| `api-not-enabled` | The API/service is not activated for the key's project |
| `invalid-key` | Key string rejected as invalid/expired |
| `over-quota` | Valid but quota/billing exceeded |
| `denied` | Rejected for another reason |
| `inconclusive` | Could not be determined server-side (e.g. JS-loader runtime referrer check) |
| `error` | Network/transport error |

| Risk badge | Trigger |
|---|---|
| **CRITICAL** | An unrestricted **billable** service is reachable |
| **UNRESTRICTED** | A service is reachable from anywhere (no referrer/IP lock) |
| **RESTRICTED** | All reachable probes were referrer/IP-locked |
| **UNKNOWN** | Not audited, or nothing reachable |

> Pricing/cost notes are approximate public list prices and shown for awareness
> only — actual cost depends on SKU tier, free monthly allowances, and token
> counts.

## Permissions

| Permission | Why |
|---|---|
| `<all_urls>` host access | Read page DOM/network on any site and fetch its scripts for scanning |
| `webRequest` | Observe `key=` params and `X-Goog-Api-Key` headers on Google requests |
| `storage` | Persist findings locally |
| `scripting`, `tabs` | Per-tab badge and content coordination |
| `downloads` | Export findings as JSON/CSV |

## Project structure

```
manifest.json            MV3 manifest
background.js            service worker: network sniff, bundle scan, audit runner, badge
content/
  patterns.js           shared key regex + helpers (content world)
  content.js            DOM / storage / resource scanner + script-URL forwarder
lib/
  keys.js               shared detection helpers (module world)
  providers.js          provider registry (Google/OpenAI/Anthropic): detect, audit, risk
  store.js              normalized, deduped findings DB (chrome.storage.local)
  audit.js              Google Maps / Places / Cloud / AI probes + risk assessment
popup/                  current-tab UI
dashboard/              all-findings UI, audit, JSON/CSV export-import
collection/             saved-keys page (revisit, annotate, re-audit, export)
icons/                  extension icons
```

## Limitations

- Detects keys in the Google `AIza…` format. Other credential types are out of scope.
- The audit reproduces server-side requests; it cannot replay a real browser's
  runtime referrer check, so a referrer-locked key used only via the Maps JS API
  may show as `inconclusive` rather than `restricted-referer`.
- Cost figures are indicative, not billing-accurate.

## Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). Please keep
the **authorized-use** framing intact and do not add features whose primary
purpose is unauthorized exploitation. Report vulnerabilities privately per
[SECURITY.md](./SECURITY.md).

## Privacy

The extension runs entirely on your device — no backend, no analytics, no
telemetry. See [PRIVACY.md](./PRIVACY.md).

## Publishing to the stores

A complete, copy-paste submission package (listing copy, permission
justifications, build step) is in
[docs/STORE_SUBMISSION.md](./docs/STORE_SUBMISSION.md). Build the upload zip with
`./build.sh` (or `.\build.ps1`).

## License

[MIT](./LICENSE) © 2026 hasif5.

## Disclaimer

This project is provided for educational and authorized security-research
purposes only. The authors accept no liability for misuse. Detecting a key does
not grant any right to use it. Always follow responsible-disclosure practices
when you find an exposed credential that is not yours.
