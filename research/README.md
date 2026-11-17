# Security Research

Defensive security research on **API Key Exposure Auditor**: a controlled, reproducible measurement of what the extension detects, what it misses, how it classifies risk, and where its documentation and behaviour disagree.

Author: Hasif Ahmed (hasif5@gmail.com, www.hasif.info)

## Scope and authorization

- Every credential used in this research is **synthetic**. Values match the format a detector looks for, but were never issued by any provider and cannot authenticate anywhere.
- All testing ran on one machine the author controls, against a fixture server bound to `127.0.0.1`. No third-party system, site, or provider API was contacted.
- The browser run enforces this at the DNS layer (only loopback resolves), and the harness records every request attempt. See [001, section 8.8](./001-credential-exposure.md#88-network-containment).
- The extension's live **audit** feature was **not** executed in the browser, because it sends discovered keys to real provider endpoints. Audit logic is exercised separately with simulated provider responses. Those results describe the extension's classification code, not provider behaviour.
- No vulnerability in a third-party product is reported here. The findings concern this project's own behaviour and documentation.

## Case study index

| ID | Title | Status | Headline result |
|---|---|---|---|
| [001](./001-credential-exposure.md) | Credential exposure across client-side surfaces | Completed 2026-11-17 | 36 of 36 declared exposures detected with correct provider and path on a 14-origin synthetic corpus; 3 of 3 predicted misses confirmed; 0 of 15 structurally invalid strings flagged; 4 of 4 format-valid or keyword-assigned lookalikes flagged; 5 observations recorded |

## Layout

```
research/
  README.md                      this file
  001-credential-exposure.md     case study: method, results, findings, limitations
  fixtures/
    synthetic.mjs                deterministic synthetic credential factory (no literals stored)
    scenarios.mjs                the test matrix and ground truth, declared before any run
    server.mjs                   zero-dependency fixture server (127.0.0.1 only)
  harness/
    logic.mjs                    Node run of the real lib/ and content/ code with mocked chrome + fetch
    browser.mjs                  real Chromium + unpacked extension, driven over raw CDP
    capture-readme-shots.mjs     captures the popup and dashboard images used in the top-level README (docs/screenshots/)
    cdp.mjs                      minimal DevTools Protocol client (no dependencies)
    scrub.mjs                    redacts credential-shaped strings before evidence is written
    scan-leaks.mjs               fails if anything credential-shaped is committed under research/
  evidence/
    results/                     machine-readable results (redacted)
    screenshots/                 dashboard captures from the real browser run
    transcripts/                 console output of the last full runs
```

## Reproduce

Requirements: Node 22 or newer (the harness uses the built-in `WebSocket`), and a Chromium build that honours `--load-extension`. Branded Chrome 137 and later ignores that switch, so use Chromium (for example the one Playwright installs). The harness auto-detects a Playwright Chromium, or set `CHROMIUM_PATH`.

```bash
node research/harness/logic.mjs        # about 5 seconds; no browser, no network
node research/harness/browser.mjs      # about 2.5 minutes; real browser, loopback only
node research/harness/scan-leaks.mjs   # confirms nothing credential-shaped is committed
```

The browser harness has two probe options that write separate files and never touch the main results:

```bash
ONLY=S09 node research/harness/browser.mjs                 # one scenario
ONLY=S09 DIRECT_NAV=1 node research/harness/browser.mjs    # open the tab directly on the URL
```

On PowerShell use `$env:ONLY='S09'; node research/harness/browser.mjs`. Two consecutive full browser runs were compared row by row (ports and timestamps excluded) and matched exactly. A third run, made after the redaction step was added, reported the same summary figures.

## Safety properties of this directory

- **No credential literals are committed.** Prefixes and bodies are assembled at runtime. `scan-leaks.mjs` runs the extension's own detector, plus a list of bare shapes the detector ignores without context (Twilio-style SIDs), over every text file here and must report zero hits.
- **Evidence is redacted.** Keys appear as prefix, tail, length, and a SHA-256 fingerprint. Snippets that contain neighbouring keys are scrubbed with the same detector.
- **Screenshots show full synthetic values.** Where the format allows, the body carries the marker `SYNTHFIXTURE`. Twilio SIDs and tokens are hex-only and carry no marker.
- **The fixtures can be run standalone** (`node research/fixtures/server.mjs`) for manual inspection in any browser.

## Capability status

Statuses come from reading the code and from what the study actually exercised. Nothing here is described as experimental or planned, because the repository does not label any feature that way.

| Capability | Implemented | Exercised in 001 |
|---|---|---|
| Provider detection (11 providers) and heuristic ("unknown") shapes | Yes | Yes (logic: 124 trials; browser: 36 exposures) |
| External bundle scan and recursive asset crawl | Yes | Yes (S01 lazy chunk) |
| Source-map decoding of `sourcesContent` | Yes | Yes (S03, including a decode-only case) |
| localStorage, sessionStorage, IndexedDB scan | Yes | Yes (S04) |
| fetch / XHR request and response interception | Yes | Yes (S05) |
| Window globals, `window.name` | Yes | Yes (S06) |
| Base64 decode-and-rescan | Yes | Yes (S07 browser; logic variants) |
| Common config path probing (`/.env`, `/config.json`, ...) | Yes | Yes (S08) |
| Response header and cookie scan | Yes | Yes (S09) |
| webRequest `key=` sniffing | Yes | Yes (S10) |
| User ignore list | Yes | Yes (S14) |
| Cross-origin dedup of one key | Yes | Yes (S01 + S04) |
| Live audit and risk assessment | Yes | Logic only, with simulated responses |
| WebSocket, EventSource, `sendBeacon` interception | Yes | Parity only (same patterns); not driven in the browser |
| Cache Storage, open and closed shadow DOM, `<template>`, URL fragment | Yes | No |
| Built-in Google/Facebook/Yahoo ignore defaults | Yes | No (only the user-added ignore list was tested) |
| webRequest `Authorization` / `x-api-key` sniffing on provider hosts | Yes | No (would send synthetic keys toward provider hostnames) |
