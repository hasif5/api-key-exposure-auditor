# Store Submission Guide

Everything needed to publish to the **Chrome Web Store** and **Microsoft Edge
Add-ons**. The repo is already store-compliant (MV3, ≤132-char description,
icons, privacy policy). This guide is the copy-paste-and-upload checklist.

> The store upload itself must be done by the account owner in the developer
> dashboard — it requires your login and (Chrome) a one-time **$5** fee. Edge is
> free.

---

## 1. Build the upload package

```bash
./build.sh         # macOS / Linux
```
```powershell
.\build.ps1        # Windows
```

This produces `dist/api-key-exposure-auditor-store.zip` containing only the
runtime files (`manifest.json`, `background.js`, `content/`, `lib/`, `popup/`,
`dashboard/`, `icons/`). Upload that zip.

---

## 2. Listing copy (paste into both dashboards)

**Name**
```
API Key Exposure Auditor
```

**Summary / short description** (≤132 chars)
```
Detects exposed Google, OpenAI & Anthropic API keys on web pages and audits their access & billing exposure. Research use only.
```

**Detailed description**
```
API Key Exposure Auditor is a security-research tool that detects exposed API keys — Google (AIza…), OpenAI (sk-…), and Anthropic (sk-ant-…) — in the pages you visit, in the page source, web storage, loaded JavaScript bundles, and network traffic, and, on demand, audits each key to determine what it can reach, how it is restricted, and whether it can incur billing.

DETECTION
• Scans the DOM, inline scripts, attributes, localStorage/sessionStorage, resource-timing entries, external JavaScript bundles, and network traffic (key= params and the X-Goog-Api-Key header).
• Logs each key once and records every origin, page, and source it was seen on.

AUDIT (opt-in, authorized keys only)
• Google keys: Maps web services, the Maps JavaScript API loader, Routes/Places (New), Roads, Gemini, Vertex AI, and other Cloud/Firebase APIs. OpenAI/Anthropic keys are validated against their APIs — bearer tokens with no restriction, so a valid one is unconditionally critical.
• Flags unrestricted keys (reachable with no referrer/IP lock) and shows free-vs-billable cost awareness.

PRIVACY
• Runs entirely on your device. No backend, no analytics, no telemetry. Findings stay in local storage until you export or clear them.

SELF-PROJECT SECURITY
The active audit performs live API calls that may incur cost. Use it only on keys that belong to you or your organization.
```

**Category:** Developer Tools
**Language:** English
**Homepage / support URL:** `https://github.com/hasif5/api-key-exposure-auditor`
**Privacy policy URL:** `https://github.com/hasif5/api-key-exposure-auditor/blob/main/PRIVACY.md`

---

## 3. Permission justifications (Chrome requires these)

| Item | Justification to paste |
|---|---|
| **Host permission `<all_urls>`** | The tool inspects pages the user chooses for exposed Google API keys; it must read page content and fetch the page's referenced scripts on any site the user is auditing. |
| **`webRequest`** | To detect keys passed in Google API request URLs (`key=`) and the `X-Goog-Api-Key` request header. |
| **`storage`** | To save detected keys and audit results locally on the user's device. |
| **`scripting`** | To coordinate the content scan and maintain the per-tab badge count. |
| **`tabs`** | To show per-tab results and the badge for the active tab. |
| **`downloads`** | To let the user export findings as JSON/CSV files. |
| **Remote code** | No. The extension executes no remotely-hosted code; it only *reads* page scripts as text to scan them. |
| **Single purpose** | Detect and audit exposed API keys (Google, OpenAI, Anthropic) for authorized security research. |

**Data-use disclosures (Chrome "Privacy practices" tab):** check that the
extension does **not** sell data, does **not** use data for unrelated purposes,
and does **not** transfer data to third parties. It handles "Website content"
solely on-device for the single purpose above.

---

## 4. Assets you still need to capture

Screenshots must show the real UI, so capture them after loading the extension:

| Asset | Spec | Suggested shot |
|---|---|---|
| Screenshot ×1–5 | 1280×800 or 640×400 PNG | The dashboard with a few audited keys (redact real keys) |
| Store icon | 128×128 PNG | Already in `icons/icon128.png` |
| Small promo tile (optional) | 440×280 PNG | Logo + name |

Tip: audit a **test key you own** so the screenshots show real classifications
without exposing anyone else's credentials.

---

## 5. Upload steps

### Chrome Web Store
1. Go to the [Developer Dashboard](https://chrome.google.com/webstore/devconsole/) and pay the one-time $5 fee if you haven't.
2. **Add new item** → upload `dist/api-key-exposure-auditor-store.zip`.
3. Fill the listing from §2, permission justifications from §3, add screenshots from §4.
4. Set the privacy policy URL, complete the data-use form, **Submit for review**.

### Microsoft Edge Add-ons
1. Go to the [Partner Center](https://partner.microsoft.com/dashboard/microsoftedge/) (free registration).
2. **Create new extension** → upload the same zip.
3. Fill the listing (same copy), add the privacy policy URL and screenshots, **Publish**.

Review typically takes a few days. Tools that read page content and credentials
get extra scrutiny — the privacy policy and the justifications above are written
to address exactly that.
