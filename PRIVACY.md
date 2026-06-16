# Privacy Policy — API Key Exposure Auditor

_Last updated: 2026-06-10_

This extension is a self-project security tool that runs **entirely on your own
device**. It has **no backend server**, performs **no analytics or telemetry**,
and its developers **never receive, see, or store any of your data**.

## What the extension accesses

To do its job, the extension reads content from the web pages you visit:

- Page source (DOM), inline scripts, element attributes, and resource URLs
- `localStorage` and `sessionStorage` of visited pages
- Linked JavaScript files referenced by the page (fetched and scanned for keys)
- Network request URLs, headers, and request/response bodies (via fetch/XHR interception) for API key detection

It uses this access for a single purpose: **detecting API keys (Google, OpenAI,
Anthropic, OpenRouter, xAI, Twilio) that are exposed in that page's content.**

## What it stores, and where

- Detected keys and their metadata (origin, page URL, source, timestamps) and any
  audit results are stored **locally** in your browser via `chrome.storage.local`.
- This data **never leaves your machine** except when **you** explicitly export it
  (the Export JSON/CSV buttons write a file to your own computer).
- You can delete all stored data at any time with the dashboard's **Clear all** button.

## Network requests the extension makes

1. **Script scanning:** it fetches scripts already referenced by the page you are
   viewing, in order to scan them for exposed keys. No data is sent anywhere.
2. **Active audit (opt-in):** only when **you** click an Audit button, the
   extension sends requests to provider API endpoints (Google, OpenAI, Anthropic,
   xAI, OpenRouter, Twilio) **using the discovered key** to determine its
   restriction and billing posture. These requests go directly from your browser
   to the provider. No third party is involved, and nothing is sent to the
   extension's developers.

The active audit is disabled until you confirm the keys are your own, and
billable probes are off by default.

## Data sharing

None. No data is transmitted to the developers or any third party. There are no
ads, no trackers, no remote logging.

## Permissions and why they are needed

| Permission | Purpose |
|---|---|
| Host access to all sites (`<all_urls>`) | Read page content and fetch the page's scripts to detect exposed keys on any site you choose to inspect |
| `webRequest` | Observe API request URLs and headers to catch keys used in network calls |
| `storage` | Save findings locally on your device |
| `scripting`, `tabs` | Maintain the per-tab badge count |
| `downloads` | Let you export findings as JSON/CSV files |

## Responsible use

This tool is designed for auditing your own projects. The active audit may incur
cost, so only audit keys that belong to you or your organization.

## Contact

Questions or concerns: open an issue at
<https://github.com/hasif5/api-key-exposure-auditor/issues>.
