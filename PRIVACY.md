# Privacy Policy — API Key Exposure Auditor

_Last updated: 2026-06-10_

This extension is a security-research tool that runs **entirely on your own
device**. It has **no backend server**, performs **no analytics or telemetry**,
and its developers **never receive, see, or store any of your data**.

## What the extension accesses

To do its job, the extension reads content from the web pages you visit:

- Page source (DOM), inline scripts, element attributes, and resource URLs
- `localStorage` and `sessionStorage` of visited pages
- Linked JavaScript files referenced by the page (fetched and scanned for keys)
- Network request URLs and the `X-Goog-Api-Key` request header for requests to Google domains

It uses this access for a single purpose: **detecting Google API keys (`AIza…`)
that are exposed in that page's content.**

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
   extension sends requests to Google API endpoints (Maps, Routes, Places, Roads,
   Gemini, Vertex AI) **using the discovered key** to determine its restriction and
   billing posture. These requests go directly from your browser to Google. No
   third party is involved, and nothing is sent to the extension's developers.

The active audit is disabled until you acknowledge that you are authorized to test
the keys, and billable probes are off by default.

## Data sharing

None. No data is transmitted to the developers or any third party. There are no
ads, no trackers, no remote logging.

## Permissions and why they are needed

| Permission | Purpose |
|---|---|
| Host access to all sites (`<all_urls>`) | Read page content and fetch the page's scripts to detect exposed keys on any site you choose to inspect |
| `webRequest` | Observe Google API request URLs and the `X-Goog-Api-Key` header to catch keys used in network calls |
| `storage` | Save findings locally on your device |
| `scripting`, `tabs` | Maintain the per-tab badge count |
| `downloads` | Let you export findings as JSON/CSV files |

## Responsible use

Detecting a key does not grant any right to use it. The active audit may incur
cost to a key's owner, so only audit keys you own or are authorized to test, and
follow responsible-disclosure practices for any exposed credential you find.

## Contact

Questions or concerns: open an issue at
<https://github.com/hasif5/google-api-key-exposure-auditor/issues>.
