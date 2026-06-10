# Contributing

Thanks for your interest in improving the **API Key Exposure Auditor**.

## Scope &amp; principles

This is a tool for **authorized, defensive security research** — detecting and
assessing *exposed* Google API keys so they can be reported and fixed.
Contributions must keep that framing. Features whose primary purpose is
unauthorized exploitation, mass abuse, or evading detection will be declined.

**Never commit real API keys** or other credentials, in code, tests, fixtures,
issues, or PRs.

## Development setup

No build step — it's a vanilla Manifest V3 extension.

1. Clone the repo.
2. Open `chrome://extensions` (or `edge://extensions`) → enable **Developer mode**.
3. **Load unpacked** → select the repo folder.
4. Edit files; reload the extension from the extensions page to pick up changes
   (use the dashboard's **Clear all** to reset stored findings while testing).

See the [README](./README.md#project-structure) for the layout.

## Coding conventions

- **Vanilla JS only** — no frameworks, no bundlers, no runtime npm dependencies.
- Match the surrounding style (naming, comment density, structure).
- Content scripts can't use ES modules — shared content-world helpers live in
  `content/patterns.js`; the module world (worker, popup, dashboard) uses
  `lib/keys.js`. Keep the two in sync if you change the detection regex.
- Keep all data on-device. Don't add telemetry, analytics, or remote calls other
  than the page's own scripts and the user-triggered Google audit.

## Before you open a PR

- Syntax-check changed files:
  ```bash
  node --check content/patterns.js content/content.js          # plain scripts
  node --input-type=module --check < lib/audit.js              # ES modules
  ```
- Load the extension and manually verify your change.
- If you touched `manifest.json`, keep `description` ≤ 132 characters.
- Fill out the PR checklist.

## Releasing (maintainers)

1. Bump `version` in `manifest.json`.
2. Commit and tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The [release workflow](./.github/workflows/release.yml) builds the store zip
   and source zip and attaches them to the GitHub Release automatically.

## Reporting security issues

Please follow [SECURITY.md](./SECURITY.md) — report vulnerabilities privately.
