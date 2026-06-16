# Contributing

Thanks for your interest in improving the **API Key Exposure Auditor**.

## Where to start

- Browse issues labeled [`good first issue`](https://github.com/hasif5/api-key-exposure-auditor/labels/good%20first%20issue) for beginner-friendly tasks.
- Check [`help wanted`](https://github.com/hasif5/api-key-exposure-auditor/labels/help%20wanted) for items where we'd especially appreciate a hand.

## Scope & principles

This is a tool for **self-project security** — helping developers find and fix
API keys accidentally exposed in their own deployments. Contributions must keep
that framing.

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
- Detection regexes live in **three places** that must stay in sync:
  `content/patterns.js`, `content/intercept.js`, and `lib/providers.js`.
  The test suite verifies parity, but keep this in mind when editing patterns.
- Keep all data on-device. Don't add telemetry, analytics, or remote calls other
  than the page's own scripts and the user-triggered audit.

## Before you open a PR

- Syntax-check changed files:
  ```bash
  node --check content/patterns.js content/content.js content/intercept.js   # plain scripts
  node --input-type=module --check < lib/audit.js                            # ES modules
  ```
- Run the logic regression tests (detection/providers/store/ignore/parity):
  ```bash
  node test/detection.test.mjs
  ```
- Load the extension and manually verify your change.
- If you touched `manifest.json`, keep `description` ≤ 132 characters.
- Fill out the PR checklist.

We aim to respond to issues and PRs within a couple of days. If you're unsure
whether an idea fits, open an issue first to discuss it.

## Releasing (maintainers)

1. Bump `version` in `manifest.json`.
2. Commit and tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The [release workflow](./.github/workflows/release.yml) builds the store zip
   and source zip and attaches them to the GitHub Release automatically.

## Reporting security issues

Please follow [SECURITY.md](./SECURITY.md) — report vulnerabilities privately.
