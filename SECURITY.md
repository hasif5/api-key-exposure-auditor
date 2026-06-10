# Security Policy

## Reporting a vulnerability in this extension

Please report security issues **privately**, not in public issues:

- Open a [private security advisory](https://github.com/hasif5/google-api-key-exposure-auditor/security/advisories/new), or
- Use the repository's **Security → Report a vulnerability** tab.

Include reproduction steps and affected version. We aim to acknowledge reports
promptly and will coordinate a fix and disclosure timeline with you.

Please do **not** include real third-party API keys or credentials in your report.

## Supported versions

The latest released version receives fixes. Older versions are not maintained.

## Responsible use &amp; disclosure of keys you find

This tool can reveal Google API keys that are exposed in public web pages. A few
ground rules:

- **Finding a key grants no right to use it.** Do not call APIs with a key you do
  not own unless you are explicitly authorized to test it.
- The active **audit** makes live requests that may incur cost to the key's owner.
  Only run it against keys you own or are authorized to assess.
- If you discover an exposed key that isn't yours, practice **responsible
  disclosure**: notify the owner (or the site operator) privately so they can
  rotate/restrict it, and do not publish the key.
- Follow all applicable laws and the
  [Google APIs Terms of Service](https://developers.google.com/terms).

This project is provided for educational and authorized security-research
purposes only; the authors accept no liability for misuse.
