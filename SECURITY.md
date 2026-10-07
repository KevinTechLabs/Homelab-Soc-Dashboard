# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems.

Report it privately through GitHub instead:
<https://github.com/KevinTechLabs/Homelab-Soc-Dashboard/security/advisories/new>
(**Security → Report a vulnerability**). Include what you found, how to
reproduce it, and what an attacker could do with it. You'll get a reply within
a few days. Please allow up to 90 days for a fix before disclosing the issue
publicly.

If you spot something in this repository that looks like a real credential,
token, address or other private detail, please report it the same way.

## Supported versions

Only the latest commit on `main` is supported.

## What's already in place

- The API listens on `127.0.0.1` behind nginx; it is not meant to be exposed to the internet.
- Response actions (blocking, acknowledging, closing alerts) need an access key.
- The Discord webhook is stored only on the server and is never sent to the browser.
- Wazuh is read through read-only accounts with SHA-256 certificate pinning.
- Screenshots use the built-in demo mode, with no real addresses or hosts.
