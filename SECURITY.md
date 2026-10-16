# Security policy

## Reporting a vulnerability

Please report vulnerabilities in sev1daemon itself privately through GitHub:
**Security → Report a vulnerability** on this repository. Don't open a public
issue for anything exploitable.

Include what you found, how to reproduce it, and the impact you expect. You'll
get an acknowledgement, and a fix or a plan, as soon as practical.

## Scope

In scope: the daemon's own code and shipped defaults, for example

- secrets (webhook URLs, tokens) leaking into logs, the state database or
  `show-config` output;
- server-side request forgery through webhook targets;
- command or argument injection through the `shell` action or advisory data;
- anything that lets feed content suppress, forge or flood alerts.

Out of scope: vulnerabilities in the advisory feeds, registries and APIs the
daemon reads (OSV, GitHub, NVD, deps.dev, package registries); report those
upstream.

## Supported versions

Fixes land on `main`. Run the latest release or `main`.
