# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** Report privately through
[GitHub Security Advisories](https://github.com/KiaroSama/Proxy-Tester/security/advisories/new).

Please include what the issue is, how to reproduce it, what an attacker gains,
and the affected version or commit. Expect an acknowledgement within a few days.
Please give a reasonable window for a fix before disclosing publicly.

## Supported versions

Only the latest commit on `main` is supported.

## What this tool does, and what that means for you

Understand the threat model before running it.

### Public proxies are untrusted infrastructure

Every proxy this tool finds is an anonymous third-party machine. Whoever runs it
can log, inspect, modify, or block anything you send through it.

- **Never send credentials, tokens, cookies, personal data, or anything
  confidential through a proxy from these lists.**
- Plain HTTP through a proxy is readable and modifiable by the proxy operator.
- Even over HTTPS the operator learns which hosts you contact and when.
- A proxy appearing in a "working" list says only that it responded. It carries
  no guarantee of honesty, availability, or safety.

### Source lists are untrusted input

Proxy lists are fetched from third-party repositories that anyone can change.
The tool treats their contents as hostile data:

- Only `http`, `socks4`, and `socks5` schemes are accepted.
- Hosts and ports are strictly validated; malformed entries are dropped.
- Loopback, private, link-local, and other reserved addresses are rejected, so a
  list cannot aim the tester at your own network.
- Parsing is capped per source, so an oversized list cannot exhaust memory.

Downloaded content is never executed, deserialized, or written outside
`output/`.

### `--verify-tls` is off by default

TLS certificates are **not** verified during proxy checks by default. This is
deliberate: the check asks "does this proxy carry traffic", and many proxies
present broken or intercepting certificates. It also means a probe response can
be forged by the proxy.

This is acceptable for reachability testing and **not** acceptable for anything
else. Pass `--verify-tls` if you need certificate validation.

### Automatic dependency installation

On first run, missing dependencies are installed with `pip` from PyPI. If you
would rather control that, install them yourself first:

```bash
pip install -r requirements.txt
```

### Output files

`output/` is git-ignored, but the proxy lists it contains are still local files
on your disk. Treat them as you would any other operational data.

## Reporting scope

In scope: flaws in this repository's own code — input validation, path
handling, credential leakage in logs or output, unsafe parsing, dependency
vulnerabilities.

Out of scope: the behaviour of third-party proxy servers, the contents of
third-party proxy lists, and the documented defaults described above (including
`--verify-tls` being off). If you believe a default is wrong, open a normal
issue rather than a security advisory.
