# Version 0.1 verification

The checks use disposable credentials and profiles. No private user vault was
copied into this repository, test output, package or screenshot.

## Local evidence

- Automated Python tests cover encrypted round trips and tampering, incorrect
  passwords, default Always ask, owner/agent separation, Auto approve restrictions,
  YOLO, one-use approval, expiry, denial, revocation, policy changes, lock, restart,
  pairing replay, validation redaction, CSRF, Host validation and payload bounds.
- Outbound tests cover private/local address rejection, DNS pinning, redirect
  refusal and literal credential-echo redaction. They use a fixture connection;
  they do not contact a real credential provider or spend API credits.
- CLI tests launch a real local host, list keys, inject a disposable key into a
  child process and exercise MCP initialize/tools/list. They check MCP cannot
  return a raw lease created outside the MCP surface.
- A real Chromium flow adds a disposable key, changes mode, pairs an agent,
  approves one raw lease, and locks the vault. Layout checks cover 320, 390, 768
  and 1280 CSS pixels. Screenshots in this directory are fixture-only.
- Dependency auditing caught vulnerable older cryptography wheels; the release
  requires cryptography 50.0.1 or later within major version 50. CI includes a
  dependency-audit gate. A clean advisory scan is point-in-time evidence only.
- The skill passes the native skill validator. The wheel and source distribution
  build successfully. GitHub Actions repeats host tests on macOS, Windows and Linux
  with Python 3.11 and 3.13, plus a Linux Chromium flow.

## Scope

Local host/browser execution was on macOS. CI results are the evidence for other
host operating systems. No physical iPhone, Android or Windows GUI was tested locally.
Clipboard permission behavior varies by browser; manual masked paste is supported.
The live OAuth consent flow was not tested with a new Tailscale account. The connector
uses the installed Tailscale client and official account/install URLs.

This was an implementation review and automated test pass, not an independent
cryptographic audit. Read SECURITY.md for limits. Do not present this release as
award-winning, certified, universally compatible, or immune to malicious local agents.
