# Security model

Latchlane 0.2 is an early public release. It has automated boundary tests, but has
not received an independent security audit. Do not infer certification from the
interface, encryption algorithm, or the presence of tests.

## What it protects

- The vault encrypts all stored keys, agent-token hashes, policy and audit data
  with AES-256-GCM, a random 96-bit nonce on each write, and version-bound associated
  data. The key is derived from the owner passphrase using scrypt (N=131072, r=8,
  p=1, a random 128-bit salt). A stolen ciphertext file requires the passphrase.
- Only the local loopback interface is bound. Remote access uses Tailscale Serve
  HTTPS. Host validation, origin validation, same-site owner cookies and a required
  custom request header protect the browser boundary. No CORS or public Funnel.
- The owner controls keys, routes, modes and pairing. Paired agent tokens only
  access the agent API. Tokens have 256 bits of randomness and are stored as hashes
  inside the encrypted vault. Pairing codes expire after five minutes and are
  consumed once. Owner sessions last 24 hours by default or 30 days when the owner
  explicitly remembers the device. Both end on lock or host restart; Sign out
  removes the browser session.
- API calls are restricted to the key's owner-configured HTTPS origin on port 443.
  DNS answers must all be public addresses. The connection pins an address while
  preserving TLS hostname verification. Redirects and environment proxies are
  disabled. Request/response sizes are bounded. Agents cannot supply auth headers.
- Always ask is the default. Auto approve uses exact owner-selected GET paths,
  without queries or bodies. It does not trust agent-supplied risk labels.
  YOLO intentionally allows all paired agents to use all keys without approval.
- Approvals are bound to one immutable operation and one agent identity, expire
  after five minutes, and are consumed before execution. Retrying an uncertain
  write requires a fresh request. Mode changes, key removal and agent revocation
  invalidate affected outstanding requests.
- Logs exclude key values, authorization headers, request bodies and query strings.
  Validation errors omit rejected input. Uvicorn access logging is disabled.

## What it does not protect

- A malicious process running as the vault host's OS user can inspect memory,
  modify code, steal the owner browser session, or read an unattended unlock file.
  Run untrusted agents on a different device or OS account. Local filesystem
  permissions are not a sandbox. Windows depends on the user profile's inherited
  ACL; POSIX mode 600 is not a Windows ACL enforcement mechanism.
- YOLO and approved `run` requests release raw keys to the client. That client can
  retain, reuse or leak the value. Latchlane cannot enforce a purpose after release,
  erase it from child memory, or recall it with revocation. Rotate at the provider.
  MCP deliberately offers no raw-key tool.
- Automatic unlocking stores a local random passphrase. Someone who obtains both
  `unattended.key` and `store.vault` can decrypt the vault. It is off by default.
- Memory zeroization is not guaranteed in Python or browsers. Swap, crash dumps,
  browser extensions, clipboard managers and clipboard sync are outside the vault's
  control. Clipboard compare-and-clear is best effort in browsers, not atomic.
- The PWA cache and the normal browser profile used by the desktop launcher can retain
  static interface files and owner-session cookies on that device. They do not contain
  vault ciphertext or agent credentials, but browser extensions and session cookies are
  part of the local device boundary.
- A provider is trusted to receive its key. Literal/common-format echo redaction
  helps with accidental disclosure; a malicious provider can encode a key in ways
  that evade it. Auto approve GET routes can still have side effects if the provider
  defines them that way. Only the owner can designate trusted paths.
- An authorized request already dispatched to a provider cannot be cancelled by
  a later lock or revocation. A successful local dispatch does not prove that a
  provider accepted or completed an operation.
- The vault host must be online and unlocked. There is no offline replication,
  conflict resolution, rollback detection for user-restored backups, high availability,
  hardware-backed isolation, multi-owner RBAC, or recovery backdoor.
- Tailscale account security, tailnet grants, host patching and disk encryption
  remain the operator's responsibility. Sharing a tailnet is not sufficient to
  access keys: agent pairing or owner sign-in is still required.

## Backups and recovery

Back up `store.vault` using your existing private backup system. Keep the passphrase
in a password manager separately. Restore only while the host is stopped and verify
it can unlock before replacing a working copy. Losing both the live data and backup
loses the keys. Losing the passphrase loses encrypted-vault access.

Do not back up the entire state directory to a public repository. It can contain
agent credentials, a one-use owner ticket and an unattended unlock file. Never
attach a vault, token, real API key or private tailnet address to a GitHub issue.

## Report a vulnerability

Use GitHub's private vulnerability reporting on this repository when available.
Otherwise open a minimal issue requesting a private contact, without exploit
credentials, personal data or a live vault. Share a disposable reproduction.

## Public release hygiene

The repository is created independently of any user's store. Tests use disposable
credentials and isolated profiles. Release checks scan tracked files and Git history
with Gitleaks, and inspect package contents. Public screenshots use only fixtures.
