---
name: latchlane
description: Set up and use Latchlane to store API keys through local clipboard capture, broker agent credential access with owner-controlled approval modes, and connect devices privately over Tailscale. Use for Latchlane installation, key storage, pairing, and authenticated service work.
---

# Latchlane

Use the installed `latchlane` CLI. If missing, read the project's README and
SECURITY.md at https://github.com/baney75/latchlane before installation. Install
with `uv tool install 'git+https://github.com/baney75/latchlane@v0.3.0'` after reviewing
the source and environment. Use supported Python 3.11+ on macOS, Windows or Linux.
Phones/tablets use the browser console through a Tailscale-connected host.

## First setup

For a first-time local setup, run `latchlane install-app`. It installs a per-user
launcher and opens Latchlane in the normal supported Chromium browser profile. The
user enters their passphrase in the owner screen, never in chat. Use `latchlane app`
for later launches. Default to
**Always ask**. Switch to Auto approve or YOLO only on an explicit user choice; the
modes are enforced by the broker. Never use owner credentials to bypass an agent
approval. Use `latchlane start` only when the user needs a technical host process.
Do not copy, migrate, print, or request a key, passphrase, pairing code, browser cookie,
or agent credential. Existing browser cookies and extensions stay in the selected normal
profile; that is a local-device trust boundary, not a credential migration.

If the user explicitly requests unattended operation, explain that its local
unlock file grants vault access to the same OS user. `latchlane init --unattended`
is an opt-in convenience, not a strong boundary against local agents. An untrusted
agent should use a different OS account/device than the vault host.

Use `latchlane doctor` for readiness. It checks the reachable broker and pairing,
not whether a provider accepts a stored credential. `agent_pairing_valid: null`
means the pairing could not be checked, for example because the vault is locked or
the broker is unavailable. Use `latchlane doctor --url http://127.0.0.1:PORT` for a
custom local port, and `latchlane owner --url http://127.0.0.1:PORT` to open that
host’s console. Never dump the state directory, environment, clipboard, credential
files, request headers, or browser cookies into tool output.
Do not import existing secrets unless requested. The installer contains no keys.

## Store a named key

Use a descriptive lowercase name. Open `latchlane capture NAME --origin HTTPS_ORIGIN`.
When known, add `--header` and `--prefix none|bearer|basic`; these only prefill the
owner-visible authentication metadata and never accept a secret argument. Omit them
to retain the capture form defaults.
The user signs into the owner console and confirms the API origin, header, and
prefix. Latchlane uses that configured header with an optional `Bearer ` or `Basic `
prefix; it does not infer provider authentication formats. Guide
them to **Watch next copy** before copying the key, then return to that window.
The browser saves the next changed value when the form is complete. If watching is
unsupported, use **Paste from clipboard** or the masked input and **Encrypt & save**.
Do not inspect their clipboard or ask them to paste the key into the conversation.

Wait for the UI's actual save outcome or inspect names through `latchlane keys` on
a paired client. Never claim provider validity from storage success. Clipboard
clearing is best effort and cannot erase clipboard history. Do not overwrite an
existing name; use a new name for rotation, then update the intended consumer.

## Pair and use

The owner creates a one-use pairing code in the console. Run `latchlane pair URL
--name NAME` in a local terminal with hidden input. The user enters the code there.
Do not ask for it in chat. Pairing tokens are saved to the private agent profile.
Use a separate LATCHLANE_HOME for separate agent identities; do not copy tokens.

Prefer `latchlane request KEY /exact/path --purpose 'Specific intended action'`.
For writes use `--method` and `--body-file` with a reviewed body. The broker pins the
key to its owner-configured HTTPS origin, blocks redirects/private IPs, and enforces
approvals. Unknown or potentially risky work must wait for the owner in Auto approve.
Do not infer safety merely from GET, and do not create trusted-route rules yourself.

A pending operation is not success. Keep waits bounded and let the user approve in
the console. Requests expire after five minutes and can be consumed once. After a
network failure, establish the provider's actual state before retrying a write.

For a trusted SDK that requires a key, use:
`latchlane run --purpose 'Specific action' KEY ENV_VARIABLE -- COMMAND ARGS`.
This releases a raw key to the child; inspect that child first and prevent credential
logging. Raw-key use always asks in Auto approve; YOLO deliberately bypasses prompts.
The child can retain the key, so broker revocation cannot recall it afterward.

For MCP use `latchlane mcp` as a stdio server: list keys, request an operation,
then consume its ID. `latchlane mcp --help` describes the command. Do not poll
faster than every two seconds. MCP provides brokered HTTP only, no raw key tool.
Stored access never authorizes unrelated destinations or actions.

## Request credentials from the owner

Use `latchlane collect --spec-file REQUEST.json` when an agent needs one or more
new named credentials. The JSON file accepts only a purpose and metadata-only
items (`name`, `kind`, HTTPS `origin`, optional `header` and `prefix`); it never
contains a value, password, username, token, route, or secret. Latchlane opens
the paired owner console at its own broker origin. `--wait` polls no faster than
every two seconds for up to 15 minutes and, if the vault is locked, opens the
local owner unlock screen before one validated retry. Use `--no-open` only where
the owner has already opened that console.

An owner may add `api_key` or `password` entries. Passwords are Unicode-capable
and lease-only: they cannot be sent through Latchlane's HTTP broker, including in
YOLO mode. A trusted child process may receive a raw lease only through the
existing owner-controlled `latchlane run` flow; never ask for a password in chat.

MCP clients can call `latchlane_collect` and `latchlane_collection_status`; both
return only IDs, statuses, and requested names. Use `latchlane mcp
--collections-only` for a metadata-only integration that must not expose the
normal broker tools. This does not add approval, change the selected mode, or
release a credential.

### Hermes

Do not change Hermes configuration automatically. For an owner-installed local
Latchlane command, use `hermes mcp add latchlane --command latchlane --args mcp`,
then restrict the tool allowlist to `latchlane_keys`, `latchlane_request`,
`latchlane_consume`, `latchlane_collect`, and `latchlane_collection_status` and
disable MCP resources and prompts. Run `hermes mcp test latchlane`, then start a
fresh session or use `/reload-mcp`. Hermes' `trust: full` keeps Latchlane's
Always ask, Auto approve, and YOLO policies as the enforcement point; choose
untrusted only when an additional Hermes confirmation is intended. Hermes uses
`trust: full` by default for an added server; do not change that setting
automatically.

To install the bundled guidance for Hermes without changing any config, run
`latchlane install-skill --directory ~/.hermes/skills/latchlane`. It refuses to
overwrite an existing skill, so review or back up an existing custom file first.

## Optional Tailscale sync

Ask whether sync is wanted unless already requested. Run `latchlane connect`; it
links to account creation/install and uses Tailscale's supported browser sign-in.
Users authorize Tailscale directly. Never collect an OAuth client secret or claim
a universal cross-tailnet OAuth integration. Its current app OAuth is tailnet-scoped.

Use private Serve HTTPS on port 8447, never Funnel. Preserve existing routes. If the
host started before Tailscale connected, restart the host to recognize its address.
Pair each agent device individually. Phones use the owner console in their browser.
Changes are shared through one online host; there are no offline vault replicas.

## Verify honestly

Use disposable test credentials and an isolated profile. Check default-deny behavior,
approval, pairing/revocation and encryption without real keys or billable requests.
Report host/client/browser platform coverage separately; no software works on every
device and this release is not an independent security certification.
