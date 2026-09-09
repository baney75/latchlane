# Using Latchlane

## Start here

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```sh
uv tool install 'git+https://github.com/baney75/latchlane@v0.2.0'
latchlane install-app
```

This installs and opens a dedicated Latchlane app window using a separate Chromium profile. It does not use your signed-in Vivaldi session. Later, open Latchlane from your Applications or Start Menu. Create a passphrase, then add your first key. The passphrase is not stored by default. Keep it in your password manager; there is no reset backdoor.

For a technical host-only process, use `latchlane start`; use `latchlane app` to open its dedicated window. `latchlane install-app --no-open` installs the launcher without opening it.

To install the agent skill:

```sh
latchlane install-skill
```

This installs into `~/.codex/skills/latchlane`. Other agents can read the same [SKILL.md](../skills/latchlane/SKILL.md), or use `--directory` to choose their skill folder.

### Three modes. One owner.

| Mode | What happens |
| --- | --- |
| **Always ask** · default | Each use needs your approval in the owner console. Approvals expire after five minutes and can be consumed once. |
| **Auto approve** | Exact GET routes you have marked as trusted can run without a prompt. Other operations and raw-key access require approval. An agent cannot label its own request “safe.” |
| **YOLO** | Paired agents can use all stored keys without prompts, including raw-key access. Only choose this for agents you trust. |

The broker enforces these modes. Agent credentials cannot change modes, approve requests, add keys, or pair other agents. Mode changes cancel outstanding requests. Revoking an agent blocks its future broker access.

**The trust boundary matters:** a process that can read the vault host’s memory, owner browser session, or unattended unlock file can bypass this boundary. For untrusted agents, run the vault on a separate host or OS account. A raw key already released to a client cannot be recalled; rotate it at the provider when necessary.

### Add a key without putting it in chat

1. Choose **Add a key**. Enter a name, the provider’s exact API origin, and its
   required header and prefix. Latchlane can attach the value as a supported API-key
   header, or as `Bearer ` or `Basic ` authentication. It never guesses a provider’s
   header format.
2. Choose **Watch next copy**, copy the API key, and return to the vault window. Supported browsers save the next changed value automatically when the form is complete.
3. On browsers that block watching, use **Paste from clipboard** or paste into the masked field and choose **Encrypt & save**.

Keys are encrypted with AES-256-GCM. The browser attempts to clear the copied value after a successful save, preserving newer content where possible. Browser clipboard APIs cannot perform an atomic compare-and-clear; clipboard history and OS sync can retain copies. Mobile browsers generally require an explicit paste gesture.

## Pair an agent

In the owner console choose **Pair an agent**, then run:

```sh
latchlane pair http://127.0.0.1:9473 --name 'My coding agent'
```

Enter the five-minute pairing code in the hidden terminal prompt. The CLI saves its access credential privately. Do not paste pairing codes into model conversations.

Use the broker for API calls so the raw key stays on the vault host:

```sh
latchlane keys
latchlane request my-service /v1/models --purpose 'List available models'
```

For SDKs that require an environment variable:

```sh
latchlane run --purpose 'Run my trusted local client' my-service SERVICE_API_KEY -- python client.py
```

This requests raw-key access and passes the value directly to the child process. The CLI does not print it, but **the child can read, retain, or log it**. Prefer the API broker when possible.

### MCP

After pairing, add this stdio server to an MCP-capable agent:

```json
{
  "mcpServers": {
    "latchlane": {
      "command": "latchlane",
      "args": ["mcp"]
    }
  }
}
```

The tools list key names, request a brokered API operation, and consume an approved
request. The MCP surface never provides a raw-key retrieval tool. Run `latchlane mcp`
locally for the same stdio server and `latchlane mcp --help` for its CLI help.

## Your devices, connected

```sh
latchlane connect
```

The guide checks for Tailscale, links to account creation and installation if needed, invokes its browser sign-in, and configures **private Tailscale Serve HTTPS on port 8447**. It preserves existing routes and never enables Funnel.

Open the resulting private address on a phone, tablet, or another computer signed into your tailnet. Sign into the owner console with your passphrase, or pair a remote agent:

```sh
latchlane pair https://your-device.your-tailnet.ts.net:8447 --name 'Laptop agent'
```

Every device sees the same live vault and permissions. **Sync uses one online host, not offline replicas.** No credential database or decryption key is distributed to agent devices. The host must stay online and unlocked for agent operations.

On phones and tablets, use the browser console and choose its install option when available. That installed web app still uses the same online host and owner session.

Tailscale handles identity-provider sign-in in its own app/browser. Its separate [app OAuth](https://tailscale.com/docs/features/oauth-apps) is currently alpha and restricted to users within the app’s tailnet; Latchlane does not pretend there is a universal public OAuth app. You do not give Latchlane a Tailscale OAuth client secret. See [device setup](devices.md).

## Where it runs

| Device | Role |
| --- | --- |
| macOS, Windows, Linux · Python 3.11+ | Vault host, CLI, or agent client |
| iPhone, iPad, Android, Chromebook | Owner console through a current browser and Tailscale; explicit paste fallback |
| Headless server | Host using `latchlane init`, then `latchlane start --no-open` |
| Other devices | Browser access if HTTPS and Tailscale are supported; no claim of a native host everywhere |

Host/CLI tests run in the repository’s macOS, Windows and Linux CI matrix. Browser layout tests cover desktop and mobile widths; this is not a physical-device certification. Version 0.2.0 is an early public release, not an independently audited secrets manager.

The desktop app flow has live default-browser verification on macOS and Linux. Windows launcher support is provided, but Windows default-browser detection has not been verified for this release.

## Local options

`latchlane doctor` checks the broker host and this agent’s pairing without revealing
key values. It reports `agent_pairing_valid: true` only after the broker accepts the
saved pairing; `false` means unpaired or revoked; `null` means it cannot verify the
pairing, such as when the broker is locked or unavailable. It does not verify that a
stored provider credential is still accepted by its provider.

Use `latchlane doctor --url http://127.0.0.1:PORT` to check a host on a custom
local port. For a passphrase vault on a custom port, open its console with
`latchlane owner --url http://127.0.0.1:PORT`. `latchlane capture NAME --origin
https://api.example.com --header X-API-Key --prefix none` opens a compact named capture form. Header and prefix are optional; omitted values keep the form defaults. `latchlane start --port PORT`
chooses a different local port.

Latchlane uses the supported default Chromium browser when it can identify one. If your default is Safari or Firefox, it will not substitute another browser. Run `latchlane owner`, then use Safari’s Add to Dock or keep the console open in Firefox.

Choose a 24-hour or 30-day remembered owner session at sign-in. Both end when the vault locks or the host restarts. **Sign out** ends that browser session. Editing key metadata with an empty secret field keeps the current secret value.

Advanced users can deliberately choose unattended operation:

```sh
latchlane init --unattended --mode yolo
```

This stores a random unlock passphrase in a local permission-restricted file. It encrypts the vault on disk but does **not** protect against someone who can read both files. It is optional, never the installation default. Keep the host isolated from untrusted agents. To open the owner console for an unattended vault, use `latchlane owner` locally; this opens a short-lived owner session without printing a credential.

Storage lives in the OS user-data directory reported by `platformdirs`, outside the repository. `LATCHLANE_HOME` selects a different private profile. Keep the host profile separate from an untrusted agent profile. Never sync `unattended.key` or an agent credential through Git.

## Develop and verify

```sh
git clone https://github.com/baney75/latchlane
cd latchlane
uv sync --extra test
uv run pytest
```

Read [SECURITY.md](../SECURITY.md) for boundaries and reporting, [architecture](architecture.md) for the design, and [release checks](release-checks.md) for what was actually tested. No telemetry, analytics, or hosted account is part of Latchlane.

MIT licensed.
