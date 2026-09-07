# Using Latchlane

## Start here

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```sh
uv tool install 'git+https://github.com/baney75/latchlane@v0.1.1'
latchlane start
```

Your browser opens the setup screen. Create a passphrase, then add your first key. The passphrase is not stored by default. Keep it in your password manager; there is no reset backdoor.

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

1. Choose **Add a key**. Enter a name and the provider’s exact API origin.
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

The tools list key names, request a brokered API operation, and consume an approved request. The MCP surface never provides a raw-key retrieval tool.

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

Tailscale handles identity-provider sign-in in its own app/browser. Its separate [app OAuth](https://tailscale.com/docs/features/oauth-apps) is currently alpha and restricted to users within the app’s tailnet; Latchlane does not pretend there is a universal public OAuth app. You do not give Latchlane a Tailscale OAuth client secret. See [device setup](devices.md).

## Where it runs

| Device | Role |
| --- | --- |
| macOS, Windows, Linux · Python 3.11+ | Vault host, CLI, or agent client |
| iPhone, iPad, Android, Chromebook | Owner console through a current browser and Tailscale; explicit paste fallback |
| Headless server | Host using `latchlane init`, then `latchlane start --no-open` |
| Other devices | Browser access if HTTPS and Tailscale are supported; no claim of a native host everywhere |

Host/CLI tests run in the repository’s macOS, Windows and Linux CI matrix. Browser layout tests cover desktop and mobile widths; this is not a physical-device certification. Version 0.1 is an early public release, not an independently audited secrets manager.

## Local options

`latchlane doctor` checks readiness without revealing keys. `latchlane capture NAME --origin https://api.example.com` opens a named capture form. `latchlane start --port PORT` chooses a different local port.

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
