<p align="center">
  <img src="docs/banner.svg" alt="Latchlane — Your keys. Your agents. Your call." width="880">
</p>

<p align="center">
  An encrypted API-key vault that asks before your agent acts.
  <br>
  Capture a key locally. Pair your agent. Decide what it can do.
</p>

<p align="center">
  <a href="https://github.com/baney75/latchlane/actions/workflows/test.yml"><img src="https://github.com/baney75/latchlane/actions/workflows/test.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/baney75/latchlane/releases"><img src="https://img.shields.io/github/v/release/baney75/latchlane?include_prereleases&color=245c45" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-245c45" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#get-started">Get started</a> ·
  <a href="docs/getting-started.md">Guide</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="https://github.com/baney75/latchlane/issues">Help & feedback</a>
</p>

## A key should not become a chat message

Latchlane keeps API keys in a vault on a computer you control. Agents request an operation through its CLI or MCP server; the broker attaches the credential and calls the provider. You see who is asking, what they want to do, and why.

The owner console handles clipboard capture, approvals, and revocation. Optional Tailscale access connects your other devices to the same vault. No hosted Latchlane account, telemetry, or macOS Keychain dependency.

## Get started

Give your agent this prompt:

```text
Set up Latchlane using https://github.com/baney75/latchlane
and its skills/latchlane/SKILL.md. Install the CLI and skill, run
latchlane install-app, then open it with latchlane app if needed.
Guide me through creating a vault and pairing my agent.
Keep Always ask on unless I choose otherwise. I will enter
passphrases and keys locally, never in chat. Ask whether I
want to connect my other devices through Tailscale.
```

Or start it yourself with [uv](https://docs.astral.sh/uv/getting-started/installation/) and Python 3.11+:

```sh
uv tool install 'git+https://github.com/baney75/latchlane@v0.2.0'
latchlane install-app
```

Latchlane installs and opens a dedicated app window with its own browser profile. Create a passphrase, choose **Add a key**, name it, and choose **Watch next copy**. Copy your key and return to the window; Latchlane encrypts it when the form is complete. Browsers that block clipboard watching offer a masked paste field. Later, open the Latchlane launcher from your Applications or Start Menu. If the default browser is Safari or Firefox, use `latchlane owner`, then add the console to Safari’s Dock or use it in Firefox. Latchlane will not substitute another browser. [Technical host setup →](docs/getting-started.md#start-here)

Choose a 24-hour or 30-day remembered owner session at sign-in; both end on lock or host restart. An agent can open a compact owner-visible capture window with `latchlane capture NAME --origin HTTPS_ORIGIN`, optionally prefilling the authentication header and prefix. The agent never receives the secret value.

## You choose how often agents ask

| Mode | Agent access |
| :--- | :--- |
| **Always ask** · installed default | You approve each use. Approval expires after five minutes and works once. |
| **Auto approve** | Only exact GET routes you previously trusted run without a prompt. Everything else requires approval. |
| **YOLO** | Paired agents can use every key without asking, including raw-key access. |

Agents cannot change the mode or approve themselves. The broker enforces the policy; a prompt is not the security boundary.

![The Latchlane owner console with permission controls and a saved example key](docs/console.png)

## Use it from your tools

After [pairing](docs/getting-started.md#pair-an-agent), an agent can list key names and make a request:

```sh
latchlane keys
latchlane request my-service /v1/models --purpose 'List available models'
```

The [MCP integration](docs/getting-started.md#mcp) exposes the same brokered workflow. For a trusted SDK that needs an environment variable, [`latchlane run`](docs/getting-started.md#pair-an-agent) can release a key directly to one child process. That process can read or retain it.

## One vault, across your devices

Run `latchlane connect` for guided Tailscale installation, browser sign-in, and private HTTPS. Use the console from a phone or pair an agent on another computer. On a phone or tablet, open the console in a browser and use its install option when available. This connects to **one online vault host**; it does not make offline copies of your secrets.

The host and CLI support macOS, Windows, and Linux. Phones and tablets use the browser console with an explicit paste fallback. [Device setup and requirements →](docs/devices.md)

## Know what protects your keys

Vault contents use AES-256-GCM with a passphrase-derived scrypt key. The passphrase is not saved by default. Agent pairing is revocable, and broker requests stay within the provider origin you configured.

A process with access to the host’s memory or owner session can bypass broker permissions. Keep untrusted agents on a separate host or OS account. Clipboard history may retain copied secrets. Optional unattended unlocking trades passphrase protection for host access controls.

This is an early release, with cross-platform CI and adversarial regression tests, **not an independently audited secrets manager**. Read the [security boundaries](SECURITY.md) before storing production credentials.

---

[Architecture](docs/architecture.md) · [Test evidence](docs/release-checks.md) · [Contributing](CONTRIBUTING.md) · [MIT license](LICENSE)
