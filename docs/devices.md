# Connect another device

Start with one trusted computer as the vault host. Keep it online for the devices
and agents that depend on it. A small private server also works.

1. Install Tailscale from https://tailscale.com/download on the host and your other
   devices. Create an account at https://login.tailscale.com/start if needed.
2. On the host, run `latchlane connect`. If not already connected, Tailscale handles
   browser sign-in directly. Latchlane never asks for an identity-provider password
   or Tailscale client secret. Complete the HTTPS consent Tailscale presents.
3. Restart `latchlane start` if it was launched before Tailscale joined the network.
4. Open the printed private HTTPS address on your other Tailscale devices. Sign in
   to the owner console with your vault passphrase. On agent computers, install the
   CLI and pair using a new one-use code from the owner console.

The connector uses HTTPS port 8447 so it does not replace a normal port-443 service.
If that route is occupied, it stops and preserves it. Never run `tailscale funnel`
on the vault port. Tailscale grants should limit reachability to your intended devices.

## What “sync” means

All devices use the same live vault through encrypted Tailscale connections. Agent
calls see the current policy. Browser consoles poll while connected, so refresh time
depends on their connection and browser throttling; no four-second guarantee applies.
Agent computers receive access tokens, not a copy of the master decryption key.
No offline vault copies are created. If you need independent offline replicas,
Latchlane does not provide that feature.

## Install the owner app

On a Mac vault host, `latchlane install-app` creates a searchable
`~/Applications/Latchlane.app` launcher and opens Latchlane with the normal supported
Chromium profile. Existing cookies and extensions remain in that browser profile; no
vault, key, pairing code, or agent credential is copied or migrated. It starts a local
host in the background when one is not running; it does not install an OS autostart
service.

On Linux, the same command creates a per-user `.desktop` launcher under the XDG data
directory. It uses the default browser only when that browser is a supported Chromium
browser. Custom `XDG_DATA_HOME` and `XDG_DATA_DIRS` locations are respected when
looking up the default browser. Unsupported defaults, such as Firefox, open the owner
console in that browser. On macOS, Safari users can choose **File → Add to Dock**;
that web app may ask them to sign in.

On iPhone, iPad, and Android, open the console in the device browser and use its
install or Add to Home Screen control when available. The installed web app still
uses the same online vault host; it is not an offline replica.

## OAuth, precisely

Tailscale's normal client sign-in uses its supported browser identity flow and lets
new users create an account. Latchlane invokes that client flow.

[Tailscale OAuth apps](https://tailscale.com/docs/features/oauth-apps) are currently
alpha and restricted to a single tailnet. One public OAuth app cannot onboard all
unrelated users' tailnets through that mechanism. Latchlane does not ship a shared
client secret or claim to implement such an app. For the encrypted network route,
see [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve).

## Mobile clipboard behavior

iOS and Android browsers normally require a user gesture to paste. Use the masked
field or Paste from clipboard. Watch next copy is available where browser clipboard
permissions support it, typically on desktop; return to the console after copying.
The UI never claims a clipboard was cleared if that operation failed.

## Host operation

For first setup on a headless server, run `latchlane init` in a private terminal.
Start with `latchlane start --no-open`, then use Tailscale to reach the console and
unlock the vault. `latchlane start` remains a foreground host and stops when its
process exits. Use your OS's service manager if persistent operation is wanted; the
CLI does not silently install an autostart service. `--unattended` is a separate,
explicit trust choice.
