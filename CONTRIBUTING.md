# Contributing to Latchlane

Help make the first key capture, approval, or device connection easier to get right.
Open an issue with the behavior you expected, what happened, and your OS and browser.
Use disposable credentials in reproductions. Never attach a real vault, pairing code,
agent token, clipboard contents, or private Tailscale address.

For security reports, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Work locally

```sh
git clone https://github.com/baney75/latchlane
cd latchlane
uv sync --extra test
uv run pytest
```

The browser check uses a temporary vault and disposable credentials:

```sh
uv run --with playwright playwright install chromium
uv run --with playwright python tests/browser_check.py
```

Keep changes focused. Explain the user-visible behavior and include a check that
would fail without your fix. Changes to permissions or credential handling need
failure-path coverage, including failed persistence and revoked access. UI changes
should include desktop and narrow-screen screenshots made with fixture data.

Use relative documentation links, runnable commands, and claims supported by the
implementation. Keep the README focused on understanding and starting the product;
put detailed operating instructions in the guide.
