# Version 0.3.0 release evidence

## Verified locally

- `uv run pytest -q` passed: 78 tests using disposable vaults and credentials.
- `uv run --with playwright python tests/browser_check.py` passed. It covers owner
  setup, pairing, approval, revocation, lock, key editing, and responsive owner
  layouts with disposable data.
- `uv run --with playwright python tests/browser_credentials.py` passed. It covers
  owner-reviewed collection completion, password type boundaries, 1Password,
  Bitwarden, Apple, and generic CSV mappings, partial selection, cancellation,
  malformed input, lock scrubbing, and 320px, 390px, and 1280px owner forms.
- The collection and import screenshots were inspected at desktop and 390px widths.
- The independent Python MCP SDK transcript passed with protocol `2024-11-05`:
  default MCP discovery returned five Latchlane tools and `--collections-only`
  returned only `latchlane_collect` and `latchlane_collection_status`.
- The default browser path was verified as
  `/Applications/Vivaldi.app/Contents/MacOS/Vivaldi`. Latchlane launches supported
  Chromium browsers in their normal profile; it does not create a separate profile.
- Dependency audit found no known vulnerabilities.

## CI coverage

The GitHub Actions matrix runs the Python suite on macOS, Windows, and Linux with
Python 3.11 and 3.13. The browser job installs Chromium and runs both browser
scripts. CI results must be read from the workflow for the commit being released;
this document does not claim a remote workflow run.

## Limits

These checks use disposable data and isolated profiles. They do not establish an
independent security audit, physical-device certification, provider acceptance of a
stored credential, a live Hermes account integration, or a connected ChatGPT tunnel.
Hermes and tunnel commands in [Agent integrations](agents.md) are prepared local
configuration instructions only.
