# Version 0.2.0 release evidence

## Observed locally

- The complete Python suite passed: 65 tests, including deterministic concurrency
  regressions.
- The complete Chromium flow passed with disposable data: setup mismatch, pairing,
  approve, deny, revoke, lock, key editing, 24-hour and 30-day sessions, compact
  capture, and cache behavior.
- Native Vivaldi app mode reported `display-mode: standalone`; the manifest and
  installability checks reported no errors, and the service worker was active.
- The macOS icon conversion produced a real `.icns`. Default-browser detection and
  background fixture-host startup were exercised locally.
- Dependency audit found no known vulnerabilities. Dependencies were unchanged.
- Gitleaks found no secrets in the Git history, final staged changes, or extracted
  release package.

The final Chromium suite passed after the clipboard cleanup correction. Native
Vivaldi also passed first setup, remembered sign-in, and prefilled manual capture
with immediate save confirmation. These checks used disposable vaults and profiles.

## Release CI

The [release workflow](https://github.com/baney75/latchlane/actions/workflows/test.yml)
checks the platform matrix. No CI result is recorded here until that workflow runs
for the release candidate.

## Limits

Remembered owner sessions end on vault lock or host restart. Safari and Firefox use
manual desktop-install guidance. Physical mobile-device behavior and Windows GUI
behavior were not tested locally. Latchlane is not an independently audited secrets
manager; see `SECURITY.md` for the trust boundary and recovery limits.
