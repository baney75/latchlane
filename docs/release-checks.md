# Version 0.2.1 release evidence

## Observed locally

- The complete Python suite passed: 71 tests, including deterministic concurrency
  regressions.
- The retained disposable Chromium evidence covers setup mismatch, pairing, approve,
  deny, revoke, lock, key editing, 24-hour and 30-day sessions, compact capture, and
  cache behavior. It predates this candidate’s install-profile change.
- For this candidate, a separate disposable Node Playwright fixture covered the
  pre-unlock installation guide at desktop and 390px mobile widths, including a
  native-install event fixture and the non-secret agent setup prompt.
- The 0.2.0 Vivaldi PWA installability, standalone display, and capture checks are
  reused unchanged. They do not prove a fresh native install for 0.2.1.
- For 0.2.1, the macOS launcher was observed opening the normal Vivaldi profile with
  `--app` and the existing browser PID, rather than creating an isolated profile. The
  explicit console URL was preserved.
- The macOS icon conversion produced a real `.icns`. Linux default-browser handling
  has unit and CI coverage; no live Linux desktop session was observed.
- Dependency audit found no known vulnerabilities. Dependencies were unchanged.
- Gitleaks found no secrets in the Git history, final staged changes, or extracted
  release package.

The retained Chromium suite passed after the clipboard cleanup correction. The earlier
native Vivaldi first setup, remembered sign-in, and prefilled manual capture evidence
used disposable vaults and profiles; it is historical context rather than fresh 0.2.1
native setup proof.

## Install-profile lesson

The launcher must open the user’s default supported Chromium profile with `--app`, so
their existing browser session and extensions behave as they do in the normal browser.
It must preserve an explicitly supplied console URL. The earlier check passed only
because it asserted an isolated disposable profile argument, which proved a fixture
launch but missed the product requirement. Browser checks now need to assert the
default-profile launch shape as well as the app URL.

## Release CI

The [release workflow](https://github.com/baney75/latchlane/actions/workflows/test.yml)
checks the platform matrix. No CI result is recorded here until that workflow runs
for the release candidate.

## Limits

Remembered owner sessions end on vault lock or host restart. Safari and Firefox use
manual desktop-install guidance. Physical mobile-device behavior and Windows GUI
behavior were not tested locally. Latchlane is not an independently audited secrets
manager; see `SECURITY.md` for the trust boundary and recovery limits.
