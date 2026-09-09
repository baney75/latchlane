# Password-manager CSV import

Latchlane imports an owner-selected CSV into the owner console. It is for
reviewing a small batch of logins before saving them as password credentials. The
CSV is parsed in that browser. Latchlane does not upload it to a third-party service,
log its values, keep it in browser storage, or delete the source export. When the
configured vault host is another computer through Tailscale, only the explicitly
selected and reviewed credential fields are sent to that vault host for encryption.
CSV exports are plaintext, so store or remove the original according to your own
backup and password-manager practice.

The importer reads at most 1 MiB, parses at most 200 records, and saves at most 20
explicitly selected records in one batch. Secret values remain masked in review.
No row is selected automatically. Cancel, successful save, lock, logout, and page
hide clear the import state and file control.

## Supported CSV columns

The importer recognizes these common login columns and presents a mapping review
when it cannot match them. You can map a generic CSV manually before review.

| Stored field | Recognized columns |
| --- | --- |
| Name | `Title`, `Name`, `name` |
| HTTPS destination | `Website`, `URL`, `Url`, `login_uri` |
| Username | `Username`, `User Name`, `login_username` |
| Password | `Password`, `login_password` |

1Password 8 CSV Login items normally use `Title`, `Website`, `Username`, and
`Password` as described in [1Password’s export guide](https://support.1password.com/export/).
Bitwarden individual-vault CSV login items use `name`, `login_uri`,
`login_username`, and `login_password`; its organization-vault export uses the same
login fields with a different leading collection column. See Bitwarden’s
[CSV import format](https://bitwarden.com/help/condition-bitwarden-import/).
Apple Passwords CSV exports are mapped by the common title/name, URL, username, and
password aliases because Apple does not publish a stable public CSV header contract;
see Apple’s [export instructions](https://support.apple.com/en-ge/guide/passwords/mchl35b12625/2.0/mac/26).

Only valid HTTPS origins can be saved. Review every inferred destination, type, and
name. The importer does not infer provider authentication headers or trusted API
routes from a password-manager export.

## What import and autofill cannot do

The importer accepts CSV only. It does not import `.1pux`, Bitwarden JSON, Apple
keychain databases, browser profiles, or other proprietary formats. It does not
import passkeys, TOTP or one-time-password values, security questions, notes,
custom fields, cards, identities, shared vault access, or Sign in with Apple access.

The normal add/edit password form names its username and password fields so a
browser or installed password-manager extension may offer its ordinary autofill
interface. That behavior is controlled by the browser and the credential provider.
Latchlane cannot select, scrape, export, or automatically fill a login stored for a
different website. Use the password-manager extension to choose a saved login, or
paste into the masked field yourself.

Passwords saved in Latchlane are Unicode-capable and lease-only. They never travel
through Latchlane's HTTP broker as a header, including in YOLO. A raw lease can pass
one to a trusted child process through the existing owner-controlled flow; it does
not automate a website login.
