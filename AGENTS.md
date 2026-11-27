# Repository notes

- KasswordManager is a dependency-free Chrome Manifest V3 extension for fictional test data. Use browser APIs and keep credentials in plaintext under the `testVaultByOrigin` key in `chrome.storage.local`.
- Write UI text, errors, and documentation in English. `TODO.md` is the Japanese planning document.

## Behavior to preserve

- Match both a configured origin and Chrome's host permission before serving requests from a top-level page. HTTP is for loopback hosts. A subdomain wildcard matches subdomains, and `:*` matches all ports. Key accounts by exact origin, including scheme and port, even when a wildcard authorizes the page.
- `sites.js` manages permissions and script registration. `background.js` routes messages, and `vault.js` serializes changes to account storage. `content.js` runs in the isolated world and shows suggestions and confirmations in the upper-right corner of the page.
- Password generation fills sign-up fields and saves on form submission. To save an entered password, choose an existing account or create one in the page popup. Field detection uses `autocomplete`, labels, and form structure.
- `qr.js` decodes dark, head-on QR Model 2 codes in versions 1 through 10. TOTP setup lets the user choose an account, and the vault shows the current code and time remaining. `one-time-code` fields offer TOTP autofill.
- `webauthn-page.js` wraps WebAuthn in the page world. `passkeys.js` scopes approvals to the requesting document, and `authenticator.js` produces ES256 responses with a publicly known, hardcoded private key shared by all test passkeys. The extension uses discoverable credentials, none attestation, and `credProps` when requested. Require the RP ID to match the page hostname and fall back to Chrome for unsupported requests.
- Simulated user verification returns `UV=1` after approval for `required` and `UV=0` for `discouraged`. For `preferred` or an omitted setting, the checkbox controls the flag.

## Local verification

Serve `tests/index.html` as described in the README. It exercises password generation and autofill, QR-based TOTP setup, and signature verification for both button-based and Conditional UI passkey sign-in. For Conditional UI, focus the field marked `autocomplete="username webauthn"` after registering a test passkey.

To check origin isolation, serve the test page on two ports and allow both origins. Save credentials on the first port and check that they are absent from the second port's suggestions.
