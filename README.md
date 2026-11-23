# Password Manager for Test

A Chrome extension for managing test accounts with non-sensitive credentials. **Never use it with real accounts.** Passwords and TOTP secrets are stored in plaintext. All passkeys share a publicly known, hardcoded private key.

## Install

Enable **Developer mode** at `chrome://extensions`, choose **Load unpacked**, and select this directory. Configure **Allowed sites** in the popup, grant site access, and reload the page.

Accounts are scoped to the exact origin, including scheme and port.

## Test

```sh
python3 -m http.server 8000 --bind 127.0.0.1 --directory tests
```

Allow `http://127.0.0.1:8000` in the extension and open it.

[MIT License](LICENSE).
