# CipherLab - Web-Based Text Encryption Tool

A single-page web application for encrypting, decrypting and hashing text. Built for **Assignment 2: Web-Based Text Encryption Tool** using HTML, CSS, JavaScript, and a Node.js backend. No third-party packages or API keys are needed.

## Features

- Encrypt and decrypt using **Caesar Cipher**, **Vigenère Cipher**, and **AES-256-GCM**.
- Generate a one-way **SHA-256** hash (hashes cannot be decrypted).
- Copy the result, clear the form, and view understandable error messages.
- Prevent empty text, missing algorithm, or invalid encryption keys.
- Responsive single-page UI, output panel, live character count, and explanatory algorithm cards.
- AES encryption uses Node.js `crypto`, a 32-byte scrypt-derived key, fresh 16-byte random salt, fresh 12-byte random IV, and a 16-byte authentication tag.
- No database, accounts, external services, logging of messages, or storage of submitted text.

## Requirements

Install **Node.js 18 or newer** from https://nodejs.org/ (Node 22 is also supported).

## Start on Windows, macOS or Linux

1. Open Terminal, PowerShell, or VS Code terminal inside `text-encryption-tool`.
2. Run:

   ```bash
   npm start
   ```

4. Visit **http://127.0.0.1:3000** in your browser.
5. Stop the server with **Ctrl+C**.

`npm install` is not necessary: all dependencies come with Node.js.

If port 3000 is occupied, Windows PowerShell: `$env:PORT=3001; npm start`; macOS/Linux: `PORT=3001 npm start`. Open the corresponding URL.

**Do not** open `index.html` by double-clicking it: use the Node.js server so the `/api/process` endpoint exists.

## Example: Caesar encryption + decryption

1. Select **Encrypt** and **Caesar Cipher**.
2. Enter `HELLO WORLD` and set shift to `3`.
3. Click **Encrypt text**; output: `KHOOR ZRUOG`.
4. Copy the output, switch to **Decrypt**, select **Caesar Cipher**, paste the ciphertext, and enter shift `3`.
5. Click **Decrypt text**; original text returns.

## Example: AES-256-GCM

Select Encrypt > AES-256-GCM. Enter `My secret message` with the passphrase `correct horse battery staple`, then Encrypt. Copy the entire output starting with `AES256GCM.v1.`. To decrypt, switch to Decrypt > AES-256-GCM, paste the whole output and use the *same* passphrase. AES results differ with every encryption because a new salt and nonce are generated.



## Example: SHA-256

Select SHA-256 Hash, input `abc`, then Generate hash. The output is:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

A hash is not encrypted text and cannot be decrypted.

## Testing

```bash
npm test
```

Tests check classical cipher examples and reversibility, AES encryption/decryption and tampering detection, SHA-256, validation, and real HTTP endpoints.

## Project structure

```text
text-encryption-tool/
├── public/
│   ├── index.html       # semantic responsive web interface
│   ├── styles.css       # dark styling and mobile layout
│   ├── app.js           # controls, validation, fetch, copy
│   └── favicon.svg
├── tests/
│   └── crypto.test.js   # automated tests
├── docs/
│   └── screenshot_validation.png
├── crypto.js            # algorithms and backend validation
├── server.js            # HTTP server and POST /api/process
├── package.json
└── README.md
```

## API

`POST /api/process` with `Content-Type: application/json`:

```json
{"mode":"encrypt","method":"caesar","text":"HELLO","key":"3"}
```

Response: `{"result":"KHOOR","irreversible":false}`. Modes: `encrypt`, `decrypt`, `hash`. Methods for encrypt/decrypt: `caesar`, `vigenere`, `aes`. Hash ignores method and key. Invalid requests return HTTP 400 with an `error` string.

## Algorithms: educational and security notes

| Technique | Use | Security note |
| --- | --- | --- |
| Caesar | Alphabet shift by integer 1-25 | Easy to break; learning only |
| Vigenère | Repeating A-Z keyword | Historically important; learning only |
| AES-256-GCM | Modern authenticated encryption | Use long, unique passphrases; this is a classroom demo, not an audited service |
| SHA-256 | One-way cryptographic hash | Not reversible and not appropriate as a standalone password-storage system |

Caesar and Vigenère process **ASCII English A-Z letters only**; punctuation, numbers, whitespace, and other Unicode symbols remain unchanged. AES and SHA-256 process Unicode text as UTF-8.

The AES format is `AES256GCM.v1.<salt>.<iv>.<tag>.<ciphertext>` where binary fields use base64url. The format, salt and IV are not secret. The authentication tag detects an incorrect passphrase or ciphertext changes. AES and hash computations happen on the local Node server, so use it locally rather than deploying over the internet without HTTPS, authentication, security hardening, and an independent review.



## References

- Node.js cryptography documentation: https://nodejs.org/api/crypto.html
- NIST FIPS 197, Advanced Encryption Standard (AES): https://csrc.nist.gov/pubs/fips/197/final
- NIST FIPS 180-4, Secure Hash Standard: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
