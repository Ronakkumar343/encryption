# 🔐 CryptoVault Pro

A local-first security toolkit for encrypting messages and files, hashing, digital signatures, and password generation — all in one dark-themed, responsive web app.

**Zero data leaves your device.** Everything runs locally: no accounts, no server-side storage, no tracking.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat&logo=streamlit&logoColor=white)

## ✨ Features

- **Text encryption** — Encrypt and decrypt messages with AES-256-GCM, using a key derived from your password.
- **File encryption** — Encrypt and decrypt files up to 50 MB with the same authenticated encryption.
- **Hashing** — Hash text or files with multiple algorithms.
- **HMAC** — Generate message authentication codes to prove data hasn't been tampered with.
- **Digital signatures** — Generate Ed25519 key pairs, sign data, and verify signatures.
- **Password generator** — Strong random passwords (configurable length, digits, symbols) with a built-in strength meter.
- **Base64 tools** — Encode and decode Base64.
- **Random bytes generator** — Cryptographically secure random data.
- **File integrity checker** — Compare file hashes to confirm a file is unchanged.

## 🔒 How the encryption works

- **Algorithm:** AES-256-GCM (authenticated encryption — tampering is detected on decrypt)
- **Key derivation:** PBKDF2-HMAC stretches your password into a 256-bit key using a random salt
- **Nonce:** a fresh random nonce is generated for every encryption, so encrypting the same message twice produces different output

Passwords are never stored anywhere. If you lose the password for an encrypted message or file, it cannot be recovered — by design.

## 🚀 Run it locally

```bash
git clone https://github.com/Ronakkumar343/encryption.git
cd encryption
pip install -r requirements.txt
streamlit run encryption.py
```

**Requirements:** Python 3, `streamlit>=1.28.0`, `cryptography>=41.0.0`

## 🗂️ Project structure

```
encryption.py      — the entire app: crypto core + Streamlit UI (729 lines)
requirements.txt   — Python dependencies
```

## 👤 Author

Built by **Ronak Kumar** — student developer from Mithi, Pakistan, working toward Computer Science at MIT.
