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

## 🔍 Self-audit (23 November 2026)

The repo's own scanner (`secret_scan` 0.4.0) was run over fresh clones of
all six of Ronak's public repos. No real secret was found in any of them.

| Repo (HEAD) | Files scanned | Findings | Result |
|---|---|---|---|
| encryption (`ed147de`) | 18 | 13 | All 13 are the scanner's own test fixtures (see below) |
| weather-ai-predictor (`738a99c`) | 15 | 0 | Clean |
| Chessmate (`ce6c84a`) | 7 | 0 | Clean |
| yt-ai (`53726aa`) | 9 | 0 | Clean |
| unit-conversion (`3a77589`) | 12 | 0 | Clean (`omniconvert-pro.zip` skipped — binary, not scanned) |
| gesture-to-speech (`6e140f4`) | 19 | 0 | Clean |

The 13 findings in `encryption` are all in `secret_scan`'s own test files
(`tests/test_detect.py`, `tests/test_entropy.py`, `tests/test_report.py`,
`tests/test_scan.py`) and all synthetic by construction: Amazon's documented
example key (shown here redacted as `AKIA...MPLE`, exactly as the scanner
prints it), bare private-key header strings with no
key body, and hand-written test strings such as `correct-horse-battery-staple-99`.
They stay in place because the tests need them; nothing was removed, and no
real credential was found, so no fix was needed.

## 👤 Author

Built by **Ronak Kumar** — student developer from Mithi, Pakistan, working toward Computer Science at MIT.
