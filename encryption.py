"""
CryptoVault Pro — Advanced Security Toolkit (Responsive)
==========================================================
Install: pip install streamlit cryptography
Run:     streamlit run app.py

Features:
  • AES‑256‑GCM text & file encryption (password‑based)
  • SHA‑256 / SHA‑512 / SHA‑3 hashing
  • HMAC (keyed hash)
  • Ed25519 digital signatures for messages & files
  • Strong password generator & strength meter
  • Base64 encode / decode
  • Random bytes & UUID generator
  • File integrity checker (compare hashes)
  • Fully responsive UI for desktop & mobile
  • Zero‑knowledge: all processing is local

Author: Ronak Kumar — https://ronakprogrammer.netlify.app
"""

import streamlit as st
import os
import base64
import hashlib
import hmac as hmac_module
import secrets
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend

# ============================================================
# Page config
# ============================================================
st.set_page_config(
    page_title="CryptoVault Pro",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# Responsive CSS – dark theme, mobile‑first adaptations
# ============================================================
def inject_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@600&family=Inter:wght@400;600&display=swap');

    /* Base */
    .stApp {
        background: #0e1117;
        color: #e0e0e0;
        font-family: 'Inter', sans-serif;
    }

    /* Hero */
    .hero {
        text-align: center;
        padding: 1.5rem 0 1rem 0;
    }
    .hero h1 {
        font-family: 'Orbitron', sans-serif;
        font-size: clamp(2rem, 5vw, 2.8rem);
        background: linear-gradient(135deg, #00d2ff, #3a7bd5);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 15px rgba(0,210,255,0.3);
        margin-bottom: 0.2rem;
    }
    .hero .subtitle {
        font-size: 1rem;
        color: #8a9bb5;
        margin-top: 0.3rem;
    }
    .hero .crafted {
        font-size: 0.9rem;
        color: #6b7280;
        margin-top: 0.2rem;
    }
    .hero a {
        color: #00d2ff;
        text-decoration: none;
        font-weight: 600;
    }
    .hero a:hover {
        text-decoration: underline;
    }

    /* Cards */
    .card {
        background: rgba(20,22,35,0.9);
        border: 1px solid #2a2a3c;
        border-radius: 16px;
        padding: 2rem;
        margin: 1rem 0;
        box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }

    /* Buttons */
    .stButton > button {
        font-weight: 600;
        border-radius: 12px;
        background: linear-gradient(135deg, #00d2ff, #3a7bd5);
        color: white;
        border: none;
        padding: 0.7rem 2rem;
        box-shadow: 0 0 15px rgba(0,210,255,0.3);
        transition: 0.2s;
        width: 100%;               /* full width on small screens */
        max-width: 300px;
    }
    .stButton > button:hover {
        box-shadow: 0 0 25px rgba(0,210,255,0.6);
        transform: translateY(-2px);
    }

    /* Download buttons */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #10b981, #059669) !important;
        box-shadow: 0 0 12px rgba(16,185,129,0.3);
        width: 100%;
        max-width: 300px;
    }
    .stDownloadButton > button:hover {
        box-shadow: 0 0 20px rgba(16,185,129,0.6);
    }

    /* Inputs */
    div[data-baseweb="input"], div[data-baseweb="textarea"] {
        background: #1a1d28 !important;
        border: 1px solid #2d3748 !important;
        border-radius: 10px !important;
        color: #d1d5db !important;
    }

    /* Code blocks */
    pre, code {
        background: #0f1119 !important;
        border: 1px solid #2d3748;
        border-radius: 12px;
        padding: 1rem;
        white-space: pre-wrap;
        word-break: break-all;
        color: #cbd5e1;
    }

    /* Strength bar */
    .strength-bar {
        height: 6px;
        border-radius: 3px;
        margin-top: 5px;
    }

    /* Footer */
    .footer {
        text-align: center;
        margin-top: 3rem;
        padding: 1.5rem 1rem;
        border-top: 1px solid #2a2a3c;
        color: #6c7a9c;
        font-size: 0.9rem;
    }
    .footer a {
        color: #00d2ff;
        text-decoration: none;
        font-weight: 600;
    }
    .footer a:hover {
        text-decoration: underline;
    }

    /* ======= Mobile specific ======= */
    @media (max-width: 768px) {
        .hero h1 {
            font-size: 2rem !important;
        }
        .hero .subtitle {
            font-size: 0.9rem;
        }
        .card {
            padding: 1.2rem;
            margin: 0.8rem 0;
        }
        .stButton > button, .stDownloadButton > button {
            padding: 0.7rem 1.5rem;
            font-size: 0.95rem;
        }
        /* Make columns stack without extra spacing */
        [data-testid="column"] {
            padding-left: 0 !important;
            padding-right: 0 !important;
        }
        /* Adjust radio buttons for touch */
        .stRadio > div {
            flex-direction: column;
        }
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: #131720;
        border-right: 1px solid #1f2937;
    }
    .sidebar-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.4rem;
        color: #00d2ff;
        text-align: center;
        padding: 1rem 0 0.5rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

# ============================================================
# Cryptographic constants
# ============================================================
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
PBKDF2_ITERATIONS = 600_000

# ============================================================
# Core crypto functions
# ============================================================
def derive_key(salt: bytes, password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_text(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(salt, password)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(salt + nonce + ciphertext).decode("ascii")

def decrypt_text(payload: str, password: str) -> str:
    try:
        combined = base64.urlsafe_b64decode(payload)
    except Exception:
        raise ValueError("Invalid base64 encoding.")
    if len(combined) < SALT_LEN + NONCE_LEN + 1:
        raise ValueError("Payload too short or tampered.")
    salt = combined[:SALT_LEN]
    nonce = combined[SALT_LEN:SALT_LEN+NONCE_LEN]
    ciphertext = combined[SALT_LEN+NONCE_LEN:]
    key = derive_key(salt, password)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

def encrypt_file_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(salt, password)
    aesgcm = AESGCM(key)
    return salt + nonce + aesgcm.encrypt(nonce, data, None)

def decrypt_file_bytes(data: bytes, password: str) -> bytes:
    if len(data) < SALT_LEN + NONCE_LEN + 1:
        raise ValueError("File too short.")
    salt = data[:SALT_LEN]
    nonce = data[SALT_LEN:SALT_LEN+NONCE_LEN]
    ciphertext = data[SALT_LEN+NONCE_LEN:]
    key = derive_key(salt, password)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def hash_data(data: bytes, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()

def hmac_data(key: bytes, message: bytes, algo: str) -> str:
    h = hmac_module.new(key, message, digestmod=algo)
    return h.hexdigest()

def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

def sign_data(private_pem: bytes, message: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    return private_key.sign(message)

def verify_signature(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(public_pem)
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False

def generate_strong_password(length=24, upper=True, digits=True, symbols=True):
    chars = "abcdefghijklmnopqrstuvwxyz"
    if upper:
        chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if digits:
        chars += "0123456789"
    if symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.<>?"
    return ''.join(secrets.choice(chars) for _ in range(length))

# ============================================================
# UI helpers
# ============================================================
def copy_button(text: str, label: str = "📋 Copy"):
    """Custom HTML copy button."""
    escaped = text.replace("`", "\\`").replace("$", "\\$")
    html = f"""
    <div style="margin:0.4rem 0;">
        <button id="cpbtn" style="
            background: linear-gradient(135deg, #00d2ff, #3a7bd5);
            border: none; border-radius: 8px; color: white;
            padding: 0.5rem 1.5rem; font-weight: 600;
            cursor: pointer; box-shadow: 0 0 10px rgba(0,210,255,0.3);
            transition: 0.2s; width:100%; max-width:200px;"
            onmouseover="this.style.boxShadow='0 0 20px rgba(0,210,255,0.7)';"
            onmouseout="this.style.boxShadow='0 0 10px rgba(0,210,255,0.3)';"
            onclick="
                navigator.clipboard.writeText(`{escaped}`).then(() => {{
                    this.innerText = '✓ Copied';
                    this.style.background = '#10b981';
                    setTimeout(() => {{
                        this.innerText = '{label}';
                        this.style.background = 'linear-gradient(135deg, #00d2ff, #3a7bd5)';
                    }}, 2000);
                }}).catch(() => alert('Copy failed'));
            ">{label}</button>
    </div>
    """
    st.components.v1.html(html, height=50)

def output_with_copy(text: str, copy_label="📋 Copy"):
    st.code(text, language="text")
    copy_button(text, copy_label)

def password_strength_meter(pw: str):
    if not pw:
        return
    length = len(pw)
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(not c.isalnum() for c in pw)
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_lower and has_upper: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    if score <= 2:
        label, color, width = "Weak", "#ef4444", "33%"
    elif score <= 3:
        label, color, width = "Moderate", "#f59e0b", "66%"
    else:
        label, color, width = "Strong", "#10b981", "100%"
    st.markdown(
        f"<div style='font-size:0.8rem; color:{color}; margin-top:4px;'>{label}</div>"
        f"<div class='strength-bar' style='background:{color}; width:{width};'></div>",
        unsafe_allow_html=True
    )

def file_uploader_restricted(label, max_mb=50):
    f = st.file_uploader(label)
    if f and f.size > max_mb * 1024 * 1024:
        st.error(f"File too large (max {max_mb} MB)")
        return None
    return f

# ============================================================
# Feature modules
# ============================================================
def text_encrypt():
    st.subheader("🔒 Encrypt a message")
    with st.form("enc_form"):
        msg = st.text_area("Message", height=120, placeholder="Type your secret here...")
        pw = st.text_input("Password", type="password", placeholder="Strong password")
        password_strength_meter(pw)
        if st.form_submit_button("Encrypt"):
            if not msg.strip():
                st.warning("Enter a message.")
            elif not pw:
                st.warning("Enter a password.")
            else:
                with st.spinner("Encrypting..."):
                    enc = encrypt_text(msg, pw)
                st.success("Encrypted!")
                output_with_copy(enc, "📋 Copy Ciphertext")

def text_decrypt():
    st.subheader("🔓 Decrypt a message")
    enc = st.text_area("Encrypted text", height=120, placeholder="Paste the ciphertext...")
    pw = st.text_input("Password", type="password", key="dec_pw", placeholder="Your password")
    if st.button("Decrypt"):
        if not enc.strip():
            st.warning("Paste encrypted text.")
        elif not pw:
            st.warning("Enter password.")
        else:
            with st.spinner("Decrypting..."):
                try:
                    original = decrypt_text(enc.strip(), pw)
                    st.success("Decrypted!")
                    st.code(original, language="text")
                except ValueError as e:
                    st.error(f"Failed: {e}")

def file_encrypt():
    st.subheader("📁 Encrypt a file")
    f = file_uploader_restricted("Choose file", 50)
    pw = st.text_input("Password", type="password", key="fenc_pw", placeholder="Strong password")
    password_strength_meter(pw)
    if st.button("Encrypt File"):
        if not f:
            st.warning("Select a file.")
        elif not pw:
            st.warning("Enter password.")
        else:
            with st.spinner("Encrypting..."):
                enc = encrypt_file_bytes(f.read(), pw)
                out_name = f.name + ".enc"
                st.success("Done!")
                st.download_button("💾 Download encrypted file", enc, file_name=out_name)

def file_decrypt():
    st.subheader("📂 Decrypt a file")
    f = file_uploader_restricted("Choose encrypted file (.enc)", 50)
    pw = st.text_input("Password", type="password", key="fdec_pw", placeholder="Your password")
    if st.button("Decrypt File"):
        if not f:
            st.warning("Select a file.")
        elif not pw:
            st.warning("Enter password.")
        else:
            with st.spinner("Decrypting..."):
                try:
                    original = decrypt_file_bytes(f.read(), pw)
                    out_name = f.name[:-4] if f.name.endswith(".enc") else "decrypted_" + f.name
                    st.success("Decrypted!")
                    st.download_button("📥 Download original file", original, file_name=out_name)
                except ValueError as e:
                    st.error(f"Wrong password or corrupt file: {e}")

def hashing_module():
    st.subheader("#️⃣ Hash generator")
    algo = st.selectbox("Algorithm", ["sha256", "sha512", "sha3_256"])
    mode = st.radio("Input", ["Text", "File"])
    data = None
    if mode == "Text":
        txt = st.text_area("Text to hash", height=120, placeholder="Enter text...")
        if txt:
            data = txt.encode()
    else:
        f = file_uploader_restricted("Upload file", 50)
        if f:
            data = f.read()
    if st.button("Compute Hash"):
        if not data:
            st.warning("Provide input.")
        else:
            digest = hash_data(data, algo)
            st.success(f"{algo.upper()}:")
            output_with_copy(digest, "📋 Copy hash")

def hmac_module():
    st.subheader("🔏 HMAC (keyed hash)")
    algo = st.selectbox("Hash algorithm", ["sha256", "sha512", "sha3_256"])
    key_mode = st.radio("Key input", ["Text", "Hex bytes"])
    key_bytes = None
    if key_mode == "Text":
        key_text = st.text_input("Secret key (text)", type="password")
        if key_text:
            key_bytes = key_text.encode()
    else:
        key_hex = st.text_input("Secret key (hex)", placeholder="e.g., 0a1b2c")
        if key_hex:
            try:
                key_bytes = bytes.fromhex(key_hex)
            except ValueError:
                st.error("Invalid hex string")
    msg_mode = st.radio("Message input", ["Text", "File"])
    message_bytes = None
    if msg_mode == "Text":
        msg_text = st.text_area("Message", height=100)
        if msg_text:
            message_bytes = msg_text.encode()
    else:
        msg_file = file_uploader_restricted("Upload file", 50)
        if msg_file:
            message_bytes = msg_file.read()
    if st.button("Compute HMAC"):
        if not key_bytes:
            st.warning("Provide a secret key.")
        elif not message_bytes:
            st.warning("Provide a message.")
        else:
            hmac_digest = hmac_data(key_bytes, message_bytes, algo)
            st.success("HMAC:")
            output_with_copy(hmac_digest, "📋 Copy HMAC")

def signature_module():
    st.subheader("✍️ Ed25519 Digital Signatures")
    if "ed_keys" not in st.session_state:
        st.session_state.ed_keys = None
    if st.button("⚡ Generate new keypair"):
        priv, pub = generate_ed25519_keypair()
        st.session_state.ed_keys = (priv, pub)
        st.success("Keypair generated!")
    if st.session_state.ed_keys:
        priv, pub = st.session_state.ed_keys
        st.markdown("**Public key:**"); st.code(pub.decode())
        st.download_button("📥 Download public key", pub, "public.pem")
        st.markdown("**Private key (keep secret!):**"); st.code(priv.decode())
        st.download_button("📥 Download private key", priv, "private.pem")
        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Sign a message or file")
            sign_mode = st.radio("Sign what?", ["Text message", "File"], key="sign_mode")
            sign_data_bytes = None
            if sign_mode == "Text message":
                sign_text = st.text_area("Message to sign", key="sign_msg")
                if sign_text:
                    sign_data_bytes = sign_text.encode()
            else:
                sign_file = file_uploader_restricted("File to sign", 50)
                if sign_file:
                    sign_data_bytes = sign_file.read()
            if st.button("🖊️ Sign"):
                if not sign_data_bytes:
                    st.warning("Provide data to sign.")
                else:
                    sig = sign_data(priv, sign_data_bytes)
                    sig_b64 = base64.b64encode(sig).decode()
                    st.success("Signature (Base64):")
                    output_with_copy(sig_b64, "📋 Copy signature")
        with col2:
            st.markdown("#### Verify a signature")
            ver_mode = st.radio("Verify what?", ["Text message", "File"], key="ver_mode")
            ver_data_bytes = None
            if ver_mode == "Text message":
                ver_text = st.text_area("Original message", key="ver_msg")
                if ver_text:
                    ver_data_bytes = ver_text.encode()
            else:
                ver_file = file_uploader_restricted("Original file", 50)
                if ver_file:
                    ver_data_bytes = ver_file.read()
            sig_input = st.text_area("Signature (Base64)", key="ver_sig", placeholder="Paste signature...")
            if st.button("✅ Verify"):
                if not ver_data_bytes or not sig_input.strip():
                    st.warning("Provide both original data and signature.")
                else:
                    try:
                        sig_bytes = base64.b64decode(sig_input)
                        valid = verify_signature(pub, ver_data_bytes, sig_bytes)
                        if valid:
                            st.success("✅ Signature is valid!")
                        else:
                            st.error("❌ Invalid signature or data tampered.")
                    except Exception as e:
                        st.error(f"Verification error: {e}")

def password_gen():
    st.subheader("🔑 Strong password generator")
    c1, c2 = st.columns(2)
    with c1:
        length = st.slider("Length", 8, 64, 24)
        upper = st.checkbox("Uppercase", True)
    with c2:
        digits = st.checkbox("Digits", True)
        symbols = st.checkbox("Symbols", True)
    if st.button("🎲 Generate"):
        pwd = generate_strong_password(length, upper, digits, symbols)
        st.success("Your password:")
        output_with_copy(pwd, "📋 Copy password")

def base64_module():
    st.subheader("🔄 Base64 encode / decode")
    mode = st.radio("Operation", ["Encode text → Base64", "Decode Base64 → text"])
    if mode == "Encode text → Base64":
        txt = st.text_area("Text to encode", height=120)
        if st.button("Encode"):
            if txt:
                enc = base64.b64encode(txt.encode()).decode()
                st.success("Base64 encoded:")
                output_with_copy(enc, "📋 Copy base64")
            else:
                st.warning("Enter text.")
    else:
        b64 = st.text_area("Base64 string to decode", height=120)
        if st.button("Decode"):
            if b64.strip():
                try:
                    dec = base64.b64decode(b64).decode()
                    st.success("Decoded text:")
                    st.code(dec, language="text")
                except Exception:
                    st.error("Invalid Base64 string.")
            else:
                st.warning("Enter base64.")

def random_bytes_module():
    st.subheader("🎲 Random bytes & UUID generator")
    c1, c2 = st.columns(2)
    with c1:
        byte_count = st.number_input("Number of random bytes", min_value=1, max_value=1024, value=32)
        if st.button("Generate random bytes"):
            rand_bytes = os.urandom(byte_count)
            hex_str = rand_bytes.hex()
            b64_str = base64.b64encode(rand_bytes).decode()
            st.markdown("**Hex:**")
            output_with_copy(hex_str, "📋 Copy hex")
            st.markdown("**Base64:**")
            output_with_copy(b64_str, "📋 Copy base64")
    with c2:
        if st.button("Generate UUID v4"):
            new_uuid = str(uuid.uuid4())
            st.success("UUID:")
            output_with_copy(new_uuid, "📋 Copy UUID")

def file_integrity_checker():
    st.subheader("🔍 File integrity checker")
    st.markdown("Verify a file against a known hash.")
    f = file_uploader_restricted("Upload file", 50)
    algo = st.selectbox("Hash algorithm", ["sha256", "sha512", "sha3_256"])
    expected_hash = st.text_input("Expected hash (hex)", placeholder="Paste the known hash...")
    if st.button("Check Integrity"):
        if not f:
            st.warning("Upload a file.")
        elif not expected_hash.strip():
            st.warning("Enter expected hash.")
        else:
            actual = hash_data(f.read(), algo)
            if actual.lower() == expected_hash.strip().lower():
                st.success("✅ Integrity verified – hashes match!")
            else:
                st.error("❌ Hash mismatch – file may be corrupted or tampered.")
                st.markdown("**Actual hash:**")
                st.code(actual, language="text")

# ============================================================
# Main application
# ============================================================
def main():
    inject_css()

    # ---------- Hero with clickable portfolio link ----------
    st.markdown("""
    <div class="hero">
        <h1>🔐 CryptoVault Pro</h1>
        <p class="subtitle">Military‑grade encryption, hashing, signatures & more — all local</p>
        <p class="crafted">Crafted by <a href="https://ronakprogrammer.netlify.app" target="_blank">Ronak Kumar</a></p>
    </div>
    """, unsafe_allow_html=True)

    # ---------- Sidebar navigation ----------
    with st.sidebar:
        st.markdown('<div class="sidebar-title">⚙️ Modules</div>', unsafe_allow_html=True)
        module = st.radio(
            "Navigate",
            [
                "🔒 Text Encrypt", "🔓 Text Decrypt",
                "📁 File Encrypt", "📂 File Decrypt",
                "#️⃣ Hashing", "🔏 HMAC",
                "✍️ Signatures", "🔑 Password Gen",
                "🔄 Base64", "🎲 Random / UUID",
                "🔍 Integrity Check"
            ],
            label_visibility="collapsed"
        )
        st.markdown("---")
        st.markdown("<small style='color:#6b7280;'>All operations are performed locally.<br>No data ever leaves your device.</small>", unsafe_allow_html=True)

    # ---------- Render selected module ----------
    st.markdown('<div class="card">', unsafe_allow_html=True)
    if module == "🔒 Text Encrypt":
        text_encrypt()
    elif module == "🔓 Text Decrypt":
        text_decrypt()
    elif module == "📁 File Encrypt":
        file_encrypt()
    elif module == "📂 File Decrypt":
        file_decrypt()
    elif module == "#️⃣ Hashing":
        hashing_module()
    elif module == "🔏 HMAC":
        hmac_module()
    elif module == "✍️ Signatures":
        signature_module()
    elif module == "🔑 Password Gen":
        password_gen()
    elif module == "🔄 Base64":
        base64_module()
    elif module == "🎲 Random / UUID":
        random_bytes_module()
    elif module == "🔍 Integrity Check":
        file_integrity_checker()
    st.markdown('</div>', unsafe_allow_html=True)

    # ---------- Footer ----------
    st.markdown("""
    <div class="footer">
        ❤ by <a href="https://ronakprogrammer.netlify.app" target="_blank">Ronak Kumar</a> | 
        <a href="https://ronakprogrammer.netlify.app" target="_blank">Portfolio</a>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()