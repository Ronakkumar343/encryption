"""Unit tests for CryptoVault Pro core crypto functions (encryption.py).

The app is a Streamlit script, so the tests stub the `streamlit` module
before import; only the pure crypto helpers are exercised.

Run:  python -m unittest discover -s tests -v
"""
import base64
import importlib.util
import os
import sys
import types
import unittest

# --- Stub streamlit so encryption.py imports headless -----------------------
_st = types.ModuleType("streamlit")
_st.__getattr__ = lambda name: (lambda *a, **k: None)
sys.modules.setdefault("streamlit", _st)

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "encryption", os.path.join(_HERE, "..", "encryption.py")
)
cv = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cv)


class TextEncryptionTests(unittest.TestCase):
    def test_round_trip(self):
        ct = cv.encrypt_text("hello ronak", "correct horse")
        self.assertEqual(cv.decrypt_text(ct, "correct horse"), "hello ronak")

    def test_round_trip_unicode(self):
        ct = cv.encrypt_text("Mithi — Thar ✓", "pässwörd")
        self.assertEqual(cv.decrypt_text(ct, "pässwörd"), "Mithi — Thar ✓")

    def test_wrong_password_raises_value_error(self):
        # Regression: AES-GCM raises InvalidTag (not a ValueError) on a wrong
        # password; the UI only catches ValueError, so decrypt_text must
        # convert it — otherwise the app crashes with a traceback.
        ct = cv.encrypt_text("secret", "right")
        with self.assertRaises(ValueError):
            cv.decrypt_text(ct, "wrong")

    def test_tampered_ciphertext_raises_value_error(self):
        ct = cv.encrypt_text("secret", "pw")
        raw = bytearray(base64.urlsafe_b64decode(ct))
        raw[-1] ^= 1
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(ValueError):
            cv.decrypt_text(tampered, "pw")

    def test_invalid_base64_raises_value_error(self):
        with self.assertRaises(ValueError):
            cv.decrypt_text("!!!not-base64!!!", "pw")

    def test_short_payload_raises_value_error(self):
        short = base64.urlsafe_b64encode(b"tiny").decode("ascii")
        with self.assertRaises(ValueError):
            cv.decrypt_text(short, "pw")


class FileEncryptionTests(unittest.TestCase):
    def test_round_trip(self):
        blob = cv.encrypt_file_bytes(b"file-bytes-123", "pw2")
        self.assertEqual(cv.decrypt_file_bytes(blob, "pw2"), b"file-bytes-123")

    def test_wrong_password_raises_value_error(self):
        blob = cv.encrypt_file_bytes(b"data", "right")
        with self.assertRaises(ValueError):
            cv.decrypt_file_bytes(blob, "wrong")

    def test_tampered_file_raises_value_error(self):
        blob = bytearray(cv.encrypt_file_bytes(b"data", "pw"))
        blob[-1] ^= 1
        with self.assertRaises(ValueError):
            cv.decrypt_file_bytes(bytes(blob), "pw")

    def test_short_file_raises_value_error(self):
        with self.assertRaises(ValueError):
            cv.decrypt_file_bytes(b"tiny", "pw")


class HelperTests(unittest.TestCase):
    def test_hash_data_known_vector(self):
        # SHA-256 of b"abc" (FIPS 180-4 example)
        self.assertEqual(
            cv.hash_data(b"abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_derive_key_is_deterministic_per_salt(self):
        salt = b"\x00" * 16
        self.assertEqual(cv.derive_key(salt, "pw"), cv.derive_key(salt, "pw"))
        self.assertNotEqual(cv.derive_key(salt, "pw"), cv.derive_key(salt, "pw2"))


if __name__ == "__main__":
    unittest.main()
