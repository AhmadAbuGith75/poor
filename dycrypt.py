import base64
import hashlib
import getpass
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

ITERATIONS = 600_000
AAD = b"ROOT-TEAM-CTF-V1"
PREFIX = "ROOTCTF1:"

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32
    )

def decrypt_payload(payload: str, password: str) -> str:
    payload = payload.strip()

    if not payload.startswith(PREFIX):
        raise ValueError("Invalid payload format")

    encoded = payload[len(PREFIX):]
    encoded += "=" * (-len(encoded) % 4)
    raw = base64.urlsafe_b64decode(encoded)

    if len(raw) < 16 + 12 + 16:
        raise ValueError("Invalid payload length")

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    key = derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD)
    return plaintext.decode("utf-8")

def main():
    print("======================================")
    print("       ROOT TEAM :: DECRYPTION TOOL")
    print("======================================")

    encrypted_text = input("\\nEncrypted text: ").strip()
    password = getpass.getpass("Decryption key: ")

    try:
        destination = decrypt_payload(encrypted_text, password)
        print("\\n[+] Decryption successful!")
        print("[+] Destination discovered:")
        print(destination)
    except (InvalidTag, ValueError, UnicodeDecodeError, Exception):
        print("\\n[-] Don't play games, sweetheart.")
        sys.exit(1)

if __name__ == "__main__":
    main()
