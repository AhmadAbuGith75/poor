
import base64
import hashlib
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================================
# ROOT TEAM :: DECRYPTION TOOL
# ==========================================

ITERATIONS = 600_000
AAD = b"ROOT-TEAM-CTF-V1"
PREFIX = "ROOTCTF1:"


def derive_key(password, salt):

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=32
    )


def decrypt_payload(payload, password):

    payload = payload.strip()

    if not payload.startswith(PREFIX):
        raise ValueError("Invalid payload")

    encoded = payload[len(PREFIX):]

    encoded += "=" * (-len(encoded) % 4)

    raw = base64.urlsafe_b64decode(encoded)

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("Invalid encrypted data")

    key = derive_key(password, salt)

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        AAD
    )

    return plaintext.decode("utf-8")


def main():

    print("=" * 38)
    print("       ROOT TEAM :: DECRYPTION TOOL")
    print("=" * 38)
    print("\n# { Note: Provide the full text ROOTCTF1:encrypted text }")
    payload = input("\nEncrypted text: ").strip()

    password = getpass.getpass("Decryption key: ")

    try:

        result = decrypt_payload(payload, password)

        print("\n[+] Decryption successful!")
        print(f"[+] Destination: {result}")

    except Exception:

        print("\n[-] Don't play games, sweetheart.")


if __name__ == "__main__":
    main()
