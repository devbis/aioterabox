import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def change_base64_type(data: str, to_type: int) -> str:
    if to_type == 1:
        return data.replace('-', '+').replace('_', '/')
    elif to_type == 2:
        return data.replace('+', '-').replace('/', '_')
    return data


def b64decode_loose(s: str) -> bytes:
    s = s.strip()
    # url-safe → standard
    s = change_base64_type(s, 1)
    # padding
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.b64decode(s)


def decrypt_aes(pp1: str, pp2: str) -> str:
    key = pp2.encode("utf-8")
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")

    iv_str = pp1[:16]
    cipher_b64_str = pp1[16:]
    iv = iv_str.encode("utf-8")

    cipher_text = b64decode_loose(cipher_b64_str)

    # AES-128-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(cipher_text) + decryptor.finalize()

    # PKCS7 unpadding
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()

    return plain.decode("utf-8")


def encrypt_rsa(message: str, public_key_pem: str, mode: int = 1) -> str:
    # Mode 2: Apply MD5 hash and length padding
    if mode == 2:
        digest = hashes.Hash(hashes.MD5())
        digest.update(message.encode("utf-8"))
        md5_hash = digest.finalize().hex()
        message = md5_hash + ('' if len(md5_hash) >= 10 else '0') + str(len(md5_hash))

    # Load public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8"),
    )

    # Perform RSA encryption
    encrypted = public_key.encrypt(
        message.encode("utf-8"),
        asym_padding.PKCS1v15(),
    )

    # Return as Base64 string
    return base64.b64encode(encrypted).decode("utf-8")


def sign_download(s1: str, s2: str) -> str:
    # Initialize permutation array (p) and key array (a)
    p = list(range(256))
    a = [ord(s1[i % len(s1)]) for i in range(256)]
    result = []

    # Key-scheduling algorithm (KSA)
    j = 0
    for i in range(256):
        j = (j + p[i] + a[i]) % 256
        p[i], p[j] = p[j], p[i]  # swap

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    for q in range(len(s2)):
        i = (i + 1) % 256
        j = (j + p[i]) % 256
        p[i], p[j] = p[j], p[i]  # swap
        k = p[(p[i] + p[j]) % 256]
        result.append(ord(s2[q]) ^ k)

    # Return the result as Base64
    return base64.b64encode(bytes(result)).decode("utf-8")
