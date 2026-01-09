from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from passlib.context import CryptContext

context = CryptContext(schemes=['argon2'])


def get_password_hash(plain_password: str) -> str:
    """
    Args:
        plain_password (str): secret
    Returns:
        str: hashed secret
    """
    return context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Args:
        plain_password (str): secret
        hashed_password (str): stored hash
    Returns:
        bool: is password and hash matching
    """
    return context.verify(plain_password, hashed_password)


def generate_rsa_key_pair() -> tuple[bytes, bytes]:
    """
    Returns:
        tuple[bytes, bytes]: a pair of RSA keys
    """
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.exportKey()
    public_key_pem = public_key.export_key()

    return private_key_pem, public_key_pem


def _derive_key_from_password_and_salt(password: str, salt: bytes):
    """
    Args:
        password (str): password to derive key from
        salt (bytes): salt bytes
    Returns:
        bytes: derived AES key (SHA-256 digest)
    """
    hash = SHA256.new(password.encode() + salt)
    key = hash.digest()

    return key


def encrypt_private_key(private_key_pem: bytes, password: str, salt: bytes) -> bytes:
    """
    Args:
        private_key_pem (bytes): private key in PEM format
        password (str): password to encrypt with
        salt (bytes): salt used for key derivation
    Returns:
        bytes: encrypted private key blob (nonce + tag + ciphertext)
    """
    aes_key = _derive_key_from_password_and_salt(password, salt)

    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM)

    encrypted_key, tag = cipher.encrypt_and_digest(private_key_pem)

    encrypted_blob = cipher.nonce + tag + encrypted_key

    return encrypted_blob


def decrypt_private_key(encrypted_blob: bytes, password: str, salt: bytes):
    """
    Args:
        encrypted_blob (bytes): blob produced by encrypt_private_key
        password (str): password used to decrypt
        salt (bytes): salt used for key derivation
    Returns:
        bytes: decrypted private key PEM
    """
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    encrypted_private_key = encrypted_blob[32:]

    aes_key = _derive_key_from_password_and_salt(password, salt)

    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM, nonce=nonce)
    decrypted_key = cipher.decrypt_and_verify(encrypted_private_key, tag)

    return decrypted_key


def generate_random_aes_key() -> bytes:
    """
    Returns:
        bytes: random 32-byte AES key
    """
    return get_random_bytes(32)


def encrypt_aes_key(aes_key: bytes, public_key_pem: bytes) -> bytes:
    """
    Args:
        aes_key (bytes): AES key to encrypt
        public_key_pem (bytes): recipient public key in PEM format
    Returns:
        bytes: RSA-encrypted AES key
    """
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)

    encrypted_aes_key = cipher.encrypt(aes_key)

    return encrypted_aes_key


def decrypt_aes_key(encrypted_aes_key: bytes, private_key_pem: bytes) -> bytes:
    """
    Args:
        encrypted_aes_key (bytes): RSA-encrypted AES key
        private_key_pem (bytes): recipient private key in PEM format
    Returns:
        bytes: decrypted AES key
    """
    private_key = RSA.import_key(private_key_pem)
    decipher = PKCS1_OAEP.new(private_key)

    decrypted_aes_key = decipher.decrypt(encrypted_aes_key)

    return decrypted_aes_key


def encrypt_content(content: bytes, aes_key: bytes) -> bytes:
    """
    Args:
        content (bytes): plaintext content
        aes_key (bytes): AES key for encryption
    Returns:
        bytes: encrypted blob (nonce + tag + ciphertext)
    """

    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM)

    encrypted_content, tag = cipher.encrypt_and_digest(content)
    encrypted_blob = cipher.nonce + tag + encrypted_content

    return encrypted_blob


def decrypt_content(encrypted_blob: bytes, aes_key: bytes) -> bytes:
    """
    Args:
        encrypted_blob (bytes): blob produced by encrypt_content
        aes_key (bytes): AES key for decryption
    Returns:
        bytes: decrypted plaintext content
    """
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    encrypted_content = encrypted_blob[32:]

    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM, nonce=nonce)
    decrypted_content = cipher.decrypt_and_verify(encrypted_content, tag)

    return decrypted_content


# TODO signature
