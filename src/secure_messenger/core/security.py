from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from passlib.context import CryptContext

context = CryptContext(schemes=['argon2'])


def get_password_hash(plain_password: str) -> str:
    """
    Args:
        plain_password (str): The plain text password to hash.
    Returns:
        str: The hashed password string.
    """
    return context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The hashed password to compare against.
    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return context.verify(plain_password, hashed_password)


def generate_rsa_key_pair() -> tuple[bytes, bytes]:
    """
    Args:
        None
    Returns:
        tuple[bytes, bytes]: The private and public RSA keys in PEM format.
    """
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()

    private_key_pem = private_key.exportKey()
    public_key_pem = public_key.export_key()

    return private_key_pem, public_key_pem


def _derive_key_from_password_and_salt(password: str, salt: bytes) -> bytes:
    """
    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt to use for key derivation.
    Returns:
        bytes: The derived key.
    """
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )

    return key


def encrypt_private_key(private_key_pem: bytes, password: str, salt: bytes) -> bytes:
    """
    Args:
        private_key_pem (bytes): Private key in PEM format.
        password (str): Password to encrypt with.
        salt (bytes): Salt used for key derivation.
    Returns:
        bytes: Encrypted private key blob (nonce + tag + ciphertext).
    """
    aes_key = _derive_key_from_password_and_salt(password, salt)

    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM)

    encrypted_key, tag = cipher.encrypt_and_digest(private_key_pem)

    encrypted_blob = cipher.nonce + tag + encrypted_key

    return encrypted_blob


def decrypt_private_key(encrypted_blob: bytes, password: str, salt: bytes) -> bytes:
    """
    Args:
        encrypted_blob (bytes): Encrypted private key blob.
        password (str): Password to decrypt with.
        salt (bytes): Salt used for key derivation.
    Returns:
        bytes: Decrypted private key in PEM format.
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
    Args:
        None
    Returns:
        bytes: Randomly generated AES key.
    """
    return get_random_bytes(32)


def generate_random_salt() -> bytes:
    """
    Args:
        None
    Returns:
        bytes: Randomly generated salt.
    """
    return get_random_bytes(16)


def encrypt_aes_key(aes_key: bytes, public_key_pem: bytes) -> bytes:
    """
    Args:
        aes_key (bytes): AES key to encrypt.
        public_key_pem (bytes): Recipient's public key in PEM format.
    Returns:
        bytes: Encrypted AES key.
    """
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)

    encrypted_aes_key = cipher.encrypt(aes_key)

    return encrypted_aes_key


def decrypt_aes_key(encrypted_aes_key: bytes, private_key_pem: bytes) -> bytes:
    """
    Args:
        encrypted_aes_key (bytes): Encrypted AES key.
        private_key_pem (bytes): Private key in PEM format for decryption.
    Returns:
        bytes: Decrypted AES key.
    """
    private_key = RSA.import_key(private_key_pem)
    decipher = PKCS1_OAEP.new(private_key)

    decrypted_aes_key = decipher.decrypt(encrypted_aes_key)

    return decrypted_aes_key


def encrypt_content(content: bytes, aes_key: bytes) -> bytes:
    """
    Args:
        content (bytes): Content to encrypt.
        aes_key (bytes): AES key to use for encryption.
    Returns:
        bytes: Encrypted content blob (nonce + tag + ciphertext).
    """

    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM)

    encrypted_content, tag = cipher.encrypt_and_digest(content)
    encrypted_blob = cipher.nonce + tag + encrypted_content

    return encrypted_blob


def decrypt_content(encrypted_blob: bytes, aes_key: bytes) -> bytes:
    """
    Args:
        encrypted_blob (bytes): Encrypted content blob.
        aes_key (bytes): AES key to use for decryption.
    Returns:
        bytes: Decrypted content.
    """
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    encrypted_content = encrypted_blob[32:]

    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM, nonce=nonce)
    decrypted_content = cipher.decrypt_and_verify(encrypted_content, tag)

    return decrypted_content


def generate_signature(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Args:
        data (bytes): Data to sign.
        private_key_pem (bytes): Private key in PEM format for signing.
    Returns:
        bytes: Signature of the data.
    """
    key = RSA.import_key(private_key_pem)
    hashed_data = SHA256.new(data)

    signer = pss.new(key)
    signature = signer.sign(hashed_data)

    return signature


def verify_signature(data: bytes, public_key_pem: bytes, signature: bytes) -> None:
    """
    Args:
        data (bytes): Data whose signature is to be verified.
        public_key_pem (bytes): Public key in PEM format for verification.
        signature (bytes): Signature to verify.
    Returns:
        None: Raises an exception if verification fails.
    """
    key = RSA.import_key(public_key_pem)
    hashed_data = SHA256.new(data)

    verifier = pss.new(key)

    verifier.verify(hashed_data, signature)


def get_content_hash(data: bytes) -> bytes:
    """
    Args:
        data (bytes): Data to hash.
    Returns:
        bytes: SHA256 hash of the data.
    """
    return SHA256.new(data).digest()
