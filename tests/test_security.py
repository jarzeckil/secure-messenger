from Crypto.PublicKey import RSA
import pytest

from secure_messenger.core import security


def test_password_hashing():
    password = 'supersecretpassword'
    hashed = security.get_password_hash(password)

    assert hashed != password
    assert isinstance(hashed, str)

    assert security.verify_password(password, hashed) is True
    assert security.verify_password('wrongpassword', hashed) is False


def test_rsa_key_pair_generation():
    private_pem, public_pem = security.generate_rsa_key_pair()

    assert isinstance(private_pem, bytes)
    assert isinstance(public_pem, bytes)

    # Verify we can import them back
    priv_key = RSA.import_key(private_pem)
    pub_key = RSA.import_key(public_pem)

    assert priv_key.has_private()
    assert not pub_key.has_private()


def test_private_key_encryption_decryption():
    private_pem, _ = security.generate_rsa_key_pair()
    password = 'encryptionpassword'
    salt = security.get_random_bytes(16)

    encrypted_blob = security.encrypt_private_key(private_pem, password, salt)
    assert isinstance(encrypted_blob, bytes)
    assert encrypted_blob != private_pem

    decrypted_pem = security.decrypt_private_key(encrypted_blob, password, salt)
    assert decrypted_pem == private_pem


def test_private_key_decryption_wrong_password():
    private_pem, _ = security.generate_rsa_key_pair()
    password = 'encryptionpassword'
    wrong_password = 'wrongpassword'
    salt = security.get_random_bytes(16)

    encrypted_blob = security.encrypt_private_key(private_pem, password, salt)

    # AES-GCM should raise ValueError on tag mismatch (decryption failure)
    with pytest.raises(ValueError):
        security.decrypt_private_key(encrypted_blob, wrong_password, salt)


def test_aes_key_generation():
    key = security.generate_random_aes_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_aes_key_encryption_decryption():
    private_pem, public_pem = security.generate_rsa_key_pair()
    aes_key = security.generate_random_aes_key()

    encrypted_aes_key = security.encrypt_aes_key(aes_key, public_pem)
    assert isinstance(encrypted_aes_key, bytes)
    assert encrypted_aes_key != aes_key

    decrypted_aes_key = security.decrypt_aes_key(encrypted_aes_key, private_pem)
    assert decrypted_aes_key == aes_key


def test_content_encryption_decryption():
    aes_key = security.generate_random_aes_key()
    content = b'This is a secret message.'

    encrypted_blob = security.encrypt_content(content, aes_key)
    assert isinstance(encrypted_blob, bytes)
    assert encrypted_blob != content

    decrypted_content = security.decrypt_content(encrypted_blob, aes_key)
    assert decrypted_content == content


def test_content_decryption_tampering():
    aes_key = security.generate_random_aes_key()
    content = b'Important data'

    encrypted_blob = security.encrypt_content(content, aes_key)

    # Tamper with the encrypted blob (e.g. change last byte)
    tampered_blob = encrypted_blob[:-1] + bytes([encrypted_blob[-1] ^ 0xFF])

    with pytest.raises(ValueError):
        security.decrypt_content(tampered_blob, aes_key)


def test_signature_generation_verification():
    private_pem, public_pem = security.generate_rsa_key_pair()
    data = b'Signed data'

    signature = security.generate_signature(data, private_pem)
    assert isinstance(signature, bytes)

    # Should not raise exception
    security.verify_signature(data, public_pem, signature)


def test_signature_verification_fail():
    private_pem, public_pem = security.generate_rsa_key_pair()
    data = b'Signed data'
    signature = security.generate_signature(data, private_pem)

    wrong_data = b'Tampered data'

    with pytest.raises(ValueError):
        security.verify_signature(wrong_data, public_pem, signature)


def test_salt_generation():
    salt1 = security.generate_random_salt()
    salt2 = security.generate_random_salt()

    assert isinstance(salt1, bytes)
    assert len(salt1) == 16
    assert salt1 != salt2
