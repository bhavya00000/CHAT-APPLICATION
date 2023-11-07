import base64

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem, private_pem



def encrypt_rsa(aes_key, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    aes_key_bytes = aes_key.encode('utf-8')
    enc_aes_key = public_key.encrypt(aes_key_bytes, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    return enc_aes_key.decode('latin-1')


def decrypt_rsa(enc_aes_key, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key.encode('latin-1'))
    # aes_key is bytes type variable
    return aes_key


# AES
def generate_aes_key():
    aes_key = get_random_bytes(16)
    return aes_key


def encrypt_aes(message, aes_key):
    if len(aes_key) != 16:
        raise ValueError("AES key must be 16 bytes long")

    # Padding to make the message length a multiple of 16
    padding_length = 16 - (len(message) % 16)
    message += bytes([padding_length] * padding_length)

    cipher_text = bytearray()
    previous_block = aes_key

    for i in range(0, len(message), 16):
        block = message[i:i + 16]
        xor_result = bytes([a ^ b for a, b in zip(block, previous_block)])
        cipher_text.extend(xor_result)
        previous_block = xor_result

    nonce = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(cipher_text))

    enc_mssge = [nonce, tag, ciphertext]

    return enc_mssge


def decrypt_aes(enc_mssge, aes_key):
    nonce, tag, ciphertext = enc_mssge[0], enc_mssge[1], enc_mssge[2]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    message = cipher.decrypt_and_verify(ciphertext, tag)
    return message.decode()

# RSA Digital Signature


def rsa_ds_signer(aes_key, rsa_priv_key):
    message = aes_key
    h = SHA256.new(message)
    signature = pkcs1_15.new(RSA.import_key(rsa_priv_key)).sign(h)
    return signature.decode('latin-1')


def rsa_ds_verifier(aes_key, signature, rsa_pub_key):
    message = aes_key
    h = SHA256.new(message)
    try:
        pkcs1_15.new(RSA.import_key(rsa_pub_key)).verify(
            h, signature.encode('latin-1'))
        print("verification success ", flush=True)
        return True
    except ValueError:
        return False


def sha_md_create(value):
    # Create a new SHA-256 hash object
    sha256_hash = SHA256.new()

    # Update the hash object with the bytes of the input value
    sha256_hash.update(str(value).encode())

    return sha256_hash
