from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

def generate_keys(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    os.makedirs(f'keys/{username}', exist_ok=True)

    with open(f'keys/{username}/private.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    with open(f'keys/{username}/public.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def sign_data(username, data):
    with open(f'keys/{username}/private.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return signature

def verify_signature(username, data, signature):
    with open(f'keys/{username}/public.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except:
        return False