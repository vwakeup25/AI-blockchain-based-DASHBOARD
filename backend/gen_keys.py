from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# 1. Generate Fernet key for encryption
fernet_key = Fernet.generate_key()
with open("fernet.key", "wb") as f:
    f.write(fernet_key)
print("✅ Successfully generated 'fernet.key'")

# 2. Generate Ed25519 private key for signing
private_key = ed25519.Ed25519PrivateKey.generate()
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("ed25519_private.key", "wb") as f:
    f.write(pem_private)
print("✅ Successfully generated 'ed25519_private.key'")

# 3. Generate the corresponding public key for verification
public_key = private_key.public_key()
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("ed25519_public.key", "wb") as f:
    f.write(pem_public)
print("✅ Successfully generated 'ed25519_public.key'")
