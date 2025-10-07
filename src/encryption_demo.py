from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

class EncryptionDemo:
    """Demo các thuật toán encryption được dùng trong TLS"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def demo_aes_gcm(self):
        """Demo AES-256-GCM encryption (dùng trong TLS)"""
        print(f"\n{'='*60}")
        print(f"🔐 AES-256-GCM ENCRYPTION DEMO")
        print(f"{'='*60}")
        
        # Generate key và nonce
        key = os.urandom(32)  # 256 bits
        nonce = os.urandom(12)  # 96 bits cho GCM
        
        print(f"Key (256-bit): {key.hex()[:32]}...")
        print(f"Nonce (96-bit): {nonce.hex()}")
        
        # Plaintext
        plaintext = b"Hello, this is a secure TLS message!"
        print(f"\nPlaintext: {plaintext.decode()}")
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Associated data (không mã hóa nhưng được authenticate)
        associated_data = b"TLS 1.3 Application Data"
        encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        print(f"\nCiphertext: {ciphertext.hex()}")
        print(f"Auth Tag: {tag.hex()}")
        
        # Decrypt
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        ).decryptor()
        
        decryptor.authenticate_additional_data(associated_data)
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        print(f"\n✓ Decrypted: {decrypted.decode()}")
        print(f"✓ Authentication successful!")
    
    def demo_rsa_encryption(self):
        """Demo RSA encryption (key exchange)"""
        print(f"\n{'='*60}")
        print(f"🔑 RSA KEY EXCHANGE DEMO")
        print(f"{'='*60}")
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        print("✓ RSA 2048-bit key pair generated")
        
        # Pre-master secret
        pre_master_secret = os.urandom(48)
        print(f"\nPre-master secret: {pre_master_secret.hex()[:32]}...")
        
        # Encrypt với public key
        encrypted = public_key.encrypt(
            pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Encrypted: {encrypted.hex()[:32]}...")
        
        # Decrypt với private key
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print(f"\n✓ Decrypted matches: {pre_master_secret == decrypted}")