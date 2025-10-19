"""
Advanced Cryptography Demonstrations
ECDH Key Exchange, Key Derivation Functions, và Advanced Protocols
"""
import os
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESOCB3
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import struct
import hashlib

class AdvancedCryptographyDemo:
    """Advanced cryptographic protocols và algorithms demo"""
    
    def __init__(self):
        self.backend = default_backend()
        
    def comprehensive_crypto_demo(self):
        """Demo comprehensive cryptographic concepts"""
        print(f"\n{'='*120}")
        print(f"🔬 ADVANCED CRYPTOGRAPHY DEMONSTRATIONS")
        print(f"{'='*120}")
        
        # 1. Key Exchange Protocols
        self.demo_key_exchange_protocols()
        
        # 2. Key Derivation Functions
        self.demo_key_derivation_functions()
        
        # 3. Authenticated Encryption
        self.demo_authenticated_encryption()
        
        # 4. Digital Signatures
        self.demo_digital_signatures()
        
        # 5. Hash Functions & MACs
        self.demo_hash_and_mac()
        
        # 6. Post-Quantum Readiness
        self.demo_post_quantum_considerations()
        
        print(f"\n🏆 Advanced Cryptography Demo Complete!")
    
    def demo_key_exchange_protocols(self):
        """Demo various key exchange protocols"""
        print(f"\n🔄 KEY EXCHANGE PROTOCOLS")
        print(f"{'─'*120}")
        
        # 1. ECDH (Elliptic Curve Diffie-Hellman)
        print(f"\n🔹 ECDH Key Exchange:")
        self.demo_ecdh()
        
        # 2. Traditional DH
        print(f"\n🔹 Traditional Diffie-Hellman:")
        self.demo_traditional_dh()
        
        # 3. RSA Key Transport
        print(f"\n🔹 RSA Key Transport:")
        self.demo_rsa_key_transport()
    
    def demo_ecdh(self):
        """Demo ECDH key exchange với different curves"""
        curves = {
            'P-256': ec.SECP256R1(),
            'P-384': ec.SECP384R1(),
            'P-521': ec.SECP521R1()
        }
        
        for curve_name, curve in curves.items():
            print(f"  📊 {curve_name} Curve:")
            
            # Generate key pairs
            alice_private = ec.generate_private_key(curve, self.backend)
            bob_private = ec.generate_private_key(curve, self.backend)
            
            alice_public = alice_private.public_key()
            bob_public = bob_private.public_key()
            
            # Key exchange
            alice_shared = alice_private.exchange(ec.ECDH(), bob_public)
            bob_shared = bob_private.exchange(ec.ECDH(), alice_public)
            
            # Verify shared secrets match
            secrets_match = alice_shared == bob_shared
            
            print(f"    Alice Private: {alice_private.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()[:80]}...")
            print(f"    Bob Private:   {bob_private.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()[:80]}...")
            print(f"    Shared Secret: {alice_shared.hex()[:32]}...")
            print(f"    Secrets Match: {'✅' if secrets_match else '❌'}")
            print(f"    Secret Length: {len(alice_shared)} bytes")
            print()
    
    def demo_traditional_dh(self):
        """Demo traditional Diffie-Hellman"""
        # Generate DH parameters (simplified for demo)
        print(f"  📊 Traditional DH (2048-bit):")
        
        # In practice, would use standardized groups
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=self.backend)
        
        # Generate private keys
        alice_private = parameters.generate_private_key()
        bob_private = parameters.generate_private_key()
        
        alice_public = alice_private.public_key()
        bob_public = bob_private.public_key()
        
        # Key exchange
        alice_shared = alice_private.exchange(bob_public)
        bob_shared = bob_private.exchange(alice_public)
        
        print(f"    Parameter Size: 2048 bits")
        print(f"    Generator: 2")
        print(f"    Shared Secret: {alice_shared.hex()[:32]}...")
        print(f"    Secrets Match: {'✅' if alice_shared == bob_shared else '❌'}")
        print(f"    Performance: Slower than ECDH (larger keys)")
        print()
    
    def demo_rsa_key_transport(self):
        """Demo RSA key transport"""
        print(f"  📊 RSA Key Transport:")
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        # Generate session key
        session_key = os.urandom(32)  # 256-bit AES key
        
        # Encrypt session key with public key
        encrypted_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt with private key
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print(f"    RSA Key Size: 2048 bits")
        print(f"    Session Key: {session_key.hex()}")
        print(f"    Encrypted: {encrypted_key.hex()[:32]}...")
        print(f"    Decrypted: {decrypted_key.hex()}")
        print(f"    Keys Match: {'✅' if session_key == decrypted_key else '❌'}")
        print(f"    PFS: ❌ (same private key used)")
        print()
    
    def demo_key_derivation_functions(self):
        """Demo key derivation functions"""
        print(f"\n🔑 KEY DERIVATION FUNCTIONS")
        print(f"{'─'*120}")
        
        password = b"SecurePassword123!"
        salt = os.urandom(16)
        
        # 1. PBKDF2
        print(f"🔹 PBKDF2 (Password-Based Key Derivation):")
        start_time = time.time()
        kdf_pbkdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        pbkdf2_key = kdf_pbkdf2.derive(password)
        pbkdf2_time = time.time() - start_time
        
        print(f"  Password: {password.decode()}")
        print(f"  Salt: {salt.hex()}")
        print(f"  Iterations: 100,000")
        print(f"  Derived Key: {pbkdf2_key.hex()}")
        print(f"  Time: {pbkdf2_time:.3f} seconds")
        print()
        
        # 2. Scrypt
        print(f"🔹 Scrypt (Memory-Hard KDF):")
        start_time = time.time()
        kdf_scrypt = Scrypt(
            length=32,
            salt=salt,
            n=2**14,  # CPU/Memory cost
            r=8,      # Block size
            p=1,      # Parallelization
            backend=self.backend
        )
        scrypt_key = kdf_scrypt.derive(password)
        scrypt_time = time.time() - start_time
        
        print(f"  Password: {password.decode()}")
        print(f"  Salt: {salt.hex()}")
        print(f"  N (Cost): 16,384")
        print(f"  Derived Key: {scrypt_key.hex()}")
        print(f"  Time: {scrypt_time:.3f} seconds")
        print()
        
        # 3. HKDF (HMAC-based KDF)
        print(f"🔹 HKDF (HMAC-Based KDF):")
        input_key = os.urandom(32)  # High-entropy source
        info = b"TLS 1.3 Application Key"
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=self.backend
        )
        hkdf_key = hkdf.derive(input_key)
        
        print(f"  Input Key: {input_key.hex()[:32]}...")
        print(f"  Salt: {salt.hex()}")
        print(f"  Info: {info.decode()}")
        print(f"  Derived Key: {hkdf_key.hex()}")
        print(f"  Use Case: TLS 1.3 key derivation")
        print()
        
        # TLS 1.3 style key derivation
        print(f"🔹 TLS 1.3 Key Derivation:")
        self.demo_tls13_key_derivation()
    
    def demo_tls13_key_derivation(self):
        """Demo TLS 1.3 key derivation process"""
        print(f"  📋 Simulating TLS 1.3 Key Schedule:")
        
        # Simulated shared secret from ECDH
        shared_secret = os.urandom(32)
        
        # Early Secret (from PSK or zeros)
        early_secret = self.hkdf_extract(b"", b"\x00" * 32)
        print(f"    Early Secret: {early_secret.hex()[:32]}...")
        
        # Handshake Secret
        handshake_secret = self.hkdf_extract(early_secret, shared_secret)
        print(f"    Handshake Secret: {handshake_secret.hex()[:32]}...")
        
        # Derive handshake keys
        client_hs_key = self.hkdf_expand_label(handshake_secret, b"c hs traffic", b"", 32)
        server_hs_key = self.hkdf_expand_label(handshake_secret, b"s hs traffic", b"", 32)
        
        print(f"    Client Handshake Key: {client_hs_key.hex()[:32]}...")
        print(f"    Server Handshake Key: {server_hs_key.hex()[:32]}...")
        
        # Master Secret
        master_secret = self.hkdf_extract(handshake_secret, b"\x00" * 32)
        print(f"    Master Secret: {master_secret.hex()[:32]}...")
        
        # Application keys
        client_app_key = self.hkdf_expand_label(master_secret, b"c ap traffic", b"", 32)
        server_app_key = self.hkdf_expand_label(master_secret, b"s ap traffic", b"", 32)
        
        print(f"    Client Application Key: {client_app_key.hex()[:32]}...")
        print(f"    Server Application Key: {server_app_key.hex()[:32]}...")
        print()
    
    def hkdf_extract(self, salt, ikm):
        """HKDF Extract step"""
        if not salt:
            salt = b"\x00" * 32
        h = hmac.HMAC(salt, hashes.SHA256(), self.backend)
        h.update(ikm)
        return h.finalize()
    
    def hkdf_expand_label(self, secret, label, context, length):
        """TLS 1.3 HKDF-Expand-Label"""
        hkdf_label = struct.pack(">H", length) + struct.pack("B", len(label)) + label + struct.pack("B", len(context)) + context
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=hkdf_label,
            backend=self.backend
        )
        return hkdf.derive(secret)
    
    def demo_authenticated_encryption(self):
        """Demo authenticated encryption algorithms"""
        print(f"\n🔐 AUTHENTICATED ENCRYPTION")
        print(f"{'─'*120}")
        
        plaintext = b"This is sensitive data that needs both confidentiality and integrity protection."
        associated_data = b"Header information"
        
        # 1. AES-GCM
        print(f"🔹 AES-GCM (Galois/Counter Mode):")
        aes_key = os.urandom(32)
        aes_nonce = os.urandom(12)
        
        aesgcm = AESGCM(aes_key)
        aes_ciphertext = aesgcm.encrypt(aes_nonce, plaintext, associated_data)
        aes_decrypted = aesgcm.decrypt(aes_nonce, aes_ciphertext, associated_data)
        
        print(f"  Key Size: 256 bits")
        print(f"  Nonce: {aes_nonce.hex()}")
        print(f"  Plaintext: {plaintext.decode()}")
        print(f"  Associated Data: {associated_data.decode()}")
        print(f"  Ciphertext: {aes_ciphertext.hex()[:32]}...")
        print(f"  Decrypted: {aes_decrypted.decode()}")
        print(f"  Match: {'✅' if plaintext == aes_decrypted else '❌'}")
        print()
        
        # 2. ChaCha20-Poly1305
        print(f"🔹 ChaCha20-Poly1305:")
        chacha_key = os.urandom(32)
        chacha_nonce = os.urandom(12)
        
        chacha = ChaCha20Poly1305(chacha_key)
        chacha_ciphertext = chacha.encrypt(chacha_nonce, plaintext, associated_data)
        chacha_decrypted = chacha.decrypt(chacha_nonce, chacha_ciphertext, associated_data)
        
        print(f"  Key Size: 256 bits")
        print(f"  Nonce: {chacha_nonce.hex()}")
        print(f"  Ciphertext: {chacha_ciphertext.hex()[:32]}...")
        print(f"  Decrypted: {chacha_decrypted.decode()}")
        print(f"  Match: {'✅' if plaintext == chacha_decrypted else '❌'}")
        print()
        
        # 3. AES-OCB3
        try:
            print(f"🔹 AES-OCB3 (Offset Codebook):")
            ocb_key = os.urandom(32)
            ocb_nonce = os.urandom(12)
            
            aesocb = AESOCB3(ocb_key)
            ocb_ciphertext = aesocb.encrypt(ocb_nonce, plaintext, associated_data)
            ocb_decrypted = aesocb.decrypt(ocb_nonce, ocb_ciphertext, associated_data)
            
            print(f"  Key Size: 256 bits")
            print(f"  Nonce: {ocb_nonce.hex()}")
            print(f"  Ciphertext: {ocb_ciphertext.hex()[:32]}...")
            print(f"  Decrypted: {ocb_decrypted.decode()}")
            print(f"  Match: {'✅' if plaintext == ocb_decrypted else '❌'}")
            print(f"  Performance: Higher than GCM (parallel processing)")
        except Exception as e:
            print(f"  ⚠️  AES-OCB3 not available: {e}")
        print()
    
    def demo_digital_signatures(self):
        """Demo digital signature algorithms"""
        print(f"\n✍️  DIGITAL SIGNATURES")
        print(f"{'─'*120}")
        
        message = b"Important message requiring authentication"
        
        # 1. RSA-PSS
        print(f"🔹 RSA-PSS (Probabilistic Signature Scheme):")
        rsa_private = rsa.generate_private_key(65537, 2048, self.backend)
        rsa_public = rsa_private.public_key()
        
        rsa_signature = rsa_private.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        try:
            rsa_public.verify(
                rsa_signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            rsa_valid = True
        except:
            rsa_valid = False
        
        print(f"  Key Size: 2048 bits")
        print(f"  Message: {message.decode()}")
        print(f"  Signature: {rsa_signature.hex()[:32]}...")
        print(f"  Verification: {'✅ Valid' if rsa_valid else '❌ Invalid'}")
        print()
        
        # 2. ECDSA
        print(f"🔹 ECDSA (Elliptic Curve Digital Signature):")
        ec_private = ec.generate_private_key(ec.SECP256R1(), self.backend)
        ec_public = ec_private.public_key()
        
        ec_signature = ec_private.sign(message, ec.ECDSA(hashes.SHA256()))
        
        try:
            ec_public.verify(ec_signature, message, ec.ECDSA(hashes.SHA256()))
            ec_valid = True
        except:
            ec_valid = False
        
        print(f"  Curve: P-256")
        print(f"  Message: {message.decode()}")
        print(f"  Signature: {ec_signature.hex()[:32]}...")
        print(f"  Verification: {'✅ Valid' if ec_valid else '❌ Invalid'}")
        print(f"  Advantage: Smaller signatures than RSA")
        print()
    
    def demo_hash_and_mac(self):
        """Demo hash functions và MACs"""
        print(f"\n🏷️  HASH FUNCTIONS & MESSAGE AUTHENTICATION CODES")
        print(f"{'─'*120}")
        
        message = b"Message to authenticate and verify integrity"
        
        # Hash functions
        print(f"🔹 Cryptographic Hash Functions:")
        hash_algorithms = [
            ('SHA-256', hashes.SHA256()),
            ('SHA-384', hashes.SHA384()),
            ('SHA-512', hashes.SHA512()),
            ('BLAKE2b', hashes.BLAKE2b(64)),
            ('SHA3-256', hashes.SHA3_256())
        ]
        
        for name, algorithm in hash_algorithms:
            digest = hashes.Hash(algorithm, backend=self.backend)
            digest.update(message)
            hash_value = digest.finalize()
            
            print(f"  {name}: {hash_value.hex()[:32]}... ({len(hash_value)} bytes)")
        
        print()
        
        # MAC algorithms
        print(f"🔹 Message Authentication Codes:")
        mac_key = os.urandom(32)
        
        # HMAC
        hmac_sha256 = hmac.HMAC(mac_key, hashes.SHA256(), backend=self.backend)
        hmac_sha256.update(message)
        hmac_value = hmac_sha256.finalize()
        
        print(f"  HMAC-SHA256: {hmac_value.hex()}")
        print(f"  Key: {mac_key.hex()[:16]}...")
        print(f"  Message: {message.decode()}")
        
        # Verify HMAC
        hmac_verify = hmac.HMAC(mac_key, hashes.SHA256(), backend=self.backend)
        hmac_verify.update(message)
        try:
            hmac_verify.verify(hmac_value)
            print(f"  Verification: ✅ Valid")
        except:
            print(f"  Verification: ❌ Invalid")
        print()
    
    def demo_post_quantum_considerations(self):
        """Demo post-quantum cryptography considerations"""
        print(f"\n🌌 POST-QUANTUM CRYPTOGRAPHY CONSIDERATIONS")
        print(f"{'─'*120}")
        
        print(f"🔹 Current Status:")
        print(f"  • Current algorithms (RSA, ECDSA, ECDH) vulnerable to quantum computers")
        print(f"  • NIST Post-Quantum Cryptography standardization ongoing")
        print(f"  • Hybrid approaches recommended during transition")
        print()
        
        print(f"🔹 Algorithm Categories:")
        pqc_algorithms = {
            'Lattice-based': ['CRYSTALS-Kyber (KEM)', 'CRYSTALS-Dilithium (Signature)', 'FALCON (Signature)'],
            'Code-based': ['Classic McEliece (KEM)'],
            'Multivariate': ['Rainbow (Signature) - Broken'],
            'Hash-based': ['SPHINCS+ (Signature)']
        }
        
        for category, algorithms in pqc_algorithms.items():
            print(f"  {category}:")
            for alg in algorithms:
                print(f"    • {alg}")
        print()
        
        print(f"🔹 Key Size Comparison (Security Level 1):")
        comparison = [
            ('RSA-2048', '256 bytes', 'Classical'),
            ('P-256', '32 bytes', 'Classical'),
            ('Kyber-512', '800 bytes', 'Post-Quantum'),
            ('Dilithium2', '1,312 bytes', 'Post-Quantum'),
            ('FALCON-512', '666 bytes', 'Post-Quantum')
        ]
        
        print(f"  {'Algorithm':<15} {'Key/Sig Size':<15} {'Type'}")
        print(f"  {'-'*45}")
        for alg, size, type_str in comparison:
            print(f"  {alg:<15} {size:<15} {type_str}")
        
        print()
        print(f"🔹 Migration Strategy:")
        print(f"  1. Crypto-agility: Design systems to easily swap algorithms")
        print(f"  2. Hybrid mode: Use both classical and post-quantum algorithms")
        print(f"  3. Monitor NIST standardization progress")
        print(f"  4. Implement quantum-safe TLS when available")
        print(f"  5. Consider AES-256 (quantum-resistant symmetric crypto)")
        print()
        
        # Demo quantum-resistant symmetric crypto
        print(f"🔹 Quantum-Resistant Symmetric Cryptography:")
        print(f"  • AES-256: Effectively 128-bit security against quantum")
        print(f"  • ChaCha20: Also quantum-resistant")
        print(f"  • SHA-256: Provides ~128-bit quantum security")
        
        # Demo AES-256 for quantum resistance
        qr_key = os.urandom(32)  # 256-bit key
        qr_nonce = os.urandom(12)
        qr_data = b"Quantum-resistant encrypted data"
        
        aesgcm_qr = AESGCM(qr_key)
        qr_ciphertext = aesgcm_qr.encrypt(qr_nonce, qr_data, None)
        
        print(f"  AES-256-GCM Demo:")
        print(f"    Key: {qr_key.hex()[:32]}... (256-bit)")
        print(f"    Ciphertext: {qr_ciphertext.hex()[:32]}...")
        print(f"    Quantum Security: ~128 bits")


if __name__ == "__main__":
    demo = AdvancedCryptographyDemo()
    demo.comprehensive_crypto_demo()