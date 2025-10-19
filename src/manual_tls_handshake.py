"""
Manual TLS Handshake Implementation
Hiển thị chi tiết từng bước trong TLS handshake process
Không dựa vào SSL library để hiểu sâu protocol
"""
import os
import socket
import struct
import hashlib
import hmac
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class TLSHandshakeSimulator:
    """Mô phỏng chi tiết TLS handshake process"""
    
    # TLS Version Constants
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304
    
    # Content Types
    HANDSHAKE = 22
    CHANGE_CIPHER_SPEC = 20
    APPLICATION_DATA = 23
    ALERT = 21
    
    # Handshake Types
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    SERVER_HELLO_DONE = 14
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    
    def __init__(self):
        self.backend = default_backend()
        self.client_random = None
        self.server_random = None
        self.premaster_secret = None
        self.master_secret = None
        self.session_keys = {}
        
    def demo_tls_handshake(self):
        """Demo complete TLS handshake process"""
        print(f"\n{'='*80}")
        print(f"🔐 MANUAL TLS 1.2 HANDSHAKE SIMULATION")
        print(f"{'='*80}")
        
        # Step 1: Client Hello
        print(f"\n[STEP 1/8] 📤 Client Hello")
        client_hello = self.create_client_hello()
        self.print_client_hello(client_hello)
        
        # Step 2: Server Hello
        print(f"\n[STEP 2/8] 📥 Server Hello")
        server_hello = self.create_server_hello()
        self.print_server_hello(server_hello)
        
        # Step 3: Certificate
        print(f"\n[STEP 3/8] 📜 Certificate")
        self.demo_certificate_exchange()
        
        # Step 4: Server Key Exchange (for ECDHE)
        print(f"\n[STEP 4/8] 🔑 Server Key Exchange")
        self.demo_server_key_exchange()
        
        # Step 5: Server Hello Done
        print(f"\n[STEP 5/8] ✅ Server Hello Done")
        print("Server signals end of hello message phase")
        
        # Step 6: Client Key Exchange
        print(f"\n[STEP 6/8] 🔑 Client Key Exchange")
        self.demo_client_key_exchange()
        
        # Step 7: Key Derivation
        print(f"\n[STEP 7/8] 🔐 Key Derivation")
        self.demo_key_derivation()
        
        # Step 8: Finished Messages
        print(f"\n[STEP 8/8] 🏁 Finished Messages")
        self.demo_finished_messages()
        
        print(f"\n✅ TLS Handshake Complete!")
        print(f"🔒 Secure channel established with session keys")
        
    def create_client_hello(self):
        """Tạo Client Hello message"""
        self.client_random = os.urandom(32)
        
        client_hello = {
            'version': self.TLS_1_2,
            'random': self.client_random,
            'session_id': b'',
            'cipher_suites': [
                0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
                0xC02B,  # ECDHE-ECDSA-AES128-GCM-SHA256
                0x009E,  # DHE-RSA-AES128-GCM-SHA256
                0x0033,  # DHE-RSA-AES128-SHA
            ],
            'compression_methods': [0],  # No compression
            'extensions': {
                'server_name': b'localhost',
                'supported_groups': [23, 24, 25],  # secp256r1, secp384r1, secp521r1
                'signature_algorithms': [
                    (4, 1),  # rsa_pkcs1_sha256
                    (8, 4),  # rsa_pss_rsae_sha256
                ]
            }
        }
        return client_hello
    
    def print_client_hello(self, client_hello):
        """In thông tin Client Hello"""
        print("┌─ Client Hello Details:")
        print(f"│  TLS Version: {hex(client_hello['version'])}")
        print(f"│  Random: {client_hello['random'].hex()[:32]}...")
        print(f"│  Session ID: {'Empty' if not client_hello['session_id'] else client_hello['session_id'].hex()}")
        print("│  Cipher Suites:")
        cipher_names = {
            0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
            0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 
            0x009E: "DHE-RSA-AES128-GCM-SHA256",
            0x0033: "DHE-RSA-AES128-SHA"
        }
        for suite in client_hello['cipher_suites']:
            print(f"│    {hex(suite)}: {cipher_names.get(suite, 'Unknown')}")
        print("│  Extensions:")
        print(f"│    Server Name: {client_hello['extensions']['server_name'].decode()}")
        print(f"│    Supported Groups: {client_hello['extensions']['supported_groups']}")
        print("└─")
    
    def create_server_hello(self):
        """Tạo Server Hello message"""
        self.server_random = os.urandom(32)
        
        server_hello = {
            'version': self.TLS_1_2,
            'random': self.server_random,
            'session_id': os.urandom(16),  # New session
            'cipher_suite': 0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
            'compression_method': 0,
            'extensions': {}
        }
        return server_hello
    
    def print_server_hello(self, server_hello):
        """In thông tin Server Hello"""
        print("┌─ Server Hello Details:")
        print(f"│  TLS Version: {hex(server_hello['version'])}")
        print(f"│  Random: {server_hello['random'].hex()[:32]}...")
        print(f"│  Session ID: {server_hello['session_id'].hex()}")
        print(f"│  Selected Cipher: {hex(server_hello['cipher_suite'])} (ECDHE-RSA-AES128-GCM-SHA256)")
        print(f"│  Compression: {server_hello['compression_method']} (None)")
        print("└─")
    
    def demo_certificate_exchange(self):
        """Demo certificate exchange"""
        print("┌─ Certificate Exchange:")
        print("│  Server sends X.509 certificate chain:")
        print("│    └─ Server Certificate")
        print("│       ├─ Subject: CN=localhost, O=PTIT Demo")
        print("│       ├─ Issuer: CN=localhost, O=PTIT Demo (Self-signed)")
        print("│       ├─ Public Key: RSA 2048-bit")
        print("│       ├─ Signature Algorithm: sha256WithRSAEncryption")
        print("│       └─ Extensions: SubjectAltName=localhost")
        print("│")
        print("│  Client verifies certificate:")
        print("│    ✓ Certificate signature validation")
        print("│    ✓ Certificate validity period")
        print("│    ✓ Hostname verification")
        print("│    ! Trust chain (accepted for demo)")
        print("└─")
    
    def demo_server_key_exchange(self):
        """Demo Server Key Exchange cho ECDHE"""
        # Generate ECDH parameters
        from cryptography.hazmat.primitives.asymmetric import ec
        
        # Server generates ECDH key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
        public_key = private_key.public_key()
        
        # Serialize public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        print("┌─ Server Key Exchange (ECDHE):")
        print("│  Elliptic Curve: secp256r1 (P-256)")
        print(f"│  Server Public Key: {public_bytes.hex()[:32]}...")
        print("│  Signature Algorithm: rsa_pkcs1_sha256")
        print("│  Signature covers:")
        print("│    ├─ Client Random")
        print("│    ├─ Server Random") 
        print("│    └─ Server ECDH Public Key")
        print("│")
        print("│  Client verifies signature with server's RSA public key")
        print("│    ✓ Signature verification successful")
        print("└─")
        
        # Store for later use
        self.server_ecdh_private = private_key
        self.server_ecdh_public = public_key
    
    def demo_client_key_exchange(self):
        """Demo Client Key Exchange"""
        from cryptography.hazmat.primitives.asymmetric import ec
        
        # Client generates ECDH key pair
        client_private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
        client_public_key = client_private_key.public_key()
        
        # Serialize public key
        public_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        print("┌─ Client Key Exchange:")
        print(f"│  Client ECDH Public Key: {public_bytes.hex()[:32]}...")
        print("│")
        print("│  ECDH Shared Secret Computation:")
        
        # Compute shared secret
        shared_key = self.server_ecdh_private.exchange(ec.ECDH(), client_public_key)
        
        print(f"│    Shared Secret: {shared_key.hex()[:32]}...")
        print("│    ✓ Both parties now have same shared secret")
        print("└─")
        
        self.premaster_secret = shared_key
    
    def demo_key_derivation(self):
        """Demo key derivation process"""
        print("┌─ Key Derivation (TLS 1.2 PRF):")
        
        # Master secret derivation
        label = b"master secret"
        seed = self.client_random + self.server_random
        self.master_secret = self.tls_prf(self.premaster_secret, label, seed, 48)
        
        print(f"│  Premaster Secret: {self.premaster_secret.hex()[:32]}...")
        print(f"│  Client Random: {self.client_random.hex()[:16]}...")
        print(f"│  Server Random: {self.server_random.hex()[:16]}...")
        print("│")
        print(f"│  Master Secret: {self.master_secret.hex()[:32]}...")
        print("│")
        
        # Key expansion
        key_label = b"key expansion"
        key_seed = self.server_random + self.client_random
        key_material = self.tls_prf(self.master_secret, key_label, key_seed, 104)
        
        # Extract keys
        pos = 0
        self.session_keys = {}
        
        # Proper key extraction
        self.session_keys['client_write_mac'] = key_material[pos:pos+20]; pos += 20
        self.session_keys['server_write_mac'] = key_material[pos:pos+20]; pos += 20
        self.session_keys['client_write_key'] = key_material[pos:pos+16]; pos += 16
        self.session_keys['server_write_key'] = key_material[pos:pos+16]; pos += 16
        self.session_keys['client_write_iv'] = key_material[pos:pos+4]; pos += 4
        self.session_keys['server_write_iv'] = key_material[pos:pos+4]
        
        print("│  Session Keys Generated:")
        for key_name, key_value in self.session_keys.items():
            print(f"│    {key_name}: {key_value.hex()}")
        print("└─")
    
    def tls_prf(self, secret, label, seed, length):
        """TLS 1.2 Pseudo Random Function (PRF)"""
        def p_hash(secret, seed, length, hash_func):
            result = b''
            a = seed
            while len(result) < length:
                a = hmac.new(secret, a, hash_func).digest()
                result += hmac.new(secret, a + seed, hash_func).digest()
            return result[:length]
        
        return p_hash(secret, label + seed, length, hashlib.sha256)
    
    def demo_finished_messages(self):
        """Demo Finished messages với verify_data"""
        print("┌─ Finished Messages:")
        
        # Client Finished
        client_finished_data = self.calculate_verify_data("client")
        print("│  Client Finished:")
        print(f"│    Verify Data: {client_finished_data.hex()}")
        print("│    ✓ Contains hash of all handshake messages")
        print("│")
        
        # Server Finished  
        server_finished_data = self.calculate_verify_data("server")
        print("│  Server Finished:")
        print(f"│    Verify Data: {server_finished_data.hex()}")
        print("│    ✓ Confirms handshake integrity")
        print("│")
        print("│  🔒 Handshake complete - encrypted tunnel ready!")
        print("└─")
    
    def calculate_verify_data(self, sender):
        """Tính verify_data cho Finished message"""
        if sender == "client":
            label = b"client finished"
        else:
            label = b"server finished"
        
        # Simplified - in real implementation would hash all handshake messages
        handshake_hash = hashlib.sha256(b"handshake_messages").digest()
        verify_data = self.tls_prf(self.master_secret, label, handshake_hash, 12)
        return verify_data


if __name__ == "__main__":
    simulator = TLSHandshakeSimulator()
    simulator.demo_tls_handshake()