"""
TLS/SSL Implementation Demo using Python cryptography library
Demonstrates: Certificate generation, TLS handshake, encryption/decryption
"""

import os
import socket
import ssl
import json
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading
import time

# ==================== CERTIFICATE GENERATION ====================
class CertificateAuthority:
    """Tạo CA và certificates cho TLS"""
    
    def __init__(self):
        self.backend = default_backend()
        
    def generate_private_key(self, key_size=2048):
        """Generate RSA private key"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        return private_key
    
    def create_self_signed_cert(self, private_key, common_name, days_valid=365):
        """Tạo self-signed certificate"""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Hanoi"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Hanoi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName(f"*.{common_name}"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).sign(private_key, hashes.SHA256(), self.backend)
        
        return cert
    
    def save_certificate(self, cert, filename):
        """Lưu certificate vào file"""
        with open(filename, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"✓ Certificate saved: {filename}")
    
    def save_private_key(self, private_key, filename, password=None):
        """Lưu private key vào file"""
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        
        with open(filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption
            ))
        print(f"✓ Private key saved: {filename}")


# ==================== TLS SERVER ====================
class TLSServer:
    """Custom TLS Server với detailed logging"""
    
    def __init__(self, host='localhost', port=8443, certfile='server.crt', keyfile='server.key'):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.running = False
        
    def start(self):
        """Khởi động TLS server"""
        # Tạo SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certfile, self.keyfile)
        
        # Cấu hình cipher suites
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Chỉ dùng TLS 1.2+
        
        print(f"\n{'='*60}")
        print(f"🔒 TLS SERVER STARTING")
        print(f"{'='*60}")
        print(f"Host: {self.host}")
        print(f"Port: {self.port}")
        print(f"Certificate: {self.certfile}")
        print(f"Waiting for connections...\n")
        
        # Tạo socket và bind
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(5)
            
            with context.wrap_socket(sock, server_side=True) as ssock:
                self.running = True
                
                while self.running:
                    try:
                        conn, addr = ssock.accept()
                        print(f"📥 Connection from: {addr}")
                        
                        # In thông tin TLS
                        self.print_tls_info(conn)
                        
                        # Nhận và xử lý dữ liệu
                        data = conn.recv(1024).decode()
                        print(f"📨 Received (encrypted): {len(data)} bytes")
                        print(f"📝 Decrypted message: {data}")
                        
                        # Gửi response
                        response = f"Server received: {data}"
                        conn.send(response.encode())
                        print(f"📤 Sent response: {response}\n")
                        
                        conn.close()
                        
                    except KeyboardInterrupt:
                        print("\n🛑 Server shutting down...")
                        self.running = False
                        break
                    except Exception as e:
                        print(f"❌ Error: {e}")
    
    def print_tls_info(self, conn):
        """In thông tin chi tiết về TLS connection"""
        print(f"\n{'─'*60}")
        print(f"🔐 TLS HANDSHAKE COMPLETED")
        print(f"{'─'*60}")
        
        cipher = conn.cipher()
        if cipher:
            print(f"TLS Version: {conn.version()}")
            print(f"Cipher Suite: {cipher[0]}")
            print(f"Encryption: {cipher[1]}")
            print(f"Key Exchange: {cipher[2]} bits")
        
        # Certificate info
        cert = conn.getpeercert()
        if cert:
            print(f"\nClient Certificate Info:")
            print(f"Subject: {dict(x[0] for x in cert['subject'])}")
        
        print(f"{'─'*60}\n")


# ==================== TLS CLIENT ====================
class TLSClient:
    """Custom TLS Client với detailed logging"""
    
    def __init__(self, host='localhost', port=8443, ca_cert='server.crt'):
        self.host = host
        self.port = port
        self.ca_cert = ca_cert
    
    def connect_and_send(self, message):
        """Kết nối và gửi message qua TLS"""
        print(f"\n{'='*60}")
        print(f"🔓 TLS CLIENT STARTING")
        print(f"{'='*60}")
        print(f"Connecting to: {self.host}:{self.port}")
        print(f"CA Certificate: {self.ca_cert}\n")
        
        # Tạo SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(self.ca_cert)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        
        print("🔄 Starting TLS Handshake...")
        print(f"\nHandshake Steps:")
        print(f"1. ➤ Client Hello (Sending supported ciphers)")
        time.sleep(0.5)
        print(f"2. ➤ Server Hello (Received cipher selection)")
        time.sleep(0.5)
        print(f"3. ➤ Certificate Exchange")
        time.sleep(0.5)
        print(f"4. ➤ Key Exchange (ECDHE)")
        time.sleep(0.5)
        print(f"5. ✓ Handshake Complete!")
        
        # Kết nối
        with socket.create_connection((self.host, self.port)) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                
                # In thông tin TLS
                self.print_tls_info(ssock)
                
                # Gửi message
                print(f"\n📤 Sending encrypted message...")
                print(f"Plaintext: {message}")
                ssock.send(message.encode())
                
                # Nhận response
                response = ssock.recv(1024).decode()
                print(f"📥 Received response: {response}")
    
    def print_tls_info(self, ssock):
        """In thông tin chi tiết về TLS connection"""
        print(f"\n{'─'*60}")
        print(f"🔐 CONNECTION ESTABLISHED")
        print(f"{'─'*60}")
        
        cipher = ssock.cipher()
        print(f"TLS Version: {ssock.version()}")
        print(f"Cipher Suite: {cipher[0]}")
        print(f"Protocol: {cipher[1]}")
        print(f"Key Size: {cipher[2]} bits")
        
        # Certificate verification
        cert = ssock.getpeercert()
        print(f"\n✓ Server Certificate Verified")
        print(f"Subject: {dict(x[0] for x in cert['subject'])}")
        print(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
        print(f"Valid from: {cert['notBefore']}")
        print(f"Valid until: {cert['notAfter']}")
        print(f"{'─'*60}")


# ==================== ENCRYPTION DEMO ====================
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


# ==================== MAIN DEMO ====================
def main():
    """Main demo function"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║          TLS/SSL IMPLEMENTATION DEMO                         ║
║          Using Python Cryptography Library                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Menu
    while True:
        print("\n" + "="*60)
        print("DEMO OPTIONS:")
        print("="*60)
        print("1. Generate Certificates (CA & Server)")
        print("2. Start TLS Server")
        print("3. Run TLS Client (connect to server)")
        print("4. Demo Encryption Algorithms (AES-GCM, RSA)")
        print("5. Full Demo (All steps)")
        print("0. Exit")
        print("="*60)
        
        choice = input("\nSelect option: ").strip()
        
        if choice == "1":
            # Generate certificates
            ca = CertificateAuthority()
            
            print("\n🔧 Generating certificates...")
            private_key = ca.generate_private_key()
            cert = ca.create_self_signed_cert(private_key, "localhost")
            
            ca.save_private_key(private_key, "server.key")
            ca.save_certificate(cert, "server.crt")
            
            print("\n✓ Certificates generated successfully!")
            print("  - server.key (private key)")
            print("  - server.crt (certificate)")
        
        elif choice == "2":
            # Start server
            if not os.path.exists("server.crt") or not os.path.exists("server.key"):
                print("\n❌ Certificates not found! Run option 1 first.")
                continue
            
            server = TLSServer()
            try:
                server.start()
            except Exception as e:
                print(f"❌ Server error: {e}")
        
        elif choice == "3":
            # Run client
            if not os.path.exists("server.crt"):
                print("\n❌ Certificate not found! Run option 1 first.")
                continue
            
            message = input("Enter message to send: ").strip() or "Hello TLS Server!"
            client = TLSClient()
            try:
                client.connect_and_send(message)
            except Exception as e:
                print(f"❌ Client error: {e}")
                print("💡 Make sure server is running (option 2)")
        
        elif choice == "4":
            # Demo encryption
            demo = EncryptionDemo()
            demo.demo_aes_gcm()
            demo.demo_rsa_encryption()
        
        elif choice == "5":
            print("\n🚀 Running full demo...")
            
            # Step 1: Generate certs
            print("\n[STEP 1/3] Generating certificates...")
            ca = CertificateAuthority()
            private_key = ca.generate_private_key()
            cert = ca.create_self_signed_cert(private_key, "localhost")
            ca.save_private_key(private_key, "server.key")
            ca.save_certificate(cert, "server.crt")
            
            # Step 2: Demo encryption
            print("\n[STEP 2/3] Demonstrating encryption algorithms...")
            demo = EncryptionDemo()
            demo.demo_aes_gcm()
            demo.demo_rsa_encryption()
            
            # Step 3: Instructions
            print("\n[STEP 3/3] Server/Client Demo")
            print("To test TLS connection:")
            print("1. Run this program in terminal 1: Select option 2 (Start Server)")
            print("2. Run this program in terminal 2: Select option 3 (Run Client)")
            
        elif choice == "0":
            print("\n👋 Goodbye!")
            break
        
        else:
            print("\n❌ Invalid option!")


if __name__ == "__main__":
    main()