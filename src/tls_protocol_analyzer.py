"""
Advanced Cipher Suites và TLS Protocol Comparison
Demo multiple cipher suites, TLS 1.2 vs 1.3, Perfect Forward Secrecy
"""
import ssl
import socket
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os

class TLSProtocolAnalyzer:
    """Phân tích và demo các TLS protocols và cipher suites"""
    
    def __init__(self):
        self.backend = default_backend()
        
        # TLS 1.2 Cipher Suites
        self.tls12_ciphers = {
            'ECDHE-RSA-AES256-GCM-SHA384': {
                'key_exchange': 'ECDHE',
                'authentication': 'RSA', 
                'encryption': 'AES-256-GCM',
                'mac': 'SHA384',
                'pfs': True,
                'security': 'High'
            },
            'ECDHE-RSA-AES128-GCM-SHA256': {
                'key_exchange': 'ECDHE',
                'authentication': 'RSA',
                'encryption': 'AES-128-GCM', 
                'mac': 'SHA256',
                'pfs': True,
                'security': 'High'
            },
            'ECDHE-RSA-CHACHA20-POLY1305': {
                'key_exchange': 'ECDHE',
                'authentication': 'RSA',
                'encryption': 'ChaCha20-Poly1305',
                'mac': 'Integrated',
                'pfs': True,
                'security': 'High'
            },
            'DHE-RSA-AES256-GCM-SHA384': {
                'key_exchange': 'DHE',
                'authentication': 'RSA',
                'encryption': 'AES-256-GCM',
                'mac': 'SHA384', 
                'pfs': True,
                'security': 'Medium'
            },
            'RSA-AES256-GCM-SHA384': {
                'key_exchange': 'RSA',
                'authentication': 'RSA',
                'encryption': 'AES-256-GCM',
                'mac': 'SHA384',
                'pfs': False,
                'security': 'Medium'
            }
        }
        
        # TLS 1.3 Cipher Suites
        self.tls13_ciphers = {
            'TLS_AES_256_GCM_SHA384': {
                'encryption': 'AES-256-GCM',
                'hash': 'SHA384',
                'security': 'High'
            },
            'TLS_CHACHA20_POLY1305_SHA256': {
                'encryption': 'ChaCha20-Poly1305',
                'hash': 'SHA256',
                'security': 'High'
            },
            'TLS_AES_128_GCM_SHA256': {
                'encryption': 'AES-128-GCM', 
                'hash': 'SHA256',
                'security': 'High'
            }
        }
    
    def comprehensive_tls_analysis(self):
        """Demo comprehensive TLS analysis"""
        print(f"\n{'='*100}")
        print(f"🔐 COMPREHENSIVE TLS PROTOCOL & CIPHER SUITE ANALYSIS")
        print(f"{'='*100}")
        
        # 1. TLS Protocol Comparison
        self.compare_tls_versions()
        
        # 2. Cipher Suite Analysis
        self.analyze_cipher_suites()
        
        # 3. Perfect Forward Secrecy Demo
        self.demo_perfect_forward_secrecy()
        
        # 4. Key Exchange Comparison
        self.compare_key_exchanges()
        
        # 5. Encryption Algorithm Performance
        self.compare_encryption_performance()
        
        # 6. Security Assessment
        self.security_recommendations()
    
    def compare_tls_versions(self):
        """So sánh TLS 1.2 vs TLS 1.3"""
        print(f"\n📊 TLS VERSION COMPARISON")
        print(f"{'─'*100}")
        
        comparison = {
            'Feature': ['Handshake RTT', 'Perfect Forward Secrecy', 'Key Exchange', 'Cipher Negotiation', 
                       'Certificate Encryption', 'Resumption', 'Downgrade Protection'],
            'TLS 1.2': ['2-RTT', 'Optional (ECDHE/DHE)', 'RSA, ECDHE, DHE', 'Explicit', 
                       'No', 'Session ID/Ticket', 'Limited'],
            'TLS 1.3': ['1-RTT (0-RTT possible)', 'Always (mandatory)', 'ECDHE, DHE only', 'Implicit',
                       'Yes', 'PSK-based', 'Strong']
        }
        
        # Print comparison table
        print(f"{'Feature':<25} {'TLS 1.2':<30} {'TLS 1.3':<30}")
        print('─' * 90)
        
        for i in range(len(comparison['Feature'])):
            print(f"{comparison['Feature'][i]:<25} {comparison['TLS 1.2'][i]:<30} {comparison['TLS 1.3'][i]:<30}")
        
        print(f"\n🔹 TLS 1.2 Characteristics:")
        print("  • Flexible but complex configuration")
        print("  • Backward compatibility with older systems")
        print("  • Optional PFS (depends on cipher suite)")
        print("  • Certificate sent in plaintext")
        
        print(f"\n🔹 TLS 1.3 Improvements:")
        print("  • Simplified, more secure by design") 
        print("  • Always provides Perfect Forward Secrecy")
        print("  • Faster handshake (1-RTT)")
        print("  • Encrypted certificate exchange")
        print("  • Removed legacy/insecure algorithms")
        
    def analyze_cipher_suites(self):
        """Phân tích chi tiết cipher suites"""
        print(f"\n🔐 CIPHER SUITE ANALYSIS")
        print(f"{'─'*100}")
        
        print(f"\n📋 TLS 1.2 Cipher Suites:")
        print(f"{'Cipher Suite':<40} {'Key Exch':<10} {'Auth':<8} {'Encryption':<20} {'MAC':<15} {'PFS':<6} {'Security'}")
        print('─' * 105)
        
        for cipher, details in self.tls12_ciphers.items():
            pfs_indicator = '✓' if details['pfs'] else '❌'
            security_color = '🟢' if details['security'] == 'High' else '🟡' if details['security'] == 'Medium' else '🔴'
            
            print(f"{cipher:<40} {details['key_exchange']:<10} {details['authentication']:<8} "
                  f"{details['encryption']:<20} {details['mac']:<15} {pfs_indicator:<6} "
                  f"{security_color} {details['security']}")
        
        print(f"\n📋 TLS 1.3 Cipher Suites:")
        print(f"{'Cipher Suite':<35} {'Encryption':<25} {'Hash':<15} {'Security'}")
        print('─' * 85)
        
        for cipher, details in self.tls13_ciphers.items():
            security_color = '🟢' if details['security'] == 'High' else '🟡'
            print(f"{cipher:<35} {details['encryption']:<25} {details['hash']:<15} {security_color} {details['security']}")
        
        # Security recommendations
        print(f"\n💡 Cipher Suite Recommendations:")
        print("  🟢 Recommended: ECDHE-RSA-AES256-GCM-SHA384, TLS_AES_256_GCM_SHA384")
        print("  🟡 Acceptable: ECDHE-RSA-AES128-GCM-SHA256, DHE-RSA-AES256-GCM-SHA384")
        print("  🔴 Avoid: RSA key exchange (no PFS), RC4, 3DES, MD5")
    
    def demo_perfect_forward_secrecy(self):
        """Demo Perfect Forward Secrecy"""
        print(f"\n🔑 PERFECT FORWARD SECRECY DEMONSTRATION")
        print(f"{'─'*100}")
        
        print("Perfect Forward Secrecy ensures that session keys cannot be compromised")
        print("even if the server's private key is later compromised.\n")
        
        # Demo ECDHE key exchange
        print("🔹 ECDHE Key Exchange (provides PFS):")
        
        # Generate ephemeral keys for both parties
        server_private = ec.generate_private_key(ec.SECP256R1(), self.backend)
        client_private = ec.generate_private_key(ec.SECP256R1(), self.backend)
        
        server_public = server_private.public_key()
        client_public = client_private.public_key()
        
        # Exchange public keys and compute shared secrets
        server_shared = server_private.exchange(ec.ECDH(), client_public)
        client_shared = client_private.exchange(ec.ECDH(), server_public)
        
        print(f"  Server ephemeral private: {server_private.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()[:100]}...")
        print(f"  Client ephemeral private: {client_private.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()[:100]}...")
        print(f"  Shared secret: {server_shared.hex()[:32]}...")
        print(f"  ✓ Secrets match: {server_shared == client_shared}")
        
        print("\n  📋 PFS Properties:")
        print("    • Ephemeral keys are generated per session")
        print("    • Private keys are discarded after use")
        print("    • Past sessions remain secure if long-term key compromised")
        print("    • Each session has unique encryption keys")
        
        # Contrast with RSA key exchange
        print(f"\n🔹 RSA Key Exchange (NO PFS):")
        print("  • Uses server's static RSA private key")
        print("  • Same private key used for all sessions")
        print("  • If private key compromised, ALL past sessions compromised")
        print("  • ❌ Does not provide Perfect Forward Secrecy")
    
    def compare_key_exchanges(self):
        """So sánh các phương pháp key exchange"""
        print(f"\n🔄 KEY EXCHANGE COMPARISON")
        print(f"{'─'*100}")
        
        methods = {
            'RSA': {
                'description': 'Client encrypts premaster secret with server public key',
                'pfs': False,
                'performance': 'Fast',
                'security': 'Medium',
                'notes': 'Vulnerable if private key compromised'
            },
            'DHE': {
                'description': 'Diffie-Hellman with ephemeral keys',
                'pfs': True,
                'performance': 'Slow',
                'security': 'High', 
                'notes': 'CPU intensive, provides PFS'
            },
            'ECDHE': {
                'description': 'Elliptic Curve Diffie-Hellman ephemeral',
                'pfs': True,
                'performance': 'Fast',
                'security': 'High',
                'notes': 'Best balance of security and performance'
            }
        }
        
        print(f"{'Method':<8} {'PFS':<6} {'Performance':<12} {'Security':<10} {'Description'}")
        print('─' * 80)
        
        for method, details in methods.items():
            pfs_indicator = '✓' if details['pfs'] else '❌'
            security_color = '🟢' if details['security'] == 'High' else '🟡' if details['security'] == 'Medium' else '🔴'
            
            print(f"{method:<8} {pfs_indicator:<6} {details['performance']:<12} {security_color} {details['security']:<9} {details['description']}")
            print(f"{'':>37} {details['notes']}")
            print()
    
    def compare_encryption_performance(self):
        """So sánh performance của encryption algorithms"""
        print(f"\n⚡ ENCRYPTION ALGORITHM PERFORMANCE")
        print(f"{'─'*100}")
        
        # Test data
        test_data = b"This is test data for encryption performance measurement" * 100
        
        print(f"Test data size: {len(test_data)} bytes\n")
        
        # AES-256-GCM
        print("🔹 AES-256-GCM:")
        aes_key = os.urandom(32)
        aes_nonce = os.urandom(12)
        
        start_time = datetime.now()
        aesgcm = AESGCM(aes_key)
        for _ in range(1000):
            ciphertext = aesgcm.encrypt(aes_nonce, test_data, None)
        aes_time = (datetime.now() - start_time).total_seconds()
        
        print(f"  Key size: 256 bits")
        print(f"  Block cipher: AES")
        print(f"  Mode: GCM (authenticated encryption)")
        print(f"  Performance: {1000/aes_time:.0f} operations/second")
        
        # ChaCha20-Poly1305
        print("\n🔹 ChaCha20-Poly1305:")
        chacha_key = os.urandom(32)
        chacha_nonce = os.urandom(12)
        
        start_time = datetime.now()
        chacha = ChaCha20Poly1305(chacha_key)
        for _ in range(1000):
            ciphertext = chacha.encrypt(chacha_nonce, test_data, None)
        chacha_time = (datetime.now() - start_time).total_seconds()
        
        print(f"  Key size: 256 bits")
        print(f"  Stream cipher: ChaCha20")
        print(f"  MAC: Poly1305 (authenticated encryption)")
        print(f"  Performance: {1000/chacha_time:.0f} operations/second")
        
        # Comparison
        print(f"\n📊 Performance Comparison:")
        if aes_time < chacha_time:
            print(f"  🏆 AES-256-GCM is {chacha_time/aes_time:.1f}x faster")
            print(f"      (Especially on hardware with AES-NI support)")
        else:
            print(f"  🏆 ChaCha20-Poly1305 is {aes_time/chacha_time:.1f}x faster")
            print(f"      (Better on systems without AES hardware acceleration)")
        
        print(f"\n💡 Algorithm Selection Guidelines:")
        print("  • AES-GCM: Use when hardware acceleration available (Intel AES-NI)")
        print("  • ChaCha20-Poly1305: Use on mobile/embedded devices")
        print("  • Both provide authenticated encryption")
        print("  • Both are quantum-resistant (current algorithms)")
    
    def security_recommendations(self):
        """Đưa ra recommendations về security"""
        print(f"\n🛡️  TLS SECURITY RECOMMENDATIONS")
        print(f"{'─'*100}")
        
        print("🔹 Protocol Version:")
        print("  ✅ Use TLS 1.3 when possible")
        print("  ✅ TLS 1.2 minimum for backward compatibility")
        print("  ❌ Disable TLS 1.1 and earlier")
        print("  ❌ Disable SSL 3.0 and earlier")
        
        print("\n🔹 Cipher Suite Selection:")
        print("  ✅ Prioritize ECDHE/DHE for Perfect Forward Secrecy")
        print("  ✅ Use AES-GCM or ChaCha20-Poly1305 for encryption")
        print("  ✅ SHA-256 or stronger for hashing")
        print("  ❌ Avoid RSA key exchange")
        print("  ❌ Avoid CBC mode ciphers (padding oracle attacks)")
        print("  ❌ Avoid RC4, 3DES, DES")
        
        print("\n🔹 Certificate Security:")
        print("  ✅ RSA 2048-bit minimum (4096-bit preferred)")
        print("  ✅ ECDSA P-256 or P-384")
        print("  ✅ SHA-256 signature algorithm")
        print("  ✅ Certificate validity ≤ 1 year")
        print("  ❌ Avoid SHA-1 signatures")
        print("  ❌ Avoid MD5 signatures")
        
        print("\n🔹 Implementation Security:")
        print("  ✅ Enable HSTS (HTTP Strict Transport Security)")
        print("  ✅ Certificate pinning for critical applications")
        print("  ✅ OCSP stapling for revocation checking")
        print("  ✅ Session resumption for performance")
        print("  ✅ Regular security updates")
        
        print("\n🔹 Configuration Examples:")
        print("  Apache/Nginx: Use Mozilla SSL Configuration Generator")
        print("  Python: Use ssl.create_default_context()")
        print("  OpenSSL: Update to latest version")
        print("  Cipher string: 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'")


if __name__ == "__main__":
    analyzer = TLSProtocolAnalyzer()
    analyzer.comprehensive_tls_analysis()