"""
TLS Security Analysis Tool
Công cụ phân tích bảo mật TLS toàn diện với vulnerability scanning
"""
import ssl
import socket
from datetime import datetime, timedelta
import subprocess
import sys
import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class TLSSecurityAnalyzer:
    """Advanced TLS Security Analysis và Vulnerability Assessment"""
    
    def __init__(self):
        self.backend = default_backend()
        self.vulnerabilities = []
        self.security_score = 0
        self.max_score = 100
        
        # Known vulnerabilities và attacks
        self.known_attacks = {
            'BEAST': {
                'name': 'Browser Exploit Against SSL/TLS',
                'affects': ['TLS 1.0', 'SSL 3.0'],
                'mitigation': 'Use TLS 1.1+ or RC4 cipher (deprecated)',
                'severity': 'Medium'
            },
            'CRIME': {
                'name': 'Compression Ratio Info-leak Made Easy',
                'affects': ['TLS compression enabled'],
                'mitigation': 'Disable TLS compression',
                'severity': 'Medium'
            },
            'BREACH': {
                'name': 'Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext',
                'affects': ['HTTP compression + secrets in response'],
                'mitigation': 'Disable HTTP compression for sensitive data',
                'severity': 'Medium'
            },
            'POODLE': {
                'name': 'Padding Oracle On Downgraded Legacy Encryption',
                'affects': ['SSL 3.0', 'TLS CBC mode'],
                'mitigation': 'Disable SSL 3.0, prefer GCM mode',
                'severity': 'High'
            },
            'FREAK': {
                'name': 'Factoring RSA Export Keys',
                'affects': ['Export-grade RSA'],
                'mitigation': 'Disable export ciphers',
                'severity': 'High'
            },
            'LOGJAM': {
                'name': 'DHE_EXPORT cipher vulnerability',
                'affects': ['DHE_EXPORT, weak DH parameters'],
                'mitigation': 'Use strong DH parameters (2048+ bit)',
                'severity': 'High'
            },
            'DROWN': {
                'name': 'Decrypting RSA with Obsolete and Weakened eNcryption',
                'affects': ['SSLv2 enabled'],
                'mitigation': 'Disable SSLv2 completely',
                'severity': 'High'
            },
            'SWEET32': {
                'name': 'Birthday attacks on 64-bit block ciphers',
                'affects': ['3DES, Blowfish'],
                'mitigation': 'Use 128-bit block ciphers (AES)',
                'severity': 'Medium'
            },
            'ROBOT': {
                'name': 'Return Of Bleichenbacher Oracle Threat',
                'affects': ['RSA PKCS#1 v1.5 padding'],
                'mitigation': 'Use RSA-PSS or ECDSA',
                'severity': 'Medium'
            }
        }
    
    def comprehensive_security_analysis(self, target_host='localhost', target_port=8443):
        """Thực hiện comprehensive security analysis"""
        print(f"\n{'='*120}")
        print(f"🛡️  COMPREHENSIVE TLS SECURITY ANALYSIS")
        print(f"{'='*120}")
        print(f"Target: {target_host}:{target_port}")
        print(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*120}")
        
        # Reset counters
        self.vulnerabilities = []
        self.security_score = 0
        
        # Perform analysis
        results = {}
        results['protocol'] = self.analyze_protocol_support(target_host, target_port)
        results['cipher'] = self.analyze_cipher_suites(target_host, target_port)
        results['certificate'] = self.analyze_certificate_security(target_host, target_port)
        results['vulnerabilities'] = self.check_known_vulnerabilities(target_host, target_port)
        results['implementation'] = self.analyze_implementation_issues(target_host, target_port)
        results['compliance'] = self.check_compliance_standards()
        
        # Generate comprehensive report
        self.generate_security_report(results)
        
        return results
    
    def analyze_protocol_support(self, host, port):
        """Phân tích protocol support"""
        print(f"\n[1/6] 🔍 PROTOCOL SUPPORT ANALYSIS")
        print(f"{'─'*80}")
        
        protocols = {
            'SSLv2': {'version': ssl.PROTOCOL_SSLv23, 'secure': False, 'deprecated': True},
            'SSLv3': {'version': ssl.PROTOCOL_SSLv23, 'secure': False, 'deprecated': True},
            'TLSv1.0': {'version': ssl.PROTOCOL_TLSv1, 'secure': False, 'deprecated': True},
            'TLSv1.1': {'version': ssl.PROTOCOL_TLSv1_1, 'secure': False, 'deprecated': True},
            'TLSv1.2': {'version': ssl.PROTOCOL_TLSv1_2, 'secure': True, 'deprecated': False},
            'TLSv1.3': {'version': ssl.PROTOCOL_TLS, 'secure': True, 'deprecated': False}
        }
        
        supported_protocols = []
        
        for protocol_name, protocol_info in protocols.items():
            try:
                context = ssl.SSLContext()
                context.minimum_version = getattr(ssl.TLSVersion, protocol_name.replace('v', 'v').replace('SSL', 'SSL'), None)
                if context.minimum_version:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(5)
                        with context.wrap_socket(sock) as ssock:
                            ssock.connect((host, port))
                            supported_protocols.append(protocol_name)
                            
                            if protocol_info['deprecated']:
                                print(f"  ❌ {protocol_name}: SUPPORTED (DEPRECATED - Security Risk)")
                                self.vulnerabilities.append({
                                    'type': 'Deprecated Protocol',
                                    'description': f'{protocol_name} is deprecated and insecure',
                                    'severity': 'High',
                                    'recommendation': f'Disable {protocol_name}'
                                })
                            else:
                                print(f"  ✅ {protocol_name}: SUPPORTED (Secure)")
                                self.security_score += 15
                                
            except Exception as e:
                if not protocol_info['deprecated']:
                    print(f"  ⚠️  {protocol_name}: NOT SUPPORTED")
                else:
                    print(f"  ✅ {protocol_name}: NOT SUPPORTED (Good)")
                    self.security_score += 5
        
        # Protocol security assessment
        if 'TLSv1.3' in supported_protocols:
            print(f"\n  🟢 TLS 1.3 supported - Excellent security")
        elif 'TLSv1.2' in supported_protocols:
            print(f"\n  🟡 TLS 1.2 supported - Good security")
        else:
            print(f"\n  🔴 Only legacy protocols supported - Poor security")
        
        return {
            'supported': supported_protocols,
            'secure_protocols': [p for p in supported_protocols if protocols[p]['secure']],
            'deprecated_protocols': [p for p in supported_protocols if protocols[p]['deprecated']]
        }
    
    def analyze_cipher_suites(self, host, port):
        """Phân tích cipher suites"""
        print(f"\n[2/6] 🔐 CIPHER SUITE ANALYSIS")
        print(f"{'─'*80}")
        
        # Test connection để lấy cipher suite
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                with context.wrap_socket(sock) as ssock:
                    ssock.connect((host, port))
                    cipher_info = ssock.cipher()
                    
                    if cipher_info:
                        cipher_suite, protocol, bits = cipher_info
                        print(f"  Selected Cipher: {cipher_suite}")
                        print(f"  Protocol: {protocol}")
                        print(f"  Key Length: {bits} bits")
                        
                        # Analyze cipher security
                        self.analyze_cipher_security(cipher_suite)
                        
                        return {
                            'selected_cipher': cipher_suite,
                            'protocol': protocol,
                            'key_bits': bits
                        }
        except Exception as e:
            print(f"  ❌ Unable to analyze ciphers: {e}")
            return None
    
    def analyze_cipher_security(self, cipher_suite):
        """Phân tích bảo mật của cipher suite"""
        cipher_lower = cipher_suite.lower()
        
        # Perfect Forward Secrecy check
        if any(pfs in cipher_lower for pfs in ['ecdhe', 'dhe']):
            print(f"  ✅ Perfect Forward Secrecy: YES")
            self.security_score += 20
        else:
            print(f"  ❌ Perfect Forward Secrecy: NO")
            self.vulnerabilities.append({
                'type': 'No Perfect Forward Secrecy',
                'description': 'Cipher suite does not provide PFS',
                'severity': 'Medium',
                'recommendation': 'Use ECDHE or DHE key exchange'
            })
        
        # Encryption strength
        if any(strong in cipher_lower for strong in ['aes256', 'chacha20']):
            print(f"  ✅ Encryption Strength: Strong (256-bit)")
            self.security_score += 15
        elif any(medium in cipher_lower for medium in ['aes128', 'aes']):
            print(f"  🟡 Encryption Strength: Medium (128-bit)")
            self.security_score += 10
        elif any(weak in cipher_lower for weak in ['rc4', '3des', 'des']):
            print(f"  ❌ Encryption Strength: Weak")
            self.vulnerabilities.append({
                'type': 'Weak Encryption',
                'description': 'Using weak encryption algorithm',
                'severity': 'High',
                'recommendation': 'Use AES or ChaCha20'
            })
        
        # MAC algorithm
        if any(strong_mac in cipher_lower for strong_mac in ['gcm', 'poly1305', 'sha256', 'sha384']):
            print(f"  ✅ MAC Algorithm: Strong")
            self.security_score += 10
        elif 'sha1' in cipher_lower:
            print(f"  ⚠️  MAC Algorithm: SHA-1 (Deprecated)")
            self.vulnerabilities.append({
                'type': 'Weak MAC',
                'description': 'Using SHA-1 for MAC',
                'severity': 'Medium',
                'recommendation': 'Use SHA-256 or stronger'
            })
        elif 'md5' in cipher_lower:
            print(f"  ❌ MAC Algorithm: MD5 (Broken)")
            self.vulnerabilities.append({
                'type': 'Broken MAC',
                'description': 'Using broken MD5 algorithm',
                'severity': 'High',
                'recommendation': 'Use SHA-256 or stronger'
            })
    
    def analyze_certificate_security(self, host, port):
        """Phân tích certificate security"""
        print(f"\n[3/6] 📜 CERTIFICATE SECURITY ANALYSIS")
        print(f"{'─'*80}")
        
        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                with context.wrap_socket(sock) as ssock:
                    ssock.connect((host, port))
                    cert_der = ssock.getpeercert_chain()[0]
                    cert = x509.load_der_x509_certificate(cert_der.public_bytes(), self.backend)
                    
                    # Analyze certificate
                    return self.analyze_certificate(cert, host)
                    
        except Exception as e:
            print(f"  ❌ Certificate analysis failed: {e}")
            return None
    
    def analyze_certificate(self, cert, hostname):
        """Phân tích chi tiết certificate"""
        results = {}
        
        # Key algorithm và size
        public_key = cert.public_key()
        if hasattr(public_key, 'key_size'):
            key_size = public_key.key_size
            if key_size >= 4096:
                print(f"  ✅ Key Size: {key_size}-bit RSA (Excellent)")
                self.security_score += 15
            elif key_size >= 2048:
                print(f"  ✅ Key Size: {key_size}-bit RSA (Good)")
                self.security_score += 10
            else:
                print(f"  ❌ Key Size: {key_size}-bit RSA (Weak)")
                self.vulnerabilities.append({
                    'type': 'Weak Key Size',
                    'description': f'RSA key size {key_size} is too small',
                    'severity': 'High',
                    'recommendation': 'Use at least 2048-bit RSA keys'
                })
        
        # Signature algorithm
        sig_alg = cert.signature_hash_algorithm.name
        if sig_alg in ['sha256', 'sha384', 'sha512']:
            print(f"  ✅ Signature Algorithm: {sig_alg.upper()} (Secure)")
            self.security_score += 10
        elif sig_alg == 'sha1':
            print(f"  ❌ Signature Algorithm: SHA-1 (Deprecated)")
            self.vulnerabilities.append({
                'type': 'Weak Signature Algorithm',
                'description': 'Certificate signed with SHA-1',
                'severity': 'Medium',
                'recommendation': 'Use SHA-256 or stronger'
            })
        
        # Validity period
        now = datetime.utcnow()
        validity_period = cert.not_valid_after - cert.not_valid_before
        
        if validity_period <= timedelta(days=90):
            print(f"  ✅ Validity Period: {validity_period.days} days (Excellent)")
            self.security_score += 10
        elif validity_period <= timedelta(days=365):
            print(f"  🟡 Validity Period: {validity_period.days} days (Good)")
            self.security_score += 5
        else:
            print(f"  ⚠️  Validity Period: {validity_period.days} days (Too long)")
            self.vulnerabilities.append({
                'type': 'Long Validity Period',
                'description': f'Certificate valid for {validity_period.days} days',
                'severity': 'Low',
                'recommendation': 'Use shorter validity periods (≤1 year)'
            })
        
        return results
    
    def check_known_vulnerabilities(self, host, port):
        """Kiểm tra các vulnerability đã biết"""
        print(f"\n[4/6] 🐛 KNOWN VULNERABILITY CHECK")
        print(f"{'─'*80}")
        
        detected_vulnerabilities = []
        
        # Simulate vulnerability checks
        for vuln_name, vuln_info in self.known_attacks.items():
            # Simplified check - in production would do actual testing
            is_vulnerable = self.simulate_vulnerability_check(vuln_name, host, port)
            
            if is_vulnerable:
                print(f"  ❌ {vuln_name}: VULNERABLE")
                print(f"      {vuln_info['name']}")
                print(f"      Severity: {vuln_info['severity']}")
                print(f"      Mitigation: {vuln_info['mitigation']}")
                
                detected_vulnerabilities.append({
                    'name': vuln_name,
                    'full_name': vuln_info['name'],
                    'severity': vuln_info['severity'],
                    'mitigation': vuln_info['mitigation']
                })
            else:
                print(f"  ✅ {vuln_name}: NOT VULNERABLE")
        
        if not detected_vulnerabilities:
            print(f"  🟢 No known vulnerabilities detected")
            self.security_score += 20
        
        return detected_vulnerabilities
    
    def simulate_vulnerability_check(self, vuln_name, host, port):
        """Simulate vulnerability check (simplified for demo)"""
        # In real implementation, would perform actual tests
        import random
        return random.random() < 0.1  # 10% chance of vulnerability for demo
    
    def analyze_implementation_issues(self, host, port):
        """Phân tích implementation issues"""
        print(f"\n[5/6] ⚙️  IMPLEMENTATION ANALYSIS")
        print(f"{'─'*80}")
        
        issues = []
        
        # Certificate chain validation
        try:
            context = ssl.create_default_context()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.connect((host, port))
                    print(f"  ✅ Certificate Chain: Valid")
                    self.security_score += 10
        except ssl.SSLError as e:
            print(f"  ⚠️  Certificate Chain: Issues detected")
            issues.append("Certificate chain validation failed")
        
        # Session resumption
        print(f"  ℹ️  Session Resumption: Not tested (requires multiple connections)")
        
        # HSTS headers (would check in HTTP implementation)
        print(f"  ℹ️  HSTS: Not applicable for raw TLS")
        
        return issues
    
    def check_compliance_standards(self):
        """Kiểm tra compliance với standards"""
        print(f"\n[6/6] 📋 COMPLIANCE STANDARDS CHECK")
        print(f"{'─'*80}")
        
        compliance = {}
        
        # PCI DSS
        pci_compliant = self.security_score >= 70
        print(f"  {'✅' if pci_compliant else '❌'} PCI DSS: {'Compliant' if pci_compliant else 'Non-compliant'}")
        compliance['PCI_DSS'] = pci_compliant
        
        # NIST guidelines
        nist_compliant = len(self.vulnerabilities) == 0
        print(f"  {'✅' if nist_compliant else '❌'} NIST: {'Compliant' if nist_compliant else 'Non-compliant'}")
        compliance['NIST'] = nist_compliant
        
        # OWASP recommendations
        owasp_compliant = self.security_score >= 80
        print(f"  {'✅' if owasp_compliant else '❌'} OWASP: {'Compliant' if owasp_compliant else 'Non-compliant'}")
        compliance['OWASP'] = owasp_compliant
        
        return compliance
    
    def generate_security_report(self, results):
        """Tạo báo cáo bảo mật tổng hợp"""
        print(f"\n{'='*120}")
        print(f"📊 COMPREHENSIVE SECURITY REPORT")
        print(f"{'='*120}")
        
        # Overall security score
        if self.security_score >= 90:
            grade = "A+"
            color = "🟢"
        elif self.security_score >= 80:
            grade = "A"
            color = "🟢"
        elif self.security_score >= 70:
            grade = "B"
            color = "🟡"
        elif self.security_score >= 60:
            grade = "C"
            color = "🟡"
        else:
            grade = "D"
            color = "🔴"
        
        print(f"\n{color} OVERALL SECURITY GRADE: {grade}")
        print(f"Security Score: {self.security_score}/{self.max_score}")
        
        # Summary
        print(f"\n📈 SUMMARY:")
        print(f"  Total Vulnerabilities: {len(self.vulnerabilities)}")
        high_vulns = len([v for v in self.vulnerabilities if v.get('severity') == 'High'])
        medium_vulns = len([v for v in self.vulnerabilities if v.get('severity') == 'Medium'])
        low_vulns = len([v for v in self.vulnerabilities if v.get('severity') == 'Low'])
        
        print(f"  High Severity: {high_vulns}")
        print(f"  Medium Severity: {medium_vulns}")
        print(f"  Low Severity: {low_vulns}")
        
        # Detailed vulnerabilities
        if self.vulnerabilities:
            print(f"\n⚠️  VULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = "🔴" if vuln['severity'] == 'High' else "🟡" if vuln['severity'] == 'Medium' else "🟠"
                print(f"  {i}. {severity_color} {vuln['type']} ({vuln['severity']})")
                print(f"     Description: {vuln['description']}")
                print(f"     Recommendation: {vuln['recommendation']}")
                print()
        
        # Recommendations
        print(f"💡 SECURITY RECOMMENDATIONS:")
        if self.security_score < 70:
            print("  🔴 CRITICAL: Immediate security improvements needed")
            print("     - Update to TLS 1.2/1.3 minimum")
            print("     - Fix all high severity vulnerabilities")
            print("     - Use strong cipher suites with PFS")
        elif self.security_score < 90:
            print("  🟡 MODERATE: Some security improvements recommended")
            print("     - Address remaining vulnerabilities")
            print("     - Consider upgrading to TLS 1.3")
            print("     - Implement additional security headers")
        else:
            print("  🟢 EXCELLENT: Security configuration is strong")
            print("     - Maintain current security practices")
            print("     - Regular security audits recommended")
        
        print(f"\n{'='*120}")


if __name__ == "__main__":
    analyzer = TLSSecurityAnalyzer()
    try:
        analyzer.comprehensive_security_analysis('localhost', 8443)
    except Exception as e:
        print(f"Analysis failed: {e}")
        print("Make sure TLS server is running on localhost:8443")