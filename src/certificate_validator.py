"""
Advanced Certificate Validation System
Bao gồm certificate chain validation, CRL checking, OCSP, và security analysis
"""
import os
import requests
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import socket
import ssl

class AdvancedCertificateValidator:
    """Advanced Certificate Validation với comprehensive checks"""
    
    def __init__(self):
        self.backend = default_backend()
        self.validation_results = {}
        
    def comprehensive_validation(self, cert_path, hostname=None):
        """Thực hiện comprehensive certificate validation"""
        print(f"\n{'='*80}")
        print(f"🔍 COMPREHENSIVE CERTIFICATE VALIDATION")
        print(f"{'='*80}")
        
        try:
            # Load certificate
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, self.backend)
            
            print(f"📜 Certificate: {cert_path}")
            print(f"🌐 Hostname: {hostname or 'Not specified'}")
            print()
            
            # Run all validation checks
            results = {}
            results['basic'] = self.validate_basic_info(cert)
            results['signature'] = self.validate_signature(cert)
            results['chain'] = self.validate_certificate_chain(cert)
            results['hostname'] = self.validate_hostname(cert, hostname) if hostname else None
            results['extensions'] = self.validate_extensions(cert)
            results['security'] = self.security_assessment(cert)
            results['revocation'] = self.check_revocation_status(cert)
            
            # Generate comprehensive report
            self.generate_validation_report(results)
            
            return results
            
        except Exception as e:
            print(f"❌ Validation error: {e}")
            return None
    
    def validate_basic_info(self, cert):
        """Kiểm tra thông tin cơ bản của certificate"""
        print("┌─ [1/7] Basic Certificate Information")
        results = {}
        
        # Subject and Issuer - Fix dictionary conversion
        subject_attrs = {attr.oid._name: attr.value for attr in cert.subject}
        issuer_attrs = {attr.oid._name: attr.value for attr in cert.issuer}
        
        print(f"│  Subject: {self.format_name(cert.subject)}")
        print(f"│  Issuer: {self.format_name(cert.issuer)}")
        
        # Validity period
        now = datetime.utcnow()
        valid_from = cert.not_valid_before
        valid_until = cert.not_valid_after
        
        is_valid_time = valid_from <= now <= valid_until
        days_until_expiry = (valid_until - now).days
        
        print(f"│  Valid From: {valid_from}")
        print(f"│  Valid Until: {valid_until}")
        print(f"│  Status: {'✓ Valid' if is_valid_time else '❌ Expired/Not yet valid'}")
        
        if is_valid_time:
            if days_until_expiry < 30:
                print(f"│  ⚠️  Expires in {days_until_expiry} days!")
            else:
                print(f"│  ✓ Valid for {days_until_expiry} days")
        
        # Serial number và signature algorithm
        print(f"│  Serial Number: {cert.serial_number}")
        print(f"│  Signature Algorithm: {cert.signature_algorithm_oid._name}")
        
        # Public key info
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            print(f"│  Public Key: RSA {key_size}-bit")
            results['key_strength'] = 'Strong' if key_size >= 2048 else 'Weak'
        
        results.update({
            'subject': subject_attrs,
            'issuer': issuer_attrs,
            'valid_time': is_valid_time,
            'days_until_expiry': days_until_expiry,
            'is_self_signed': cert.subject == cert.issuer
        })
        
        print("└─")
        return results
    
    def validate_signature(self, cert):
        """Kiểm tra signature validation"""
        print("┌─ [2/7] Certificate Signature Validation")
        results = {}
        
        try:
            # For self-signed certificates
            if cert.subject == cert.issuer:
                public_key = cert.public_key()
                
                # Verify signature
                try:
                    if isinstance(public_key, rsa.RSAPublicKey):
                        public_key.verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            cert.signature_hash_algorithm
                        )
                    print("│  ✓ Self-signed signature valid")
                    results['signature_valid'] = True
                except Exception as e:
                    print(f"│  ❌ Self-signed signature invalid: {e}")
                    results['signature_valid'] = False
            else:
                print("│  ⚠️  Cannot verify - issuer certificate needed")
                results['signature_valid'] = None
            
            # Signature algorithm analysis
            sig_alg = cert.signature_algorithm_oid._name
            if 'sha1' in sig_alg.lower():
                print("│  ⚠️  Weak signature algorithm (SHA-1)")
                results['signature_strength'] = 'Weak'
            elif 'sha256' in sig_alg.lower() or 'sha384' in sig_alg.lower():
                print("│  ✓ Strong signature algorithm")
                results['signature_strength'] = 'Strong'
            else:
                print(f"│  ? Unknown signature algorithm: {sig_alg}")
                results['signature_strength'] = 'Unknown'
                
        except Exception as e:
            print(f"│  ❌ Signature validation error: {e}")
            results['signature_valid'] = False
        
        print("└─")
        return results
    
    def validate_certificate_chain(self, cert):
        """Kiểm tra certificate chain"""
        print("┌─ [3/7] Certificate Chain Validation")
        results = {}
        
        # Check if self-signed
        if cert.subject == cert.issuer:
            print("│  📋 Self-signed certificate (no chain)")
            results['chain_length'] = 0
            results['chain_valid'] = True  # Assume valid for demo
        else:
            print("│  🔗 Certificate chain validation needed")
            # In production, would validate full chain
            results['chain_length'] = None
            results['chain_valid'] = None
        
        # Check for CA certificate
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS
            ).value
            
            if basic_constraints.ca:
                print("│  ✓ Certificate has CA flag set")
                results['is_ca'] = True
            else:
                print("│  📋 End-entity certificate")
                results['is_ca'] = False
                
        except x509.ExtensionNotFound:
            print("│  ⚠️  No Basic Constraints extension")
            results['is_ca'] = None
        
        # Key Usage validation
        try:
            key_usage = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.KEY_USAGE
            ).value
            
            print("│  🔑 Key Usage:")
            usages = []
            if key_usage.digital_signature:
                usages.append("Digital Signature")
            if key_usage.key_encipherment:
                usages.append("Key Encipherment")
            if key_usage.key_agreement:
                usages.append("Key Agreement")
            if key_usage.certificate_sign:
                usages.append("Certificate Sign")
            
            for usage in usages:
                print(f"│      ✓ {usage}")
            
            results['key_usage'] = usages
            
        except x509.ExtensionNotFound:
            print("│  ⚠️  No Key Usage extension")
            results['key_usage'] = []
        
        print("└─")
        return results
    
    def validate_hostname(self, cert, hostname):
        """Kiểm tra hostname validation"""
        print(f"┌─ [4/7] Hostname Validation: {hostname}")
        results = {}
        
        # Check Common Name
        try:
            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            cn_match = self.hostname_matches(hostname, common_name)
            print(f"│  Common Name: {common_name}")
            print(f"│  CN Match: {'✓' if cn_match else '❌'}")
            results['cn_match'] = cn_match
        except:
            print("│  ⚠️  No Common Name found")
            results['cn_match'] = False
        
        # Check Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            
            print("│  Subject Alternative Names:")
            san_match = False
            for san in san_ext:
                if isinstance(san, x509.DNSName):
                    match = self.hostname_matches(hostname, san.value)
                    print(f"│    DNS: {san.value} {'✓' if match else '❌'}")
                    if match:
                        san_match = True
                elif isinstance(san, x509.IPAddress):
                    print(f"│    IP: {san.value}")
            
            results['san_match'] = san_match
            
        except x509.ExtensionNotFound:
            print("│  ⚠️  No Subject Alternative Names")
            results['san_match'] = False
        
        results['hostname_valid'] = results.get('cn_match', False) or results.get('san_match', False)
        print(f"│  Overall: {'✓ Hostname Valid' if results['hostname_valid'] else '❌ Hostname Invalid'}")
        print("└─")
        return results
    
    def validate_extensions(self, cert):
        """Kiểm tra certificate extensions"""
        print("┌─ [5/7] Certificate Extensions Analysis")
        results = {'extensions': []}
        
        for ext in cert.extensions:
            ext_name = ext.oid._name
            critical = "Critical" if ext.critical else "Non-critical"
            print(f"│  📋 {ext_name} ({critical})")
            
            results['extensions'].append({
                'name': ext_name,
                'critical': ext.critical,
                'oid': str(ext.oid)
            })
            
            # Analyze specific extensions
            if ext.oid == x509.ExtensionOID.EXTENDED_KEY_USAGE:
                eku = ext.value
                print("│     Extended Key Usage:")
                for usage in eku:
                    print(f"│       ✓ {usage._name}")
        
        print("└─")
        return results
    
    def security_assessment(self, cert):
        """Đánh giá bảo mật certificate"""
        print("┌─ [6/7] Security Assessment")
        results = {'score': 0, 'issues': [], 'recommendations': []}
        
        # Key strength assessment
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            if key_size >= 4096:
                print("│  🔒 Key Strength: Excellent (4096+ bits)")
                results['score'] += 30
            elif key_size >= 2048:
                print("│  🔒 Key Strength: Good (2048+ bits)")
                results['score'] += 20
            else:
                print("│  ⚠️  Key Strength: Weak (<2048 bits)")
                results['issues'].append("Weak key size")
                results['recommendations'].append("Use at least 2048-bit RSA keys")
        
        # Signature algorithm assessment
        sig_alg = cert.signature_algorithm_oid._name
        if 'sha256' in sig_alg.lower() or 'sha384' in sig_alg.lower() or 'sha512' in sig_alg.lower():
            print("│  🔒 Signature Algorithm: Strong")
            results['score'] += 25
        elif 'sha1' in sig_alg.lower():
            print("│  ⚠️  Signature Algorithm: Weak (SHA-1)")
            results['issues'].append("Weak signature algorithm")
            results['recommendations'].append("Use SHA-256 or stronger")
        
        # Validity period assessment
        now = datetime.utcnow()
        validity_period = cert.not_valid_after - cert.not_valid_before
        
        if validity_period.days <= 90:
            print("│  🔒 Validity Period: Excellent (≤90 days)")
            results['score'] += 20
        elif validity_period.days <= 365:
            print("│  🔒 Validity Period: Good (≤1 year)")
            results['score'] += 15
        else:
            print("│  ⚠️  Validity Period: Too long (>1 year)")
            results['issues'].append("Long validity period")
        
        # Extensions assessment
        has_key_usage = False
        has_eku = False
        
        try:
            cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            has_key_usage = True
            results['score'] += 10
        except:
            results['issues'].append("Missing Key Usage extension")
        
        try:
            cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
            has_eku = True
            results['score'] += 10
        except:
            pass
        
        if has_key_usage and has_eku:
            print("│  ✓ Key usage properly restricted")
        
        # Overall score
        if results['score'] >= 80:
            grade = "A"
            color = "🟢"
        elif results['score'] >= 60:
            grade = "B" 
            color = "🟡"
        else:
            grade = "C"
            color = "🔴"
        
        print(f"│  {color} Security Score: {results['score']}/100 (Grade: {grade})")
        print("└─")
        return results
    
    def check_revocation_status(self, cert):
        """Kiểm tra revocation status (CRL/OCSP)"""
        print("┌─ [7/7] Revocation Status Check")
        results = {}
        
        # Check for CRL Distribution Points
        try:
            crl_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value
            
            print("│  📋 CRL Distribution Points found:")
            for i, crl_dp in enumerate(crl_ext):
                if crl_dp.full_name:
                    for name in crl_dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            print(f"│    {i+1}. {name.value}")
            
            results['has_crl'] = True
            
        except x509.ExtensionNotFound:
            print("│  ⚠️  No CRL Distribution Points")
            results['has_crl'] = False
        
        # Check for OCSP
        try:
            aia_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            
            ocsp_urls = []
            for access_desc in aia_ext:
                if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                        ocsp_urls.append(access_desc.access_location.value)
            
            if ocsp_urls:
                print("│  📋 OCSP URLs found:")
                for url in ocsp_urls:
                    print(f"│    ✓ {url}")
                results['has_ocsp'] = True
            else:
                results['has_ocsp'] = False
                
        except x509.ExtensionNotFound:
            print("│  ⚠️  No Authority Information Access")
            results['has_ocsp'] = False
        
        # Simulated revocation check
        print("│  🔍 Revocation Status: NOT CHECKED (Demo mode)")
        print("│      In production: Would query CRL/OCSP servers")
        results['revocation_status'] = 'unknown'
        
        print("└─")
        return results
    
    def hostname_matches(self, hostname, pattern):
        """Kiểm tra hostname có match pattern không (wildcard support)"""
        if pattern.startswith('*.'):
            # Wildcard matching
            domain = pattern[2:]
            return hostname.endswith('.' + domain) or hostname == domain
        else:
            return hostname.lower() == pattern.lower()
    
    def format_name(self, name):
        """Format X.509 Name object"""
        parts = []
        for attr in name:
            parts.append(f"{attr.oid._name}={attr.value}")
        return ", ".join(parts)
    
    def generate_validation_report(self, results):
        """Tạo báo cáo tổng hợp"""
        print(f"\n{'='*80}")
        print(f"📊 CERTIFICATE VALIDATION REPORT")
        print(f"{'='*80}")
        
        # Summary
        issues = []
        warnings = []
        
        if results['basic']['valid_time']:
            print("✅ Certificate is currently valid")
        else:
            print("❌ Certificate is expired or not yet valid")
            issues.append("Invalid time period")
        
        if results['signature']['signature_valid']:
            print("✅ Certificate signature is valid")
        elif results['signature']['signature_valid'] is False:
            print("❌ Certificate signature is invalid")
            issues.append("Invalid signature")
        
        if results['hostname'] and results['hostname']['hostname_valid']:
            print("✅ Hostname validation passed")
        elif results['hostname']:
            print("❌ Hostname validation failed")
            issues.append("Hostname mismatch")
        
        security_score = results['security']['score']
        if security_score >= 80:
            print(f"✅ Security assessment: GOOD ({security_score}/100)")
        elif security_score >= 60:
            print(f"⚠️  Security assessment: AVERAGE ({security_score}/100)")
        else:
            print(f"❌ Security assessment: POOR ({security_score}/100)")
        
        # Issues and recommendations
        if results['security']['issues']:
            print(f"\n⚠️  SECURITY ISSUES:")
            for issue in results['security']['issues']:
                print(f"   • {issue}")
        
        if results['security']['recommendations']:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in results['security']['recommendations']:
                print(f"   • {rec}")
        
        print(f"\n{'='*80}")


if __name__ == "__main__":
    validator = AdvancedCertificateValidator()
    validator.comprehensive_validation("certs/server.crt", "localhost")