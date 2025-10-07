"""
Module quản lý chứng chỉ và khóa cho TLS/SSL
Sử dụng thư viện cryptography để tạo, quản lý và lưu chứng chỉ
"""
from datetime import datetime, timedelta
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class CertificateManager:
    """Quản lý tạo và lưu trữ chứng chỉ TLS/SSL"""
    
    def __init__(self):
        self.backend = default_backend()
        
        # Đảm bảo thư mục certs tồn tại
        os.makedirs("certs", exist_ok=True)
        
    def generate_private_key(self, key_size=2048):
        """Tạo khóa riêng tư RSA"""
        print(f"Đang tạo khóa RSA {key_size}-bit...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        print(f"✓ Đã tạo khóa RSA thành công")
        return private_key
    
    def create_self_signed_cert(self, private_key, common_name, days_valid=365):
        """Tạo chứng chỉ tự ký"""
        print(f"Đang tạo chứng chỉ cho {common_name}...")
        
        # Thông tin subject và issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Hanoi"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Hanoi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PTIT Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Tạo chứng chỉ
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
        
        print(f"✓ Đã tạo chứng chỉ thành công")
        return cert
    
    def save_certificate(self, cert, filename):
        """Lưu chứng chỉ vào file"""
        print(f"Đang lưu chứng chỉ vào {filename}...")
        with open(filename, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"✓ Đã lưu chứng chỉ: {filename}")
    
    def save_private_key(self, private_key, filename, password=None):
        """Lưu khóa riêng tư vào file"""
        print(f"Đang lưu khóa riêng tư vào {filename}...")
        
        # Sử dụng mã hóa nếu có mật khẩu
        encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        
        with open(filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        print(f"✓ Đã lưu khóa riêng tư: {filename}")
    
    def display_certificate_info(self, cert_path):
        """Hiển thị thông tin chứng chỉ từ file"""
        print(f"Thông tin chứng chỉ: {cert_path}")
        
        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                
                print(f"\nSubject: {cert.subject}")
                print(f"Issuer: {cert.issuer}")
                print(f"Valid from: {cert.not_valid_before}")
                print(f"Valid until: {cert.not_valid_after}")
                print(f"Serial number: {cert.serial_number}")
                print(f"Signature algorithm: {cert.signature_algorithm_oid._name}")
        except Exception as e:
            print(f"Lỗi khi đọc chứng chỉ: {e}")


if __name__ == "__main__":
    # Demo chức năng
    manager = CertificateManager()
    key = manager.generate_private_key()
    cert = manager.create_self_signed_cert(key, "localhost")
    manager.save_private_key(key, "certs/server.key")
    manager.save_certificate(cert, "certs/server.crt")
    manager.display_certificate_info("certs/server.crt")